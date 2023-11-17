// SPDX-License-Identifier: GPL-2.0+

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/videodev2.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <media/frame_vector.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-event.h>
#include <media/videobuf2-memops.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>

#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>

#include "linux/videodev2.h"
#include "protocol.h"
#include "session.h"
#include "descriptor.h"

#define VIRTIO_MEDIA_NUM_EVENT_BUFS 16

#define DEFAULT_DRIVER_NAME "virtio_media"

/* High-enough number to not conflict with the official virtio device numbers */
#define VIRTIO_ID_MEDIA 0x3b

/*
 * Name of the driver to expose to user-space.
 *
 * This is configurable because v4l2-compliance has workarounds specific to
 * some drivers. When proxying these directly from the host, this allows it to
 * apply them as needed.
 */
static char *driver_name = NULL;
module_param(driver_name, charp, 0660);

/**
 * Virtio-media device.
 */
struct virtio_media {
	struct v4l2_device v4l2_dev;
	struct video_device video_dev;

	struct virtio_device *virtio_dev;
	struct virtqueue *commandq;
	struct virtqueue *eventq;
	struct work_struct eventq_work;

	/* Buffer for event descriptors. */
	void *event_buffer;

	/* List of active decoding sessions */
	struct list_head sessions;
	/* Protects `sessions` */
	struct mutex sessions_lock;

	/* Make sure we don't have two threads processing events at the same time */
	struct mutex events_process_lock;

	union {
		struct virtio_media_cmd_open open;
		struct virtio_media_cmd_munmap munmap;
	} cmd;

	union {
		struct virtio_media_resp_open open;
		struct virtio_media_resp_munmap munmap;
	} resp;

	/* Protects `cmd_buf` and `resp_buf` */
	struct mutex bufs_lock;

	/* Waitqueue for host responses on the command queue */
	wait_queue_head_t wq;
};

static inline struct virtio_media *
to_virtio_media(struct video_device *video_dev)
{
	return container_of(video_dev, struct virtio_media, video_dev);
}

#define DESC_CHAIN_MAX_LEN SG_MAX_SINGLE_ALLOC

/**
 * Allocate a new session. The id and list fields must still be set by the caller.
 */
static struct virtio_media_session *
virtio_media_session_alloc(struct virtio_media *vv, u32 id,
			   bool nonblocking_dequeue)
{
	struct virtio_media_session *session;
	int i;
	int ret;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		goto err_session;

	session->shadow_buf = kzalloc(VIRTIO_BUF_SIZE, GFP_KERNEL);
	if (!session->shadow_buf)
		goto err_shadow_buf;

	ret = sg_alloc_table(&session->command_sgs, DESC_CHAIN_MAX_LEN,
			     GFP_KERNEL);
	if (ret) {
		goto err_payload_sgs;
	}

	session->id = id;
	session->nonblocking_dequeue = nonblocking_dequeue;

	INIT_LIST_HEAD(&session->list);
	v4l2_fh_init(&session->fh, &vv->video_dev);
	v4l2_fh_add(&session->fh);

	for (i = 0; i <= VIRTIO_MEDIA_LAST_QUEUE; i++)
		INIT_LIST_HEAD(&session->queues[i].pending_dqbufs);
	mutex_init(&session->dqbufs_lock);

	init_waitqueue_head(&session->dqbufs_wait);

	mutex_lock(&vv->sessions_lock);
	list_add_tail(&session->list, &vv->sessions);
	mutex_unlock(&vv->sessions_lock);

	return session;

err_payload_sgs:
	kfree(session->shadow_buf);
err_shadow_buf:
	kfree(session);
err_session:
	return ERR_PTR(-ENOMEM);
}

/**
 * Close and destroy `session`.
 */
static void virtio_media_session_close(struct virtio_media *vv,
				       struct virtio_media_session *session)
{
	int i;

	mutex_lock(&vv->sessions_lock);
	list_del(&session->list);
	mutex_unlock(&vv->sessions_lock);

	v4l2_fh_del(&session->fh);
	v4l2_fh_exit(&session->fh);

	sg_free_table(&session->command_sgs);

	for (i = 0; i <= VIRTIO_MEDIA_LAST_QUEUE; i++)
		if (session->queues[i].buffers)
			vfree(session->queues[i].buffers);

	kfree(session->shadow_buf);
	kfree(session);
}

/**
 * Lookup the session with `id`.
 */
static struct virtio_media_session *
virtio_media_find_session(struct virtio_media *vv, u32 id)
{
	struct list_head *p;
	struct virtio_media_session *session = NULL;

	mutex_lock(&vv->sessions_lock);
	list_for_each(p, &vv->sessions) {
		struct virtio_media_session *s =
			list_entry(p, struct virtio_media_session, list);
		if (s->id == id) {
			session = s;
			break;
		}
	}
	mutex_unlock(&vv->sessions_lock);

	return session;
}

/**
 * Callback parameters to the virtio command queue.
 */
struct virtio_media_cmd_callback_param {
	struct virtio_media *vv;
	/* Flag to switch once the command is completed */
	bool done_flag;
	/* Size of the received response */
	size_t resp_len;
};

/**
 * Callback for the command queue. This just wakes up the thread that was
 * waiting on the command to complete.
 */
static void commandq_callback(struct virtqueue *queue)
{
	unsigned int len;
	struct virtio_media_cmd_callback_param *param;

	while ((param = virtqueue_get_buf(queue, &len))) {
		param->done_flag = true;
		param->resp_len = len;
		wake_up(&param->vv->wq);
	}

	virtqueue_enable_cb(queue);
}

/**
 * Returns 0 in case of success, or a negative error code.
 */
static int virtio_media_kick_command(struct virtio_media *vv,
				     struct scatterlist **sgs,
				     const size_t out_sgs, const size_t in_sgs,
				     size_t *resp_len)
{
	struct virtio_media_cmd_callback_param cb_param = {
		.vv = vv,
		.done_flag = false,
		.resp_len = 0,
	};
	struct virtio_media_resp_header *resp_header;
	int ret;

	ret = virtqueue_add_sgs(vv->commandq, sgs, out_sgs, in_sgs, &cb_param,
				GFP_ATOMIC);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to add sgs to command virtqueue\n");
		return ret;
	}

	if (!virtqueue_kick(vv->commandq)) {
		v4l2_err(&vv->v4l2_dev, "failed to kick command virtqueue\n");
		return -EINVAL;
	}

	/* Wait for the response. */
	ret = wait_event_timeout(vv->wq, cb_param.done_flag, 5 * HZ);
	if (ret == 0) {
		v4l2_err(&vv->v4l2_dev,
			 "timed out waiting for response to command\n");
		return -ETIMEDOUT;
	}

	if (resp_len)
		*resp_len = cb_param.resp_len;

	if (in_sgs > 0) {
		/* 
		 * If we expect a response, make sure we have at least a response header - anything shorter is
		 * invalid.
		 */
		if (cb_param.resp_len < sizeof(*resp_header)) {
			v4l2_err(&vv->v4l2_dev,
				 "received response header is too short\n");
			return -EINVAL;
		}

		resp_header = sg_virt(sgs[out_sgs]);
		if (resp_header->status)
			/* Host returns a positive error code. */
			return -resp_header->status;
	}

	return 0;
}

/**
 * Send a command to the host and wait for its response.
 * @vv: the virtio_media device to communicate with.
 * @minimum_resp_len: the minimum length of the response expected by the caller
 * in case the command succeeded. Anything shorter than that will result in an
 * error.
 *
 * Returns 0 in case of success or an error code. If an error is returned,
 * resp_len might not have been updated.
 */
static int virtio_media_send_command(struct virtio_media *vv,
				     struct scatterlist **sgs,
				     const size_t out_sgs, const size_t in_sgs,
				     size_t minimum_resp_len, size_t *resp_len)
{
	size_t local_resp_len = resp_len ? *resp_len : 0;
	int ret = virtio_media_kick_command(vv, sgs, out_sgs, in_sgs,
					    &local_resp_len);
	if (resp_len)
		*resp_len = local_resp_len;

	/* If the host could not process the command, there is no valid response */
	if (ret < 0)
		return ret;

	/* Make sure the host wrote a complete reply. */
	if (local_resp_len < minimum_resp_len) {
		v4l2_err(
			&vv->v4l2_dev,
			"received response is too short: received %d, expected at least %zu\n",
			local_resp_len, minimum_resp_len);
		return -EINVAL;
	}

	return 0;
}

/**
 * Send the event buffer to the host so it can return it back to us filled with
 * the next event that occurred.
 */
static int virtio_media_send_event_buffer(struct virtio_media *vv,
					  void *event_buffer)
{
	struct scatterlist *sgs[1], vresp;
	int ret;

	sg_init_one(&vresp, event_buffer, VIRTIO_MEDIA_EVENT_MAX_SIZE);
	sgs[0] = &vresp;

	ret = virtqueue_add_sgs(vv->eventq, sgs, 0, 1, event_buffer,
				GFP_ATOMIC);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to add sgs to event virtqueue\n");
		return ret;
	}

	if (!virtqueue_kick(vv->eventq)) {
		v4l2_err(&vv->v4l2_dev, "failed to kick event virtqueue\n");
		return -EINVAL;
	}

	return 0;
}

static void eventq_callback(struct virtqueue *queue)
{
	struct virtio_media *vv = queue->vdev->priv;

	schedule_work(&vv->eventq_work);
}

static void
virtio_media_process_dqbuf_event(struct virtio_media *vv,
				 struct virtio_media_session *session,
				 struct virtio_media_event_dqbuf *dqbuf_evt)
{
	struct virtio_media_buffer *dqbuf;
	const enum v4l2_buf_type queue_type = dqbuf_evt->buffer.type;
	struct virtio_media_queue_state *queue;
	typeof(dqbuf->buffer.m) buffer_m;
	typeof(dqbuf->buffer.m.planes[0].m) plane_m;
	int i;

	if (queue_type >= ARRAY_SIZE(session->queues)) {
		v4l2_err(&vv->v4l2_dev,
			 "unmanaged queue %d passed to dqbuf event",
			 dqbuf_evt->buffer.type);
		return;
	}
	queue = &session->queues[queue_type];

	if (dqbuf_evt->buffer.index >= queue->allocated_bufs) {
		v4l2_err(&vv->v4l2_dev,
			 "invalid buffer ID %d for queue %d in dqbuf event",
			 dqbuf_evt->buffer.index, dqbuf_evt->buffer.type);
		return;
	}

	dqbuf = &queue->buffers[dqbuf_evt->buffer.index];

	/*
	 * Preserve the 'm' union that was passed to us during QBUF so userspace
	 * gets back the information it submitted.
	 */
	buffer_m = dqbuf->buffer.m;
	memcpy(&dqbuf->buffer, &dqbuf_evt->buffer, sizeof(dqbuf->buffer));
	dqbuf->buffer.m = buffer_m;
	if (V4L2_TYPE_IS_MULTIPLANAR(dqbuf->buffer.type)) {
		if (dqbuf->buffer.length > VIDEO_MAX_PLANES) {
			v4l2_err(
				&vv->v4l2_dev,
				"invalid number of planes received from host for a multiplanar buffer\n");
			return;
		}
		for (i = 0; i < dqbuf->buffer.length; i++) {
			plane_m = dqbuf->planes[i].m;
			memcpy(&dqbuf->planes[i], &dqbuf_evt->planes[i],
			       sizeof(struct v4l2_plane));
			dqbuf->planes[i].m = plane_m;
		}
	}

	mutex_lock(&session->dqbufs_lock);
	list_add_tail(&dqbuf->list,
		      &session->queues[dqbuf->buffer.type].pending_dqbufs);
	mutex_unlock(&session->dqbufs_lock);
	session->queues[dqbuf->buffer.type].queued_bufs -= 1;
	wake_up(&session->dqbufs_wait);
}

void virtio_media_process_events(struct virtio_media *vv)
{
	struct virtio_media_event_error *error_evt;
	struct virtio_media_event_dqbuf *dqbuf_evt;
	struct virtio_media_event_event *event_evt;
	struct virtio_media_session *session;
	struct virtio_media_event_header *evt;
	unsigned int len;

	mutex_lock(&vv->events_process_lock);

	while ((evt = virtqueue_get_buf(vv->eventq, &len))) {
		/* Make sure we received enough data */
		if (len < sizeof(*evt)) {
			v4l2_err(
				&vv->v4l2_dev,
				"event is too short: got %u, expected at least %zu\n",
				len, sizeof(*evt));
			goto end_of_event;
		}

		session = virtio_media_find_session(vv, evt->session_id);
		if (session == NULL) {
			v4l2_err(&vv->v4l2_dev, "cannot find session %d\n",
				 evt->session_id);
			goto end_of_event;
		}

		switch (evt->event) {
		case VIRTIO_MEDIA_EVT_ERROR:
			if (len < sizeof(*error_evt)) {
				v4l2_err(
					&vv->v4l2_dev,
					"error event is too short: got %u, expected %zu\n",
					len, sizeof(*error_evt));
				break;
			}
			error_evt = (struct virtio_media_event_error *)evt;
			v4l2_err(&vv->v4l2_dev,
				 "received error %d for session %d",
				 error_evt->errno, error_evt->hdr.session_id);
			/* TODO close session! */
			break;

		/*
		 * Dequeued buffer: put it into the right queue so user-space can dequeue
		 * it.
		 */
		case VIRTIO_MEDIA_EVT_DQBUF:
			if (len < sizeof(*dqbuf_evt)) {
				v4l2_err(
					&vv->v4l2_dev,
					"dqbuf event is too short: got %u, expected %zu\n",
					len, sizeof(*dqbuf_evt));
				break;
			}
			dqbuf_evt = (struct virtio_media_event_dqbuf *)evt;
			virtio_media_process_dqbuf_event(vv, session,
							 dqbuf_evt);
			break;

		case VIRTIO_MEDIA_EVT_EVENT:
			if (len < sizeof(*event_evt)) {
				v4l2_err(
					&vv->v4l2_dev,
					"stream event is too short: got %u expected %zu\n",
					len, sizeof(*event_evt));
				break;
			}

			event_evt = (struct virtio_media_event_event *)evt;
			v4l2_event_queue_fh(&session->fh, &event_evt->event);
			break;

		default:
			v4l2_err(&vv->v4l2_dev, "unknown event type %d\n",
				 evt->event);
			break;
		}

end_of_event:
		virtio_media_send_event_buffer(vv, evt);
	}

	virtqueue_enable_cb(vv->eventq);

	mutex_unlock(&vv->events_process_lock);
}

/**
 * Event callback. This processes the returned event buffer and immediately
 * sends it again to the host so it can send us the next event without ever
 * starving.
 */
void virtio_media_event_work(struct work_struct *work)
{
	struct virtio_media *vv =
		container_of(work, struct virtio_media, eventq_work);

	virtio_media_process_events(vv);
}

/**
 * Opens the device and create a new session.
 */
static int virtio_media_device_open(struct file *file)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_cmd_open *cmd_open = &vv->cmd.open;
	struct virtio_media_resp_open *resp_open = &vv->resp.open;
	struct scatterlist cmd_sg = {}, resp_sg = {};
	struct scatterlist *sgs[2] = { &cmd_sg, &resp_sg };
	struct virtio_media_session *session;
	u32 session_id;
	int ret;

	sg_set_buf(&cmd_sg, cmd_open, sizeof(*cmd_open));
	sg_mark_end(&cmd_sg);

	sg_set_buf(&resp_sg, resp_open, sizeof(*resp_open));
	sg_mark_end(&resp_sg);

	mutex_lock(&vv->bufs_lock);
	cmd_open->hdr.cmd = VIRTIO_MEDIA_CMD_OPEN;
	ret = virtio_media_send_command(vv, sgs, 1, 1, sizeof(*resp_open),
					NULL);
	session_id = resp_open->session_id;
	mutex_unlock(&vv->bufs_lock);
	if (ret < 0)
		return ret;

	session = virtio_media_session_alloc(vv, session_id,
					     (file->f_flags & O_NONBLOCK));
	if (IS_ERR(session))
		return PTR_ERR(session);

	file->private_data = &session->fh;

	return 0;
}

/**
 * Close a previously opened session.
 */
static int virtio_media_device_close(struct file *file)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session =
		fh_to_session(file->private_data);
	struct virtio_media_cmd_close *cmd_close = &session->cmd.close;
	struct scatterlist cmd_sg = {};
	struct scatterlist *sgs[1] = { &cmd_sg };
	int ret;

	cmd_close->hdr.cmd = VIRTIO_MEDIA_CMD_CLOSE;
	cmd_close->session_id = session->id;

	sg_set_buf(&cmd_sg, cmd_close, sizeof(*cmd_close));
	sg_mark_end(&cmd_sg);

	ret = virtio_media_send_command(vv, sgs, 1, 0, 0, NULL);
	if (ret < 0)
		return ret;

	virtio_media_session_close(vv, session);

	return 0;
}

/**
 * Implements poll logic for a virtio-media device.
 */
static __poll_t virtio_media_device_poll(struct file *file, poll_table *wait)
{
	struct virtio_media_session *session =
		fh_to_session(file->private_data);
	struct virtio_media_queue_state *input_queue =
		&session->queues[V4L2_BUF_TYPE_VIDEO_CAPTURE];
	struct virtio_media_queue_state *output_queue =
		&session->queues[V4L2_BUF_TYPE_VIDEO_OUTPUT];
	__poll_t req_events = poll_requested_events(wait);
	__poll_t rc = 0;

	poll_wait(file, &session->dqbufs_wait, wait);
	poll_wait(file, &session->fh.wait, wait);

	/*
	 * This function is adequate for m2m devices, however we may need to detect
	 * the device type and provide variants if this doesn't work with other kinds
	 * of devices.
	 */

	mutex_lock(&session->dqbufs_lock);
	if (req_events & (EPOLLIN | EPOLLRDNORM | EPOLLOUT | EPOLLWRNORM)) {
		if ((!input_queue->streaming ||
		     input_queue->queued_bufs == 0) &&
		    (!output_queue->streaming ||
		     output_queue->queued_bufs == 0)) {
			rc |= EPOLLERR;
		} else {
			if (!list_empty(&input_queue->pending_dqbufs))
				rc |= EPOLLIN | EPOLLRDNORM;

			if (!list_empty(&output_queue->pending_dqbufs))
				rc |= EPOLLOUT | EPOLLWRNORM;
		}
	}
	mutex_unlock(&session->dqbufs_lock);

	if (v4l2_event_pending(&session->fh))
		rc |= EPOLLPRI;

	return rc;
}

/**
 * Inform the host that a previously created MMAP mapping is no longer needed
 * and can be removed.
 */
static void virtio_media_vma_close(struct vm_area_struct *vma)
{
	struct virtio_media *vv = vma->vm_private_data;
	struct virtio_media_cmd_munmap *cmd_munmap = &vv->cmd.munmap;
	struct virtio_media_resp_munmap *resp_munmap = &vv->resp.munmap;
	struct scatterlist cmd_sg = {}, resp_sg = {};
	struct scatterlist *sgs[2] = { &cmd_sg, &resp_sg };
	int ret;

	sg_set_buf(&cmd_sg, cmd_munmap, sizeof(*cmd_munmap));
	sg_mark_end(&cmd_sg);

	sg_set_buf(&resp_sg, resp_munmap, sizeof(*resp_munmap));
	sg_mark_end(&resp_sg);

	mutex_lock(&vv->bufs_lock);
	cmd_munmap->hdr.cmd = VIRTIO_MEDIA_CMD_MUNMAP;
	cmd_munmap->offset = vma->vm_pgoff << PAGE_SHIFT;
	ret = virtio_media_send_command(vv, sgs, 1, 1, sizeof(*resp_munmap),
					NULL);
	mutex_unlock(&vv->bufs_lock);
	if (ret < 0) {
		v4l2_err(&vv->v4l2_dev, "host failed to unmap buffer: %d\n",
			 ret);
	}
}

static struct vm_operations_struct virtio_media_vm_ops = {
	.close = virtio_media_vma_close,
};

/**
 * Perform a mmap request from the guest.
 *
 * This requests the host to map a MMAP buffer for us, so we can make that
 * mapping visible into the user-space address space.
 */
static int virtio_media_device_mmap(struct file *file,
				    struct vm_area_struct *vma)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session =
		fh_to_session(file->private_data);
	struct virtio_media_cmd_mmap *cmd_mmap = &session->cmd.mmap;
	struct virtio_media_resp_mmap *resp_mmap = &session->resp.mmap;
	struct scatterlist cmd_sg = {}, resp_sg = {};
	struct scatterlist *sgs[2] = { &cmd_sg, &resp_sg };
	int ret;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
		return -EINVAL;

	cmd_mmap->hdr.cmd = VIRTIO_MEDIA_CMD_MMAP;
	cmd_mmap->session_id = session->id;
	cmd_mmap->flags =
		(vma->vm_flags & VM_WRITE) ? VIRTIO_MEDIA_MMAP_FLAG_RW : 0;
	cmd_mmap->offset = vma->vm_pgoff << PAGE_SHIFT;

	sg_set_buf(&cmd_sg, cmd_mmap, sizeof(*cmd_mmap));
	sg_mark_end(&cmd_sg);

	sg_set_buf(&resp_sg, resp_mmap, sizeof(*resp_mmap));
	sg_mark_end(&resp_sg);

	/*
	 * The host performs reference counting and is smart enough to return the
	 * same guest physical address if this is called several times on the same
	 * buffer.
	 */
	ret = virtio_media_send_command(vv, sgs, 1, 1, sizeof(*resp_mmap),
					NULL);
	if (ret < 0)
		return ret;

	vma->vm_private_data = vv;

	if (vma->vm_end - vma->vm_start > PAGE_ALIGN(resp_mmap->len)) {
		virtio_media_vma_close(vma);
		return -EINVAL;
	}

	ret = io_remap_pfn_range(vma, vma->vm_start,
				 resp_mmap->addr >> PAGE_SHIFT,
				 vma->vm_end - vma->vm_start,
				 vma->vm_page_prot);
	if (ret)
		return ret;

	vma->vm_ops = &virtio_media_vm_ops;

	return 0;
}

/* Convert a V4L2 IOCTL into the IOCTL code we can give to the host */
#define VIRTIO_MEDIA_IOCTL_CODE(IOCTL) ((IOCTL >> _IOC_NRSHIFT) & _IOC_NRMASK)

/**
 * Send an ioctl that has no driver payload, but expects a reponse from the host (i.e. an
 * ioctl specified with _IOR).
 *
 * Returns 0 in case of success, or a negative error code.
 */
static int virtio_media_send_r_ioctl(struct v4l2_fh *fh, u32 ioctl_code,
				     const void *ioctl_data,
				     size_t ioctl_data_len)
{
	struct video_device *video_dev = fh->vdev;
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct scatterlist *sgs[3];
	struct scatterlist_filler filler = {
		.descs = session->command_sgs.sgl,
		.num_descs = DESC_CHAIN_MAX_LEN,
		.cur_desc = 0,
		.shadow_buffer = session->shadow_buf,
		.shadow_buffer_size = VIRTIO_BUF_SIZE,
		.shadow_buffer_pos = 0,
		.sgs = sgs,
		.num_sgs = ARRAY_SIZE(sgs),
		.cur_sg = 0,
	};
	int ret;

	/* Command descriptor */
	ret = scatterlist_filler_add_ioctl_cmd(&filler, session, ioctl_code);
	if (ret)
		return ret;

	/* Response descriptor */
	ret = scatterlist_filler_add_ioctl_resp(&filler, session);
	if (ret)
		return ret;

	/* Response payload */
	ret = scatterlist_filler_add_data(&filler, (void *)ioctl_data,
					  ioctl_data_len);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to prepare command descriptor chain\n");
		return ret;
	}

	ret = virtio_media_send_command(
		vv, sgs, 1, 2,
		sizeof(struct virtio_media_resp_ioctl) + ioctl_data_len, NULL);
	if (ret < 0)
		return ret;

	return 0;
}
/**
 * Send an ioctl that does not expect a reply beyond an error status (i.e. an
 * ioctl specified with _IOW) to the host.
 *
 * Returns 0 in case of success, or a negative error code.
 */
static int virtio_media_send_w_ioctl(struct v4l2_fh *fh, u32 ioctl_code,
				     const void *ioctl_data,
				     size_t ioctl_data_len)
{
	struct video_device *video_dev = fh->vdev;
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct scatterlist *sgs[3];
	struct scatterlist_filler filler = {
		.descs = session->command_sgs.sgl,
		.num_descs = DESC_CHAIN_MAX_LEN,
		.cur_desc = 0,
		.shadow_buffer = session->shadow_buf,
		.shadow_buffer_size = VIRTIO_BUF_SIZE,
		.shadow_buffer_pos = 0,
		.sgs = sgs,
		.num_sgs = ARRAY_SIZE(sgs),
		.cur_sg = 0,
	};
	int ret;

	/* Command descriptor */
	ret = scatterlist_filler_add_ioctl_cmd(&filler, session, ioctl_code);
	if (ret)
		return ret;

	/* Command payload */
	ret = scatterlist_filler_add_data(&filler, (void *)ioctl_data,
					  ioctl_data_len);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to prepare command descriptor chain\n");
		return ret;
	}

	/* Response descriptor */
	ret = scatterlist_filler_add_ioctl_resp(&filler, session);
	if (ret)
		return ret;

	ret = virtio_media_send_command(
		vv, sgs, 2, 1, sizeof(struct virtio_media_resp_ioctl), NULL);
	if (ret < 0)
		return ret;

	/* TODO error code returned by ioctl? */

	return 0;
}

/**
 * Sends an ioctl that expects a response of exactly the same size as the
 * input (i.e. an ioctl specified with _IOWR) to the host.
 *
 * This corresponds to what most V4L2 ioctls do. For instance VIDIOC_ENUM_FMT
 * takes a partially-initialized struct v4l2_fmtdesc and returns its filled
 * version.
 *
 * Ioctls specified with _IOR can also use this, since the host will simply
 * ignore the extra input data provided.
 *
 * Returns 0 in case of success, or a negative error code.
 */
static int virtio_media_send_wr_ioctl(struct v4l2_fh *fh, u32 ioctl_code,
				      void *ioctl_data, size_t ioctl_data_len,
				      size_t min_resp_payload)
{
	struct video_device *video_dev = fh->vdev;
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct scatterlist *sgs[4];
	struct scatterlist_filler filler = {
		.descs = session->command_sgs.sgl,
		.num_descs = DESC_CHAIN_MAX_LEN,
		.cur_desc = 0,
		.shadow_buffer = session->shadow_buf,
		.shadow_buffer_size = VIRTIO_BUF_SIZE,
		.shadow_buffer_pos = 0,
		.sgs = sgs,
		.num_sgs = ARRAY_SIZE(sgs),
		.cur_sg = 0,
	};
	int ret;

	/* Command descriptor */
	ret = scatterlist_filler_add_ioctl_cmd(&filler, session, ioctl_code);
	if (ret)
		return ret;

	/* Command payload */
	ret = scatterlist_filler_add_data(&filler, (void *)ioctl_data,
					  ioctl_data_len);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to prepare command descriptor chain\n");
		return ret;
	}

	/* Response descriptor */
	ret = scatterlist_filler_add_ioctl_resp(&filler, session);
	if (ret)
		return ret;

	/* Response payload, same as command */
	ret = scatterlist_filler_add_sg(&filler, filler.sgs[1]);
	if (ret)
		return ret;

	ret = virtio_media_send_command(vv, sgs, 2, 2,
					sizeof(struct virtio_media_resp_ioctl) +
						min_resp_payload,
					NULL);
	if (ret < 0)
		return ret;

	ret = scatterlist_filler_retrieve_data(session, filler.sgs[1],
					       ioctl_data, ioctl_data_len);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to retrieve response descriptor chain\n");
		return ret;
	}

	return 0;
}

static int virtio_media_send_buffer_ioctl(struct v4l2_fh *fh, u32 ioctl_code,
					  struct v4l2_buffer *b)
{
	struct video_device *video_dev = fh->vdev;
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct v4l2_plane *planes_backup = NULL;
	u32 length_backup = 0;
	struct scatterlist *sgs[64];
	size_t num_cmd_sgs;
	struct scatterlist_filler filler = {
		.descs = session->command_sgs.sgl,
		.num_descs = DESC_CHAIN_MAX_LEN,
		.cur_desc = 0,
		.shadow_buffer = session->shadow_buf,
		.shadow_buffer_size = VIRTIO_BUF_SIZE,
		.shadow_buffer_pos = 0,
		.sgs = sgs,
		.num_sgs = ARRAY_SIZE(sgs),
		.cur_sg = 0,
	};
	size_t resp_len;
	int ret;

	if (b->type > VIRTIO_MEDIA_LAST_QUEUE) {
		v4l2_err(&vv->v4l2_dev, "unsupported queue: %d\n", b->type);
		return -EINVAL;
	}

	if (V4L2_TYPE_IS_MULTIPLANAR(b->type)) {
		planes_backup = b->m.planes;
		length_backup = b->length;
	}

	/* Command descriptor */
	ret = scatterlist_filler_add_ioctl_cmd(&filler, session, ioctl_code);
	if (ret)
		return ret;

	/* Command payload (struct v4l2_buffer) */
	ret = scatterlist_filler_add_buffer(&filler, b, true);
	if (ret < 0) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to prepare command descriptor chain\n");
		return ret;
	}

	num_cmd_sgs = filler.cur_sg;

	/* Response descriptor */
	ret = scatterlist_filler_add_ioctl_resp(&filler, session);
	if (ret)
		return ret;

	/* Response payload (same as input, but no userptr mapping) */
	ret = scatterlist_filler_add_buffer(&filler, b, false);
	if (ret < 0) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to prepare response descriptor chain\n");
		return ret;
	}

	ret = virtio_media_send_command(
		vv, filler.sgs, num_cmd_sgs, filler.cur_sg - num_cmd_sgs,
		sizeof(struct virtio_media_resp_ioctl) + sizeof(*b), &resp_len);

	if (V4L2_TYPE_IS_MULTIPLANAR(b->type)) {
		b->m.planes = planes_backup;
		if (b->length > length_backup)
			return -ENOSPC;
	}

	if (ret < 0)
		return ret;

	resp_len -= sizeof(struct virtio_media_resp_ioctl);

	/* Make sure that the reply's length covers our v4l2_buffer */
	if (resp_len < sizeof(*b))
		return -EINVAL;

	ret = scatterlist_filler_retrieve_buffer(session, &sgs[num_cmd_sgs + 1],
						 b, length_backup);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to retrieve response descriptor chain\n");
		return ret;
	}

	/* TODO ideally we should not be doing this twice, but the scatterlist may screw us up here? */
	if (V4L2_TYPE_IS_MULTIPLANAR(b->type)) {
		b->m.planes = planes_backup;
		if (b->length > length_backup)
			return -ENOSPC;
	}

	return 0;
}

/**
 * Queues an ioctl that sends a v4l2_ext_controls to the host and receives an updated version.
 *
 * v4l2_ext_controls has a pointer to an array of v4l2_ext_control, and also
 * potentially pointers to user-space memory that we need to map properly,
 * hence the dedicated function.
 *
 */
static int virtio_media_send_ext_controls_ioctl(struct v4l2_fh *fh,
						u32 ioctl_code,
						struct v4l2_ext_controls *ctrls)
{
	struct video_device *video_dev = fh->vdev;
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	size_t num_cmd_sgs;
	struct v4l2_ext_control *controls_backup = ctrls->controls;
	const u32 num_ctrls = ctrls->count;
	struct scatterlist *sgs[64];
	struct scatterlist_filler filler = {
		.descs = session->command_sgs.sgl,
		.num_descs = DESC_CHAIN_MAX_LEN,
		.cur_desc = 0,
		.shadow_buffer = session->shadow_buf,
		.shadow_buffer_size = VIRTIO_BUF_SIZE,
		.shadow_buffer_pos = 0,
		.sgs = sgs,
		.num_sgs = ARRAY_SIZE(sgs),
		.cur_sg = 0,
	};
	size_t resp_len = 0;
	int ret;

	/* Command descriptor */
	ret = scatterlist_filler_add_ioctl_cmd(&filler, session, ioctl_code);
	if (ret)
		return ret;

	/* v4l2_controls and its pointees */
	ret = scatterlist_filler_add_ext_ctrls(&filler, ctrls, true);
	if (ret)
		return ret;

	num_cmd_sgs = filler.cur_sg;

	/* Response descriptor */
	ret = scatterlist_filler_add_ioctl_resp(&filler, session);
	if (ret)
		return ret;

	/*
	 * Response payload (same as input but without userptrs)
	 * TODO ideally that's what we want, but the current device requires the userptrs to be mapped.
	 * Also it may be a violation of virtio to write into memory that was mapped in the device-readable descriptors?
	 */
	ret = scatterlist_filler_add_ext_ctrls(&filler, ctrls, true);
	if (ret)
		return ret;

	ret = virtio_media_send_command(
		vv, filler.sgs, num_cmd_sgs, filler.cur_sg - num_cmd_sgs,
		sizeof(struct virtio_media_resp_ioctl) + sizeof(*ctrls),
		&resp_len);

	/* Just in case the host touched these. */
	ctrls->controls = controls_backup;
	if (ctrls->count != num_ctrls) {
		v4l2_err(
			&vv->v4l2_dev,
			"device returned a number of extended controls different than submitted\n");
	}
	if (ctrls->count > num_ctrls)
		return -ENOSPC;

	/* Event if we have received an error, we may need to read our payload back */
	if (ret < 0 && resp_len >= sizeof(struct virtio_media_resp_ioctl) +
					   sizeof(*ctrls)) {
		/* Deliberately ignore the error here as we want to return the earliest one */
		scatterlist_filler_retrieve_ext_ctrls(
			session, &sgs[num_cmd_sgs + 1], ctrls);
		return ret;
	}

	resp_len -= sizeof(struct virtio_media_resp_ioctl);

	/* Make sure that the reply's length covers our v4l2_ext_controls */
	if (resp_len < sizeof(*ctrls))
		return -EINVAL;

	ret = scatterlist_filler_retrieve_ext_ctrls(
		session, &sgs[num_cmd_sgs + 1], ctrls);
	if (ret)
		return ret;

	return 0;
}

/**
 * Helper function to clear the list of buffers waiting to be dequeued on a
 * queue that has just been streamed off.
 */
static void
virtio_media_clear_pending_dqbufs(struct virtio_media *vv,
				  struct virtio_media_session *session,
				  enum v4l2_buf_type queue)
{
	struct list_head *p, *n;

	if (queue > VIRTIO_MEDIA_LAST_QUEUE)
		return;

	mutex_lock(&session->dqbufs_lock);

	list_for_each_safe(p, n, &session->queues[queue].pending_dqbufs) {
		struct virtio_media_buffer *dqbuf =
			list_entry(p, struct virtio_media_buffer, list);

		list_del(&dqbuf->list);
	}

	mutex_unlock(&session->dqbufs_lock);
}

/*
 * V4L2 ioctl handlers.
 *
 * Most of these functions just forward the ioctl to the host, with some
 * exceptions. Most notably, DQBUF is not forwarded since the host notifies us
 * of dequeued buffers using an event.
 */

static int virtio_media_querycap(struct file *file, void *fh,
				 struct v4l2_capability *cap)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);

	/* TODO add proper number? */
	strncpy(cap->bus_info, "platform:virtio-media0", sizeof(cap->bus_info));

	if (!driver_name) {
		strncpy(cap->driver, DEFAULT_DRIVER_NAME, sizeof(cap->driver));
	} else {
		strncpy(cap->driver, driver_name, sizeof(cap->driver));
	}
	virtio_cread_bytes(vv->virtio_dev, 8, cap->card, sizeof(cap->card));

	cap->capabilities = video_dev->device_caps | V4L2_CAP_DEVICE_CAPS;
	cap->device_caps = video_dev->device_caps;

	return 0;
}

static int virtio_media_enum_fmt(struct file *file, void *fh,
				 struct v4l2_fmtdesc *fmt_desc)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUM_FMT), fmt_desc,
		sizeof(*fmt_desc), sizeof(*fmt_desc));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enum_framesizes(struct file *file, void *fh,
					struct v4l2_frmsizeenum *fsize)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUM_FRAMESIZES), fsize,
		sizeof(*fsize), sizeof(*fsize));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enum_frameintervals(struct file *file, void *fh,
					    struct v4l2_frmivalenum *fival)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUM_FRAMEINTERVALS), fival,
		sizeof(*fival), sizeof(*fival));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_fmt(struct file *file, void *fh,
			      struct v4l2_format *format)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(fh,
					 VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_FMT),
					 format, sizeof(*format),
					 sizeof(*format));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_try_fmt(struct file *file, void *fh,
				struct v4l2_format *format)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_TRY_FMT), format,
		sizeof(*format), sizeof(*format));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_fmt(struct file *file, void *fh,
			      struct v4l2_format *format)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(fh,
					 VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_FMT),
					 format, sizeof(*format),
					 sizeof(*format));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_queryctrl(struct file *file, void *fh,
				  struct v4l2_queryctrl *ctrl)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QUERYCTRL), ctrl,
		sizeof(*ctrl), sizeof(*ctrl));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_query_ext_ctrl(struct file *file, void *fh,
				       struct v4l2_query_ext_ctrl *ctrl)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QUERY_EXT_CTRL), ctrl,
		sizeof(*ctrl), sizeof(*ctrl));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_ext_ctrls(struct file *file, void *fh,
				    struct v4l2_ext_controls *ctrls)
{
	int ret;

	ret = virtio_media_send_ext_controls_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_EXT_CTRLS), ctrls);
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_ext_ctrls(struct file *file, void *fh,
				    struct v4l2_ext_controls *ctrls)
{
	int ret;

	ret = virtio_media_send_ext_controls_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_EXT_CTRLS), ctrls);
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_try_ext_ctrls(struct file *file, void *fh,
				      struct v4l2_ext_controls *ctrls)
{
	int ret;

	ret = virtio_media_send_ext_controls_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_TRY_EXT_CTRLS), ctrls);
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_dv_timings(struct file *file, void *fh,
				     struct v4l2_dv_timings *timings)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_DV_TIMINGS), timings,
		sizeof(*timings), sizeof(*timings));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_dv_timings(struct file *file, void *fh,
				     struct v4l2_dv_timings *timings)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_DV_TIMINGS), timings,
		sizeof(*timings), sizeof(*timings));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_query_dv_timings(struct file *file, void *fh,
					 struct v4l2_dv_timings *timings)
{
	int ret;

	ret = virtio_media_send_r_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QUERY_DV_TIMINGS), timings,
		sizeof(*timings));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enum_dv_timings(struct file *file, void *fh,
					struct v4l2_enum_dv_timings *timings)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUM_DV_TIMINGS), timings,
		sizeof(*timings), sizeof(*timings));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_dv_timings_cap(struct file *file, void *fh,
				       struct v4l2_dv_timings_cap *timings)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_DV_TIMINGS_CAP), timings,
		sizeof(*timings), sizeof(*timings));
	if (ret)
		return ret;

	return 0;
}

static int
virtio_media_subscribe_event(struct v4l2_fh *fh,
			     const struct v4l2_event_subscription *sub)
{
	struct video_device *video_dev = fh->vdev;
	struct virtio_media *vv = to_virtio_media(video_dev);
	int ret;

	/* First subscribe to the event in the guest. */
	switch (sub->type) {
	case V4L2_EVENT_SOURCE_CHANGE:
		ret = v4l2_src_change_event_subscribe(fh, sub);
		break;
	default:
		ret = v4l2_event_subscribe(fh, sub, 1, NULL);
		break;
	}
	if (ret)
		return ret;

	/* Then ask the host to signal us these events. */
	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_SUBSCRIBE_EVENT), sub,
		sizeof(*sub));
	if (ret < 0) {
		v4l2_event_unsubscribe(fh, sub);
		return ret;
	}

	/*
	 * Subscribing to an event may result in that event being signaled
	 * immediately. Process all pending events to make sure we don't miss it.
	 */
	if (sub->flags & V4L2_EVENT_SUB_FL_SEND_INITIAL) {
		virtio_media_process_events(vv);
	}

	return 0;
}

static int
virtio_media_unsubscribe_event(struct v4l2_fh *fh,
			       const struct v4l2_event_subscription *sub)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_UNSUBSCRIBE_EVENT), sub,
		sizeof(*sub));
	if (ret < 0)
		return ret;

	ret = v4l2_event_unsubscribe(fh, sub);
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_streamon(struct file *file, void *fh,
				 enum v4l2_buf_type i)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	int ret;

	if (i > VIRTIO_MEDIA_LAST_QUEUE) {
		v4l2_err(&vv->v4l2_dev, "unsupported queue: %d\n", i);
		return -EINVAL;
	}

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_STREAMON), &i, sizeof(i));
	if (ret < 0)
		return ret;

	session->queues[i].streaming = true;

	return 0;
}

static int virtio_media_streamoff(struct file *file, void *fh,
				  enum v4l2_buf_type i)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct virtio_media_queue_state *queue;
	int ret;

	if (i > VIRTIO_MEDIA_LAST_QUEUE) {
		v4l2_err(&vv->v4l2_dev, "unsupported queue: %d\n", i);
		return -EINVAL;
	}

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_STREAMOFF), &i, sizeof(i));
	if (ret < 0)
		return ret;

	queue = &session->queues[i];

	queue->streaming = false;
	queue->queued_bufs = 0;

	virtio_media_clear_pending_dqbufs(vv, session, i);

	return 0;
}

static int virtio_media_reqbufs(struct file *file, void *fh,
				struct v4l2_requestbuffers *b)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct virtio_media_queue_state *queue;
	int ret;

	if (b->type > VIRTIO_MEDIA_LAST_QUEUE) {
		v4l2_err(&vv->v4l2_dev, "unsupported queue: %d\n", b->type);
		return -EINVAL;
	}

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_REQBUFS), b, sizeof(*b),
		sizeof(*b));
	if (ret)
		return ret;

	queue = &session->queues[b->type];

	vfree(queue->buffers);
	queue->buffers = NULL;

	/* REQBUFS(0) is an implicit STREAMOFF. */
	if (b->count == 0) {
		virtio_media_clear_pending_dqbufs(vv, session, b->type);
		queue->queued_bufs = 0;
		queue->streaming = false;
	} else {
		queue->buffers =
			vzalloc(sizeof(struct virtio_media_buffer) * b->count);
		if (!queue->buffers) {
			return -ENOMEM;
		}
	}

	queue->allocated_bufs = b->count;

	/* TODO remove once we support DMABUFs */
	b->capabilities &= ~V4L2_BUF_CAP_SUPPORTS_DMABUF;

	return 0;
}

static int virtio_media_querybuf(struct file *file, void *fh,
				 struct v4l2_buffer *b)
{
	int ret;

	ret = virtio_media_send_buffer_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QUERYBUF), b);
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_create_bufs(struct file *file, void *fh,
				    struct v4l2_create_buffers *b)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session = fh_to_session(fh);
	struct virtio_media_queue_state *queue;
	struct virtio_media_buffer *buffers;
	u32 type = b->format.type;
	int ret;

	if (type > VIRTIO_MEDIA_LAST_QUEUE) {
		v4l2_err(&vv->v4l2_dev, "unsupported queue: %d\n", type);
		return -EINVAL;
	}

	queue = &session->queues[type];

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_CREATE_BUFS), b, sizeof(*b),
		sizeof(*b));
	if (ret)
		return ret;

	/* If count is zero, we were just checking for format. */
	if (b->count == 0)
		return 0;

	buffers = queue->buffers;

	queue->buffers = vzalloc(sizeof(struct virtio_media_buffer) *
				 (b->index + b->count));
	if (!queue->buffers) {
		queue->buffers = buffers;
		return -ENOMEM;
	}

	memcpy(queue->buffers, buffers,
	       sizeof(*buffers) * queue->allocated_bufs);
	vfree(buffers);

	queue->allocated_bufs = b->index + b->count;

	return 0;
}

static int virtio_media_prepare_buf(struct file *file, void *fh,
				    struct v4l2_buffer *b)
{
	int ret;

	ret = virtio_media_send_buffer_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_PREPARE_BUF), b);
	if (ret)
		return ret;

	/* TODO should we store some information? */

	return 0;
}

static int virtio_media_qbuf(struct file *file, void *fh, struct v4l2_buffer *b)
{
	struct virtio_media_session *session = fh_to_session(fh);
	struct virtio_media_queue_state *queue;
	struct virtio_media_buffer *buffer;
	int ret;

	ret = virtio_media_send_buffer_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QBUF), b);
	if (ret)
		return ret;

	/*
	 * Store the buffer information so we can retrieve it again when DQBUF
	 * occurs.
	 */
	queue = &session->queues[b->type];
	queue->queued_bufs += 1;
	buffer = &queue->buffers[b->index];
	memcpy(&buffer->buffer, b, sizeof(*b));
	if (V4L2_TYPE_IS_MULTIPLANAR(b->type) && b->length > 0) {
		memcpy(buffer->planes, b->m.planes,
		       sizeof(struct v4l2_plane) * b->length);
	}

	return 0;
}

static int virtio_media_dqbuf(struct file *file, void *fh,
			      struct v4l2_buffer *b)
{
	struct video_device *video_dev = video_devdata(file);
	struct virtio_media *vv = to_virtio_media(video_dev);
	struct virtio_media_session *session =
		fh_to_session(file->private_data);
	struct virtio_media_buffer *dqbuf;
	struct virtio_media_queue_state *queue;
	struct list_head *buffer_queue;
	struct v4l2_plane *planes_backup = NULL;
	const bool is_multiplanar = V4L2_TYPE_IS_MULTIPLANAR(b->type);
	int ret;

	if (b->type > VIRTIO_MEDIA_LAST_QUEUE) {
		v4l2_err(&vv->v4l2_dev, "unsupported queue for dqbuf: %d\n",
			 b->type);
		return -EINVAL;
	}

	queue = &session->queues[b->type];
	buffer_queue = &queue->pending_dqbufs;

	/* Only block for a buffer if the file has been opened with O_NONBLOCK. */
	if (session->nonblocking_dequeue) {
		if (list_empty(buffer_queue))
			return -EAGAIN;
	} else if (queue->allocated_bufs == 0) {
		return -EINVAL;
	} else if (!queue->streaming) {
		return -EINVAL;
	} else {
		ret = wait_event_interruptible(session->dqbufs_wait,
					       !list_empty(buffer_queue));
		if (ret)
			return -EINTR;
	}

	mutex_lock(&session->dqbufs_lock);
	dqbuf = list_first_entry(buffer_queue, struct virtio_media_buffer,
				 list);
	list_del(&dqbuf->list);
	mutex_unlock(&session->dqbufs_lock);

	if (is_multiplanar) {
		size_t nb_planes = min(b->length, (u32)VIDEO_MAX_PLANES);
		memcpy(b->m.planes, dqbuf->planes,
		       nb_planes * sizeof(struct v4l2_plane));
		planes_backup = b->m.planes;
	}

	memcpy(b, &dqbuf->buffer, sizeof(*b));

	if (is_multiplanar) {
		b->m.planes = planes_backup;
	}

	return 0;
}

static int virtio_media_enum_input(struct file *file, void *fh,
				   struct v4l2_input *input)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUMINPUT), input,
		sizeof(*input), sizeof(*input));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_input(struct file *file, void *fh, unsigned int *i)
{
	u32 input;
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_INPUT), &input,
		sizeof(input), sizeof(input));
	if (ret)
		return ret;

	*i = input;

	return 0;
}

static int virtio_media_querymenu(struct file *file, void *fh,
				  struct v4l2_querymenu *m)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QUERYMENU), m, sizeof(*m),
		sizeof(*m));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_input(struct file *file, void *fh, unsigned int i)
{
	u32 input = i;
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_INPUT), &input,
		sizeof(input), sizeof(input));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enum_output(struct file *file, void *fh,
				    struct v4l2_output *output)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUMOUTPUT), output,
		sizeof(*output), sizeof(*output));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_output(struct file *file, void *fh, unsigned int *o)
{
	u32 output;
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_OUTPUT), &output,
		sizeof(output), sizeof(output));
	if (ret)
		return ret;

	*o = output;

	return 0;
}

static int virtio_media_s_output(struct file *file, void *fh, unsigned int o)
{
	u32 output = o;
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_OUTPUT), &output,
		sizeof(output), sizeof(output));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enumaudio(struct file *file, void *fh,
				  struct v4l2_audio *a)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUMAUDIO), a, sizeof(*a),
		sizeof(*a));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_audio(struct file *file, void *fh,
				struct v4l2_audio *a)
{
	int ret;

	ret = virtio_media_send_r_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_AUDIO), a, sizeof(*a));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_audio(struct file *file, void *fh,
				const struct v4l2_audio *a)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_AUDIO), a, sizeof(*a));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enumaudout(struct file *file, void *fh,
				   struct v4l2_audioout *a)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUMAUDOUT), a, sizeof(*a),
		sizeof(*a));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_audout(struct file *file, void *fh,
				 struct v4l2_audioout *a)
{
	int ret;

	ret = virtio_media_send_r_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_AUDOUT), a, sizeof(*a));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_audout(struct file *file, void *fh,
				 const struct v4l2_audioout *a)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_AUDOUT), a, sizeof(*a));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_modulator(struct file *file, void *fh,
				    struct v4l2_modulator *m)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_MODULATOR), m, sizeof(*m),
		sizeof(*m));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_modulator(struct file *file, void *fh,
				    const struct v4l2_modulator *m)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_MODULATOR), m, sizeof(*m));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_selection(struct file *file, void *fh,
				    struct v4l2_selection *s)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_SELECTION), s, sizeof(*s),
		sizeof(*s));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_selection(struct file *file, void *fh,
				    struct v4l2_selection *s)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_SELECTION), s, sizeof(*s),
		sizeof(*s));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_enc_index(struct file *file, void *fh,
				    struct v4l2_enc_idx *i)
{
	int ret;

	ret = virtio_media_send_r_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_ENC_INDEX), i, sizeof(*i));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_encoder_cmd(struct file *file, void *fh,
				    struct v4l2_encoder_cmd *cmd)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENCODER_CMD), cmd,
		sizeof(*cmd), sizeof(*cmd));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_try_encoder_cmd(struct file *file, void *fh,
					struct v4l2_encoder_cmd *cmd)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_TRY_ENCODER_CMD), cmd,
		sizeof(*cmd), sizeof(*cmd));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_decoder_cmd(struct file *file, void *fh,
				    struct v4l2_decoder_cmd *cmd)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_DECODER_CMD), cmd,
		sizeof(*cmd), sizeof(*cmd));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_try_decoder_cmd(struct file *file, void *fh,
					struct v4l2_decoder_cmd *cmd)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_TRY_DECODER_CMD), cmd,
		sizeof(*cmd), sizeof(*cmd));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_parm(struct file *file, void *fh,
			       struct v4l2_streamparm *p)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(fh,
					 VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_PARM),
					 p, sizeof(*p), sizeof(*p));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_parm(struct file *file, void *fh,
			       struct v4l2_streamparm *p)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(fh,
					 VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_PARM),
					 p, sizeof(*p), sizeof(*p));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_std(struct file *file, void *fh, v4l2_std_id *s)
{
	int ret;

	ret = virtio_media_send_r_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_STD), s, sizeof(*s));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_std(struct file *file, void *fh, v4l2_std_id s)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_STD), &s, sizeof(s));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_querystd(struct file *file, void *fh, v4l2_std_id *s)
{
	int ret;

	ret = virtio_media_send_r_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_QUERYSTD), s, sizeof(*s));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enumstd(struct file *file, void *fh,
				struct v4l2_standard *s)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUMSTD), s, sizeof(*s),
		sizeof(*s));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_tuner(struct file *file, void *fh,
				struct v4l2_tuner *t)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_TUNER), t, sizeof(*t),
		sizeof(*t));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_tuner(struct file *file, void *fh,
				const struct v4l2_tuner *t)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_TUNER), t, sizeof(*t));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_frequency(struct file *file, void *fh,
				    struct v4l2_frequency *f)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_FREQUENCY), f, sizeof(*f),
		sizeof(*f));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_frequency(struct file *file, void *fh,
				    const struct v4l2_frequency *f)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_FREQUENCY), f, sizeof(*f));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_enum_freq_bands(struct file *file, void *fh,
					struct v4l2_frequency_band *f)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_ENUM_FREQ_BANDS), f,
		sizeof(*f), sizeof(*f));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_g_sliced_vbi_cap(struct file *file, void *fh,
					 struct v4l2_sliced_vbi_cap *c)
{
	int ret;

	ret = virtio_media_send_wr_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_G_SLICED_VBI_CAP), c,
		sizeof(*c), sizeof(*c));
	if (ret)
		return ret;

	return 0;
}

static int virtio_media_s_hw_freq_seek(struct file *file, void *fh,
				       const struct v4l2_hw_freq_seek *s)
{
	int ret;

	ret = virtio_media_send_w_ioctl(
		fh, VIRTIO_MEDIA_IOCTL_CODE(VIDIOC_S_HW_FREQ_SEEK), s,
		sizeof(*s));
	if (ret)
		return ret;

	return 0;
}

static const struct v4l2_ioctl_ops virtio_media_ioctl_ops = {
	/* VIDIOC_QUERYCAP handler */
	.vidioc_querycap = virtio_media_querycap,

	/* VIDIOC_ENUM_FMT handlers */
	.vidioc_enum_fmt_vid_cap = virtio_media_enum_fmt,
	.vidioc_enum_fmt_vid_overlay = virtio_media_enum_fmt,
	.vidioc_enum_fmt_vid_out = virtio_media_enum_fmt,
	.vidioc_enum_fmt_sdr_cap = virtio_media_enum_fmt,
	.vidioc_enum_fmt_sdr_out = virtio_media_enum_fmt,
	.vidioc_enum_fmt_meta_cap = virtio_media_enum_fmt,
	.vidioc_enum_fmt_meta_out = virtio_media_enum_fmt,

	/* VIDIOC_G_FMT handlers */
	.vidioc_g_fmt_vid_cap = virtio_media_g_fmt,
	.vidioc_g_fmt_vid_overlay = virtio_media_g_fmt,
	.vidioc_g_fmt_vid_out = virtio_media_g_fmt,
	.vidioc_g_fmt_vid_out_overlay = virtio_media_g_fmt,
	.vidioc_g_fmt_vbi_cap = virtio_media_g_fmt,
	.vidioc_g_fmt_vbi_out = virtio_media_g_fmt,
	.vidioc_g_fmt_sliced_vbi_cap = virtio_media_g_fmt,
	.vidioc_g_fmt_sliced_vbi_out = virtio_media_g_fmt,
	.vidioc_g_fmt_vid_cap_mplane = virtio_media_g_fmt,
	.vidioc_g_fmt_vid_out_mplane = virtio_media_g_fmt,
	.vidioc_g_fmt_sdr_cap = virtio_media_g_fmt,
	.vidioc_g_fmt_sdr_out = virtio_media_g_fmt,
	.vidioc_g_fmt_meta_cap = virtio_media_g_fmt,
	.vidioc_g_fmt_meta_out = virtio_media_g_fmt,

	/* VIDIOC_S_FMT handlers */
	.vidioc_s_fmt_vid_cap = virtio_media_s_fmt,
	.vidioc_s_fmt_vid_overlay = virtio_media_s_fmt,
	.vidioc_s_fmt_vid_out = virtio_media_s_fmt,
	.vidioc_s_fmt_vid_out_overlay = virtio_media_s_fmt,
	.vidioc_s_fmt_vbi_cap = virtio_media_s_fmt,
	.vidioc_s_fmt_vbi_out = virtio_media_s_fmt,
	.vidioc_s_fmt_sliced_vbi_cap = virtio_media_s_fmt,
	.vidioc_s_fmt_sliced_vbi_out = virtio_media_s_fmt,
	.vidioc_s_fmt_vid_cap_mplane = virtio_media_s_fmt,
	.vidioc_s_fmt_vid_out_mplane = virtio_media_s_fmt,
	.vidioc_s_fmt_sdr_cap = virtio_media_s_fmt,
	.vidioc_s_fmt_sdr_out = virtio_media_s_fmt,
	.vidioc_s_fmt_meta_cap = virtio_media_s_fmt,
	.vidioc_s_fmt_meta_out = virtio_media_s_fmt,

	/* VIDIOC_TRY_FMT handlers */
	.vidioc_try_fmt_vid_cap = virtio_media_try_fmt,
	.vidioc_try_fmt_vid_overlay = virtio_media_try_fmt,
	.vidioc_try_fmt_vid_out = virtio_media_try_fmt,
	.vidioc_try_fmt_vid_out_overlay = virtio_media_try_fmt,
	.vidioc_try_fmt_vbi_cap = virtio_media_try_fmt,
	.vidioc_try_fmt_vbi_out = virtio_media_try_fmt,
	.vidioc_try_fmt_sliced_vbi_cap = virtio_media_try_fmt,
	.vidioc_try_fmt_sliced_vbi_out = virtio_media_try_fmt,
	.vidioc_try_fmt_vid_cap_mplane = virtio_media_try_fmt,
	.vidioc_try_fmt_vid_out_mplane = virtio_media_try_fmt,
	.vidioc_try_fmt_sdr_cap = virtio_media_try_fmt,
	.vidioc_try_fmt_sdr_out = virtio_media_try_fmt,
	.vidioc_try_fmt_meta_cap = virtio_media_try_fmt,
	.vidioc_try_fmt_meta_out = virtio_media_try_fmt,

	/* Buffer handlers */
	.vidioc_reqbufs = virtio_media_reqbufs,
	.vidioc_querybuf = virtio_media_querybuf,
	.vidioc_qbuf = virtio_media_qbuf,
	.vidioc_expbuf = NULL,
	.vidioc_dqbuf = virtio_media_dqbuf,
	.vidioc_create_bufs = virtio_media_create_bufs,
	.vidioc_prepare_buf = virtio_media_prepare_buf,
	/* Overlay interface not supported yet */
	.vidioc_overlay = NULL,
	/* Overlay interface not supported yet */
	.vidioc_g_fbuf = NULL,
	/* Overlay interface not supported yet */
	.vidioc_s_fbuf = NULL,

	/* Stream on/off */
	.vidioc_streamon = virtio_media_streamon,
	.vidioc_streamoff = virtio_media_streamoff,

	/* Standard handling */
	.vidioc_g_std = virtio_media_g_std,
	.vidioc_s_std = virtio_media_s_std,
	.vidioc_querystd = virtio_media_querystd,

	/* Input handling */
	.vidioc_enum_input = virtio_media_enum_input,
	.vidioc_g_input = virtio_media_g_input,
	.vidioc_s_input = virtio_media_s_input,

	/* Output handling */
	.vidioc_enum_output = virtio_media_enum_output,
	.vidioc_g_output = virtio_media_g_output,
	.vidioc_s_output = virtio_media_s_output,

	/* Control handling */
	.vidioc_queryctrl = virtio_media_queryctrl,
	.vidioc_query_ext_ctrl = virtio_media_query_ext_ctrl,
	/* covered by vidio_g_ext_ctrls */
	.vidioc_g_ctrl = NULL,
	/* covered by vidio_g_ext_ctrls */
	.vidioc_s_ctrl = NULL,
	.vidioc_g_ext_ctrls = virtio_media_g_ext_ctrls,
	.vidioc_s_ext_ctrls = virtio_media_s_ext_ctrls,
	.vidioc_try_ext_ctrls = virtio_media_try_ext_ctrls,
	.vidioc_querymenu = virtio_media_querymenu,

	/* Audio ioctls */
	.vidioc_enumaudio = virtio_media_enumaudio,
	.vidioc_g_audio = virtio_media_g_audio,
	.vidioc_s_audio = virtio_media_s_audio,

	/* Audio out ioctls */
	.vidioc_enumaudout = virtio_media_enumaudout,
	.vidioc_g_audout = virtio_media_g_audout,
	.vidioc_s_audout = virtio_media_s_audout,
	.vidioc_g_modulator = virtio_media_g_modulator,
	.vidioc_s_modulator = virtio_media_s_modulator,

	/* Crop ioctls */
	/* Not directly an ioctl (part of VIDIOC_CROPCAP), so no need to implement */
	.vidioc_g_pixelaspect = NULL,
	.vidioc_g_selection = virtio_media_g_selection,
	.vidioc_s_selection = virtio_media_s_selection,

	/* Compression ioctls */
	/* Deprecated in V4L2. */
	.vidioc_g_jpegcomp = NULL,
	/* Deprecated in V4L2. */
	.vidioc_s_jpegcomp = NULL,
	.vidioc_g_enc_index = virtio_media_g_enc_index,
	.vidioc_encoder_cmd = virtio_media_encoder_cmd,
	.vidioc_try_encoder_cmd = virtio_media_try_encoder_cmd,
	.vidioc_decoder_cmd = virtio_media_decoder_cmd,
	.vidioc_try_decoder_cmd = virtio_media_try_decoder_cmd,

	/* Stream type-dependent parameter ioctls */
	.vidioc_g_parm = virtio_media_g_parm,
	.vidioc_s_parm = virtio_media_s_parm,

	/* Tuner ioctls */
	.vidioc_g_tuner = virtio_media_g_tuner,
	.vidioc_s_tuner = virtio_media_s_tuner,
	.vidioc_g_frequency = virtio_media_g_frequency,
	.vidioc_s_frequency = virtio_media_s_frequency,
	.vidioc_enum_freq_bands = virtio_media_enum_freq_bands,

	/* Sliced VBI cap */
	.vidioc_g_sliced_vbi_cap = virtio_media_g_sliced_vbi_cap,

	/* Log status ioctl */
	/* Guest-only operation */
	.vidioc_log_status = NULL,

	.vidioc_s_hw_freq_seek = virtio_media_s_hw_freq_seek,

	.vidioc_enum_framesizes = virtio_media_enum_framesizes,
	.vidioc_enum_frameintervals = virtio_media_enum_frameintervals,

	/* DV Timings IOCTLs */
	.vidioc_s_dv_timings = virtio_media_s_dv_timings,
	.vidioc_g_dv_timings = virtio_media_g_dv_timings,
	.vidioc_query_dv_timings = virtio_media_query_dv_timings,
	.vidioc_enum_dv_timings = virtio_media_enum_dv_timings,
	.vidioc_dv_timings_cap = virtio_media_dv_timings_cap,
	.vidioc_g_edid = NULL,
	.vidioc_s_edid = NULL,

	.vidioc_subscribe_event = virtio_media_subscribe_event,
	.vidioc_unsubscribe_event = virtio_media_unsubscribe_event,

	/* For other private ioctls */
	.vidioc_default = NULL,
};

static long virtio_media_device_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	struct video_device *vfd = video_devdata(file);
	struct v4l2_fh *vfh = NULL;
	struct v4l2_standard standard;
	v4l2_std_id std_id = 0;
	int ret;

	if (test_bit(V4L2_FL_USES_V4L2_FH, &vfd->flags))
		vfh = file->private_data;

	/*
	 * We need to handle a few ioctls manually because their result rely on
	 * vfd->tvnorms, which is normally updated by the driver as S_INPUT is
	 * called. Since we want to just pass these ioctls through, we have to hijack
	 * them from here.
	 */
	switch (cmd) {
	case VIDIOC_S_STD:
		ret = copy_from_user(&std_id, (void __user *)arg,
				     sizeof(std_id));
		if (ret)
			return -EINVAL;
		return virtio_media_s_std(file, vfh, std_id);
	case VIDIOC_ENUMSTD: {
		ret = copy_from_user(&standard, (void __user *)arg,
				     sizeof(standard));
		if (ret)
			return -EINVAL;
		ret = virtio_media_enumstd(file, vfh, &standard);
		if (ret)
			return ret;
		ret = copy_to_user((void __user *)arg, &standard,
				   sizeof(standard));
		if (ret)
			return -EINVAL;
		return 0;
	}
	case VIDIOC_QUERYSTD: {
		ret = virtio_media_querystd(file, vfh, &std_id);
		if (ret)
			return ret;
		ret = copy_to_user((void __user *)arg, &std_id, sizeof(std_id));
		if (ret)
			return -EINVAL;
		return 0;
	}
	default:
		return video_ioctl2(file, cmd, arg);
	}
}

static const struct v4l2_file_operations virtio_media_fops = {
	.owner = THIS_MODULE,
	.open = virtio_media_device_open,
	.release = virtio_media_device_close,
	.poll = virtio_media_device_poll,
	.unlocked_ioctl = virtio_media_device_ioctl,
	.mmap = virtio_media_device_mmap,
};

static int virtio_media_probe(struct virtio_device *virtio_dev)
{
	struct device *dev = &virtio_dev->dev;
	struct virtqueue *vqs[2];
	static vq_callback_t *vq_callbacks[] = {
		commandq_callback,
		eventq_callback,
	};
	static const char *const vq_names[] = { "command", "event" };
	struct virtio_media *vv;
	struct video_device *vd;
	int i;
	int ret;

	vv = devm_kzalloc(dev, sizeof(*vv), GFP_KERNEL);
	if (!vv)
		return -ENOMEM;

	vv->event_buffer = devm_kzalloc(
		dev, VIRTIO_MEDIA_EVENT_MAX_SIZE * VIRTIO_MEDIA_NUM_EVENT_BUFS,
		GFP_KERNEL);
	if (!vv->event_buffer) {
		return -ENOMEM;
	}

	mutex_init(&vv->bufs_lock);

	INIT_LIST_HEAD(&vv->sessions);
	mutex_init(&vv->sessions_lock);
	mutex_init(&vv->events_process_lock);

	vv->virtio_dev = virtio_dev;
	virtio_dev->priv = vv;

	init_waitqueue_head(&vv->wq);

	ret = v4l2_device_register(dev, &vv->v4l2_dev);
	if (ret)
		return ret;

	ret = virtio_find_vqs(virtio_dev, 2, vqs, vq_callbacks, vq_names, NULL);
	if (ret)
		goto err_find_vqs;

	vv->commandq = vqs[0];
	vv->eventq = vqs[1];
	INIT_WORK(&vv->eventq_work, virtio_media_event_work);

	virtio_device_ready(virtio_dev);

	vd = &vv->video_dev;

	vd->v4l2_dev = &vv->v4l2_dev;
	vd->vfl_type = VFL_TYPE_VIDEO;
	vd->ioctl_ops = &virtio_media_ioctl_ops;
	vd->fops = &virtio_media_fops;
	vd->device_caps = virtio_cread32(virtio_dev, 0);
	if (vd->device_caps & (V4L2_CAP_VIDEO_M2M | V4L2_CAP_VIDEO_M2M_MPLANE))
		vd->vfl_dir |= VFL_DIR_M2M;
	else if (vd->device_caps &
		 (V4L2_CAP_VIDEO_OUTPUT | V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE))
		vd->vfl_dir |= VFL_DIR_TX;
	else
		vd->vfl_dir = VFL_DIR_RX;
	vd->release = video_device_release_empty;
	strscpy(vd->name, "virtio-media", sizeof(vd->name));

	video_set_drvdata(vd, vv);

	/* TODO find out when we should enable this ioctl? */
	v4l2_disable_ioctl(vd, VIDIOC_S_HW_FREQ_SEEK);

	ret = video_register_device(vd, virtio_cread32(virtio_dev, 4), 0);
	if (ret)
		return ret;

	for (i = 0; i < VIRTIO_MEDIA_NUM_EVENT_BUFS; i++) {
		ret = virtio_media_send_event_buffer(
			vv, vv->event_buffer + VIRTIO_MEDIA_EVENT_MAX_SIZE * i);
		if (ret) {
			goto send_event_buffer;
		}
	}

	return 0;

send_event_buffer:
	video_unregister_device(&vv->video_dev);
	virtio_dev->config->del_vqs(virtio_dev);
err_find_vqs:
	v4l2_device_unregister(&vv->v4l2_dev);

	return ret;
}

static void virtio_media_remove(struct virtio_device *virtio_dev)
{
	struct virtio_media *vv = virtio_dev->priv;
	struct list_head *p, *n;

	virtio_reset_device(virtio_dev);

	v4l2_device_unregister(&vv->v4l2_dev);
	virtio_dev->config->del_vqs(virtio_dev);
	video_unregister_device(&vv->video_dev);

	list_for_each_safe(p, n, &vv->sessions) {
		struct virtio_media_session *s =
			list_entry(p, struct virtio_media_session, list);

		virtio_media_session_close(vv, s);
	}
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_MEDIA, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {};

static struct virtio_driver virtio_media_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = DEFAULT_DRIVER_NAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_media_probe,
	.remove = virtio_media_remove,
};

module_virtio_driver(virtio_media_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("virtio media driver");
MODULE_AUTHOR("Alexandre Courbot <acourbot@chromium.org>");
MODULE_LICENSE("GPL");
