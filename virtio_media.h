// SPDX-License-Identifier: GPL-2.0+

#ifndef __VIRTIO_MEDIA_H
#define __VIRTIO_MEDIA_H

#include <media/v4l2-device.h>

#include "protocol.h"

#define DESC_CHAIN_MAX_LEN SG_MAX_SINGLE_ALLOC

#define VIRTIO_MEDIA_DEFAULT_DRIVER_NAME "virtio_media"

extern char *driver_name;

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

/* virtio_media_driver.c */

int virtio_media_send_command(struct virtio_media *vv, struct scatterlist **sgs,
			      const size_t out_sgs, const size_t in_sgs,
			      size_t minimum_resp_len, size_t *resp_len);
void virtio_media_process_events(struct virtio_media *vv);

/* virtio_media_ioctls.c */

long virtio_media_device_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg);
extern const struct v4l2_ioctl_ops virtio_media_ioctl_ops;

#endif // __VIRTIO_MEDIA_H
