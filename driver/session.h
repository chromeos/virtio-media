// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0+

/*
 * Definitions of virtio-media session related structures.
 *
 * Copyright (c) 2023-2024 Google LLC.
 */

#ifndef __VIRTIO_MEDIA_SESSION_H
#define __VIRTIO_MEDIA_SESSION_H

#include <linux/scatterlist.h>
#include <media/v4l2-fh.h>

#include "protocol.h"

#define VIRTIO_MEDIA_LAST_QUEUE (V4L2_BUF_TYPE_META_OUTPUT)

/**
 * Size of our virtio shadow and event buffers. 16K should definitely be enough
 * to contain anything we need.
 */
#define VIRTIO_SHADOW_BUF_SIZE 0x4000

struct virtio_media_sg_entry {
	u64 start;
	u32 len;
	u32 __padding;
};

/**
 * struct virtio_media_buffer - Current state of a given buffer.
 *
 * @buffer: struct v4l2_buffer with current information about the buffer.
 * @planes: backing planes array for @buffer.
 * @list: link into the list of buffers pending dequeue.
 */
struct virtio_media_buffer {
	struct v4l2_buffer buffer;
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	struct list_head list;
};

/**
 * struct virtio_media_queue_state - Represents the state of a V4L2 queue.
 *
 * @streaming: Whether the queue is currently streaming.
 * @allocated_bufs: How many buffers are currently allocated.
 * @is_capture_last: set to true when the last buffer has been received on a
 * 	capture queue, so we can return -EPIPE on subsequent DQBUF requests.
 * @buffers: Buffer state array of size @allocated_bufs.
 * @queued_bufs: How many buffers are currently queued at the host.
 * @pending_dqbufs: Buffers that are available for being dequeued.
 */
struct virtio_media_queue_state {
	bool streaming;
	size_t allocated_bufs;
	bool is_capture_last;

	struct virtio_media_buffer *buffers;
	size_t queued_bufs;
	struct list_head pending_dqbufs;
};

/**
 * struct virtio_media_session - A session on a virtio_media device, created whenever the device is opened.
 *
 * @fh: file handler for the session.
 * @id: session ID used to communicate with the device.
 * @nonblocking_dequeue: whether dequeue should block or not (nonblocking if file opened with O_NONBLOCK).
 * @uses_mplane: whether the queues for this session use the MPLANE API or not.
 * @cmd: union of session-related commands. Each session can have one command currently running.
 * @resp: union of session-related responses.
 * @shadow_buf: shadow buffer where commandq data can be staged before being sent to the device.
 * @command_sg: SG table gathering descriptors for a given command and its response.
 * @queues: state of all the queues for this session.
 * @dqbufs_lock: protects pending_dqbufs of virtio_media_queue_state.
 * @dqbufs_wait: waitqueue for dequeued buffers, if VIDIOC_DQBUF needs to block or when polling.
 * @list: link into the list of sessions for the device.
 */
struct virtio_media_session {
	struct v4l2_fh fh;
	u32 id;
	bool nonblocking_dequeue;
	bool uses_mplane;

	union {
		struct virtio_media_cmd_close close;
		struct virtio_media_cmd_ioctl ioctl;
		struct virtio_media_cmd_mmap mmap;
	} cmd;

	union {
		struct virtio_media_resp_ioctl ioctl;
		struct virtio_media_resp_mmap mmap;
	} resp;

	void *shadow_buf;

	struct sg_table command_sgs;

	struct virtio_media_queue_state queues[VIRTIO_MEDIA_LAST_QUEUE + 1];
	struct mutex dqbufs_lock;
	wait_queue_head_t dqbufs_wait;

	struct list_head list;
};

static inline struct virtio_media_session *fh_to_session(struct v4l2_fh *fh)
{
	return container_of(fh, struct virtio_media_session, fh);
}

#endif // __VIRTIO_MEDIA_SESSION_H
