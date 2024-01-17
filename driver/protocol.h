// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0+

/*
 * Definitions of virtio-media protocol structures.
 *
 * Copyright (c) 2023-2024 Google LLC.
 */

#ifndef __VIRTIO_MEDIA_PROTOCOL_H
#define __VIRTIO_MEDIA_PROTOCOL_H

#include <linux/videodev2.h>

/*
 * Virtio protocol definition.
 */

/**
 * struct virtio_media_cmd_header - Header for all virtio commands from the driver to the device on the commandq.
 *
 * @cmd: one of VIRTIO_MEDIA_CMD_*.
 * @__padding: must be set to zero by the guest.
 */
struct virtio_media_cmd_header {
	u32 cmd;
	u32 __padding;
};

/**
 * struct virtio_media_resp_header - Header for all virtio responses from the device to the driver on the commandq.
 *
 * @status: 0 if the command was successful, or one of the standard Linux error
 *          codes.
 * @__padding: must be set to zero by the device.
 */
struct virtio_media_resp_header {
	u32 status;
	u32 __padding;
};

/**
 * VIRTIO_MEDIA_CMD_OPEN - Command for creating a new session.
 *
 * This is the equivalent of calling `open` on a V4L2 device node. Upon
 * success, a session id is returned which can be used to perform other
 * commands on the session, notably ioctls.
 */
#define VIRTIO_MEDIA_CMD_OPEN 1

/**
 * struct virtio_media_cmd_open - Driver command for VIRTIO_MEDIA_CMD_OPEN.
 *
 * @hdr: header which cmd member is set to VIRTIO_MEDIA_CMD_OPEN.
 */
struct virtio_media_cmd_open {
	struct virtio_media_cmd_header hdr;
};

/**
 * struct virtio_media_resp_open - Device response for VIRTIO_MEDIA_CMD_OPEN.
 *
 * @hdr: header containing the status of the command.
 * @session_id: if hdr.status == 0, contains the id of the newly created session.
 * @__padding: must be set to zero by the device.
 */
struct virtio_media_resp_open {
	struct virtio_media_resp_header hdr;
	u32 session_id;
	u32 __padding;
};

/**
 * VIRTIO_MEDIA_CMD_OPEN - Command for closing an active session.
 *
 * This is the equivalent of calling `close` on a previously opened V4L2 FD.
 * All resources associated with this session will be freed and the session ID shall not be used again after queueing this command.
 *
 * This command does not require a response from the device.
 */
#define VIRTIO_MEDIA_CMD_CLOSE 2

/**
 * struct virtio_media_cmd_close - Driver command for VIRTIO_MEDIA_CMD_CLOSE.
 *
 * @hdr: header which cmd member is set to VIRTIO_MEDIA_CMD_CLOSE.
 * @session_id: id of the session to close.
 * @__padding: must be set to zero by the driver.
 */
struct virtio_media_cmd_close {
	struct virtio_media_cmd_header hdr;
	u32 session_id;
	u32 __padding;
};

/**
 * VIRTIO_MEDIA_CMD_IOCTL - Command for executing an ioctl on an open session.
 *
 * This command asks the device to run one of the `VIDIOC_*` ioctls on the active session.
 *
 * @hdr: header which cmd member is set to VIRTIO_MEDIA_CMD_IOCTL.
 * @session_id: id of the session to run this ioctl on.
 * @code: code of the ioctl.
 *
 * The code of the ioctl is extracted from the VIDIOC_* definitions in
 * `videodev2.h`, and consists of the second argument of the `_IO*` macro.
 *
 * Each ioctl has a payload, which is defined by the third argument of the
 * `_IO*` macro defining it. It can be writable by the driver (`_IOW`), the
 * device (`_IOR`), or both (`_IOWR`).
 *
 * If an ioctl is writable by the driver, it must be followed by a
 * driver-writable descriptor containing the payload.
 *
 * If an ioctl is writable by the device, it must be followed by a
 * device-writable descriptor of the size of the payload that the device will
 * write into.
 *
 */
#define VIRTIO_MEDIA_CMD_IOCTL 3

/**
 * struct virtio_media_cmd_ioctl - Driver command for VIRTIO_MEDIA_CMD_IOCTL.
 *
 * @hdr: header which cmd member is set to VIRTIO_MEDIA_CMD_IOCTL.
 * @session_id: id of the session to run the ioctl on.
 * @code: code of the ioctl to run.
 */
struct virtio_media_cmd_ioctl {
	struct virtio_media_cmd_header hdr;
	u32 session_id;
	u32 code;
};

/**
 * struct virtio_media_resp_ioctl - Device response for VIRTIO_MEDIA_CMD_IOCTL.
 *
 * @hdr: header containing the status of the ioctl.
 */
struct virtio_media_resp_ioctl {
	struct virtio_media_resp_header hdr;
};

#define VIRTIO_MEDIA_MMAP_FLAG_RW (1 << 0)

/**
 * VIRTIO_MEDIA_CMD_MMAP - Command for mapping a MMAP buffer into the guest's address space.
 *
 */
#define VIRTIO_MEDIA_CMD_MMAP 4

/**
 * struct virtio_media_cmd_mmap - Driver command for VIRTIO_MEDIA_CMD_MMAP.
 */
struct virtio_media_cmd_mmap {
	struct virtio_media_cmd_header hdr;
	u32 session_id;
	u32 flags;
	u64 offset;
};

/**
 * struct virtio_media_resp_mmap - Device response for VIRTIO_MEDIA_CMD_MMAP.
 *
 * @hdr: header containing the status of the command.
 * @addr: device physical address of the start of the mapping.
 * @len: length of the mapping.
 */
struct virtio_media_resp_mmap {
	struct virtio_media_resp_header hdr;
	u64 addr;
	u64 len;
};

/**
 * VIRTIO_MEDIA_CMD_MUNMAP - Unmap a MMAP buffer previously mapped using VIRTIO_MEDIA_CMD_MMAP.
 */
#define VIRTIO_MEDIA_CMD_MUNMAP 5

/**
 * struct virtio_media_cmd_munmap - Driver command for VIRTIO_MEDIA_CMD_MUNMAP.
 *
 * @guest_addr: guest physical address at which the buffer has been previously
 * mapped.
 */
struct virtio_media_cmd_munmap {
	struct virtio_media_cmd_header hdr;
	u64 guest_addr;
};

/**
 * struct virtio_media_resp_munmap - Device response for VIRTIO_MEDIA_CMD_MUNMAP.
 *
 * @hdr: header containing the status of the command.
 */
struct virtio_media_resp_munmap {
	struct virtio_media_resp_header hdr;
};

#define VIRTIO_MEDIA_EVT_ERROR 0
#define VIRTIO_MEDIA_EVT_DQBUF 1
#define VIRTIO_MEDIA_EVT_EVENT 2

/**
 * struct virtio_media_event_header - Header for events queued by the device for the driver on the eventq.
 *
 * @event: one of VIRTIO_MEDIA_EVT_*
 * @session_id: ID of the session the event applies to.
 */
struct virtio_media_event_header {
	u32 event;
	u32 session_id;
};

/**
 * struct virtio_media_event_error - Device-side error.
 *
 * Upon receiving this event, the session mentioned in the header is considered corrupted and closed.
 *
 * @hdr: header for the event.
 * @errno: error code describing the kind of error that occurred.
 */
struct virtio_media_event_error {
	struct virtio_media_event_header hdr;
	u32 errno;
	u32 __padding;
};

/**
 * struct virtio_media_event_dqbuf - Signals that a buffer is not being used anymore by the device and is returned to the driver.
 *
 * @hdr: header for the event.
 * @buffer: struct v4l2_buffer describing the buffer that has been dequeued.
 */
struct virtio_media_event_dqbuf {
	struct virtio_media_event_header hdr;
	struct v4l2_buffer buffer;
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
};

/**
 * struct virtio_media_event_event - Signals that a V4L2 event has been emitted for a session.
 *
 * @hdr: header for the event.
 * @event: description of the event that occurred.
 */
struct virtio_media_event_event {
	struct virtio_media_event_header hdr;
	struct v4l2_event event;
};

/**
 * Maximum size of an event. We will queue descriptors of this size on the eventq.
 */
#define VIRTIO_MEDIA_EVENT_MAX_SIZE sizeof(struct virtio_media_event_dqbuf)

#endif // __VIRTIO_MEDIA_PROTOCOL_H
