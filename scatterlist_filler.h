// SPDX-License-Identifier: GPL-2.0+

#ifndef __VIRTIO_MEDIA_DESCRIPTOR_H
#define __VIRTIO_MEDIA_DESCRIPTOR_H

#include <linux/scatterlist.h>

#include "session.h"

/**
 * struct scatterlist_filler - helper to fill a scatterlist from data.
 *
 * @descs: array of scatterlist that will be filled.
 * @num_descs: number of entries in descs.
 * @cur_desc: next descriptor to be written in descs.
 * @shadow_buffer: pointer to a shadow buffer where elements that cannot be
 * 	mapped directly into the scatterlist get copied.
 * @shadow_buffer_size: size of shadow_buffer.
 * @shadow_buffer_pos: current position in shadow_buffer.
 * @sgs: list of scatterlist pointers to eventually pass to virtio.
 * @num_sgs: total number of entries in sgs.
 * @cur_sg: next entry in @sgs to be written into.
 *
 */
struct scatterlist_filler {
	struct scatterlist *descs;
	size_t num_descs;
	size_t cur_desc;

	void *shadow_buffer;
	size_t shadow_buffer_size;
	size_t shadow_buffer_pos;

	struct scatterlist **sgs;
	size_t num_sgs;
	size_t cur_sg;
};

/**
 * scatterlist_filler_add_sg - Add a scatterlist to the list of sgs.
 */
int scatterlist_filler_add_sg(struct scatterlist_filler *filler,
			      struct scatterlist *sg);

/**
 * scatterlist_filler_add_ioctl_cmd - Add an ioctl command to the list.
 */
int scatterlist_filler_add_ioctl_cmd(struct scatterlist_filler *filler,
				     struct virtio_media_session *session,
				     u32 ioctl_code);

/**
 * scatterlist_filler_add_ioctl_resp - Add storage to receive an ioctl response to the list.
 */
int scatterlist_filler_add_ioctl_resp(struct scatterlist_filler *filler,
				      struct virtio_media_session *session);

/**
 * scatterlist_filler_add_data - Add arbitrary data to the list.
 *
 * The data will either be directly mapped, or copied into the shadow buffer to be mapped there.
 */
int scatterlist_filler_add_data(struct scatterlist_filler *filler, void *data,
				size_t len);

/**
 * scatterlist_filler_add_buffer - Add a v4l2_buffer and its planes to the list.
 *
 * The buffer and its pointers will be either directly mapped, or copied into the shadow buffer to be mapped there.
 *
 * For USERPTR buffer, the buffer data is always directly mapped, not copied.
 */
int scatterlist_filler_add_buffer(struct scatterlist_filler *filler,
				  struct v4l2_buffer *buffer, bool add_userptr);

/**
 * scatterlist_filler_add_ext_ctrls - Add a v4l2_ext_controls and its controls to the list.
 *
 * The controls will be either directly mapped, or copied into the shadow buffer to be mapped there.
 *
 * For controls with pointer data, the data is always directly mapped, not copied.
 */
int scatterlist_filler_add_ext_ctrls(struct scatterlist_filler *filler,
				     struct v4l2_ext_controls *ctrls,
				     bool add_userptrs);

/**
 * scatterlist_filler_retrieve_data - Retrieve data written by the device on the shadow buffer, if needed.
 *
 * If the shadow buffer is pointed to by @sg, copy its content back into @data.
 */
int scatterlist_filler_retrieve_data(struct virtio_media_session *session,
				     struct scatterlist *sg, void *data,
				     size_t len);

/**
 * scatterlist_filler_retrieve_buffer - Retrieve buffer data written by the device on the shadow buffer, if needed.
 *
 * If the shadow buffer is pointed to by @sg, copy its content back into @buffer.
 */
int scatterlist_filler_retrieve_buffer(struct virtio_media_session *session,
				       struct scatterlist **sgs_idx,
				       struct v4l2_buffer *buffer,
				       size_t num_planes);

/**
 * scatterlist_filler_retrieve_ext_ctrls - Retrieve controls data written by the device on the shadow buffer, if needed.
 *
 * If the shadow buffer is pointed to by @sg, copy its content back into @ctrls.
 */
int scatterlist_filler_retrieve_ext_ctrls(struct virtio_media_session *session,
					  struct scatterlist **sgs_idx,
					  struct v4l2_ext_controls *ctrls);

#endif // __VIRTIO_MEDIA_DESCRIPTOR_H
