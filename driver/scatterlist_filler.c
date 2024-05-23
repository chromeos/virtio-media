// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0+

/*
 * Scatterlist filler helpers for virtio-media.
 *
 * Copyright (c) 2023-2024 Google LLC.
 */

#include <linux/scatterlist.h>
#include <linux/moduleparam.h>
#include <media/videobuf2-memops.h>

#include "scatterlist_filler.h"
#include "session.h"

/**
 * If set to `true`, then the driver will always copy the data passed to the
 * host into the shadow buffer (instead of trying to map the source memory into
 * the SG table directly).
 */
static bool always_use_shadow_buffer = false;
module_param(always_use_shadow_buffer, bool, 0660);

/* Convert a V4L2 IOCTL into the IOCTL code we can give to the host */
#define VIRTIO_MEDIA_IOCTL_CODE(IOCTL) ((IOCTL >> _IOC_NRSHIFT) & _IOC_NRMASK)

int scatterlist_filler_add_sg(struct scatterlist_filler *filler,
			      struct scatterlist *sg)
{
	if (filler->cur_sg >= filler->num_sgs)
		return -ENOSPC;
	filler->sgs[filler->cur_sg++] = sg;

	return 0;
}

int scatterlist_filler_add_data(struct scatterlist_filler *filler, void *data,
				size_t len)
{
	BUG_ON(len == 0);

	if (filler->cur_sg >= filler->num_sgs)
		return -ENOMEM;

	if (filler->cur_desc >= filler->num_descs)
		return -ENOSPC;
	filler->sgs[filler->cur_sg] = &filler->descs[filler->cur_desc];

	if (!always_use_shadow_buffer && virt_addr_valid(data + len)) {
		/* 
		 * If "data" is in the 1:1 physical memory mapping then we can
		 * use a single SG entry and avoid copying.
		 */
		struct page *page = virt_to_page(data);
		size_t offset = (((size_t)data) & ~PAGE_MASK);
		struct scatterlist *next_desc =
			&filler->descs[filler->cur_desc];

		memset(next_desc, 0, sizeof(*next_desc));
		sg_set_page(next_desc, page, len, offset);
		filler->cur_desc++;
	} else if (!always_use_shadow_buffer && is_vmalloc_addr(data)) {
		int prev_pfn = -2;

		/* 
		 * If "data" has been vmalloc'ed, we need one at most entry per
		 * memory page but can avoid copying.
		 */
		while (len > 0) {
			struct page *page = vmalloc_to_page(data);
			int cur_pfn = page_to_pfn(page);
			/* All pages but the first will start at offset 0. */
			unsigned long offset =
				(((unsigned long)data) & ~PAGE_MASK);
			size_t len_in_page = min(PAGE_SIZE - offset, len);
			struct scatterlist *next_desc =
				&filler->descs[filler->cur_desc];

			if (filler->cur_desc >= filler->num_descs)
				return -ENOSPC;

			/* Optimize contiguous pages */
			if (cur_pfn == prev_pfn + 1) {
				(next_desc - 1)->length += len_in_page;
			} else {
				memset(next_desc, 0, sizeof(*next_desc));
				sg_set_page(next_desc, page, len_in_page,
					    offset);
				filler->cur_desc++;
			}
			data += len_in_page;
			len -= len_in_page;
			prev_pfn = cur_pfn;
		}
	} else {
		/*
		 * As a last resort, copy into the shadow buffer and reference
		 * it with a single SG entry.
		 */
		void *shadow_buffer =
			filler->shadow_buffer + filler->shadow_buffer_pos;
		struct page *page = virt_to_page(shadow_buffer);
		unsigned long offset =
			(((unsigned long)shadow_buffer) & ~PAGE_MASK);
		struct scatterlist *next_desc =
			&filler->descs[filler->cur_desc];

		if (len >
		    filler->shadow_buffer_size - filler->shadow_buffer_pos)
			return -ENOSPC;

		memcpy(shadow_buffer, data, len);
		memset(next_desc, 0, sizeof(*next_desc));
		sg_set_page(next_desc, page, len, offset);
		filler->cur_desc++;
		filler->shadow_buffer_pos += len;
	}

	sg_mark_end(&filler->descs[filler->cur_desc - 1]);
	filler->cur_sg++;

	return 0;
}

int scatterlist_filler_add_ioctl_cmd(struct scatterlist_filler *filler,
				     struct virtio_media_session *session,
				     u32 ioctl_code)
{
	struct virtio_media_cmd_ioctl *cmd_ioctl = &session->cmd.ioctl;

	cmd_ioctl->hdr.cmd = VIRTIO_MEDIA_CMD_IOCTL;
	cmd_ioctl->session_id = session->id;
	cmd_ioctl->code = VIRTIO_MEDIA_IOCTL_CODE(ioctl_code);

	return scatterlist_filler_add_data(filler, cmd_ioctl,
					   sizeof(*cmd_ioctl));
}

int scatterlist_filler_add_ioctl_resp(struct scatterlist_filler *filler,
				      struct virtio_media_session *session)
{
	struct virtio_media_resp_ioctl *resp_ioctl = &session->resp.ioctl;

	return scatterlist_filler_add_data(filler, resp_ioctl,
					   sizeof(*resp_ioctl));
}

int scatterlist_filler_retrieve_data(struct virtio_media_session *session,
				     struct scatterlist *sg, void *data,
				     size_t len)
{
	void *shadow_buf = session->shadow_buf;
	void *kaddr = pfn_to_kaddr(page_to_pfn(sg_page(sg))) + sg->offset;

	BUG_ON(len == 0);

	/*
	 * If our SG entry points inside the shadow buffer, copy the data back to its
	 * origin.
	 */
	if (kaddr >= shadow_buf &&
	    kaddr < shadow_buf + VIRTIO_SHADOW_BUF_SIZE) {
		if (kaddr + len >= shadow_buf + VIRTIO_SHADOW_BUF_SIZE)
			return -EINVAL;

		BUG_ON(sg->length != len);

		memcpy(data, kaddr, len);
	}

	return 0;
}

/*
 * num_planes if the number of planes in the original buffer provided by user-space.
 *
 * @num_buffer_sgs: number of SGs that were used by this buffer. Useful to know
 * if we have SG lists for USERPTR buffers that we need to free.
 */
int scatterlist_filler_retrieve_buffer(struct virtio_media_session *session,
				       struct scatterlist **buffer_sgs,
				       struct v4l2_buffer *b, size_t num_planes)
{
	struct v4l2_plane *planes = NULL;
	int i = 0;
	int ret;

	/* Keep data that will be overwritten but that we need to check later */
	if (V4L2_TYPE_IS_MULTIPLANAR(b->type)) {
		planes = b->m.planes;
	}

	ret = scatterlist_filler_retrieve_data(session, buffer_sgs[i++], b,
					       sizeof(*b));
	if (ret)
		return ret;

	if (planes != NULL && num_planes > 0) {
		b->m.planes = planes;
		if (b->length > num_planes)
			return -ENOSPC;

		ret = scatterlist_filler_retrieve_data(
			session, buffer_sgs[i++], b->m.planes,
			sizeof(struct v4l2_plane) * num_planes);
		if (ret)
			return ret;
	}

	return 0;
}

int scatterlist_filler_retrieve_ext_ctrls(struct virtio_media_session *session,
					  struct scatterlist **ctrls_sgs,
					  int num_ctrls_sgs,
					  struct v4l2_ext_controls *ctrls)
{
	struct v4l2_ext_control *controls_backup = ctrls->controls;
	int i = 0;
	int ret;

	ret = scatterlist_filler_retrieve_data(session, ctrls_sgs[i++], ctrls,
					       sizeof(*ctrls));
	if (ret)
		return ret;

	ctrls->controls = controls_backup;

	if (ctrls->count > 0 && ctrls->controls) {
		ret = scatterlist_filler_retrieve_data(
			session, ctrls_sgs[i++], ctrls->controls,
			sizeof(struct v4l2_ext_control) * ctrls->count);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * prepare_userptr_to_host - 
 *
 * Returns -EFAULT if `userptr` was not a valid user address, which is a case
 * the driver should consider as "normal" operation. All other failures signal
 * a problem with the driver.
 */
static int prepare_userptr_to_host(struct scatterlist_filler *filler,
				   unsigned long userptr, unsigned long length,
				   struct virtio_media_sg_entry **sg_list,
				   int *nents)
{
	struct sg_table sg_table = {};
	struct frame_vector *framevec;
	struct scatterlist *sg_iter;
	struct page **pages;
	unsigned int pages_count;
	unsigned int offset = userptr & ~PAGE_MASK;
	size_t entries_size;
	int i;
	int ret;

	framevec = vb2_create_framevec(userptr, length, true);
	if (IS_ERR(framevec)) {
		if (PTR_ERR(framevec) != -EFAULT) {
			printk("error creating frame vector for userptr 0x%lx, length 0x%lx: %ld\n",
			       userptr, length, PTR_ERR(framevec));
		} else {
			/* -EINVAL is expected in case of invalid userptr. */
			framevec = ERR_PTR(-EINVAL);
		}
		return PTR_ERR(framevec);
	}

	pages = frame_vector_pages(framevec);
	if (IS_ERR(pages)) {
		printk("error getting vector pages\n");
		ret = PTR_ERR(pages);
		goto done;
	}
	pages_count = frame_vector_count(framevec);
	/* TODO turn into a SG list directly here and skip the sg table step */
	ret = sg_alloc_table_from_pages(&sg_table, pages, pages_count, offset,
					length, 0);
	if (ret) {
		printk("error creating sg table\n");
		goto done;
	}

	/* Allocate our actual SG in the shadow buffer. */
	*nents = sg_nents(sg_table.sgl);
	entries_size = sizeof(**sg_list) * *nents;
	if (filler->shadow_buffer_pos + entries_size >
	    filler->shadow_buffer_size) {
		ret = -ENOMEM;
		goto free_sg;
	}

	*sg_list = filler->shadow_buffer + filler->shadow_buffer_pos;
	filler->shadow_buffer_pos += entries_size;

	for_each_sgtable_sg(&sg_table, sg_iter, i) {
		struct virtio_media_sg_entry *sg_entry = &(*sg_list)[i];
		sg_entry->start = sg_phys(sg_iter);
		sg_entry->len = sg_iter->length;
	}

free_sg:
	sg_free_table(&sg_table);

done:
	vb2_destroy_framevec(framevec);
	return ret;
}

static int scatterlist_filler_add_userptr(struct scatterlist_filler *filler,
					  unsigned long userptr,
					  unsigned long length)
{
	int ret;
	int nents;
	struct virtio_media_sg_entry *sg_list;

	ret = prepare_userptr_to_host(filler, userptr, length, &sg_list,
				      &nents);
	if (ret)
		return ret;

	ret = scatterlist_filler_add_data(filler, sg_list,
					  sizeof(*sg_list) * nents);
	if (ret)
		return ret;

	return 0;
}

int scatterlist_filler_add_buffer(struct scatterlist_filler *filler,
				  struct v4l2_buffer *b)
{
	int i;
	int ret;

	/* Fixup: plane length must be zero if userptr is NULL */
	if (!V4L2_TYPE_IS_MULTIPLANAR(b->type) &&
	    b->memory == V4L2_MEMORY_USERPTR && b->m.userptr == 0)
		b->length = 0;

	/* v4l2_buffer */
	ret = scatterlist_filler_add_data(filler, b, sizeof(*b));
	if (ret)
		return ret;

	if (V4L2_TYPE_IS_MULTIPLANAR(b->type) && b->length > 0) {
		/* Fixup: plane length must be zero if userptr is NULL */
		if (b->memory == V4L2_MEMORY_USERPTR) {
			for (i = 0; i < b->length; i++) {
				struct v4l2_plane *plane = &b->m.planes[i];

				if (plane->m.userptr == 0)
					plane->length = 0;
			}
		}

		/* Array of v4l2_planes */
		ret = scatterlist_filler_add_data(filler, b->m.planes,
						  sizeof(struct v4l2_plane) *
							  b->length);
		if (ret)
			return ret;
	}

	return 0;
}

int scatterlist_filler_add_buffer_userptr(struct scatterlist_filler *filler,
					  struct v4l2_buffer *b)
{
	int i;
	int ret;

	if (b->memory != V4L2_MEMORY_USERPTR)
		return 0;

	if (V4L2_TYPE_IS_MULTIPLANAR(b->type)) {
		for (i = 0; i < b->length; i++) {
			struct v4l2_plane *plane = &b->m.planes[i];
			if (b->memory == V4L2_MEMORY_USERPTR &&
			    plane->length > 0) {
				ret = scatterlist_filler_add_userptr(
					filler, plane->m.userptr,
					plane->length);
				if (ret)
					return ret;
			}
		}
	} else if (b->length > 0) {
		ret = scatterlist_filler_add_userptr(filler, b->m.userptr,
						     b->length);
		if (ret)
			return ret;
	}

	return 0;
}

int scatterlist_filler_add_ext_ctrls(struct scatterlist_filler *filler,
				     struct v4l2_ext_controls *ctrls,
				     bool add_userptrs)
{
	int i;
	int ret;

	/* v4l2_ext_controls */
	ret = scatterlist_filler_add_data(filler, ctrls, sizeof(*ctrls));
	if (ret)
		return ret;

	if (ctrls->count > 0) {
		/* array of v4l2_controls */
		ret = scatterlist_filler_add_data(filler, ctrls->controls,
						  sizeof(ctrls->controls[0]) *
							  ctrls->count);
		if (ret)
			return ret;
	}

	if (!add_userptrs)
		return 0;

	/* Pointers to user memory in individual controls */
	for (i = 0; i < ctrls->count; i++) {
		struct v4l2_ext_control *ctrl = &ctrls->controls[i];
		if (ctrl->size > 0) {
			ret = scatterlist_filler_add_userptr(
				filler, (unsigned long)ctrl->ptr, ctrl->size);
			if (ret)
				return ret;
		}
	}

	return 0;
}
