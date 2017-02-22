/* -*- mode: C; c-file-style: "k&r"; tab-width 4; indent-tabs-mode: t; -*- */

/*
 * Copyright (C) 2013 Rob Clark <robclark@freedesktop.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Rob Clark <robclark@freedesktop.org>
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "kgsl_priv.h"

#include <linux/fb.h>

static int kgsl_bo_offset(struct fd_bo *bo, uint64_t *offset)
{
	struct kgsl_bo *kgsl_bo = to_kgsl_bo(bo);

	*offset = kgsl_bo->gpuaddr;

	return 0;
}

static int kgsl_bo_cpu_prep(struct fd_bo *bo, struct fd_pipe *pipe, uint32_t op)
{
	uint32_t timestamp = kgsl_bo_get_timestamp(to_kgsl_bo(bo));

	if (op & DRM_FREEDRENO_PREP_NOSYNC) {
		uint32_t current;
		int ret;

		/* special case for is_idle().. we can't really handle that
		 * properly in kgsl (perhaps we need a way to just disable
		 * the bo-cache for kgsl?)
		 */
		if (!pipe)
			return -EBUSY;

		ret = kgsl_pipe_timestamp(to_kgsl_pipe(pipe), &current);
		if (ret)
			return ret;

		if (timestamp > current)
			return -EBUSY;

		return 0;
	}

	if (timestamp)
		fd_pipe_wait(pipe, timestamp);

	return 0;
}

static void kgsl_bo_cpu_fini(struct fd_bo *bo)
{
}

static int kgsl_bo_madvise(struct fd_bo *bo, int willneed)
{
	return willneed; /* not supported by kgsl */
}

static void kgsl_bo_destroy(struct fd_bo *bo)
{
	struct kgsl_bo *kgsl_bo = to_kgsl_bo(bo);
	gsl_memdesc_t memdesc = {
			.gpuaddr = kgsl_bo->gpuaddr,
	};
	struct _kgsl_sharedmem_free_t req = {
			.memdesc = &memdesc,
	};
	int ret;

	printf("@MF@ %s gpuaddr=%08x\n", __func__, kgsl_bo->gpuaddr);

	ret = ioctl(kgsl_bo->dev->pipe->fd, IOCTL_KGSL_SHAREDMEM_FREE, &req);
	if (ret) {
		ERROR_MSG("sharedmem free failed: %s", strerror(errno));
	}

	free(kgsl_bo);
}

static void *kgsl_bo_map(struct fd_bo *bo)
{
	struct kgsl_bo *kgsl_bo = to_kgsl_bo(bo);
	uint64_t offset;
	int ret;
	void *p;

	ret = kgsl_bo_offset(bo, &offset);
	if (ret) {
		return NULL;
	}

	p = mmap(0, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED,
			kgsl_bo->dev->pipe->fd, offset);
	if (p == MAP_FAILED) {
		ERROR_MSG("mmap failed: %s", strerror(errno));
		return NULL;
	}
	return p;
}

static const struct fd_bo_funcs funcs = {
		.offset = kgsl_bo_offset,
		.cpu_prep = kgsl_bo_cpu_prep,
		.cpu_fini = kgsl_bo_cpu_fini,
		.madvise = kgsl_bo_madvise,
		.destroy = kgsl_bo_destroy,
		.map = kgsl_bo_map,
};

/* allocate a buffer handle: */
drm_private int kgsl_bo_new_handle(struct fd_device *dev,
		uint32_t size, uint32_t flags, uint32_t *handle)
{
	struct kgsl_device *kgsl_dev = to_kgsl_device(dev);
	gsl_memdesc_t memdesc;
	struct _kgsl_sharedmem_alloc_t req = {
			.device_id = GSL_DEVICE_YAMATO,
			.sizebytes = size,
			.flags = GSL_MEMFLAGS_ALIGN4K,
			.memdesc = &memdesc,
	};
	int ret;

	ret = ioctl(kgsl_dev->pipe->fd, IOCTL_KGSL_SHAREDMEM_ALLOC, &req);
	if (ret) {
		ERROR_MSG("gpumem allocation failed: %s", strerror(errno));
		return ret;
	}
	printf("@MF@ %s size=0x%x flags=0x%x => gpuaddr %08x\n", __func__, size, flags, memdesc.gpuaddr);

	*handle = memdesc.gpuaddr;

	return 0;
}

/* allocate a new buffer object */
drm_private struct fd_bo * kgsl_bo_from_handle(struct fd_device *dev,
		uint32_t size, uint32_t handle)
{
	struct kgsl_device *kgsl_dev = to_kgsl_device(dev);
	struct kgsl_bo *kgsl_bo;
	struct fd_bo *bo;
	unsigned i;

	kgsl_bo = calloc(1, sizeof(*kgsl_bo));
	if (!kgsl_bo)
		return NULL;

	kgsl_bo->gpuaddr = handle;
	kgsl_bo->dev = kgsl_dev;
	bo = &kgsl_bo->base;
	bo->funcs = &funcs;

	for (i = 0; i < ARRAY_SIZE(kgsl_bo->list); i++)
		list_inithead(&kgsl_bo->list[i]);

	return bo;
}

drm_private uint32_t kgsl_bo_gpuaddr(struct kgsl_bo *kgsl_bo, uint32_t offset)
{
	return kgsl_bo->gpuaddr + offset;
}

/*
 * Super-cheezy way to synchronization between mesa and ddx..  the
 * SET_ACTIVE ioctl gives us a way to stash a 32b # w/ a GEM bo, and
 * GET_BUFINFO gives us a way to retrieve it.  We use this to stash
 * the timestamp of the last ISSUEIBCMDS on the buffer.
 *
 * To avoid an obscene amount of syscalls, we:
 *  1) Only set the timestamp for buffers w/ an flink name, ie.
 *     only buffers shared across processes.  This is enough to
 *     catch the DRI2 buffers.
 *  2) Only set the timestamp for buffers submitted to the 3d ring
 *     and only check the timestamps on buffers submitted to the
 *     2d ring.  This should be enough to handle synchronizing of
 *     presentation blit.  We could do synchronization in the other
 *     direction too, but that would be problematic if we are using
 *     the 3d ring from DDX, since client side wouldn't know this.
 *
 * The waiting on timestamp happens before flush, and setting of
 * timestamp happens after flush.  It is transparent to the user
 * of libdrm_freedreno as all the tracking of buffers happens via
 * _emit_reloc()..
 */

drm_private void kgsl_bo_set_timestamp(struct kgsl_bo *kgsl_bo,
		uint32_t timestamp)
{
#if 0
	struct fd_bo *bo = &kgsl_bo->base;
	if (bo->name) {
		struct drm_kgsl_gem_active req = {
				.handle = bo->handle,
				.active = timestamp,
		};
		int ret;

		ret = drmCommandWrite(bo->dev->fd, DRM_KGSL_GEM_SET_ACTIVE,
				&req, sizeof(req));
		if (ret) {
			ERROR_MSG("set active failed: %s", strerror(errno));
		}
	}
#endif
}

drm_private uint32_t kgsl_bo_get_timestamp(struct kgsl_bo *kgsl_bo)
{
	uint32_t timestamp = 0;
#if 0
	struct fd_bo *bo = &kgsl_bo->base;
	if (bo->name) {
		struct drm_kgsl_gem_bufinfo req = {
				.handle = bo->handle,
		};
		int ret;

		ret = drmCommandWriteRead(bo->dev->fd, DRM_KGSL_GEM_GET_BUFINFO,
				&req, sizeof(req));
		if (ret) {
			ERROR_MSG("get bufinfo failed: %s", strerror(errno));
			return 0;
		}

		timestamp = req.active;
	}
#endif
	return timestamp;
}
