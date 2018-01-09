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


static int kgsl_pipe_get_param(struct fd_pipe *pipe,
		enum fd_param_id param, uint64_t *value)
{
	struct kgsl_pipe *kgsl_pipe = to_kgsl_pipe(pipe);
	switch (param) {
	case FD_DEVICE_ID:
		*value = kgsl_pipe->devinfo.device_id;
		return 0;
	case FD_GPU_ID: {
		uint32_t chip_id = kgsl_pipe->devinfo.chip_id;

		*value = ((chip_id >> 8) & 0xF) +
			(((chip_id >> 12) & 0xF) * 10) +
			(((chip_id >> 16) & 0xF) * 100);
		return 0;
	}
	case FD_GMEM_SIZE:
		*value = kgsl_pipe->devinfo.gmem_sizebytes;
		return 0;
	case FD_CHIP_ID:
		*value = kgsl_pipe->devinfo.chip_id;
		return 0;
	case FD_MAX_FREQ:
	case FD_TIMESTAMP:
	case FD_NR_RINGS:
		/* unsupported on kgsl */
		return -1;
	default:
		ERROR_MSG("invalid param id: %d", param);
		return -1;
	}
}

static int kgsl_pipe_wait(struct fd_pipe *pipe, uint32_t timestamp,
		uint64_t timeout)
{
	struct kgsl_pipe *kgsl_pipe = to_kgsl_pipe(pipe);
	struct _kgsl_cmdstream_waittimestamp_t req = {
			.device_id = GSL_DEVICE_YAMATO,
			.timestamp = timestamp,
			.timeout   = 5000,
	};
	int ret;

	do {
		ret = ioctl(kgsl_pipe->fd, IOCTL_KGSL_CMDSTREAM_WAITTIMESTAMP, &req);
	} while ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN)));
	if (ret)
		ERROR_MSG("waittimestamp failed! %d (%s)", ret, strerror(errno));
	else
		kgsl_pipe_process_pending(kgsl_pipe, timestamp);
	return ret;
}

drm_private int kgsl_pipe_timestamp(struct kgsl_pipe *kgsl_pipe,
		uint32_t *timestamp)
{
	gsl_timestamp_t ts;
	struct _kgsl_cmdstream_readtimestamp_t req = {
			.device_id = GSL_DEVICE_YAMATO,
			.type = GSL_TIMESTAMP_RETIRED,
			.timestamp = &ts,
	};
	int ret = ioctl(kgsl_pipe->fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP, &req);
	if (ret) {
		ERROR_MSG("readtimestamp failed! %d (%s)",
				ret, strerror(errno));
		return ret;
	}
	*timestamp = ts;
	return 0;
}

static void kgsl_pipe_destroy(struct fd_pipe *pipe)
{
	struct kgsl_pipe *kgsl_pipe = to_kgsl_pipe(pipe);
	struct _kgsl_context_destroy_t req = {
			.device_id = GSL_DEVICE_YAMATO,
			.drawctxt_id = kgsl_pipe->drawctxt_id,
	};

	DEBUG_MSG("@MF@ %s [%p] fd=%d drawctxt=%d\n", __func__, kgsl_pipe, kgsl_pipe->fd, kgsl_pipe->drawctxt_id);

	if (kgsl_pipe->drawctxt_id)
		ioctl(kgsl_pipe->fd, IOCTL_KGSL_CONTEXT_DESTROY, &req);

	if (kgsl_pipe->fd >= 0)
		close(kgsl_pipe->fd);

	free(kgsl_pipe);
}

static const struct fd_pipe_funcs funcs = {
		.ringbuffer_new = kgsl_ringbuffer_new,
		.get_param = kgsl_pipe_get_param,
		.wait = kgsl_pipe_wait,
		.destroy = kgsl_pipe_destroy,
};

drm_private int is_kgsl_pipe(struct fd_pipe *pipe)
{
	return pipe->funcs == &funcs;
}

/* add buffer to submit list when it is referenced in cmdstream: */
drm_private void kgsl_pipe_add_submit(struct kgsl_pipe *kgsl_pipe,
		struct kgsl_bo *kgsl_bo)
{
	struct fd_pipe *pipe = &kgsl_pipe->base;
	struct fd_bo *bo = &kgsl_bo->base;
	struct list_head *list = &kgsl_bo->list[pipe->id];
	if (LIST_IS_EMPTY(list)) {
		fd_bo_ref(bo);
	} else {
		list_del(list);
	}
	list_addtail(list, &kgsl_pipe->submit_list);
}

/* prepare buffers on submit list before flush: */
drm_private void kgsl_pipe_pre_submit(struct kgsl_pipe *kgsl_pipe)
{
	struct fd_pipe *pipe = &kgsl_pipe->base;
	struct kgsl_bo *kgsl_bo = NULL;

	if (!kgsl_pipe->p3d)
		kgsl_pipe->p3d = fd_pipe_new(pipe->dev, FD_PIPE_3D);

	LIST_FOR_EACH_ENTRY(kgsl_bo, &kgsl_pipe->submit_list, list[pipe->id]) {
		uint32_t timestamp = kgsl_bo_get_timestamp(kgsl_bo);
		if (timestamp)
			fd_pipe_wait(kgsl_pipe->p3d, timestamp);
	}
}

/* process buffers on submit list after flush: */
drm_private void kgsl_pipe_post_submit(struct kgsl_pipe *kgsl_pipe,
		uint32_t timestamp)
{
	struct fd_pipe *pipe = &kgsl_pipe->base;
	struct kgsl_bo *kgsl_bo = NULL, *tmp;

	LIST_FOR_EACH_ENTRY_SAFE(kgsl_bo, tmp, &kgsl_pipe->submit_list, list[pipe->id]) {
		struct list_head *list = &kgsl_bo->list[pipe->id];
		list_del(list);
		kgsl_bo->timestamp[pipe->id] = timestamp;
		list_addtail(list, &kgsl_pipe->pending_list);

		kgsl_bo_set_timestamp(kgsl_bo, timestamp);
	}

	if (!kgsl_pipe_timestamp(kgsl_pipe, &timestamp))
		kgsl_pipe_process_pending(kgsl_pipe, timestamp);
}

drm_private void kgsl_pipe_process_pending(struct kgsl_pipe *kgsl_pipe,
		uint32_t timestamp)
{
	struct fd_pipe *pipe = &kgsl_pipe->base;
	struct kgsl_bo *kgsl_bo = NULL, *tmp;

	LIST_FOR_EACH_ENTRY_SAFE(kgsl_bo, tmp, &kgsl_pipe->pending_list, list[pipe->id]) {
		struct list_head *list = &kgsl_bo->list[pipe->id];
		if (kgsl_bo->timestamp[pipe->id] > timestamp)
			return;
		list_delinit(list);
		kgsl_bo->timestamp[pipe->id] = 0;
		fd_bo_del(&kgsl_bo->base);
	}
}

static int getprop(int fd, enum _gsl_property_type_t type,
		void *value, int sizebytes)
{
	struct _kgsl_device_getproperty_t req = {
			.device_id = GSL_DEVICE_YAMATO,
			.type = type,
			.value = value,
			.sizebytes = sizebytes,
	};
	return ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &req);
}

#define GETPROP(fd, prop, x) do { \
	if (getprop((fd), GSL_PROP_##prop, &(x), sizeof(x))) {     \
		ERROR_MSG("failed to get property: " #prop);            \
		goto fail;                                              \
	} } while (0)


static int kgsl_pipe_start(int fd)
{
	kgsl_device_start_t req = {
		.device_id = GSL_DEVICE_YAMATO,
		.flags = 0
	};

	return ioctl(fd, IOCTL_KGSL_DEVICE_START, &req);
}

drm_private struct fd_pipe * kgsl_pipe_new(struct fd_device *dev,
		enum fd_pipe_id id, uint32_t prio)
{
	static const char *paths[] = {
			[FD_PIPE_3D] = "/dev/gsl_kmod",
			[FD_PIPE_2D] = "/dev/kgsl-2d0",
	};
	struct kgsl_device *kgsl_dev = to_kgsl_device(dev);
	unsigned int drawctxt_id;
	struct _kgsl_context_create_t req = {
			.device_id = GSL_DEVICE_YAMATO,
			.drawctxt_id = &drawctxt_id,
			.type = GSL_CONTEXT_TYPE_OPENGL,
			.flags = 0x2, // ???
	};
	struct kgsl_pipe *kgsl_pipe = NULL;
	struct fd_pipe *pipe = NULL;
	int ret, fd;

	fd = open(paths[id], O_RDWR);
	if (fd < 0) {
		ERROR_MSG("could not open %s device: %d (%s)",
				paths[id], fd, strerror(errno));
		goto fail;
	}

	ret = kgsl_pipe_start(fd);
	if (ret) {
		ERROR_MSG("Failed to start (%d)\n", ret);
		goto fail;
	}


	ret = ioctl(fd, IOCTL_KGSL_CONTEXT_CREATE, &req);
	if (ret) {
		ERROR_MSG("failed to allocate context: %d (%s)",
				ret, strerror(errno));
		goto fail;
	}

	kgsl_pipe = calloc(1, sizeof(*kgsl_pipe));
	if (!kgsl_pipe) {
		ERROR_MSG("allocation failed");
		goto fail;
	}

	pipe = &kgsl_pipe->base;
	pipe->funcs = &funcs;

	kgsl_pipe->fd = fd;
	kgsl_pipe->drawctxt_id = (uint32_t)drawctxt_id;

	list_inithead(&kgsl_pipe->submit_list);
	list_inithead(&kgsl_pipe->pending_list);

	//GETPROP(fd, VERSION,     kgsl_pipe->version);
	GETPROP(fd, DEVICE_INFO, kgsl_pipe->devinfo);
/*
	if (kgsl_pipe->devinfo.gpu_id >= 500) {
		ERROR_MSG("64b unsupported with kgsl");
		goto fail;
	}
*/
	INFO_MSG("Pipe Info:");
	INFO_MSG(" Device:          %s", paths[id]);
	INFO_MSG(" Chip-id:         %d.%d.%d.%d",
			(kgsl_pipe->devinfo.chip_id >> 24) & 0xff,
			(kgsl_pipe->devinfo.chip_id >> 16) & 0xff,
			(kgsl_pipe->devinfo.chip_id >>  8) & 0xff,
			(kgsl_pipe->devinfo.chip_id >>  0) & 0xff);
	INFO_MSG(" Device-id:       %d", kgsl_pipe->devinfo.device_id);
//	INFO_MSG(" GPU-id:          %d", kgsl_pipe->devinfo.gpu_id);
	INFO_MSG(" MMU enabled:     %d", kgsl_pipe->devinfo.mmu_enabled);
	INFO_MSG(" GMEM Base addr:  0x%08x", kgsl_pipe->devinfo.gmem_gpubaseaddr);
	INFO_MSG(" GMEM size:       0x%08x", kgsl_pipe->devinfo.gmem_sizebytes);
#if 0
	INFO_MSG(" Driver version:  %d.%d",
			kgsl_pipe->version.drv_major, kgsl_pipe->version.drv_minor);
	INFO_MSG(" Device version:  %06x",
			kgsl_pipe->chip_id);
#endif
	DEBUG_MSG("@MF@ %s pipe=%p chipId=%08x fd=%d drawctxt=%d\n", __func__,
		kgsl_pipe,
		kgsl_pipe->devinfo.chip_id,
		kgsl_pipe->fd,
		kgsl_pipe->drawctxt_id);

	kgsl_dev->pipe = kgsl_pipe;
	return pipe;
fail:
	if (pipe)
		fd_pipe_del(pipe);
	return NULL;
}
