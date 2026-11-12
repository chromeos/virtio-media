# virtio-media-libcamera

A [libcamera](https://libcamera.org/) capture backend for virtio-media, implementing
`virtio_media::devices::capture_device::CaptureBackend`.

## Why

The `v4l2_device_proxy` device forwards a host V4L2 node into the guest, which covers cameras the
host exposes as plain V4L2 capture devices — in practice, UVC webcams. Cameras behind an ISP
pipeline (Raspberry Pi camera modules, Intel IPU6 laptop cameras, most ARM SoC sensors) have no
usable V4L2 capture node and are reachable only through libcamera. This backend makes those
cameras available to guests.

## Usage

```rust
use virtio_media::devices::capture_device::CaptureDevice;
use virtio_media_libcamera::LibcameraBackend;

let backend = LibcameraBackend::new(camera_index)?;
let device = CaptureDevice::new(event_queue, host_mapper, backend)?;
```

`camera_index` selects among the cameras libcamera enumerates, in its own ordering. Note that a
single physical device may present as several cameras: an HP HD Camera, for instance, enumerates
both an RGB sensor and an IR sensor.

## libcamera version requirement

The [`libcamera`](https://crates.io/crates/libcamera) crate binds a specific range of libcamera
releases and rejects anything outside it at build time. Version 0.7 of the crate supports libcamera
0.4.0 through 0.7.0.

Distributions lag well behind: Ubuntu 24.04 ships libcamera 0.2.0, which is rejected. Building
libcamera from source is currently the practical option on most systems:

```sh
sudo apt install -y meson ninja-build pkg-config \
  python3-yaml python3-ply python3-jinja2 \
  libyaml-dev libgnutls28-dev openssl \
  libudev-dev libevent-dev libdrm-dev libjpeg-dev

git clone https://git.libcamera.org/libcamera/libcamera.git
cd libcamera
git checkout v0.7.0     # a tag, not master: the version is derived from `git describe`,
                        # and a master build reports 0.7.0+123-abc1234
meson setup build
ninja -C build
sudo ninja -C build install
sudo ldconfig
```

Then point `pkg-config` at the new installation:

```sh
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
pkg-config --modversion libcamera   # expect 0.7.0
```

There is no need to remove a distribution libcamera: the sonames differ, so both coexist.

## Design notes

**All libcamera state lives on a dedicated thread.** libcamera's ownership chain is
`CameraManager` → `Camera<'_>` → `ActiveCamera<'_>`, where every handle borrows from the manager, so
holding them in a struct would be self-referential. Keeping them on a thread's stack avoids the
problem and matches libcamera's threading model, since `on_request_completed` already fires on its
own thread. The backend itself holds only channel endpoints.

**Frames are copied.** libcamera owns a small fixed set of framebuffers and cycles them
continuously; the guest independently owns up to 32 MMAP buffers. Each completed request is copied
into a queued guest buffer, and dropped if none is waiting — normal camera behaviour when the
consumer is slow. Zero-copy would be a worthwhile follow-up.

**Buffer sizes come from libcamera, never from a formula.** The allocation size per format is not
predictable: MJPEG 1280x720 allocates two bytes per pixel while GREY 640x360 allocates exactly one.
`sizeimage` and the guest buffer size both come from `StreamConfiguration::get_frame_size()` after
`validate()`.

**Startup frames are filtered.** A UVC camera emits junk for the first few requests after `start()`,
which libcamera flags as `Startup` or `Error`. Measured sequences 0, 1 and 3 arrived with
`bytes_used` of 2560, 32 and 42721 against a steady state near 80000, with sequence 2 never
arriving. Forwarding them would hand the guest corrupt JPEGs on every `STREAMON`.

**Frame rate is measured, not assumed.** libcamera's UVC pipeline handler exposes no
`FrameDurationLimits`, and the true rate is not stable: the same camera was measured at 10, 14 and
29 fps as auto-exposure varied the exposure time. The backend maintains an exponential moving
average of the observed interval and reports it through `frame_interval_ns`, defaulting to 30 fps
before any frames have been seen. Omitting the rate ioctls entirely is worse in practice —
applications then guess, and ffmpeg assumes 10 fps, timing every recording wrongly.

## Testing

Verified with `v4l2-compliance -d0 -s` under crosvm against an HP HD Camera, on both the RGB sensor
(MJPEG and YUYV, eight and five frame sizes) and the IR sensor (GREY, one mode): 54 tests, 0
failures on each.
