# Virtio-media

This is a virtio protocol definition, companion Linux guest kernel driver, and
set of host-side devices for virtualizing media devices using virtio, following
the same model (and structures) as V4L2. It can be used to virtualize cameras,
codec devices, or any other device supported by V4L2.

Want to try it? See the [TRY_IT_OUT document](/TRY_IT_OUT.md).

V4L2 is a UAPI that allows a less privileged entity (user-space) to use video
hardware exposed by a more privileged entity (the kernel). Virtio-media is an
encapsulation of this API into virtio, turning it into a virtualization API for
all classes of video devices supported by V4L2, where the host plays the role of
the kernel and the guest the role of user-space.

The host is therefore responsible for presenting a virtual device that behaves
like an actual V4L2 device, which the guest can control.

This repository includes a simple guest Linux kernel module supporting this
protocol. On the host side, devices can be implemented in several ways:

1. By forwarding a V4L2 device from the host into a guest. This works if the
   device is already supported by V4L2 on the host.
2. By emulating a V4L2 device on the host, from the actual interface that the
   device provides.

Note that virtio-media does not require the use of a V4L2 device driver or of
Linux on the host or guest side - V4L2 is only used as a host-guest protocol,
and both sides are free to convert it from/to any model that they wish to use.

The complete definition of V4L2 structures and ioctls can be found under the
[V4L2 UAPI documentation](https://www.kernel.org/doc/html/latest/userspace-api/media/index.html),
which should be referred to alongside this document.

## Driver status

The driver (in the `driver/` directory) should be working and supporting most
V4L2 features, with the exception of the following:

- [Read/Write API](https://www.kernel.org/doc/html/v4.8/media/uapi/v4l/rw.html),
  which is obsolete and inefficient.
- Overlay interface and associated ioctls, i.e.
  - `VIDIOC_OVERLAY`
  - `VIDIOC_G/S_FBUF`
- `DMABUF` buffers (this will be supported at least for virtio objects, other
  kinds of DMABUFs may or may not be usable)
- `VIDIOC_EXPBUF` (to be implemented)
- `VIDIOC_G/S_EDID` (to be implemented if it makes sense in a virtual context)
- Media API and requests. This will probably be supported in the future behind a
  feature flag.

## Devices status

The `devices/` directory contains a Rust crate implementing helper functions to
parse the protocol, interfaces to easily implement devices, and a couple of
device implementations. It is written to be easily pluggable on any VMM. See the
rustdoc in the `devices/` directory for more information.

Implemented devices are:

- A simple video capture device generating a pattern (`simple_device.rs`),
  purely software-based and thus not requiring any kind of hardware. This is
  here for reference and testing purposes.
- A proxy device for host V4L2 devices, i.e. a device allowing to expose a host
  V4L2 device to the guest almost as-is (`v4l2_device_proxy.rs`).

* A FFmpeg-based video decoder device as a separate crate in
  `extras/ffmpeg-decoder`.

## Virtio device ID

Virtio-media uses device ID `48`.

## Virtqueues

There are two queues in use:

0 : commandq - queue for driver commands and device responses to these commands.
The device MUST return the descriptor chains it receives as soon as possible,
and must never hold to them for indefinite periods of time.

1 : eventq - queue for events sent by the device to the driver. The driver MUST
re-queue the descriptor chains returned by the device as soon as possible, and
must never hold on them for indefinite periods of time.

## Configuration area

The configuration area contains the following information:

```c
struct virtio_v4l2_config {
    /// The device_caps field of struct video_device.
    u32 device_caps;
    /// The vfl_devnode_type of the device.
    u32 device_type;
    /// The `card` field of v4l2_capability.
    u8 card[32];
}
```

## Shared memory regions

Shared memory region `0` is used to map `MMAP` buffers into the guest using the
`VIRTIO_MEDIA_CMD_MMAP` command. If the host does not provide it, then `MMAP`
buffers cannot be mapped into the guest.

## Protocol

All structures managing the virtio protocol are defined and documented in
`protocol.h`. Please refer to this file whenever a `virtio_media_cmd_*` or
`virtio_media_resp_*` structure is mentioned.

Commands are queued on the `commandq` by the driver for the device to process.
They all start by an instance of `struct virtio_media_cmd_header` and include
device-writable descriptors for the device to write the result of the command in
a `struct virtio_media_resp_header`.

The errors returned by each command are standard Linux kernel error codes. For
instance, a command that contains invalid options will return `EINVAL`.

Events are sent on the `eventq` by the device for the driver to handle. They all
start by an instance of `struct virtio_media_event_header`.

## Session management

In order to use the device, the driver needs to open a session. This act is
equivalent to opening the `/dev/videoX` device file of the V4L2 device.
Depending on the type of device, it may be possible to open several sessions
concurrently.

A session is opened by queueing a `struct virtio_media_cmd_open` along with a
descriptor to receive a `struct virtio_media_resp_open` to the commandq. An open
session can be closed with `struct virtio_media_cmd_close`.

While the session is opened, its ID can be used to perform actions on it, most
commonly V4L2 ioctls.

## Ioctls

Ioctls are the main way to interact with V4L2 devices, and therefore
virtio-media features a command to perform an ioctl on an open session.

In order to perform an ioctl, the driver queues a
`struct virtio_media_cmd_ioctl` along with a descriptor to receive a
`struct virtio_media_resp_ioctl` on the commandq. The code of the ioctl can be
extracted from the
[videodev2.h](https://www.kernel.org/doc/html/latest/userspace-api/media/v4l/videodev.html)
header file, which defines the ioctls' codes, type of payload, and direction.
For instance, the `VIDIOC_G_FMT` ioctl is defined as follows:

```c
#define VIDIOC_G_FMT _IOWR('V',  4, struct v4l2_format)
```

This tells us that its ioctl code is `4`, that its payload is a
`struct v4l2_format`, and that its direction is `WR`, i.e. the payload is
written by both the driver and the device.

The payload layout is always a 64-bit representation of the corresponding V4L2
structure, irrespective of the host and guest architecture.

### Ioctls payload

The payload of an ioctl in the descriptor chain follows the command structure,
the reponse structure, or both depending on the direction:

- An `_IOR` ioctl is read-only for the driver, meaning the payload follows the
  response in the device-writable section of the descriptor chain.
- An `_IOW` ioctl is read-only for the device, meaning the payload follows the
  command in the driver-writable section of the descriptor chain.
- An `_IORW` ioctl is writable by both the device and driver, meaning the
  payload must follow both the command in the driver-writable section of the
  descriptor chain, and the response in the device-writable section.

For instance, the `VIDIOC_G_STD` ioctl is defined as follows:

```c
#define VIDIOC_G_STD _IOR('V', 23, v4l2_std_id)
```

Thus, its layout on the commandq will be:

```text
+-------------------------------------+
| struct virtio_media_cmd_ioctl       |
+=====================================+
| struct virtio_media_resp_ioctl      |
+-------------------------------------+
| v4l2_std_id                         |
+-------------------------------------+
```

(in these diagrams, the `====` line signals the delimitation between
device-readable and device-writable descriptors).

`VIDIOC_SUBSCRIBE_EVENT` is defined as follows:

```c
#define VIDIOC_SUBSCRIBE_EVENT _IOW('V', 90, struct v4l2_event_subscription)
```

Meaning its layout on the commandq will be:

```text
+-------------------------------------+
| struct virtio_media_cmd_ioctl       |
+-------------------------------------+
| struct v4l2_event_subscription      |
+=====================================+
| struct virtio_media_resp_ioctl      |
+-------------------------------------+
```

Finally, `VIDIOC_G_FMT` is a `WR` ioctl:

```c
#define VIDIOC_G_FMT _IOWR('V',  4, struct v4l2_format)
```

Its layout on the commandq will thus be:

```text
+-------------------------------------+
| struct virtio_media_cmd_ioctl       |
+-------------------------------------+
| struct v4l2_format                  |
+=====================================+
| struct virtio_media_resp_ioctl      |
+-------------------------------------+
| struct v4l2_format                  |
+-------------------------------------+
```

A common optimization for `WR` ioctls is to provide the payload using
descriptors that both point to the same buffer. This mimics the behavior of V4L2
ioctls where the data is only passed once and used as both input and output by
the kernel.

In case of success, the device MUST always write the payload in the
device-writable part of the descriptor chain.

In case of failure, the device is free to write the payload in the
device-writable part of the descriptor chain or not. Some errors may still
result in the payload being updated, and in this case the device is expected to
write the updated payload (for instance, `G_EXT_CTRLS` may return `EINVAL` but
update the `size` member of the requested controls if the provided size was not
enough). If the device has not written the payload after an error, the driver
MUST assume that the payload has not been modified.

### Handling of pointers in ioctl payload

A few structures used as ioctl payloads contain pointers the link to further
data needed for the ioctl. There are notably:

- The `planes` pointer of `struct v4l2_buffer`, which size is determined by the
  `length` member,
- The `controls` pointer of `struct v4l2_ext_controls`, which size is determined
  by the `count` member.

If the size of the pointed area is determined to be non-zero, then the main
payload is immediately followed by the pointed data in their order of appearance
in the structure, and the pointer value itself is ignored by the device, which
must also return the value initially passed by the driver. For instance, for a
`struct v4l2_ext_controls` which `count` is `16`:

```text
+--------------------------------------+
| struct v4l2_ext_controls             |
+--------------------------------------+
| struct v4l2_ext_control for plane 0  |
| struct v4l2_ext_control for plane 1  |
| ...                                  |
| struct v4l2_ext_control for plane 15 |
+--------------------------------------+
```

Similarly, a multiplanar `struct v4l2_buffer` with its `length` member set to 3
will be laid out as follows:

```text
+-------------------------------------+
| struct v4l2_buffer                  |
+-------------------------------------+
| struct v4l2_plane for plane 0       |
| struct v4l2_plane for plane 1       |
| struct v4l2_plane for plane 2       |
+-------------------------------------+
```

### Handling of pointers to userspace memory

A few pointers are special in that they point to userspace memory. They are:

- The `m.userptr` member of `struct v4l2_buffer` and `struct v4l2_plane`
  (technically an `unsigned long`, but designated a userspace address),
- The `ptr` member of `struct v4l2_ext_ctrl`.

These pointers can cover large areas of scattered memory, which has the
potential to require more descriptors than the virtio queue can provide. For
these particular pointers only, a list of `struct virtio_media_sg_entry` that
covers the needed amount of memory for the pointer is used instead of using
descriptors to map the pointed memory directly.

For each such pointer to read, the device reads as many SG entries as needed to
cover the length of the pointed buffer, as described by its parent structure
(`length` member of `struct v4l2_buffer` or `struct v4l2_plane` for buffer
memory, and `size` member of `struct v4l2_ext_control` for control data).

Since the device never needs to modify the list of SG entries, it is only
provided by the driver in the device-readable section of the descriptor chain,
and not repeated in the device-writable section, even for `WR` ioctls.

To illustrate the data layout, here is what the descriptor chain of a
`VIDIOC_QBUF` ioctl queueing a 3-planar `USERPTR` buffer would look like:

```text
+---------------------------------------------------+
| struct virtio_media_cmd_ioctl                     |
+---------------------------------------------------+
| struct v4l2_buffer                                |
+---------------------------------------------------+
| struct v4l2_plane for plane 0                     |
| struct v4l2_plane for plane 1                     |
| struct v4l2_plane for plane 2                     |
+---------------------------------------------------+
| array of struct virtio_media_sg_entry for plane 0 |
+---------------------------------------------------+
| array of struct virtio_media_sg_entry for plane 1 |
+---------------------------------------------------+
| array of struct virtio_media_sg_entry for plane 2 |
+===================================================+
| struct virtio_media_resp_ioctl                    |
+---------------------------------------------------+
| struct v4l2_buffer                                |
+---------------------------------------------------+
| struct v4l2_plane for plane 0                     |
| struct v4l2_plane for plane 1                     |
| struct v4l2_plane for plane 2                     |
+---------------------------------------------------+
```

Since the ioctl is `RW`, the payload is repeated in both the device-readable and
device-writable sections of the descriptor chain, but the device-writable
section does not include the SG lists to guest memory.

### Unsupported ioctls

A few ioctls are replaced by other, more suitable mechanisms. If being requested
these ioctls, the device must return the same response as it would for an
unknown ioctl, i.e. `ENOTTY`.

- `VIDIOC_QUERYCAP` is replaced by reading the configuration area.
- `VIDIOC_DQBUF` is replaced by a dedicated event.
- `VIDIOC_DQEVENT` is replaced by a dedicated event.
- `VIDIOC_G_JPEGCOMP` and `VIDIOC_S_JPEGCOMP` are deprecated and replaced by the
  controls of the JPEG class.
- `VIDIOC_LOG_STATUS` is a guest-only operation and shall not be implemented by
  the host.

## Events

Events are a way for the device to inform the driver about asynchronous events
that it should know about. In virtio-media, they are used as a replacement for
the `VIDIOC_DQBUF` and `VIDIOC_DQEVENT` ioctls and the polling mechanism, which
would be impractical to implement on top of virtio.

### Dequeued buffer events

A `struct virtio_media_event_dqbuf` event is queued on the eventq by the device
every time a buffer previously queued using the `VIDIOC_QBUF` ioctl is done
being processed and can be used by the driver again. This is like an implicit
`VIDIOC_DQBUF` ioctl.

Pointer values in the `struct v4l2_buffer` and `struct v4l2_plane` are
meaningless and must be ignored by the driver. It is recommended that the device
sets them to `NULL` in order to avoid leaking potential host addresses.

Note that in the case of a `USERPTR` buffer, the `struct v4l2_buffer` used as
event payload is not followed by the buffer memory: since that memory is the
same that the driver submitted with the `VIDIOC_QBUF`, it would be redundant to
have it here.

### Dequeued V4L2 event event

A `struct virtio_media_event_event` event is queued on the eventq by the device
every time an event the driver previously subscribed to using the
`VIDIOC_SUBSCRIBE_EVENT` ioctl has been signaled. This is like an implicit
`VIDIOC_DQEVENT` ioctl.

## Memory types

The semantics of the three V4L2 memory types (`MMAP`, `USERPTR` and `DMABUF`)
can easily be mapped to a guest/host context.

### MMAP

In virtio-media, `MMAP` buffers are provisioned by the host, just like they are
by the kernel in regular V4L2. Similarly to how userspace can map a `MMAP`
buffer into its address space using `mmap` and `munmap`, the virtio-media driver
can map host buffers into the guest space by queueing the
`struct virtio_media_cmd_mmap` and `struct virtio_media_cmd_munmap` commands to
the commandq.

### USERPTR

In virtio-media, `USERPTR` buffers and provisioned by the guest, just like they
are by userspace in regular V4L2. Instances of `struct v4l2_buffer` and
`struct v4l2_plane` of this type are followed by a series of descriptors mapping
the buffer backing memory in guest space.

For the host convenience, the backing memory must start with a new descriptor -
this allows the host to easily map the buffer memory to render into it instead
of having to do a copy.

The host must not alter the pointer values provided by the guest, i.e. the
`m.userptr` member of `struct v4l2_buffer` and `struct v4l2_plane` must be
returned to the guest with the same value as it was provided.

### DMABUF

In virtio-media, `DMABUF` buffers are provisioned by a virtio object, just like
they are by a DMABUF in regular V4L2. Virtio objects are 16-bytes UUIDs and do
not fit in the placeholders for file descriptors, so they follow their embedding
data structure as needed and the device must leave the V4L2 structure
placeholder unchanged. For instance, a 3-planar `struct v4l2_buffer` with the
`V4L2_MEMORY_DMABUF` memory type will have the following layout:

```text
+-------------------------------------+
| struct v4l2_buffer                  |
+-------------------------------------+
| struct v4l2_plane for plane 0       |
| struct v4l2_plane for plane 1       |
| struct v4l2_plane for plane 2       |
+-------------------------------------+
| 16 byte UUID for plane 0            |
+-------------------------------------+
| 16 byte UUID for plane 1            |
+-------------------------------------+
| 16 byte UUID for plane 2            |
+-------------------------------------+
```

Contrary to `USERPTR` buffers, virtio objects UUIDs need to be added in both the
device-readable and device-writable section of the descriptor chain.

Host-allocated buffers with the `V4L2_MEMORY_MMAP` memory type can also be
exported as virtio objects for use with another virtio device using the
`VIDIOC_EXPBUF` ioctl. The `fd` placefolder of `v4l2_exportbuffer` means that
space for the UUID needs to be reserved right after that structure, so the ioctl
layout will looks as follows:

```text
+-------------------------------------+
| struct virtio_media_cmd_ioctl       |
+-------------------------------------+
| struct v4l2_exportbuffer            |
+-------------------------------------+
| 16 bytes UUID for exported buffer   |
+=====================================+
| struct virtio_media_resp_ioctl      |
+-------------------------------------+
| struct v4l2_exportbuffer            |
+-------------------------------------+
| 16 bytes UUID for exported buffer   |
+-------------------------------------+
```
