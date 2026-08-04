// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generic virtio-media CAPTURE device, parameterized over a frame source.
//!
//! This module owns the V4L2 semantics: Format negotiation, buffer states, MMAP allocation, the
//! `DequeueBufferEvent` path - and knows nothing about where frames come from. Backends implement
//! [`CaptureBackend`] and live outside this crate when they carry native dependencies, following the
//! same split as [`crate::devices::video_decoder`] and `extras/ffmpeg-decoder`.
//!
//! Two backends exist today: A pattern generator in [`crate::devices::test_capture_backend`], which
//! needs no hardware and makes this device testable under `v4l2-compliance` on any machine, and a
//! libcamera-backed one in `extras/libcamera-camera`.

use std::collections::VecDeque;
use std::io;
use std::io::Result as IoResult;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use v4l2r::bindings;
use v4l2r::bindings::v4l2_fmtdesc;
use v4l2r::bindings::v4l2_format;
use v4l2r::bindings::v4l2_frmsizeenum;
use v4l2r::bindings::v4l2_requestbuffers;
use v4l2r::ioctl::BufferCapabilities;
use v4l2r::ioctl::BufferField;
use v4l2r::ioctl::BufferFlags;
use v4l2r::ioctl::MemoryConsistency;
use v4l2r::ioctl::V4l2Buffer;
use v4l2r::ioctl::V4l2PlanesWithBackingMut;
use v4l2r::memory::MemoryType;
use v4l2r::QueueType;

use crate::ioctl::virtio_media_dispatch_ioctl;
use crate::ioctl::IoctlResult;
use crate::ioctl::VirtioMediaIoctlHandler;
use crate::memfd::MemFdBuffer;
use crate::mmap::MmapMappingManager;
use crate::protocol::DequeueBufferEvent;
use crate::protocol::SgEntry;
use crate::protocol::V4l2Event;
use crate::protocol::V4l2Ioctl;
use crate::protocol::VIRTIO_MEDIA_MMAP_FLAG_RW;
use crate::ReadFromDescriptorChain;
use crate::VirtioMediaDevice;
use crate::VirtioMediaDeviceSession;
use crate::VirtioMediaEventQueue;
use crate::VirtioMediaHostMemoryMapper;
use crate::WriteToDescriptorChain;

/// Single-planar: one buffer per frame, and what camera applications expect. `v4l2r`'s
/// [`V4l2Buffer`] handles both layouts through the same plane accessors, so this is a free choice.
/// `simple_device` picks multiplanar because it emits YU12.
const QUEUE_TYPE: QueueType = QueueType::VideoCapture;

/// Maximum number of guest buffers, matching the reference device.
const MAX_BUFFERS: u32 = 32;

/// Reported through `G_PARM` before any frames have been observed.
const DEFAULT_FRAME_INTERVAL_NS: u64 = 1_000_000_000 / 30;

// ---------------------------------------------------------------------------------------------
// eventfd
// ---------------------------------------------------------------------------------------------

/// Minimal eventfd wrapper, non-blocking and close-on-exec.
///
/// A backend signals this after queueing a frame. The session returns it from `poll_fd()` so the
/// VMM's poller calls `process_events`. Each session owns a distinct descriptor, because the poller
/// registers fds per session and epoll rejects a duplicate registration.
pub struct EventFd(OwnedFd);

impl EventFd {
    pub fn new() -> io::Result<Self> {
        // SAFETY: eventfd with valid flags returns a new fd or -1.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just created and is not owned elsewhere.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    /// Increment the counter, making the fd readable.
    pub fn signal(&self) -> io::Result<()> {
        let val: u64 = 1;
        // SAFETY: writing 8 bytes from a valid u64 to an eventfd.
        let ret = unsafe {
            libc::write(
                self.0.as_raw_fd(),
                &val as *const u64 as *const libc::c_void,
                8,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // A saturated counter is harmless: the reader drains the frame queue regardless.
            if err.raw_os_error() != Some(libc::EAGAIN) {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Reset the counter. Called at the top of `process_events`.
    pub fn drain(&self) -> io::Result<()> {
        let mut val: u64 = 0;
        // SAFETY: reading 8 bytes into a valid u64 from an eventfd.
        let ret = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                &mut val as *mut u64 as *mut libc::c_void,
                8,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN) {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

// ---------------------------------------------------------------------------------------------
// Backend interface
// ---------------------------------------------------------------------------------------------

/// A pixel format the backend can produce, in V4L2 terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatDesc {
    /// V4L2 fourcc, e.g. `V4L2_PIX_FMT_MJPEG`.
    pub fourcc: u32,
    /// Sets `V4L2_FMT_FLAG_COMPRESSED`, and means `bytesused` varies per frame.
    pub compressed: bool,
}

/// One (format, size) combination the backend supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatEntry {
    pub fourcc: u32,
    pub width: u32,
    pub height: u32,
}

/// What the backend can do, snapshotted once so ioctls never block on it.
#[derive(Debug, Clone, Default)]
pub struct CaptureCaps {
    /// Reported as the `card` field of `v4l2_capability`.
    pub card: String,
    /// Distinct formats, in `ENUM_FMT` index order.
    pub formats: Vec<FormatDesc>,
    /// Every (format, size) pair. Note that sizes are per-format, not one global list.
    pub entries: Vec<FormatEntry>,
    /// The backend's preferred configuration, used for a freshly opened device.
    pub default: Option<FormatEntry>,
}

impl CaptureCaps {
    pub fn sizes_for(&self, fourcc: u32) -> impl Iterator<Item = &FormatEntry> {
        self.entries.iter().filter(move |e| e.fourcc == fourcc)
    }

    pub fn supports(&self, fourcc: u32, width: u32, height: u32) -> bool {
        self.sizes_for(fourcc)
            .any(|e| e.width == width && e.height == height)
    }

    pub fn is_compressed(&self, fourcc: u32) -> bool {
        self.formats
            .iter()
            .find(|f| f.fourcc == fourcc)
            .map(|f| f.compressed)
            .unwrap_or(false)
    }

    /// Closest supported (format, size) to what was requested.
    ///
    /// Never fails: V4L2 requires `S_FMT`/`TRY_FMT` to adjust rather than reject.
    pub fn negotiate(&self, fourcc: u32, width: u32, height: u32) -> FormatEntry {
        // i128: the product of two u32::MAX dimensions (as probed by v4l2-compliance) overflows i64.
        let target = (width as i128) * (height as i128);
        let nearest = |acc: Option<FormatEntry>, e: &FormatEntry| -> Option<FormatEntry> {
            let score = |c: &FormatEntry| {
                (
                    ((c.width as i128) * (c.height as i128) - target).abs(),
                    c.width,
                    c.height,
                )
            };
            match acc {
                Some(best) if score(&best) <= score(e) => Some(best),
                _ => Some(*e),
            }
        };

        self.sizes_for(fourcc)
            .fold(None, nearest)
            .or_else(|| self.entries.iter().fold(None, nearest))
            .expect("backend must expose at least one format")
    }

    pub fn default_entry(&self) -> Option<FormatEntry> {
        self.default.or_else(|| {
            self.entries
                .iter()
                .max_by_key(|e| (e.width as u64) * (e.height as u64))
                .copied()
        })
    }
}

/// Geometry the backend committed to, read back after configuration.
///
/// `frame_size` is authoritative for `sizeimage` and for the size of the guest's MMAP buffers.
/// It is not computable from the format in general.
#[derive(Debug, Clone, Copy)]
pub struct StreamInfo {
    pub width: u32,
    pub height: u32,
    pub frame_size: u32,
    /// `bytesperline`. Zero for compressed formats.
    pub stride: u32,
}

/// A frame produced by the backend, already copied out of whatever buffer it arrived in.
pub struct CapturedFrame {
    pub data: Vec<u8>,
    /// Real payload length. For compressed formats this is below the allocation size.
    pub bytes_used: u32,
    /// Passed through unmodified. Gaps legitimately signal dropped frames.
    pub sequence: u32,
    /// Monotonic clock, nanoseconds.
    pub timestamp_ns: u64,
}

/// A source of frames for [`CaptureDevice`].
///
/// Implementations must not block: Every method is called from the VMM's device thread. Frames are
/// delivered by signalling the [`EventFd`] handed to [`CaptureBackend::start`] and making them
/// available through [`CaptureBackend::try_next_frame`].
pub trait CaptureBackend {
    /// Snapshotted at construction. Must not change over the backend's lifetime.
    fn caps(&self) -> &CaptureCaps;

    /// Select a format and size, returning the geometry actually committed to.
    ///
    /// Called only while stopped. The arguments have already been passed through
    /// [`CaptureCaps::negotiate`], so they name a supported combination.
    fn configure(&mut self, fourcc: u32, width: u32, height: u32) -> Result<StreamInfo, i32>;

    /// Begin producing frames, signalling `notify` as each becomes available.
    fn start(&mut self, notify: EventFd) -> Result<(), i32>;

    /// Stop producing frames and discard anything queued.
    ///
    /// Must be synchronous, per `STREAMOFF` semantics: No frame from this stream may surface after
    /// it returns.
    fn stop(&mut self) -> Result<(), i32>;

    /// Take the next available frame, if any. Never blocks.
    fn try_next_frame(&mut self) -> Option<CapturedFrame>;

    /// Frame interval in nanoseconds, if the backend can report one.
    ///
    /// The default returns `None`, which makes the device omit the rate ioctls. Backends that can
    /// measure an interval should report it. See the note on `G_PARM` in [`CaptureDevice`].
    fn frame_interval_ns(&self) -> Option<u64> {
        None
    }

    /// Estimated geometry for a combination that is not currently configured.
    ///
    /// Used only by `TRY_FMT`, which must not touch the hardware and so cannot read back a real
    /// `frame_size`. The default is a conservative two bytes per pixel with a stride of zero.
    /// Backends exposing uncompressed formats should override it, since zero is only a correct
    /// stride for compressed ones.
    fn estimate(&self, _fourcc: u32, width: u32, height: u32) -> StreamInfo {
        StreamInfo {
            width,
            height,
            frame_size: width.saturating_mul(height).saturating_mul(2),
            stride: 0,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Buffers
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum BufferState {
    /// Freshly allocated or streamed off.
    New,
    /// QBUF'd by the guest, awaiting a frame.
    Incoming,
    /// Filled and handed back via `DequeueBufferEvent`.
    Outgoing,
}

struct Buffer {
    state: BufferState,
    v4l2_buffer: V4l2Buffer,
    fd: MemFdBuffer,
    offset: u32,
}

impl Buffer {
    fn set_queued(&mut self) {
        *self.v4l2_buffer.get_first_plane_mut().bytesused = 0;
        // Clear DONE as well: A re-queued buffer still carries it from its previous dequeue.
        let flags = (self.v4l2_buffer.flags() | BufferFlags::QUEUED) - BufferFlags::DONE;
        self.v4l2_buffer.set_flags(flags);
        self.state = BufferState::Incoming;
    }

    fn set_new(&mut self) {
        *self.v4l2_buffer.get_first_plane_mut().bytesused = 0;
        let flags = self.v4l2_buffer.flags() - BufferFlags::QUEUED - BufferFlags::DONE;
        self.v4l2_buffer.set_flags(flags);
        self.state = BufferState::New;
    }

    fn set_done(&mut self, frame: &CapturedFrame, bytes_used: u32) {
        *self.v4l2_buffer.get_first_plane_mut().bytesused = bytes_used;
        self.v4l2_buffer.set_sequence(frame.sequence);
        self.v4l2_buffer.set_timestamp(bindings::timeval {
            tv_sec: (frame.timestamp_ns / 1_000_000_000) as bindings::__time_t,
            tv_usec: ((frame.timestamp_ns % 1_000_000_000) / 1_000) as bindings::__suseconds_t,
        });
        let flags = (self.v4l2_buffer.flags() - BufferFlags::QUEUED) | BufferFlags::DONE;
        self.v4l2_buffer.set_flags(flags);
        self.state = BufferState::Outgoing;
    }
}

// ---------------------------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------------------------

pub struct CaptureDeviceSession {
    id: u32,
    buffers: Vec<Buffer>,
    /// FIFO of buffer indices awaiting a frame.
    queued_buffers: VecDeque<usize>,
    streaming: bool,
    eventfd: EventFd,
}

impl VirtioMediaDeviceSession for CaptureDeviceSession {
    fn poll_fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.eventfd.as_fd())
    }
}

// ---------------------------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------------------------

/// A CAPTURE device fed by any [`CaptureBackend`].
///
/// Format state is per-device, not per-session: The pipeline has one configuration, so `S_FMT`
/// from any session reconfigures it for all, and buffers can never outlive the format they were
/// sized for.
pub struct CaptureDevice<
    B: CaptureBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
> {
    evt_queue: Q,
    mmap_manager: MmapMappingManager<HM>,
    backend: B,
    /// The backend's current configuration.
    current: FormatEntry,
    info: StreamInfo,
    /// Only one session may hold buffers at a time. `v4l2-compliance` requires this because that is
    /// how real hardware behaves.
    active_session: Option<u32>,
}

impl<B, Q, HM> CaptureDevice<B, Q, HM>
where
    B: CaptureBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
{
    pub fn new(evt_queue: Q, mapper: HM, mut backend: B) -> anyhow::Result<Self> {
        // Configure up front so a session going straight from G_FMT to REQBUFS still sizes its
        // buffers from a real frame_size rather than an estimate.
        let entry = backend
            .caps()
            .default_entry()
            .ok_or_else(|| anyhow::anyhow!("backend exposes no usable formats"))?;
        let info = backend
            .configure(entry.fourcc, entry.width, entry.height)
            .map_err(|e| anyhow::anyhow!("initial configure failed with errno {e}"))?;

        Ok(Self {
            evt_queue,
            mmap_manager: MmapMappingManager::from(mapper),
            backend,
            current: FormatEntry {
                fourcc: entry.fourcc,
                width: info.width,
                height: info.height,
            },
            info,
            active_session: None,
        })
    }

    fn format_to_v4l2(&self, entry: FormatEntry, info: &StreamInfo) -> v4l2_format {
        let pix = bindings::v4l2_pix_format {
            width: entry.width,
            height: entry.height,
            pixelformat: entry.fourcc,
            field: bindings::v4l2_field_V4L2_FIELD_NONE,
            bytesperline: info.stride,
            sizeimage: info.frame_size,
            colorspace: bindings::v4l2_colorspace_V4L2_COLORSPACE_SRGB,
            ..Default::default()
        };
        v4l2_format {
            type_: QUEUE_TYPE as u32,
            fmt: bindings::v4l2_format__bindgen_ty_1 { pix },
        }
    }

    /// Move frames from the backend into queued guest buffers.
    fn deliver_frames(&mut self, session: &mut CaptureDeviceSession) -> IoctlResult<()> {
        while let Some(frame) = self.backend.try_next_frame() {
            let Some(buf_id) = session.queued_buffers.pop_front() else {
                // Nobody is waiting for this frame. Dropping it is correct camera behaviour.
                continue;
            };
            let buffer = session.buffers.get_mut(buf_id).ok_or(libc::EIO)?;

            // Clamp rather than trust: A reconfiguration racing a completion, or a backend
            // misreporting, must never write past the memfd.
            let capacity = self.info.frame_size as usize;
            let len = frame.data.len().min(capacity);
            if frame.data.len() > capacity {
                log::warn!(
                    "frame of {} bytes exceeds buffer capacity {capacity}, truncating",
                    frame.data.len()
                );
            }

            // `impl Write for &File` and `impl Seek for &File` mean a mut binding on the shared
            // reference suffices. The buffer's file is never mutably borrowed.
            let mut file = buffer.fd.as_file();
            let mut write = file.seek(SeekFrom::Start(0)).map(|_| ());
            if write.is_ok() {
                write = file.write_all(&frame.data[..len]);
            }
            if let Err(e) = write {
                log::error!("writing frame into guest buffer: {e}");
                // Give the buffer back rather than losing it.
                session.queued_buffers.push_front(buf_id);
                return Err(libc::EIO);
            }

            buffer.set_done(&frame, len as u32);
            let v4l2_buffer = buffer.v4l2_buffer.clone();
            self.evt_queue
                .send_event(V4l2Event::DequeueBuffer(DequeueBufferEvent::new(
                    session.id,
                    v4l2_buffer,
                )));
        }
        Ok(())
    }

    fn stop_streaming(&mut self, session: &mut CaptureDeviceSession) {
        if session.streaming {
            let _ = self.backend.stop();
            session.streaming = false;
        }
        session.queued_buffers.clear();
        for buffer in session.buffers.iter_mut() {
            buffer.set_new();
        }
    }
}

impl<B, Q, HM, Reader, Writer> VirtioMediaDevice<Reader, Writer> for CaptureDevice<B, Q, HM>
where
    B: CaptureBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
    Reader: ReadFromDescriptorChain,
    Writer: WriteToDescriptorChain,
{
    type Session = CaptureDeviceSession;

    fn new_session(&mut self, session_id: u32) -> Result<Self::Session, i32> {
        let eventfd = EventFd::new().map_err(|e| {
            log::error!("creating eventfd for session {session_id}: {e}");
            libc::ENOMEM
        })?;
        Ok(CaptureDeviceSession {
            id: session_id,
            buffers: Default::default(),
            queued_buffers: Default::default(),
            streaming: false,
            eventfd,
        })
    }

    fn close_session(&mut self, mut session: Self::Session) {
        if self.active_session == Some(session.id) {
            self.stop_streaming(&mut session);
            self.active_session = None;
        }
        for buffer in &session.buffers {
            self.mmap_manager.unregister_buffer(buffer.offset);
        }
    }

    fn do_ioctl(
        &mut self,
        session: &mut Self::Session,
        ioctl: V4l2Ioctl,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> IoResult<()> {
        virtio_media_dispatch_ioctl(self, session, ioctl, reader, writer)
    }

    fn do_mmap(
        &mut self,
        session: &mut Self::Session,
        flags: u32,
        offset: u32,
    ) -> Result<(u64, u64), i32> {
        let buffer = session
            .buffers
            .iter_mut()
            .find(|b| b.offset == offset)
            .ok_or(libc::EINVAL)?;
        let rw = (flags & VIRTIO_MEDIA_MMAP_FLAG_RW) != 0;
        let fd = buffer.fd.as_file().as_fd();
        self.mmap_manager
            .create_mapping(offset, fd, rw)
            .map_err(|_| libc::EINVAL)
    }

    fn do_munmap(&mut self, guest_addr: u64) -> Result<(), i32> {
        self.mmap_manager
            .remove_mapping(guest_addr)
            .map(|_| ())
            .map_err(|_| libc::EINVAL)
    }

    fn process_events(&mut self, session: &mut Self::Session) -> Result<(), i32> {
        // Drain first: eventfd is level-triggered under epoll, and a frame arriving between the
        // drain and the reads only costs one harmless extra wakeup.
        if let Err(e) = session.eventfd.drain() {
            log::error!("draining eventfd: {e}");
            return Err(libc::EIO);
        }
        self.deliver_frames(session)
    }
}

// ---------------------------------------------------------------------------------------------
// Ioctls
// ---------------------------------------------------------------------------------------------

impl<B, Q, HM> VirtioMediaIoctlHandler for CaptureDevice<B, Q, HM>
where
    B: CaptureBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
{
    type Session = CaptureDeviceSession;

    fn enum_fmt(
        &mut self,
        _session: &Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<v4l2_fmtdesc> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        let format = *self
            .backend
            .caps()
            .formats
            .get(index as usize)
            .ok_or(libc::EINVAL)?;

        Ok(v4l2_fmtdesc {
            index,
            type_: queue as u32,
            pixelformat: format.fourcc,
            flags: if format.compressed {
                bindings::V4L2_FMT_FLAG_COMPRESSED
            } else {
                0
            },
            ..Default::default()
        })
    }

    fn g_fmt(&mut self, _session: &Self::Session, queue: QueueType) -> IoctlResult<v4l2_format> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        Ok(self.format_to_v4l2(self.current, &self.info))
    }

    fn try_fmt(
        &mut self,
        _session: &Self::Session,
        queue: QueueType,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        // SAFETY: `queue` is single-planar, so `pix` is the active union member.
        let pix = unsafe { &format.fmt.pix };
        let entry = self
            .backend
            .caps()
            .negotiate(pix.pixelformat, pix.width, pix.height);

        // TRY_FMT must not touch the hardware, so a real frame_size cannot be read back. Report the
        // live geometry when it matches, and ask the backend to estimate otherwise.
        let info = if entry == self.current {
            self.info
        } else {
            self.backend
                .estimate(entry.fourcc, entry.width, entry.height)
        };
        Ok(self.format_to_v4l2(entry, &info))
    }

    fn s_fmt(
        &mut self,
        _session: &mut Self::Session,
        queue: QueueType,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        // Reconfiguring while any session owns buffers would invalidate their size.
        if self.active_session.is_some() {
            return Err(libc::EBUSY);
        }

        // SAFETY: single-planar queue, so `pix` is the active union member.
        let pix = unsafe { &format.fmt.pix };
        let entry = self
            .backend
            .caps()
            .negotiate(pix.pixelformat, pix.width, pix.height);

        let info = self
            .backend
            .configure(entry.fourcc, entry.width, entry.height)?;

        self.current = FormatEntry {
            fourcc: entry.fourcc,
            width: info.width,
            height: info.height,
        };
        self.info = info;

        Ok(self.format_to_v4l2(self.current, &self.info))
    }

    fn enum_framesizes(
        &mut self,
        _session: &Self::Session,
        index: u32,
        pixel_format: u32,
    ) -> IoctlResult<v4l2_frmsizeenum> {
        // Sizes are per-format, not global.
        let entry = *self
            .backend
            .caps()
            .sizes_for(pixel_format)
            .nth(index as usize)
            .ok_or(libc::EINVAL)?;

        Ok(v4l2_frmsizeenum {
            index,
            pixel_format,
            type_: bindings::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_DISCRETE,
            __bindgen_anon_1: bindings::v4l2_frmsizeenum__bindgen_ty_1 {
                discrete: bindings::v4l2_frmsize_discrete {
                    width: entry.width,
                    height: entry.height,
                },
            },
            ..Default::default()
        })
    }

    fn enum_frameintervals(
        &mut self,
        _session: &Self::Session,
        index: u32,
        pixel_format: u32,
        width: u32,
        height: u32,
    ) -> IoctlResult<bindings::v4l2_frmivalenum> {
        // Only meaningful if the backend can report an interval at all.
        let interval = self.backend.frame_interval_ns().ok_or(libc::ENOTTY)?;
        if index > 0 || !self.backend.caps().supports(pixel_format, width, height) {
            return Err(libc::EINVAL);
        }
        Ok(bindings::v4l2_frmivalenum {
            index,
            pixel_format,
            width,
            height,
            type_: bindings::v4l2_frmivaltypes_V4L2_FRMIVAL_TYPE_DISCRETE,
            __bindgen_anon_1: bindings::v4l2_frmivalenum__bindgen_ty_1 {
                discrete: interval_to_fract(interval),
            },
            ..Default::default()
        })
    }

    fn g_parm(
        &mut self,
        _session: &Self::Session,
        queue: QueueType,
    ) -> IoctlResult<bindings::v4l2_streamparm> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        let interval = self.backend.frame_interval_ns().ok_or(libc::ENOTTY)?.max(1);

        let mut parm = bindings::v4l2_streamparm {
            type_: queue as u32,
            ..Default::default()
        };
        // SAFETY: the `capture` member matches the capture queue type.
        let capture = unsafe { &mut parm.parm.capture };
        // V4L2_CAP_TIMEPERFRAME must accompany ENUM_FRAMEINTERVALS: v4l2-compliance fails with
        // `has_frmintervals && !cap->capability` otherwise. S_PARM still ignores writes.
        capture.capability = bindings::V4L2_CAP_TIMEPERFRAME;
        capture.timeperframe = interval_to_fract(interval);
        capture.readbuffers = 0;
        Ok(parm)
    }

    fn s_parm(
        &mut self,
        _session: &mut Self::Session,
        mut parm: bindings::v4l2_streamparm,
    ) -> IoctlResult<bindings::v4l2_streamparm> {
        if parm.type_ != QUEUE_TYPE as u32 {
            return Err(libc::EINVAL);
        }
        let interval = self.backend.frame_interval_ns().ok_or(libc::ENOTTY)?.max(1);

        // The rate is observed, not controllable, so report it back regardless of what was asked.
        // SAFETY: type_ was just checked to be the capture queue.
        let capture = unsafe { &mut parm.parm.capture };
        capture.capability = bindings::V4L2_CAP_TIMEPERFRAME;
        capture.timeperframe = interval_to_fract(interval);
        capture.readbuffers = 0;
        Ok(parm)
    }

    fn reqbufs(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        memory: MemoryType,
        count: u32,
        _flags: MemoryConsistency,
    ) -> IoctlResult<v4l2_requestbuffers> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        // MMAP only for now. USERPTR matters for the vhost-user path, where mapping host memory
        // into the guest is the hard part.
        if memory != MemoryType::Mmap {
            return Err(libc::EINVAL);
        }
        if session.streaming {
            return Err(libc::EBUSY);
        }
        // The busy checks must precede the count == 0 handling: REQBUFS(0) from a non-owning
        // handle must return EBUSY, not succeed as a no-op.
        match self.active_session {
            Some(id) if id != session.id => return Err(libc::EBUSY),
            _ => (),
        }

        let buffer_size = self.info.frame_size;

        // REQBUFS(0) is an implicit STREAMOFF plus a free.
        if count == 0 {
            self.active_session = None;
            self.stop_streaming(session);
        } else {
            session.queued_buffers.clear();
            for buffer in session.buffers.iter_mut() {
                buffer.set_new();
            }
            self.active_session = Some(session.id);
        }

        let count = std::cmp::min(count, MAX_BUFFERS);

        // Release the previous allocation. With count == 0 this leaves the session with none.
        for buffer in &session.buffers {
            self.mmap_manager.unregister_buffer(buffer.offset);
        }

        session.buffers = (0..count)
            .map(|i| {
                let fd = MemFdBuffer::new(buffer_size as u64).map_err(|e| {
                    log::error!("failed to allocate MMAP buffer: {:#}", e);
                    libc::ENOMEM
                })?;
                let offset = self
                    .mmap_manager
                    .register_buffer(None, buffer_size)
                    .map_err(|_| libc::EINVAL)?;

                let mut v4l2_buffer = V4l2Buffer::new(queue, i, MemoryType::Mmap);
                if let V4l2PlanesWithBackingMut::Mmap(mut planes) =
                    v4l2_buffer.planes_with_backing_iter_mut()
                {
                    // Every buffer has at least one plane.
                    let mut plane = planes.next().unwrap();
                    plane.set_mem_offset(offset);
                    *plane.length = buffer_size;
                } else {
                    panic!("buffer was just created as MMAP");
                }
                v4l2_buffer.set_field(BufferField::None);
                v4l2_buffer.set_flags(BufferFlags::TIMESTAMP_MONOTONIC);

                Ok(Buffer {
                    state: BufferState::New,
                    v4l2_buffer,
                    fd,
                    offset,
                })
            })
            .collect::<Result<Vec<Buffer>, i32>>()?;

        Ok(v4l2_requestbuffers {
            count,
            type_: queue as u32,
            memory: memory as u32,
            capabilities: (BufferCapabilities::SUPPORTS_MMAP
                | BufferCapabilities::SUPPORTS_ORPHANED_BUFS)
                .bits(),
            // Must be 0 unless V4L2_BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS is advertised.
            flags: 0,
            ..Default::default()
        })
    }

    fn querybuf(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<V4l2Buffer> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        let buffer = session.buffers.get(index as usize).ok_or(libc::EINVAL)?;
        Ok(buffer.v4l2_buffer.clone())
    }

    fn qbuf(
        &mut self,
        session: &mut Self::Session,
        buffer: V4l2Buffer,
        _guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<V4l2Buffer> {
        let index = buffer.index() as usize;
        let host_buffer = session.buffers.get_mut(index).ok_or(libc::EINVAL)?;
        // Queueing an already-queued buffer is a guest bug.
        if matches!(host_buffer.state, BufferState::Incoming) {
            return Err(libc::EINVAL);
        }
        host_buffer.set_queued();
        session.queued_buffers.push_back(index);
        let ret = host_buffer.v4l2_buffer.clone();

        // Frames may already be waiting.
        if session.streaming {
            self.deliver_frames(session)?;
        }
        Ok(ret)
    }

    fn streamon(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        if queue != QUEUE_TYPE || session.buffers.is_empty() {
            return Err(libc::EINVAL);
        }
        if session.streaming {
            return Ok(());
        }
        let notify = session.eventfd.try_clone().map_err(|e| {
            log::error!("duplicating eventfd: {e}");
            libc::EIO
        })?;
        self.backend.start(notify)?;
        session.streaming = true;
        Ok(())
    }

    fn streamoff(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        if queue != QUEUE_TYPE {
            return Err(libc::EINVAL);
        }
        self.stop_streaming(session);
        Ok(())
    }

    // A capture device exposes exactly one input. v4l2-compliance expects these three to agree.
    fn g_input(&mut self, _session: &Self::Session) -> IoctlResult<i32> {
        Ok(0)
    }

    fn s_input(&mut self, _session: &mut Self::Session, input: i32) -> IoctlResult<i32> {
        if input != 0 {
            Err(libc::EINVAL)
        } else {
            Ok(0)
        }
    }

    fn enuminput(
        &mut self,
        _session: &Self::Session,
        index: u32,
    ) -> IoctlResult<bindings::v4l2_input> {
        if index != 0 {
            return Err(libc::EINVAL);
        }
        let mut input = v4l2r::bindings::v4l2_input {
            index: 0,
            type_: bindings::V4L2_INPUT_TYPE_CAMERA,
            ..Default::default()
        };
        let name = b"Camera";
        input.name[..name.len()].copy_from_slice(name);
        Ok(input)
    }
}

/// Nanoseconds to a `v4l2_fract`, as a simple `1/N` fraction rather than a GCD reduction, since
/// applications treat this as a nominal rate and per-frame timing comes from buffer timestamps.
fn interval_to_fract(interval_ns: u64) -> bindings::v4l2_fract {
    let interval_ns = interval_ns.max(1);
    // Rounded rather than truncated, so 66.5 ms reads as 15 fps rather than 15.
    let fps = (1_000_000_000u64 + interval_ns / 2) / interval_ns;
    if fps >= 1 {
        bindings::v4l2_fract {
            numerator: 1,
            denominator: fps as u32,
        }
    } else {
        // Slower than one frame per second. Report the interval directly in seconds.
        bindings::v4l2_fract {
            numerator: (interval_ns / 1_000_000_000).max(1) as u32,
            denominator: 1,
        }
    }
}

/// Frame interval reported before any frames have been observed.
pub const fn default_frame_interval_ns() -> u64 {
    DEFAULT_FRAME_INTERVAL_NS
}

#[cfg(test)]
mod tests {
    use super::interval_to_fract;
    use super::CaptureCaps;
    use super::FormatDesc;
    use super::FormatEntry;

    const FOURCC_GREY: u32 = u32::from_le_bytes(*b"GREY");
    const FOURCC_YUYV: u32 = u32::from_le_bytes(*b"YUYV");
    const FOURCC_MJPG: u32 = u32::from_le_bytes(*b"MJPG");

    /// Two formats with deliberately different size lists, mirroring a real UVC camera: it commonly
    /// exposes more compressed sizes than raw ones.
    fn caps() -> CaptureCaps {
        let entry = |fourcc, width, height| FormatEntry {
            fourcc,
            width,
            height,
        };
        CaptureCaps {
            card: "test".to_string(),
            formats: vec![
                FormatDesc {
                    fourcc: FOURCC_MJPG,
                    compressed: true,
                },
                FormatDesc {
                    fourcc: FOURCC_YUYV,
                    compressed: false,
                },
            ],
            entries: vec![
                entry(FOURCC_MJPG, 320, 240),
                entry(FOURCC_MJPG, 640, 480),
                entry(FOURCC_MJPG, 1280, 720),
                entry(FOURCC_YUYV, 320, 240),
                entry(FOURCC_YUYV, 640, 480),
            ],
            default: Some(entry(FOURCC_MJPG, 1280, 720)),
        }
    }

    #[test]
    fn sizes_are_per_format() {
        let caps = caps();
        assert_eq!(caps.sizes_for(FOURCC_MJPG).count(), 3);
        assert_eq!(caps.sizes_for(FOURCC_YUYV).count(), 2);
        assert_eq!(caps.sizes_for(FOURCC_GREY).count(), 0);

        assert!(caps.supports(FOURCC_MJPG, 1280, 720));
        // The same size under a format that does not offer it.
        assert!(!caps.supports(FOURCC_YUYV, 1280, 720));
    }

    #[test]
    fn negotiate_exact_match_is_preserved() {
        let caps = caps();
        let entry = caps.negotiate(FOURCC_YUYV, 640, 480);
        assert_eq!(entry.fourcc, FOURCC_YUYV);
        assert_eq!((entry.width, entry.height), (640, 480));
    }

    #[test]
    fn negotiate_picks_nearest_size_within_the_requested_format() {
        let caps = caps();
        // Closer to 640x480 than to 1280x720 by area.
        let entry = caps.negotiate(FOURCC_MJPG, 700, 500);
        assert_eq!(entry.fourcc, FOURCC_MJPG);
        assert_eq!((entry.width, entry.height), (640, 480));

        // A size the requested format does not offer falls back within that format, not to another.
        let entry = caps.negotiate(FOURCC_YUYV, 1280, 720);
        assert_eq!(entry.fourcc, FOURCC_YUYV);
        assert_eq!((entry.width, entry.height), (640, 480));
    }

    #[test]
    fn negotiate_falls_back_across_formats_for_an_unknown_fourcc() {
        let caps = caps();
        let entry = caps.negotiate(FOURCC_GREY, 320, 240);
        // Any supported format is acceptable. The size must be one that exists.
        assert!(caps.supports(entry.fourcc, entry.width, entry.height));
        assert_eq!((entry.width, entry.height), (320, 240));
    }

    /// Regression test: v4l2-compliance probes S_FMT with u32::MAX for both dimensions. Computing
    /// the area in i64 overflows, and crosvm builds with overflow checks enabled, so the panic took
    /// down the whole VMM rather than returning an error.
    #[test]
    fn negotiate_survives_absurd_dimensions() {
        let caps = caps();
        let entry = caps.negotiate(FOURCC_MJPG, u32::MAX, u32::MAX);
        assert!(caps.supports(entry.fourcc, entry.width, entry.height));

        let entry = caps.negotiate(FOURCC_MJPG, 0, 0);
        assert!(caps.supports(entry.fourcc, entry.width, entry.height));
    }

    #[test]
    fn default_entry_prefers_the_backend_choice() {
        let caps = caps();
        let entry = caps.default_entry().unwrap();
        assert_eq!(entry.fourcc, FOURCC_MJPG);
        assert_eq!((entry.width, entry.height), (1280, 720));
    }

    #[test]
    fn default_entry_falls_back_to_the_largest_mode() {
        let mut caps = caps();
        caps.default = None;
        let entry = caps.default_entry().unwrap();
        // Largest by area, not merely the last enumerated: enumeration order would give YUYV
        // 640x480 here.
        assert_eq!((entry.width, entry.height), (1280, 720));
    }

    /// Reducing by GCD instead gives arithmetically correct but unreadable output:
    /// A measured 66489884 ns comes out as 250000000/16622471 rather than 1/15.
    #[test]
    fn frame_intervals_are_simple_fractions() {
        let cases = [
            (1_000_000_000 / 30, 1, 30),
            (66_489_884, 1, 15), // measured on a UVC camera
            (100_000_000, 1, 10),
            (34_482_758, 1, 29),
        ];
        for (ns, num, den) in cases {
            let fract = interval_to_fract(ns);
            assert_eq!((fract.numerator, fract.denominator), (num, den), "{ns} ns");
        }
    }

    #[test]
    fn frame_intervals_handle_edges() {
        // Slower than one frame per second. Note the rounding threshold: fps rounds to 1 until the
        // interval passes 1.5 s, so this branch only engages beyond that.
        let fract = interval_to_fract(3_000_000_000);
        assert_eq!((fract.numerator, fract.denominator), (3, 1));

        // Zero must not divide by zero.
        let fract = interval_to_fract(0);
        assert!(fract.denominator > 0);
    }
}
