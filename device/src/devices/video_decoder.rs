// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;
use std::os::fd::BorrowedFd;

use v4l2r::bindings;
use v4l2r::ioctl::BufferCapabilities;
use v4l2r::ioctl::BufferField;
use v4l2r::ioctl::BufferFlags;
use v4l2r::ioctl::DecoderCmd;
use v4l2r::ioctl::EventType;
use v4l2r::ioctl::SelectionTarget;
use v4l2r::ioctl::SelectionType;
use v4l2r::ioctl::SrcChanges;
use v4l2r::ioctl::V4l2Buffer;
use v4l2r::ioctl::V4l2MplaneFormat;
use v4l2r::ioctl::V4l2PlanesWithBacking;
use v4l2r::ioctl::V4l2PlanesWithBackingMut;
use v4l2r::memory::MemoryType;
use v4l2r::Colorspace;
use v4l2r::Quantization;
use v4l2r::QueueClass;
use v4l2r::QueueDirection;
use v4l2r::QueueType;
use v4l2r::XferFunc;
use v4l2r::YCbCrEncoding;

use crate::io::ReadFromDescriptorChain;
use crate::io::WriteToDescriptorChain;
use crate::ioctl::virtio_media_dispatch_ioctl;
use crate::ioctl::IoctlResult;
use crate::ioctl::VirtioMediaIoctlHandler;
use crate::mmap::MmapMappingManager;
use crate::DequeueBufferEvent;
use crate::SessionEvent;
use crate::SgEntry;
use crate::V4l2Event;
use crate::V4l2Ioctl;
use crate::VirtioMediaDevice;
use crate::VirtioMediaDeviceSession;
use crate::VirtioMediaEventQueue;
use crate::VirtioMediaHostMemoryMapper;
use crate::VIRTIO_MEDIA_MMAP_FLAG_RW;

/// Backing MMAP memory for `VirtioVideoMediaDecoderBuffer`.
pub trait VideoDecoderBufferBacking {
    fn new(queue: QueueType, index: u32, sizes: &[usize]) -> IoctlResult<Self>
    where
        Self: Sized;

    fn fd_for_plane(&self, plane_idx: usize) -> Option<BorrowedFd>;
}

pub struct VideoDecoderBuffer<S: VideoDecoderBufferBacking> {
    v4l2_buffer: V4l2Buffer,

    /// Backend-specific storage.
    pub backing: S,
}

impl<S: VideoDecoderBufferBacking> VideoDecoderBuffer<S> {
    fn new(
        queue: QueueType,
        index: u32,
        sizes: &[usize],
        // TODO: need as many offsets as there are planes.
        mmap_offset: u32,
    ) -> IoctlResult<Self> {
        let backing = S::new(queue, index, sizes)?;

        let mut v4l2_buffer = V4l2Buffer::new(queue, index, MemoryType::Mmap);
        if let V4l2PlanesWithBackingMut::Mmap(mut planes) =
            v4l2_buffer.planes_with_backing_iter_mut()
        {
            // SAFETY: every buffer has at least one plane.
            let mut plane = planes.next().unwrap();
            plane.set_mem_offset(mmap_offset);
            *plane.length = sizes[0] as u32;
        } else {
            // SAFETY: we have just set the buffer type to MMAP. Reaching this point means a bug in
            // the code.
            panic!()
        }

        v4l2_buffer.set_flags(BufferFlags::TIMESTAMP_MONOTONIC);
        v4l2_buffer.set_field(BufferField::None);

        Ok(Self {
            v4l2_buffer,
            backing,
        })
    }

    pub fn index(&self) -> u32 {
        self.v4l2_buffer.index()
    }

    pub fn timestamp(&self) -> bindings::timeval {
        self.v4l2_buffer.timestamp()
    }
}

/// Events reported by the [`VideoDecoderBackendSession::next_event`] method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoDecoderBackendEvent {
    /// Sent whenever the format of the stream has changed. The new format can be read using
    /// [`VideoDecoderBackendSession::current_format`].
    StreamFormatChanged,
    /// Sent whenever an `OUTPUT` buffer is done processing and can be reused.
    InputBufferDone(u32),
    /// Sent whenever a decoded frame is ready on the `CAPTURE` queue.
    FrameCompleted {
        buffer_id: u32,
        timestamp: bindings::timeval,
        bytes_used: Vec<u32>,
        is_last: bool,
    },
}

/// Description of the current stream parameters, as parsed from the input.
#[derive(Clone)]
pub struct StreamParams {
    /// Minimum number of output buffers necessary to decode the stream.
    pub min_output_buffers: u32,
    /// Coded size of the stream.
    pub coded_size: (u32, u32),
    /// Visible rectangle containing the part of the frame to display.
    pub visible_rect: v4l2r::Rect,
}

/// Trait for a video decoding session.
pub trait VideoDecoderBackendSession {
    type BufferStorage: VideoDecoderBufferBacking;

    /// Decode the encoded stream in `input`, of length `bytes_used`, which corresponds to
    /// OUTPUT buffer `index`.
    ///
    /// `timestamp` is the timestamp of the frame, to be reported in any frame produced from this
    /// call.
    fn decode(
        &mut self,
        input: &Self::BufferStorage,
        index: u32,
        timestamp: bindings::timeval,
        bytes_used: u32,
    ) -> IoctlResult<()>;

    /// Use `backing` as the backing storage for output buffer `index`.
    fn use_as_output(&mut self, index: u32, backing: &mut Self::BufferStorage) -> IoctlResult<()>;

    /// Start draining the decoder pipeline for all buffers still in it.
    ///
    /// The backend will report a frame with the `V4L2_BUF_FLAG_LAST` once the drain
    /// process is completed.
    fn drain(&mut self) -> IoctlResult<()>;

    /// Remove any output buffer that has been previously added using [`use_as_output`].
    fn clear_output_buffers(&mut self) -> IoctlResult<()>;

    /// Returns the next pending event if there is one, or `None` if there aren't any.
    fn next_event(&mut self) -> Option<VideoDecoderBackendEvent>;

    /// Returns the current format set for the given `direction`, in a form suitable as a reply to
    /// `VIDIOC_G_FMT`.
    fn current_format(&self, direction: QueueDirection) -> V4l2MplaneFormat;

    /// Returns the stream parameters as read from the input.
    fn stream_params(&self) -> StreamParams;

    /// Called whenever the decoder device has allocated buffers for a given queue.
    ///
    /// This can be useful for some backends that need to know how many buffers they will work
    /// with. The default implementation does nothing, which should be suitable for backends that
    /// don't care.
    fn buffers_allocated(&mut self, _direction: QueueDirection, _num_buffers: u32) {}

    /// Returns a file descriptor that signals `POLLIN` whenever an event is pending and can be
    /// read using [`next_event`], or `None` if the backend does not support this.
    fn poll_fd(&self) -> Option<BorrowedFd> {
        None
    }

    /// Optional hook called whenever the streaming state of a queue changes. Some backends may
    /// need this information to operate properly.
    fn streaming_state(&mut self, _direction: QueueDirection, _streaming: bool) {}

    /// Optional hook called by the decoder to signal it has processed a pausing event
    /// sent by the backend.
    ///
    /// Pausing event are currently limited to [`VideoDecoderBackendEvent::StreamFormatChanged`].
    /// Whenever the resolution changes, the backend must stop processing until the decoder has
    /// adapted its conditions for decoding to resume (e.g. CAPTURE buffers of the proper size and
    /// format have been allocated).
    fn resume(&mut self) {}
}

/// State of a session.
#[derive(Debug)]
enum VideoDecoderStreamingState {
    /// Initial state, and state after a `STOP` command or a successful drain. Contains the
    /// state of both streaming queues.
    Stopped {
        input_streaming: bool,
        output_streaming: bool,
    },
    /// State when both queues are streaming.
    Running,
    /// State when a `PAUSE` command has been received. Both queues are streaming in this state.
    Paused,
}

impl Default for VideoDecoderStreamingState {
    fn default() -> Self {
        Self::Stopped {
            input_streaming: false,
            output_streaming: false,
        }
    }
}

impl VideoDecoderStreamingState {
    fn input_streamon(&mut self) {
        match self {
            Self::Stopped {
                ref mut input_streaming,
                output_streaming,
            } if !(*input_streaming) => {
                *input_streaming = true;
                // If we switch to a state where both queues are streaming, then the device is
                // running.
                if *output_streaming {
                    *self = Self::Running;
                }
            }
            Self::Stopped { .. } | Self::Running | Self::Paused => (),
        }
    }

    fn input_streamoff(&mut self) {
        match self {
            Self::Stopped {
                ref mut input_streaming,
                ..
            } => *input_streaming = false,
            Self::Running | Self::Paused => {
                *self = Self::Stopped {
                    input_streaming: false,
                    output_streaming: true,
                }
            }
        }
    }

    fn output_streamon(&mut self) {
        match self {
            Self::Stopped {
                input_streaming,
                ref mut output_streaming,
            } if !(*output_streaming) => {
                *output_streaming = true;
                // If we switch to a state where both queues are streaming, then the device is
                // running.
                if *input_streaming {
                    *self = Self::Running;
                }
            }
            Self::Stopped { .. } | Self::Running | Self::Paused => (),
        }
    }

    fn output_streamoff(&mut self) {
        match self {
            Self::Stopped {
                ref mut output_streaming,
                ..
            } => *output_streaming = false,
            Self::Running | Self::Paused => {
                *self = Self::Stopped {
                    input_streaming: true,
                    output_streaming: false,
                }
            }
        }
    }

    fn is_output_streaming(&mut self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::Stopped {
                    output_streaming: true,
                    ..
                }
        )
    }
}

/// Management of the crop rectangle.
///
/// There are two ways this parameter can be set:
///
/// * Manually by the client, by calling `VIDIOC_S_SELECTION` with `V4L2_SEL_TGT_COMPOSE`. This has
///   an effect only before the first resolution change event is emitted, and is the only way to
///   properly set the crop rectangle for codecs/hardware that don't support DRC detection.
///
/// * From the information contained in the stream, signaled via a
///   [`VideoDecoderBackendEvent::StreamFormatChanged`] event. Once this event has been emitted, the
///   crop rectangle is fixed and determined by the stream.
enum CropRectangle {
    /// Crop rectangle has not been determined from the stream yet and can be set by the client.
    Settable(v4l2r::Rect),
    /// Crop rectangle has been determined from the stream and cannot be modified.
    FromStream(v4l2r::Rect),
}

impl Deref for CropRectangle {
    type Target = v4l2r::Rect;

    fn deref(&self) -> &Self::Target {
        match self {
            CropRectangle::Settable(r) => r,
            CropRectangle::FromStream(r) => r,
        }
    }
}

/// Struct containing validated colorspace information for a format.
#[derive(Debug, Clone, Copy)]
struct V4l2FormatColorspace {
    colorspace: Colorspace,
    xfer_func: XferFunc,
    ycbcr_enc: YCbCrEncoding,
    quantization: Quantization,
}

impl Default for V4l2FormatColorspace {
    fn default() -> Self {
        Self {
            colorspace: Colorspace::Rec709,
            xfer_func: XferFunc::None,
            ycbcr_enc: YCbCrEncoding::E709,
            quantization: Quantization::LimRange,
        }
    }
}

impl V4l2FormatColorspace {
    /// Apply the colorspace information of this object to `pix_mp`.
    fn apply(self, pix_mp: &mut bindings::v4l2_pix_format_mplane) {
        pix_mp.colorspace = self.colorspace as u32;
        pix_mp.__bindgen_anon_1 = bindings::v4l2_pix_format_mplane__bindgen_ty_1 {
            ycbcr_enc: self.ycbcr_enc as u8,
        };
        pix_mp.quantization = self.quantization as u8;
        pix_mp.xfer_func = self.xfer_func as u8;
    }
}

pub struct VideoDecoderSession<S: VideoDecoderBackendSession> {
    id: u32,

    state: VideoDecoderStreamingState,

    input_buffers: Vec<VideoDecoderBuffer<S::BufferStorage>>,
    output_buffers: Vec<VideoDecoderBuffer<S::BufferStorage>>,
    /// Indices of CAPTURE buffers that are queued but not send to the backend yet because the
    /// decoder is not running.
    pending_output_buffers: Vec<u32>,

    sequence_cpt: u32,

    /// Whether the input source change event has been subscribed to by the driver. If `true` then
    /// the device will emit resolution change events.
    src_change_subscribed: bool,
    /// Whether the EOS event has been subscribed to by the driver. If `true` then the device will
    /// emit EOS events.
    eos_subscribed: bool,

    crop_rectangle: CropRectangle,

    /// Current colorspace information of the format.
    colorspace: V4l2FormatColorspace,

    /// Adapter-specific data.
    backend_session: S,
}

impl<S: VideoDecoderBackendSession> VirtioMediaDeviceSession for VideoDecoderSession<S> {
    fn poll_fd(&self) -> Option<BorrowedFd> {
        self.backend_session.poll_fd()
    }
}

impl<S: VideoDecoderBackendSession> VideoDecoderSession<S> {
    /// Returns the current format for `direction`.
    ///
    /// This is essentially like calling the backend's corresponding
    /// [`VideoDecoderBackendSession::current_format`] method, but also applies the colorspace
    /// information potentially set by the user.
    fn current_format(&self, direction: QueueDirection) -> V4l2MplaneFormat {
        let format = self.backend_session.current_format(direction);

        let mut pix_mp =
            *<V4l2MplaneFormat as AsRef<bindings::v4l2_pix_format_mplane>>::as_ref(&format);

        self.colorspace.apply(&mut pix_mp);

        V4l2MplaneFormat::from((direction, pix_mp))
    }

    fn try_decoder_cmd(&self, cmd: DecoderCmd) -> IoctlResult<DecoderCmd> {
        match cmd {
            DecoderCmd::Stop { .. } => Ok(DecoderCmd::stop()),
            DecoderCmd::Start { .. } => Ok(DecoderCmd::start()),
            DecoderCmd::Pause { .. } => {
                match &self.state {
                    // The V4L2 documentation says this should return `EPERM`, but v4l2-compliance
                    // requires `EINVAL`...
                    VideoDecoderStreamingState::Stopped { .. } => Err(libc::EINVAL),
                    VideoDecoderStreamingState::Running | VideoDecoderStreamingState::Paused => {
                        Ok(DecoderCmd::pause())
                    }
                }
            }
            DecoderCmd::Resume => {
                match &self.state {
                    // The V4L2 documentation says this should return `EPERM`, but v4l2-compliance
                    // requires `EINVAL`...
                    VideoDecoderStreamingState::Stopped { .. } => Err(libc::EINVAL),
                    VideoDecoderStreamingState::Paused | VideoDecoderStreamingState::Running => {
                        Ok(DecoderCmd::resume())
                    }
                }
            }
        }
    }

    /// Send all the output buffers that are pending to the backend, if the decoder is running.
    ///
    /// In the adapter backend, if we receive buffers this means both queues are streaming - IOW we
    /// can queue them as soon as the condition is good.
    ///
    /// In the decoder device, we need to keep them until both queues are streaming. Same applies
    /// to input buffers BTW.
    fn try_send_pending_output_buffers(&mut self) {
        if !self.state.is_output_streaming() {
            return;
        }

        for i in self.pending_output_buffers.drain(..) {
            let buffer = self.output_buffers.get_mut(i as usize).unwrap();
            self.backend_session
                .use_as_output(buffer.index(), &mut buffer.backing)
                .unwrap();
        }
    }
}

/// Trait for actual implementations of video decoding, to be used with [`VideoDecoder`].
///
/// [`VideoDecoder`] takes care of (mostly) abstracting V4L2 away ; implementors of this trait are
/// the ones that provide the actual video decoding service.
pub trait VideoDecoderBackend: Sized {
    type Session: VideoDecoderBackendSession;

    /// Create a new session with the provided `id`.
    fn new_session(&mut self, id: u32) -> IoctlResult<Self::Session>;
    /// Close and destroy `session`.
    fn close_session(&mut self, session: Self::Session);

    /// Returns the format at `index` for the given queue `direction`, or None if `index` is out of
    /// bounds.
    fn enum_formats(
        &self,
        session: &VideoDecoderSession<Self::Session>,
        direction: QueueDirection,
        index: u32,
    ) -> Option<bindings::v4l2_fmtdesc>;
    /// Returns the supported frame sizes for `pixel_format`, or None if the format is not
    /// supported.
    fn frame_sizes(&self, pixel_format: u32) -> Option<bindings::v4l2_frmsize_stepwise>;

    /// Adjust `format` to make it applicable to the queue with the given `direction` for the current `session`.
    ///
    /// This method doesn't fail, implementations must return the closest acceptable format that
    /// can be applied unchanged with [`Self::apply_format`].
    fn adjust_format(
        &self,
        session: &Self::Session,
        direction: QueueDirection,
        format: V4l2MplaneFormat,
    ) -> V4l2MplaneFormat;

    /// Applies `format` to the queue of the given `direction`. The format is adjusted if needed.
    fn apply_format(
        &self,
        session: &mut Self::Session,
        direction: QueueDirection,
        format: &V4l2MplaneFormat,
    );
}

pub struct VideoDecoder<
    D: VideoDecoderBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
> {
    backend: D,
    event_queue: Q,
    host_mapper: MmapMappingManager<HM>,
}

impl<B, Q, HM> VideoDecoder<B, Q, HM>
where
    B: VideoDecoderBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
{
    pub fn new(backend: B, event_queue: Q, host_mapper: HM) -> Self {
        Self {
            backend,
            event_queue,
            host_mapper: MmapMappingManager::from(host_mapper),
        }
    }

    /// Validate `format` for `queue` and return the adjusted format.
    fn try_format(
        &self,
        session: &VideoDecoderSession<B::Session>,
        queue: QueueType,
        format: bindings::v4l2_format,
    ) -> IoctlResult<V4l2MplaneFormat> {
        if queue.class() != QueueClass::VideoMplane {
            return Err(libc::EINVAL);
        }

        // SAFETY: safe because we have just confirmed the queue type is mplane.
        let pix_mp = unsafe { format.fmt.pix_mp };

        // Process the colorspace now so we can restore it after applying the backend adjustment.
        let colorspace = if queue.direction() == QueueDirection::Output {
            V4l2FormatColorspace {
                colorspace: Colorspace::n(pix_mp.colorspace)
                    .unwrap_or(session.colorspace.colorspace),
                xfer_func: XferFunc::n(pix_mp.xfer_func as u32)
                    .unwrap_or(session.colorspace.xfer_func),
                // TODO: safe because...
                ycbcr_enc: YCbCrEncoding::n(unsafe { pix_mp.__bindgen_anon_1.ycbcr_enc as u32 })
                    .unwrap_or(session.colorspace.ycbcr_enc),
                quantization: Quantization::n(pix_mp.quantization as u32)
                    .unwrap_or(session.colorspace.quantization),
            }
        } else {
            session.colorspace
        };

        let format = V4l2MplaneFormat::from((queue.direction(), pix_mp));

        let format =
            self.backend
                .adjust_format(&session.backend_session, queue.direction(), format);

        let mut pix_mp =
            *<V4l2MplaneFormat as AsRef<bindings::v4l2_pix_format_mplane>>::as_ref(&format);

        colorspace.apply(&mut pix_mp);

        Ok(V4l2MplaneFormat::from((queue.direction(), pix_mp)))
    }
}

impl<B, Q, HM, Reader, Writer> VirtioMediaDevice<Reader, Writer> for VideoDecoder<B, Q, HM>
where
    B: VideoDecoderBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
    Reader: ReadFromDescriptorChain,
    Writer: WriteToDescriptorChain,
{
    type Session = <Self as VirtioMediaIoctlHandler>::Session;

    fn new_session(&mut self, session_id: u32) -> Result<Self::Session, i32> {
        let backend_session = self.backend.new_session(session_id)?;

        Ok(VideoDecoderSession {
            id: session_id,
            backend_session,
            state: Default::default(),
            input_buffers: Default::default(),
            output_buffers: Default::default(),
            pending_output_buffers: Default::default(),
            sequence_cpt: 0,
            src_change_subscribed: false,
            eos_subscribed: false,
            crop_rectangle: CropRectangle::Settable(v4l2r::Rect::new(0, 0, 0, 0)),
            colorspace: Default::default(),
        })
    }

    fn close_session(&mut self, session: Self::Session) {
        // Unregister all MMAP buffers.
        for buffer in session
            .input_buffers
            .iter()
            .chain(session.output_buffers.iter())
        {
            if let V4l2PlanesWithBacking::Mmap(planes) =
                buffer.v4l2_buffer.planes_with_backing_iter()
            {
                for plane in planes {
                    self.host_mapper.unregister_buffer(plane.mem_offset());
                }
            }
        }
    }

    fn do_ioctl(
        &mut self,
        session: &mut Self::Session,
        ioctl: V4l2Ioctl,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> std::io::Result<()> {
        virtio_media_dispatch_ioctl(self, session, ioctl, reader, writer)
    }

    fn do_mmap(
        &mut self,
        session: &mut Self::Session,
        flags: u32,
        offset: u32,
    ) -> Result<(u64, u64), i32> {
        // Search for a MMAP plane with the right offset.
        // TODO: O(n), not critical but not great either.
        let (buffer, plane_idx) = session
            .input_buffers
            .iter()
            .chain(session.output_buffers.iter())
            .filter_map(|b| {
                if let V4l2PlanesWithBacking::Mmap(planes) =
                    b.v4l2_buffer.planes_with_backing_iter()
                {
                    Some(std::iter::repeat(b).zip(planes.enumerate()))
                } else {
                    None
                }
            })
            .flatten()
            .find(|(_, (_, p))| p.mem_offset() == offset)
            .map(|(b, (i, _))| (b, i))
            .ok_or(libc::EINVAL)?;
        let rw = (flags & VIRTIO_MEDIA_MMAP_FLAG_RW) != 0;

        let fd = buffer.backing.fd_for_plane(plane_idx).unwrap();

        self.host_mapper
            .create_mapping(offset, fd, rw)
            .map_err(|e| {
                log::error!(
                    "failed to map MMAP buffer at offset 0x{:x}: {:#}",
                    offset,
                    e
                );
                libc::EINVAL
            })
    }

    fn do_munmap(&mut self, guest_addr: u64) -> Result<(), i32> {
        self.host_mapper
            .remove_mapping(guest_addr)
            .map(|_| ())
            .map_err(|_| libc::EINVAL)
    }

    fn process_events(&mut self, session: &mut Self::Session) -> Result<(), i32> {
        let has_event = if let Some(event) = session.backend_session.next_event() {
            match event {
                VideoDecoderBackendEvent::InputBufferDone(id) => {
                    let Some(buffer) = session.input_buffers.get_mut(id as usize) else {
                        log::error!("no matching OUTPUT buffer with id {} to process event", id);
                        return Ok(());
                    };

                    buffer.v4l2_buffer.clear_flags(BufferFlags::QUEUED);

                    self.event_queue
                        .send_event(V4l2Event::DequeueBuffer(DequeueBufferEvent::new(
                            session.id,
                            buffer.v4l2_buffer.clone(),
                        )));
                }
                VideoDecoderBackendEvent::StreamFormatChanged => {
                    let stream_params = session.backend_session.stream_params();

                    // The crop rectangle is now determined by the stream and cannot be changed.
                    session.crop_rectangle = CropRectangle::FromStream(stream_params.visible_rect);

                    if session.src_change_subscribed {
                        self.event_queue
                            .send_event(V4l2Event::Event(SessionEvent::new(
                                session.id,
                                bindings::v4l2_event {
                                    type_: bindings::V4L2_EVENT_SOURCE_CHANGE,
                                    u: bindings::v4l2_event__bindgen_ty_1 {
                                        src_change: bindings::v4l2_event_src_change {
                                            changes: SrcChanges::RESOLUTION.bits(),
                                        },
                                    },
                                    // TODO: fill pending, sequence, and timestamp.
                                    ..Default::default()
                                },
                            )))
                    }
                }
                VideoDecoderBackendEvent::FrameCompleted {
                    buffer_id,
                    timestamp,
                    bytes_used,
                    is_last,
                } => {
                    let Some(buffer) = session.output_buffers.get_mut(buffer_id as usize) else {
                        log::error!(
                            "no matching CAPTURE buffer with id {} to process event",
                            buffer_id
                        );
                        return Ok(());
                    };

                    buffer.v4l2_buffer.clear_flags(BufferFlags::QUEUED);
                    buffer.v4l2_buffer.set_flags(BufferFlags::TIMESTAMP_COPY);
                    if is_last {
                        buffer.v4l2_buffer.set_flags(BufferFlags::LAST);
                    }
                    buffer.v4l2_buffer.set_sequence(session.sequence_cpt);
                    session.sequence_cpt += 1;
                    buffer.v4l2_buffer.set_timestamp(timestamp);
                    let first_plane = buffer.v4l2_buffer.get_first_plane_mut();
                    *first_plane.bytesused = bytes_used.first().copied().unwrap_or(0);
                    self.event_queue
                        .send_event(V4l2Event::DequeueBuffer(DequeueBufferEvent::new(
                            session.id,
                            buffer.v4l2_buffer.clone(),
                        )));

                    if is_last && session.eos_subscribed {
                        self.event_queue
                            .send_event(V4l2Event::Event(SessionEvent::new(
                                session.id,
                                bindings::v4l2_event {
                                    type_: bindings::V4L2_EVENT_EOS,
                                    ..Default::default()
                                },
                            )))
                    }
                }
            }
            true
        } else {
            false
        };

        if !has_event {
            log::warn!("process_events called but no event was pending");
        }

        Ok(())
    }
}

impl<B, Q, HM> VirtioMediaIoctlHandler for VideoDecoder<B, Q, HM>
where
    B: VideoDecoderBackend,
    Q: VirtioMediaEventQueue,
    HM: VirtioMediaHostMemoryMapper,
{
    type Session = VideoDecoderSession<B::Session>;

    fn enum_fmt(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<bindings::v4l2_fmtdesc> {
        match queue {
            QueueType::VideoOutputMplane | QueueType::VideoCaptureMplane => {
                self.backend.enum_formats(session, queue.direction(), index)
            }
            _ => None,
        }
        .ok_or(libc::EINVAL)
    }

    fn enum_framesizes(
        &mut self,
        _session: &Self::Session,
        index: u32,
        pixel_format: u32,
    ) -> IoctlResult<bindings::v4l2_frmsizeenum> {
        // We only support step-wise frame sizes.
        if index != 0 {
            return Err(libc::EINVAL);
        }

        Ok(bindings::v4l2_frmsizeenum {
            index: 0,
            pixel_format,
            type_: bindings::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_STEPWISE,
            __bindgen_anon_1: bindings::v4l2_frmsizeenum__bindgen_ty_1 {
                stepwise: self.backend.frame_sizes(pixel_format).ok_or(libc::EINVAL)?,
            },
            ..Default::default()
        })
    }

    fn g_fmt(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
    ) -> IoctlResult<bindings::v4l2_format> {
        if !matches!(
            queue,
            QueueType::VideoOutputMplane | QueueType::VideoCaptureMplane,
        ) {
            return Err(libc::EINVAL);
        }

        let format = session.current_format(queue.direction());
        let v4l2_format: &bindings::v4l2_format = format.as_ref();
        Ok(*v4l2_format)
    }

    fn try_fmt(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        format: bindings::v4l2_format,
    ) -> IoctlResult<bindings::v4l2_format> {
        let format = self.try_format(session, queue, format)?;

        let v4l2_format: &bindings::v4l2_format = format.as_ref();
        Ok(*v4l2_format)
    }

    fn s_fmt(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        format: bindings::v4l2_format,
    ) -> IoctlResult<bindings::v4l2_format> {
        let format = self.try_format(session, queue, format)?;

        self.backend
            .apply_format(&mut session.backend_session, queue.direction(), &format);

        //  Setting the colorspace information on the `OUTPUT` queue sets it for both queues.
        if queue.direction() == QueueDirection::Output {
            session.colorspace.colorspace = format.colorspace();
            session.colorspace.xfer_func = format.xfer_func();
            session.colorspace.ycbcr_enc = format.ycbcr_enc();
            session.colorspace.quantization = format.quantization();
        }

        // If the crop rectangle is still settable, adjust it to the size of the new format.
        if let CropRectangle::Settable(rect) = &mut session.crop_rectangle {
            let (width, height) = format.size();
            *rect = v4l2r::Rect::new(0, 0, width, height);
        }

        let v4l2_format: &bindings::v4l2_format = format.as_ref();
        Ok(*v4l2_format)
    }

    fn reqbufs(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        memory: MemoryType,
        count: u32,
    ) -> IoctlResult<bindings::v4l2_requestbuffers> {
        if memory != MemoryType::Mmap {
            return Err(libc::EINVAL);
        }
        // TODO: fail if streaming?

        let (buffers, count) = match queue {
            QueueType::VideoOutputMplane => (&mut session.input_buffers, count),
            QueueType::VideoCaptureMplane => (
                &mut session.output_buffers,
                // TODO: no no, we need to reallocate all the buffers if the queue parameters have
                // changed... especially if the new format won't fit into the old buffers!
                // count.max(session.backend_session.stream_params().min_output_buffers),
                count,
            ),
            _ => return Err(libc::EINVAL),
        };

        if (count as usize) < buffers.len() {
            for buffer in &buffers[count as usize..] {
                if let V4l2PlanesWithBacking::Mmap(planes) =
                    buffer.v4l2_buffer.planes_with_backing_iter()
                {
                    for plane in planes {
                        self.host_mapper.unregister_buffer(plane.mem_offset());
                    }
                }
            }
            buffers.truncate(count as usize);
        } else {
            let sizeimage = session
                .backend_session
                .current_format(queue.direction())
                .planes()
                .first()
                .ok_or(libc::EINVAL)?
                .sizeimage;
            let new_buffers = (buffers.len()..count as usize)
                .map(|i| {
                    let mmap_offset = self
                        .host_mapper
                        .register_buffer(None, sizeimage)
                        .map_err(|_| libc::EINVAL)?;

                    VideoDecoderBuffer::new(
                        queue,
                        i as u32,
                        // TODO: only single-planar formats supported.
                        &[sizeimage as usize],
                        mmap_offset,
                    )
                    .inspect_err(|_| {
                        // TODO: no, we need to unregister all the buffers and restore the
                        // previous state?
                        self.host_mapper.unregister_buffer(mmap_offset);
                    })
                })
                .collect::<IoctlResult<Vec<_>>>()?;
            buffers.extend(new_buffers);
        }

        session
            .backend_session
            .buffers_allocated(queue.direction(), count);

        Ok(bindings::v4l2_requestbuffers {
            count,
            type_: queue as u32,
            memory: memory as u32,
            capabilities: (BufferCapabilities::SUPPORTS_MMAP
                | BufferCapabilities::SUPPORTS_ORPHANED_BUFS)
                .bits(),
            flags: 0,
            reserved: Default::default(),
        })
    }

    fn querybuf(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<V4l2Buffer> {
        let buffers = match queue {
            QueueType::VideoOutputMplane => &session.input_buffers,
            QueueType::VideoCaptureMplane => &session.output_buffers,
            _ => return Err(libc::EINVAL),
        };
        let buffer = buffers.get(index as usize).ok_or(libc::EINVAL)?;

        Ok(buffer.v4l2_buffer.clone())
    }

    fn subscribe_event(
        &mut self,
        session: &mut Self::Session,
        event: v4l2r::ioctl::EventType,
        _flags: v4l2r::ioctl::SubscribeEventFlags,
    ) -> IoctlResult<()> {
        match event {
            EventType::SourceChange(0) => {
                session.src_change_subscribed = true;
                Ok(())
            }
            EventType::Eos => {
                session.eos_subscribed = true;
                Ok(())
            }
            _ => Err(libc::EINVAL),
        }
    }

    // TODO: parse the event and use an enum value to signal ALL or single event?
    fn unsubscribe_event(
        &mut self,
        session: &mut Self::Session,
        event: bindings::v4l2_event_subscription,
    ) -> IoctlResult<()> {
        let mut valid = false;

        if event.type_ == 0 || matches!(EventType::try_from(&event), Ok(EventType::SourceChange(0)))
        {
            session.src_change_subscribed = false;
            valid = true;
        }
        if event.type_ == 0 || matches!(EventType::try_from(&event), Ok(EventType::Eos)) {
            session.eos_subscribed = false;
            valid = true;
        }

        if valid {
            Ok(())
        } else {
            Err(libc::EINVAL)
        }
    }

    fn streamon(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        let buffers = match queue {
            QueueType::VideoOutputMplane => &session.input_buffers,
            QueueType::VideoCaptureMplane => &session.output_buffers,
            _ => return Err(libc::EINVAL),
        };

        let already_running = matches!(session.state, VideoDecoderStreamingState::Running);

        // Cannot stream if no buffers allocated.
        if buffers.is_empty() {
            return Err(libc::EINVAL);
        }

        match queue.direction() {
            QueueDirection::Output => session.state.input_streamon(),
            QueueDirection::Capture => session.state.output_streamon(),
        }

        session
            .backend_session
            .streaming_state(queue.direction(), true);

        if !already_running && matches!(session.state, VideoDecoderStreamingState::Running) {
            // TODO: start queueing pending buffers?
        }

        session.try_send_pending_output_buffers();

        Ok(())
    }

    fn streamoff(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        let buffers = match queue.direction() {
            QueueDirection::Output => {
                // TODO: something to do on the backend?
                session.state.input_streamoff();

                &mut session.input_buffers
            }
            QueueDirection::Capture => {
                session.backend_session.clear_output_buffers()?;
                session.state.output_streamoff();
                session.pending_output_buffers.clear();

                &mut session.output_buffers
            }
        };

        for buffer in buffers {
            buffer.v4l2_buffer.clear_flags(BufferFlags::QUEUED);
        }

        session
            .backend_session
            .streaming_state(queue.direction(), false);

        Ok(())
    }

    fn g_selection(
        &mut self,
        session: &Self::Session,
        sel_type: SelectionType,
        sel_target: SelectionTarget,
    ) -> IoctlResult<bindings::v4l2_rect> {
        match (sel_type, sel_target) {
            // Coded resolution of the stream.
            (SelectionType::Capture, SelectionTarget::CropBounds) => {
                let coded_size = session.backend_session.stream_params().coded_size;
                Ok(v4l2r::Rect::new(0, 0, coded_size.0, coded_size.1).into())
            }
            // Visible area of CAPTURE buffers.
            (
                SelectionType::Capture,
                SelectionTarget::Crop
                | SelectionTarget::CropDefault
                | SelectionTarget::ComposeDefault
                | SelectionTarget::ComposeBounds
                | SelectionTarget::Compose,
            ) => {
                //Ok(session.backend_session.stream_params().visible_rect.into())
                Ok((*session.crop_rectangle).into())
            }
            _ => Err(libc::EINVAL),
        }
    }

    fn s_selection(
        &mut self,
        session: &mut Self::Session,
        sel_type: SelectionType,
        sel_target: SelectionTarget,
        mut sel_rect: bindings::v4l2_rect,
        _sel_flags: v4l2r::ioctl::SelectionFlags,
    ) -> IoctlResult<bindings::v4l2_rect> {
        if !matches!(
            (sel_type, sel_target),
            (SelectionType::Capture, SelectionTarget::Compose)
        ) {
            return Err(libc::EINVAL);
        }

        // If the crop rectangle is still settable, allow its modification within the bounds of the
        // coded resolution.
        if let CropRectangle::Settable(rect) = &mut session.crop_rectangle {
            let coded_size = session
                .backend_session
                .current_format(QueueDirection::Capture)
                .size();
            sel_rect.left = std::cmp::max(0, sel_rect.left);
            sel_rect.top = std::cmp::max(0, sel_rect.top);
            sel_rect.width = std::cmp::min(coded_size.0, sel_rect.width - sel_rect.left as u32);
            sel_rect.height = std::cmp::min(coded_size.0, sel_rect.height - sel_rect.top as u32);

            *rect = sel_rect.into();
        }

        self.g_selection(session, sel_type, sel_target)
    }

    fn qbuf(
        &mut self,
        session: &mut Self::Session,
        buffer: V4l2Buffer,
        _guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<V4l2Buffer> {
        let buffers = match buffer.queue() {
            QueueType::VideoOutputMplane => &mut session.input_buffers,
            QueueType::VideoCaptureMplane => &mut session.output_buffers,
            _ => return Err(libc::EINVAL),
        };
        let host_buffer = buffers
            .get_mut(buffer.index() as usize)
            .ok_or(libc::EINVAL)?;

        // Check that the buffer's memory type corresponds to the one requested during allocation.
        if buffer.memory() != host_buffer.v4l2_buffer.memory() {
            return Err(libc::EINVAL);
        }

        match buffer.queue().direction() {
            QueueDirection::Output => {
                // Update buffer state
                let v4l2_buffer = &mut host_buffer.v4l2_buffer;
                v4l2_buffer.set_field(BufferField::None);
                v4l2_buffer.set_timestamp(buffer.timestamp());
                let first_plane = buffer.get_first_plane();
                *v4l2_buffer.get_first_plane_mut().bytesused = *first_plane.bytesused;
                let host_first_plane = v4l2_buffer.get_first_plane_mut();
                *host_first_plane.length = *first_plane.length;
                *host_first_plane.bytesused = *first_plane.bytesused;
                if let Some(data_offset) = host_first_plane.data_offset {
                    *data_offset = first_plane.data_offset.copied().unwrap_or(0);
                }

                let bytes_used = {
                    let first_plane = host_buffer.v4l2_buffer.get_first_plane();
                    // V4L2's spec mentions that if `bytes_used == 0` then the whole buffer is considered to be
                    // used.
                    if *first_plane.bytesused == 0 {
                        *first_plane.length
                    } else {
                        *first_plane.bytesused
                    }
                };

                session.backend_session.decode(
                    &host_buffer.backing,
                    host_buffer.index(),
                    host_buffer.timestamp(),
                    bytes_used,
                )?;

                host_buffer.v4l2_buffer.add_flags(BufferFlags::QUEUED);

                Ok(host_buffer.v4l2_buffer.clone())
            }
            QueueDirection::Capture => {
                // Update buffer state
                let v4l2_buffer = &mut host_buffer.v4l2_buffer;
                v4l2_buffer.add_flags(BufferFlags::QUEUED);
                v4l2_buffer.clear_flags(BufferFlags::LAST);
                let host_first_plane = v4l2_buffer.get_first_plane_mut();
                let first_plane = buffer.get_first_plane();
                *host_first_plane.length = *first_plane.length;
                *host_first_plane.bytesused = *first_plane.bytesused;
                if let Some(data_offset) = host_first_plane.data_offset {
                    *data_offset = first_plane.data_offset.copied().unwrap_or(0);
                }

                let res = v4l2_buffer.clone();

                session.pending_output_buffers.push(buffer.index());
                session.try_send_pending_output_buffers();

                Ok(res)
            }
        }
    }

    fn try_decoder_cmd(
        &mut self,
        session: &Self::Session,
        cmd: bindings::v4l2_decoder_cmd,
    ) -> IoctlResult<bindings::v4l2_decoder_cmd> {
        let cmd = DecoderCmd::try_from(cmd).map_err(|_| libc::EINVAL)?;
        session.try_decoder_cmd(cmd).map(Into::into)
    }

    fn decoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: bindings::v4l2_decoder_cmd,
    ) -> IoctlResult<bindings::v4l2_decoder_cmd> {
        let cmd = DecoderCmd::try_from(cmd).map_err(|_| libc::EINVAL)?;
        let cmd = session.try_decoder_cmd(cmd)?;

        // The command is valid, apply it.
        match cmd {
            DecoderCmd::Stop { .. } => {
                // Switch to stopped state if we aren't already there.
                if !matches!(session.state, VideoDecoderStreamingState::Stopped { .. }) {
                    session.state = VideoDecoderStreamingState::Stopped {
                        input_streaming: true,
                        output_streaming: true,
                    };

                    // Start the `DRAIN` sequence.
                    session.backend_session.drain()?;
                }
            }
            DecoderCmd::Start { .. } => {
                // Restart the decoder if we were in the stopped state with both queues streaming.
                if let VideoDecoderStreamingState::Stopped {
                    input_streaming,
                    output_streaming,
                } = &session.state
                {
                    if *input_streaming && *output_streaming {
                        session.state = VideoDecoderStreamingState::Running;
                        session
                            .backend_session
                            .streaming_state(QueueDirection::Capture, true);
                    }
                    session.try_send_pending_output_buffers();
                }
            }
            DecoderCmd::Pause { .. } => {
                if matches!(session.state, VideoDecoderStreamingState::Running) {
                    session.state = VideoDecoderStreamingState::Paused;
                }
            }
            DecoderCmd::Resume => {
                if matches!(session.state, VideoDecoderStreamingState::Paused) {
                    session.state = VideoDecoderStreamingState::Running;
                }
            }
        }

        Ok(cmd.into())
    }
}
