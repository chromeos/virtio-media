// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod event_queue;
pub mod ffmpeg;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;

use enumn::N;
use event_queue::EventQueue;
use ffmpeg::avcodec::AvBuffer;
use ffmpeg::avcodec::AvBufferSource;
use ffmpeg::avcodec::AvCodec;
use ffmpeg::avcodec::AvCodecContext;
use ffmpeg::avcodec::AvCodecIterator;
use ffmpeg::avcodec::AvCodecOpenError;
use ffmpeg::avcodec::AvError;
use ffmpeg::avcodec::AvFrame;
use ffmpeg::avcodec::AvFrameError;
use ffmpeg::avcodec::AvPacket;
use ffmpeg::avcodec::AvPixelFormat;
use ffmpeg::avcodec::Dimensions;
use ffmpeg::avcodec::PlaneDescriptor;
use ffmpeg::avcodec::TryReceiveResult;
use ffmpeg::avcodec::AV_PIXEL_FORMAT_NV12;
use ffmpeg::avcodec::AV_PIXEL_FORMAT_YUV420P;
use ffmpeg::swscale::ConversionError;
use ffmpeg::swscale::SwConverter;
use ffmpeg::swscale::SwConverterCreationError;
use ffmpeg::AVERROR_EOF;
use ffmpeg::AVERROR_INVALIDDATA;
use nix::errno::Errno;
use thiserror::Error as ThisError;
use virtio_media::devices::video_decoder::StreamParams;
use virtio_media::devices::video_decoder::VideoDecoderBackend;
use virtio_media::devices::video_decoder::VideoDecoderBackendEvent;
use virtio_media::devices::video_decoder::VideoDecoderBackendSession;
use virtio_media::devices::video_decoder::VideoDecoderBufferBacking;
use virtio_media::devices::video_decoder::VideoDecoderSession;
use virtio_media::ioctl::IoctlResult;
use virtio_media::memfd::MemFdBuffer;
use virtio_media::memfd::MemFdMapping;
use virtio_media::v4l2r;
use virtio_media::v4l2r::bindings;
use virtio_media::v4l2r::ioctl::V4l2MplaneFormat;
use virtio_media::v4l2r::PixelFormat;
use virtio_media::v4l2r::QueueClass;
use virtio_media::v4l2r::QueueDirection;
use virtio_media::v4l2r::QueueType;
use virtio_media::v4l2r::Rect;

use crate::ffmpeg::AV_CODEC_CAP_DR1;

type BufferPlanesFmt = [bindings::v4l2_plane_pix_format; bindings::VIDEO_MAX_PLANES as usize];

impl AvBufferSource for MemFdMapping {
    fn as_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut().as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.size()
    }
}

pub struct FfmpegDecoderBuffer {
    // Plane backing memory, for MMAP buffers only.
    fds: Vec<MemFdBuffer>,
}

// TODO: technically this is a Mmap backing? For other buffer types we provide the backing
// externally...
impl VideoDecoderBufferBacking for FfmpegDecoderBuffer {
    fn new(_queue: QueueType, _index: u32, sizes: &[usize]) -> IoctlResult<Self>
    where
        Self: Sized,
    {
        let fds = sizes
            .iter()
            .map(|size| MemFdBuffer::new(*size as u64))
            .collect::<Result<_, _>>()
            .map_err(|_| libc::ENOMEM)?;

        Ok(Self { fds })
    }

    fn fd_for_plane(&self, plane_idx: usize) -> Option<BorrowedFd> {
        self.fds.get(plane_idx).map(|memfd| memfd.as_file().as_fd())
    }
}

#[derive(Debug, Default, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, N)]
#[repr(u32)]
pub enum OutputFormat {
    #[default]
    H264 = PixelFormat::from_fourcc(b"H264").to_u32(),
    VP8 = PixelFormat::from_fourcc(b"VP80").to_u32(),
    VP9 = PixelFormat::from_fourcc(b"VP90").to_u32(),
    HEVC = PixelFormat::from_fourcc(b"HEVC").to_u32(),
}

impl OutputFormat {
    fn into_v4l2_pix_format(self, coded_size: (u32, u32)) -> bindings::v4l2_pix_format_mplane {
        // TODO: use `coded_size` to infer a reasonable size?
        const INPUT_SIZEIMAGE: u32 = 1024 * 1024;

        let mut plane_fmt: BufferPlanesFmt = Default::default();
        plane_fmt[0] = bindings::v4l2_plane_pix_format {
            bytesperline: 0,
            sizeimage: INPUT_SIZEIMAGE,
            reserved: Default::default(),
        };

        bindings::v4l2_pix_format_mplane {
            width: coded_size.0,
            height: coded_size.1,
            pixelformat: self as u32,
            plane_fmt,
            num_planes: 1,
            ..format_filler()
        }
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, N)]
#[repr(u32)]
pub enum CaptureFormat {
    NV12 = PixelFormat::from_fourcc(b"NV12").to_u32(),
}

impl From<CaptureFormat> for AvPixelFormat {
    fn from(format: CaptureFormat) -> Self {
        AvPixelFormat(match format {
            CaptureFormat::NV12 => AV_PIXEL_FORMAT_NV12.into(),
        })
    }
}

impl CaptureFormat {
    fn into_v4l2_pix_format(self, coded_size: (u32, u32)) -> bindings::v4l2_pix_format_mplane {
        let mut plane_fmt: BufferPlanesFmt = Default::default();
        let av_format = AvPixelFormat::from(self);

        let num_planes = match self {
            CaptureFormat::NV12 => {
                let plane = &mut plane_fmt[0];
                let line_size = av_format.line_size(coded_size.0, 0) as u32;
                plane.bytesperline = line_size;
                plane.sizeimage = av_format
                    .plane_sizes([line_size, line_size], coded_size.1)
                    .into_iter()
                    .sum::<usize>() as u32;
                1
            }
        };

        bindings::v4l2_pix_format_mplane {
            width: coded_size.0,
            height: coded_size.1,
            pixelformat: self as u32,
            plane_fmt,
            num_planes,
            ..format_filler()
        }
    }
}

enum FfmpegDecoderJob {
    Decode {
        /// Ffmpeg packet containing the input data.
        ///
        /// TODO: we can probably avoid the copy by keeping the input, mapping it, and using the
        /// mapping as the source of the AvPacket?
        packet: AvPacket<'static>,
        /// Index of the input buffer from which the input was received.
        input_index: u32,
    },
    Drain,
}

/// State for a session that is actively decoding.
struct DecodingContext {
    /// FIFO of input buffers waiting to be submitted.
    jobs: VecDeque<FfmpegDecoderJob>,
    /// Decoder context, dependent on the input format.
    av_context: AvCodecContext,
    /// Converter from the current AVCodec output format to the format expected by the client.
    converter: SwConverter,
    /// Set when
    accepting_output_buffers: bool,
    /// Latest `AvFrame` received from ffmpeg.
    avframe: Option<AvFrame>,
    /// Whether the context is currently draining.
    drain_state: DrainState,
}

#[derive(Debug, ThisError)]
pub enum NewDecodingContextError {
    #[error("cannot create decoder: {0}")]
    DecoderCreation(#[from] AvCodecOpenError),
    #[error("cannot create sw decoder: {0}")]
    SwConverter(#[from] SwConverterCreationError),
}

impl DecodingContext {
    /// Build a new decoding context for `codec`.
    fn new(
        codec: AvCodec,
        output_format: CaptureFormat,
        coded_size: (u32, u32),
    ) -> Result<Self, NewDecodingContextError> {
        let av_context = codec.build_decoder().and_then(|b| {
            b.set_initial_format(coded_size, AV_PIXEL_FORMAT_YUV420P);
            b.build()
        })?;

        let converter = Self::create_converter_from_context(&av_context, output_format)?;

        Ok(DecodingContext {
            jobs: Default::default(),
            av_context,
            // We accept CAPTURE buffers tentatively, as the client might know the stream format.
            accepting_output_buffers: true,
            converter,
            avframe: None,
            drain_state: DrainState::None,
        })
    }

    fn create_converter_from_context(
        av_context: &AvCodecContext,
        output_format: CaptureFormat,
    ) -> Result<SwConverter, SwConverterCreationError> {
        let avcontext = av_context.as_ref();
        let dst_pix_fmt: AvPixelFormat = output_format.into();
        log::info!(
            "creating SW converter from {}x{} {} to {:?}",
            avcontext.width,
            avcontext.height,
            avcontext.pix_fmt,
            dst_pix_fmt
        );

        SwConverter::new(
            avcontext.width as usize,
            avcontext.height as usize,
            avcontext.pix_fmt,
            dst_pix_fmt.0,
        )
    }

    /// Recreate the frame converter for this context. This should be called whenever the stream
    /// format changes.
    fn update_converter(
        &mut self,
        output_format: CaptureFormat,
    ) -> Result<(), SwConverterCreationError> {
        self.converter = Self::create_converter_from_context(&self.av_context, output_format)?;

        Ok(())
    }
}

/// An output frame ready to be decoded into.
struct AvailableOutputFrame {
    /// V4L2 buffer index for this frame.
    index: u32,
    /// CPU mappings for all the planes.
    planes: Vec<MemFdMapping>,
}

#[derive(Debug, PartialEq, Eq)]
enum DrainState {
    /// No drain at the moment.
    None,
    /// Drain has started, we are waiting for all input to be processed.
    Initiated,
    /// Ffmpeg has been flushed, we are waiting for a frame to signal with the LAST flag.
    AwaitingFinalFrame,
}

pub struct FfmpegDecoderSession {
    /// Input format currently exposed to the client. This can be changed until the first buffer is
    /// queued on the OUTPUT queue.
    input_format: (OutputFormat, AvCodec),
    /// Output format currently exposed to the client.
    output_format: CaptureFormat,
    /// Coded size set for CAPTURE buffers. Can be larger than the one reported in `stream_params`.
    coded_size: (u32, u32),
    /// TODO: actually we should be able to change the stream's coded size by setting the OUTPUT
    /// resolution. This would adjust the CAPTURE resolution too, and trigger a DRC event if the
    /// format is not large enough when the next input buffer is submitted.
    stream_params: StreamParams,

    /// Initialize once the input codec has been determined.
    context: Option<DecodingContext>,

    /// FIFO of output frames we can decode into.
    available_output_frames: VecDeque<AvailableOutputFrame>,

    /// FIFO of decoder events waiting to be dequeued.
    events: EventQueue<VideoDecoderBackendEvent>,
}

#[derive(Debug, ThisError)]
enum TrySendInputError {
    #[error("decoder context has not been created yet")]
    NoContext,
    #[error("error while sending input packet to libavcodec: {0}")]
    AvError(#[from] AvError),
    #[error("error while queueing input buffer done event: {0}")]
    EventQueue(Errno),
}

#[derive(Debug, ThisError)]
enum TryReceiveFrameError {
    #[error("decoder context has not been created yet")]
    // TODO: get the context in a caller method so we can deduplicate? Or better, set the context
    // as part of the state of the decoder?
    NoContext,
    #[error("cannot create AvFrame")]
    CannotCreateAvFrame(#[from] AvFrameError),
    #[error("decoding error: {0}")]
    DecodingError(AvError),
    #[error("error while queueing input completed event: {0}")]
    EventQueue(Errno),
    #[error("error while creating SW converter: {0}")]
    SwConverter(#[from] SwConverterCreationError),
    #[error("drain operation failed")]
    DrainFailed,
}

#[derive(Debug, ThisError)]
enum TryOutputFrameError {
    #[error("decoder context has not been created yet")]
    NoContext,
    #[error("error while creating output AvFrame")]
    AvFrame(#[from] AvFrameError),
    #[error("error while queueing frame decoded event: {0}")]
    EventQueue(Errno),
    #[error("not enough planes in target frame")]
    NotEnoughPlanes,
    #[error("error while building AvFrame: {0}")]
    CannotBuild(AvFrameError),
    #[error("error while converting frame: {0}")]
    ConversionError(ConversionError),
}

#[derive(Debug, ThisError)]
enum TryDecodeError {
    #[error("error while sending input: {0}")]
    SendInput(#[from] TrySendInputError),
    #[error("error while receiving frame: {0}")]
    ReceiveFrame(#[from] TryReceiveFrameError),
    #[error("error while outputing decoded frame: {0}")]
    OutputFrame(#[from] TryOutputFrameError),
}

impl FfmpegDecoderSession {
    /// Try to run the next input job, if any.
    ///
    /// Returns `true` if the next job has been submitted, `false` if it could not be, either
    /// because all pending work has already been queued or because the codec could not accept more
    /// input at the moment.
    fn try_send_input_job(&mut self) -> Result<bool, TrySendInputError> {
        let context = self.context.as_mut().ok_or(TrySendInputError::NoContext)?;

        let next_job = match context.jobs.pop_front() {
            None => return Ok(false),
            Some(job) => job,
        };

        match &next_job {
            FfmpegDecoderJob::Decode {
                packet,
                input_index,
            } => {
                let input_consumed = match context.av_context.try_send_packet(packet) {
                    Ok(res) => Ok(res),
                    // This could happen if we attempt to submit data while flushing.
                    Err(AvError(AVERROR_EOF)) => Ok(false),
                    // If we got invalid data, keep going in hope that we will catch a valid state later.
                    Err(AvError(AVERROR_INVALIDDATA)) => {
                        log::warn!("try_send_input: invalid data in stream, ignoring...");
                        Ok(true)
                    }
                    Err(e) => Err(TrySendInputError::from(e)),
                }?;

                // If the input job has been rejected, push it back. Otherwise, signal the input buffer can
                // be reused.
                match input_consumed {
                    false => context.jobs.push_front(next_job),
                    true => self
                        .events
                        .queue_event(VideoDecoderBackendEvent::InputBufferDone(*input_index))
                        .map_err(TrySendInputError::EventQueue)?,
                }

                Ok(input_consumed)
            }
            FfmpegDecoderJob::Drain => {
                log::debug!("drain initiated");
                // Just set the state as draining for now. We will send the actual flush command
                // when `try_receive_frame` returns `TryAgain`. This should probably not be
                // necessary but we sometimes miss the last frame if we send the flush command to
                // libavcodec earlier (which looks like a bug with libavcodec but needs to be
                // confirmed).
                context.drain_state = DrainState::Initiated;
                Ok(true)
            }
        }
    }

    /// Try to receive a frame from the context and return it if it worked.
    fn try_receive_frame(&mut self) -> Result<bool, TryReceiveFrameError> {
        let context = self
            .context
            .as_mut()
            .ok_or(TryReceiveFrameError::NoContext)?;
        let mut avframe = match context.avframe {
            // We already have a frame waiting. Wait until it is sent to process the next one.
            Some(_) => return Ok(false),
            None => AvFrame::new()?,
        };

        match context.av_context.try_receive_frame(&mut avframe) {
            Ok(TryReceiveResult::Received) => {
                // Now check whether the resolution of the stream has changed.
                let new_coded_size = (avframe.width as u32, avframe.height as u32);
                // TODO: incorrect! We need to discard these values.
                let new_visible_rect = v4l2r::Rect::new(
                    avframe.crop_left as i32,
                    avframe.crop_top as i32,
                    (avframe.crop_right - avframe.crop_left) as u32,
                    (avframe.crop_bottom - avframe.crop_top) as u32,
                );

                if new_coded_size != self.stream_params.coded_size
                    || new_visible_rect != self.stream_params.visible_rect
                {
                    log::info!(
                        "new resolution detected in stream: {:?} -> {:?}",
                        self.stream_params.coded_size,
                        new_coded_size
                    );
                    self.stream_params.coded_size = new_coded_size;
                    self.stream_params.visible_rect = new_visible_rect;
                    // Reset adjustable coded size if the new stream cannot fit into the current
                    // buffers.
                    if new_coded_size.0 > self.coded_size.0 || new_coded_size.1 > self.coded_size.1
                    {
                        self.coded_size = new_coded_size;
                    }

                    context.update_converter(self.output_format)?;

                    // TODO: change decoding state to awaiting buffers and reject output buffers
                    // until the format has been confirmed somehow? IOW we need the decoder to
                    // confirm it has acknowledged our format change before we can accept new
                    // buffers.
                    //
                    // TODO: 07/23: decoder state, check how the crosvm decoder adapter handles
                    // resolution change?

                    self.available_output_frames.clear();
                    context.accepting_output_buffers = false;

                    self.events
                        .queue_event(VideoDecoderBackendEvent::StreamFormatChanged)
                        .map_err(TryReceiveFrameError::EventQueue)?;
                }

                context.avframe = Some(avframe);

                Ok(true)
            }
            Ok(TryReceiveResult::TryAgain) => {
                // Start flushing. `try_receive_frame` will return `FlushCompleted` when the
                // flush is completed. `TryAgain` will not be returned again until the flush is
                // completed.
                if context.drain_state == DrainState::Initiated {
                    match context.av_context.flush_decoder() {
                        // Call ourselves again so we can process the flush.
                        Ok(()) => self.try_receive_frame(),
                        Err(_) => {
                            context.drain_state = DrainState::None;
                            Err(TryReceiveFrameError::DrainFailed)
                        }
                    }
                } else {
                    Ok(false)
                }
            }
            Ok(TryReceiveResult::FlushCompleted) => {
                if context.drain_state == DrainState::Initiated {
                    log::debug!(
                        "decoder drain completed ; waiting for frame to send with the LAST flag"
                    );
                    context.drain_state = DrainState::AwaitingFinalFrame;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // If we got invalid data, keep going in hope that we will catch a valid state later.
            Err(AvError(AVERROR_INVALIDDATA)) => {
                log::warn!("try_receive_frame: invalid data in stream, ignoring...");
                Ok(true)
            }
            Err(av_err) => Err(TryReceiveFrameError::DecodingError(av_err)),
        }
    }

    /// Try to output the currently decoded frame in [`DecodingContext::avframe`] into a client's output
    /// buffer.
    fn try_output_frame(&mut self) -> Result<bool, TryOutputFrameError> {
        let context = self
            .context
            .as_mut()
            .ok_or(TryOutputFrameError::NoContext)?;
        let mut output_frame = match self.available_output_frames.pop_front() {
            Some(output_frame) => output_frame,
            None => return Ok(false),
        };

        // Special case: if we are at the end of draining, send an empty frame with the LAST flag
        // set.
        if context.drain_state == DrainState::AwaitingFinalFrame {
            // ... but only if all the pending frames have been outputted.
            if context.avframe.is_some() {
                self.available_output_frames.push_front(output_frame);
                return Ok(false);
            }

            log::debug!("sending frame with LAST flag to signal end of drain");
            context.drain_state = DrainState::None;

            self.events
                .queue_event(VideoDecoderBackendEvent::FrameCompleted {
                    buffer_id: output_frame.index,
                    timestamp: bindings::timeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    },
                    bytes_used: vec![],
                    is_last: true,
                })
                .map_err(TryOutputFrameError::EventQueue)?;

            return Ok(true);
        }

        let avframe = match context.avframe.take() {
            Some(avframe) => avframe,
            None => {
                self.available_output_frames.push_front(output_frame);
                return Ok(false);
            }
        };

        let av_format: AvPixelFormat = self.output_format.into();
        let bytes_used = av_format.plane_sizes(
            // TODO: this works for NV12, but not for other formats...
            [self.coded_size.0, self.coded_size.0],
            self.coded_size.1,
        );
        // Build an AvFrame for the output frame.
        // TODO: we need to handle stride, and more complex output frame formats.
        let mut dst_avframe = {
            let mut builder = AvFrame::builder()?;
            builder.set_dimensions(Dimensions {
                width: self.coded_size.0,
                height: self.coded_size.1,
            })?;
            builder.set_format(av_format)?;

            let planes = [
                PlaneDescriptor {
                    buffer_index: 0,
                    offset: 0,
                    stride: av_format.line_size(self.coded_size.0, 0),
                },
                PlaneDescriptor {
                    buffer_index: 0,
                    offset: bytes_used[0],
                    stride: av_format.line_size(self.coded_size.0, 1),
                },
            ];

            let av_buffer = AvBuffer::new(output_frame.planes.remove(0))
                .ok_or(TryOutputFrameError::NotEnoughPlanes)?;
            builder
                .build_owned([av_buffer], planes)
                .map_err(TryOutputFrameError::CannotBuild)?
        };

        context
            .converter
            .convert(&avframe, &mut dst_avframe)
            .map_err(TryOutputFrameError::ConversionError)?;

        let timestamp = bindings::timeval {
            tv_sec: avframe.pts / 1_000_000,
            tv_usec: avframe.pts % 1_000_000,
        };

        self.events
            .queue_event(VideoDecoderBackendEvent::FrameCompleted {
                buffer_id: output_frame.index,
                timestamp,
                bytes_used: vec![bytes_used.iter().sum::<usize>() as u32],
                is_last: false,
            })
            .map_err(TryOutputFrameError::EventQueue)?;

        Ok(true)
    }

    /// Try to make progress with decoding.
    fn try_decode(&mut self) -> Result<(), TryDecodeError> {
        if self.context.is_none() {
            return Ok(());
        }

        while self.try_output_frame()? || self.try_receive_frame()? || self.try_send_input_job()? {}

        Ok(())
    }
}

impl VideoDecoderBackendSession for FfmpegDecoderSession {
    type BufferStorage = FfmpegDecoderBuffer;

    fn decode(
        &mut self,
        input: &Self::BufferStorage,
        index: u32,
        timestamp: bindings::timeval,
        bytes_used: u32,
    ) -> IoctlResult<()> {
        // The input format is decided at the time the first input buffer is queued, so this is
        // when we create our context.
        // Ensure we are in decoding state, and switch to it if we aren't.
        let context = match &mut self.context {
            Some(context) => context,
            None => {
                let codec = self.input_format.1;

                let context =
                    DecodingContext::new(codec, self.output_format, self.stream_params.coded_size)
                        .map_err(|_| libc::ENODEV)?;

                let avcontext = context.av_context.as_ref();
                log::info!(
                    "starting decoding {} at resolution {}x{} (AVContext pix_fmt {}) for output format {:?}",
                    codec.name(),
                    avcontext.width,
                    avcontext.height,
                    avcontext.pix_fmt,
                    self.output_format
                );

                self.context.get_or_insert(context)
            }
        };

        #[allow(clippy::unnecessary_cast)]
        let timestamp =
            (timestamp.tv_sec as i64).wrapping_mul(1_000_000) + (timestamp.tv_usec as i64);

        let mut input_data = vec![0u8; bytes_used as usize];
        let mut f = input.fds.first().ok_or(libc::EINVAL)?.as_file();
        f.seek(SeekFrom::Start(0)).map_err(|_| libc::EIO)?;
        f.read_exact(&mut input_data).map_err(|_| libc::EIO)?;

        let avbuffer = AvBuffer::new(input_data).ok_or(libc::ENOMEM)?;
        let avpacket = AvPacket::new_owned(timestamp, avbuffer);

        context.jobs.push_back(FfmpegDecoderJob::Decode {
            packet: avpacket,
            input_index: index,
        });

        self.try_decode().map_err(|e| {
            log::warn!("while decoding: {:#}", e);
            libc::EINVAL
        })
    }

    fn use_as_output(&mut self, index: u32, backing: &mut Self::BufferStorage) -> IoctlResult<()> {
        // Silently ignore buffers if we are not ready to accept them yet.
        if !self
            .context
            .as_ref()
            .map(|c| c.accepting_output_buffers)
            .unwrap_or(true)
        {
            return Ok(());
        }

        let planes = backing
            .fds
            .iter()
            .map(|fd| fd.mmap())
            .collect::<Result<_, _>>()
            .map_err(|_| libc::ENOMEM)?;

        self.available_output_frames
            .push_back(AvailableOutputFrame { index, planes });

        Ok(())
    }

    fn drain(&mut self) -> IoctlResult<()> {
        let context = match &mut self.context {
            Some(context) => context,
            // If the decoder is not ready, the drain command should succeed but no action shall be
            // taken.
            None => return Ok(()),
        };

        log::debug!("enqueuing drain request");
        context.jobs.push_back(FfmpegDecoderJob::Drain);
        self.try_decode().map_err(|e| {
            log::warn!("while draining: {:#}", e);
            libc::EINVAL
        })
    }

    fn clear_output_buffers(&mut self) -> IoctlResult<()> {
        self.available_output_frames.clear();
        self.events
            .retain(|event| !matches!(event, VideoDecoderBackendEvent::FrameCompleted { .. }));
        // We keep `self.context.avframe` as it is likely a DRC frame waiting for its new buffers.

        Ok(())
    }

    fn next_event(&mut self) -> Option<VideoDecoderBackendEvent> {
        self.events.dequeue_event()
    }

    fn poll_fd(&self) -> Option<BorrowedFd> {
        Some(self.events.as_fd())
    }

    fn current_format(&self, direction: QueueDirection) -> V4l2MplaneFormat {
        match direction {
            QueueDirection::Output => {
                let pix_mp = self
                    .input_format
                    .0
                    .into_v4l2_pix_format(self.stream_params.coded_size);

                V4l2MplaneFormat::from((direction, pix_mp))
            }
            QueueDirection::Capture => {
                let pix_mp = self.output_format.into_v4l2_pix_format(self.coded_size);

                V4l2MplaneFormat::from((direction, pix_mp))
            }
        }
    }

    fn stream_params(&self) -> StreamParams {
        self.stream_params.clone()
    }

    fn streaming_state(&mut self, direction: QueueDirection, streaming: bool) {
        if direction == QueueDirection::Capture && streaming {
            if let Some(context) = &mut self.context {
                context.accepting_output_buffers = true;
            }
        }
    }
}

pub struct FfmpegDecoder {
    codecs: BTreeMap<OutputFormat, AvCodec>,
}

impl FfmpegDecoder {
    /// Create a new ffmpeg decoder backend instance.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Find all the decoders supported by libav and store them.
        let codecs = AvCodecIterator::new()
            .filter_map(|codec| {
                if !codec.is_decoder() {
                    return None;
                }

                let codec_name = codec.name();

                // Only keep processing the decoders we are interested in.
                let format = match codec_name {
                    "h264" => OutputFormat::H264,
                    "hevc" => OutputFormat::HEVC,
                    "vp8" => OutputFormat::VP8,
                    "vp9" => OutputFormat::VP9,
                    _ => return None,
                };

                // We require custom buffer allocators, so ignore codecs that are not capable of
                // using them.
                if codec.capabilities() & AV_CODEC_CAP_DR1 == 0 {
                    log::info!(
                        "Skipping codec {} due to lack of DR1 capability.",
                        codec_name
                    );
                    return None;
                }

                Some((format, codec))
            })
            .collect();

        Self { codecs }
    }
}

const SUPPORTED_OUTPUT_FORMATS: [CaptureFormat; 1] = [CaptureFormat::NV12];

/// Returns a format with its invariant fields filled as expected.
fn format_filler() -> bindings::v4l2_pix_format_mplane {
    bindings::v4l2_pix_format_mplane {
        field: bindings::v4l2_field_V4L2_FIELD_NONE,
        flags: 0,
        colorspace: bindings::v4l2_colorspace_V4L2_COLORSPACE_DEFAULT,
        __bindgen_anon_1: bindings::v4l2_pix_format_mplane__bindgen_ty_1 {
            ycbcr_enc: bindings::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_DEFAULT as u8,
        },
        quantization: bindings::v4l2_quantization_V4L2_QUANTIZATION_DEFAULT as u8,
        xfer_func: bindings::v4l2_xfer_func_V4L2_XFER_FUNC_DEFAULT as u8,
        ..Default::default()
    }
}

impl VideoDecoderBackend for FfmpegDecoder {
    type Session = FfmpegDecoderSession;

    fn new_session(&mut self, _id: u32) -> IoctlResult<Self::Session> {
        const DEFAULT_CODED_SIZE: (u32, u32) = (320, 240);

        let input_format = self
            .codecs
            .iter()
            .map(|(k, v)| (*k, *v))
            .next()
            .ok_or(libc::ENODEV)?;

        Ok(FfmpegDecoderSession {
            input_format,
            output_format: SUPPORTED_OUTPUT_FORMATS
                .iter()
                .copied()
                .next()
                .unwrap_or(CaptureFormat::NV12),
            context: None,
            coded_size: DEFAULT_CODED_SIZE,
            stream_params: StreamParams {
                min_output_buffers: 4,
                coded_size: DEFAULT_CODED_SIZE,
                visible_rect: Rect {
                    left: 0,
                    top: 0,
                    width: DEFAULT_CODED_SIZE.0,
                    height: DEFAULT_CODED_SIZE.1,
                },
            },
            available_output_frames: Default::default(),
            events: EventQueue::new().map_err(|_| libc::EIO)?,
        })
    }

    fn close_session(&mut self, _session: Self::Session) {}

    fn enum_formats(
        &self,
        _session: &VideoDecoderSession<Self::Session>,
        direction: QueueDirection,
        index: u32,
    ) -> Option<bindings::v4l2_fmtdesc> {
        let pixelformat = match direction {
            QueueDirection::Output => self.codecs.iter().map(|f| *f.0).nth(index as usize)? as u32,
            QueueDirection::Capture => SUPPORTED_OUTPUT_FORMATS
                .iter()
                .copied()
                .nth(index as usize)? as u32,
        };

        Some(bindings::v4l2_fmtdesc {
            index,
            type_: QueueType::from_dir_and_class(direction, QueueClass::VideoMplane) as u32,
            pixelformat,
            ..Default::default()
        })
    }

    fn frame_sizes(&self, pixel_format: u32) -> Option<bindings::v4l2_frmsize_stepwise> {
        // Only return a value for valid formats.
        let _ = CaptureFormat::n(pixel_format)?;

        Some(bindings::v4l2_frmsize_stepwise {
            min_width: 32,
            max_width: 4096,
            step_width: 1,
            min_height: 32,
            max_height: 4096,
            step_height: 1,
        })
    }

    fn adjust_format(
        &self,
        session: &Self::Session,
        direction: QueueDirection,
        format: V4l2MplaneFormat,
    ) -> V4l2MplaneFormat {
        // Apply the requested pixel format or fall back to the current one.
        let pix_mp = match direction {
            QueueDirection::Output => {
                let pixelformat = OutputFormat::n(format.pixelformat().to_u32())
                    .unwrap_or(session.input_format.0);

                pixelformat.into_v4l2_pix_format(session.stream_params.coded_size)
            }
            QueueDirection::Capture => {
                let pixelformat = CaptureFormat::n(format.pixelformat().to_u32())
                    .unwrap_or(session.output_format);

                pixelformat.into_v4l2_pix_format(session.coded_size)
            }
        };

        V4l2MplaneFormat::from((direction, pix_mp))
    }

    fn apply_format(
        &self,
        session: &mut Self::Session,
        direction: QueueDirection,
        format: &V4l2MplaneFormat,
    ) {
        match direction {
            QueueDirection::Output => {
                let format = match OutputFormat::n(format.pixelformat().to_u32()) {
                    Some(format) => format,
                    None => return,
                };
                let avcodec = match self.codecs.get(&format).copied() {
                    Some(codec) => codec,
                    None => return,
                };

                session.input_format = (format, avcodec);
            }
            QueueDirection::Capture => {
                session.output_format = match CaptureFormat::n(format.pixelformat().to_u32()) {
                    Some(format) => format,
                    None => return,
                }
            }
        }
    }
}
