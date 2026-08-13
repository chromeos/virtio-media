// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! libcamera-backed [`CaptureBackend`] for [`virtio_media::devices::capture_device::CaptureDevice`].
//!
//! All libcamera handles live on a dedicated worker thread: they form a borrow chain rooted in
//! `CameraManager`, so holding them in a struct would be self-referential. Device commands and
//! libcamera completions arrive on a single channel as [`WorkerEvent`], so the worker is one
//! blocking `recv()` loop.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use libcamera::camera::ActiveCamera;
use libcamera::camera::CameraConfiguration;
use libcamera::camera::CameraConfigurationStatus;
use libcamera::camera_manager::CameraManager;
use libcamera::framebuffer::AsFrameBuffer;
use libcamera::framebuffer::FrameMetadataStatus;
use libcamera::framebuffer_allocator::FrameBuffer;
use libcamera::framebuffer_allocator::FrameBufferAllocator;
use libcamera::framebuffer_map::MemoryMappedFrameBuffer;
use libcamera::geometry::Size;
use libcamera::logging::LoggingLevel;
use libcamera::pixel_format::PixelFormat;
use libcamera::properties;
use libcamera::request::Request;
use libcamera::request::ReuseFlag;
use libcamera::stream::Stream;
use libcamera::stream::StreamRole;

use virtio_media::devices::capture_device::default_frame_interval_ns;
use virtio_media::devices::capture_device::CaptureBackend;
use virtio_media::devices::capture_device::CaptureCaps;
use virtio_media::devices::capture_device::CapturedFrame;
use virtio_media::devices::capture_device::EventFd;
use virtio_media::devices::capture_device::FormatDesc;
use virtio_media::devices::capture_device::FormatEntry;
use virtio_media::devices::capture_device::StreamInfo;

/// How long a stop waits for libcamera to hand back cancelled requests before giving up.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Depth of the frame queue between the worker and the device.
///
/// Must be bounded: the device only consumes frames when the VMM polls it, so an unbounded queue
/// grows without limit whenever the guest stops dequeuing. Dropping the newest frame when full is
/// correct camera behaviour.
const FRAME_QUEUE_DEPTH: usize = 4;

/// Smoothing factor for the measured frame interval, as a right shift. 1/8 settles within a second
/// or so at typical rates while ignoring single-frame jitter.
const INTERVAL_EMA_SHIFT: u32 = 3;

/// Intervals outside this range are treated as noise rather than measurements: the gap across a
/// stop/start boundary, or a stall while the guest was not dequeuing.
const MIN_PLAUSIBLE_INTERVAL_NS: u64 = 1_000_000;
const MAX_PLAUSIBLE_INTERVAL_NS: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------------------------
// Format mapping
// ---------------------------------------------------------------------------------------------

/// MJPEG has no drm-fourcc entry, so it is built from the raw identifier. Its bytes happen to match
/// V4L2's, as do YUYV's; R8 maps to V4L2's GREY under a different name.
const PF_MJPEG: PixelFormat = PixelFormat::new(u32::from_le_bytes(*b"MJPG"), 0);
const PF_YUYV: PixelFormat = PixelFormat::new(u32::from_le_bytes(*b"YUYV"), 0);
const PF_R8: PixelFormat = PixelFormat::new(u32::from_le_bytes(*b"R8  "), 0);

const FOURCC_MJPG: u32 = u32::from_le_bytes(*b"MJPG");
const FOURCC_YUYV: u32 = u32::from_le_bytes(*b"YUYV");
const FOURCC_GREY: u32 = u32::from_le_bytes(*b"GREY");

fn libcamera_to_v4l2(pf: PixelFormat) -> Option<(u32, bool)> {
    let f = pf.fourcc();
    if f == PF_MJPEG.fourcc() {
        Some((FOURCC_MJPG, true))
    } else if f == PF_YUYV.fourcc() {
        Some((FOURCC_YUYV, false))
    } else if f == PF_R8.fourcc() {
        Some((FOURCC_GREY, false))
    } else {
        None
    }
}

fn v4l2_to_libcamera(fourcc: u32) -> Option<PixelFormat> {
    match fourcc {
        FOURCC_MJPG => Some(PF_MJPEG),
        FOURCC_YUYV => Some(PF_YUYV),
        FOURCC_GREY => Some(PF_R8),
        _ => None,
    }
}

/// Rough allocation size, used only for `TRY_FMT`, which must not touch the hardware.
///
/// Measured against libcamera: MJPEG 1280x720 allocates two bytes per pixel, GREY 640x360 exactly
/// one. There is no formula that holds in general, which is why the real value always comes from
/// `StreamConfiguration::get_frame_size()` after configuring.
fn estimate_geometry(fourcc: u32, width: u32, height: u32) -> StreamInfo {
    let pixels = width.saturating_mul(height);
    let (stride, frame_size) = match fourcc {
        FOURCC_MJPG => (0, pixels.saturating_mul(2)),
        FOURCC_YUYV => (width.saturating_mul(2), pixels.saturating_mul(2)),
        FOURCC_GREY => (width, pixels),
        _ => (0, pixels.saturating_mul(2)),
    };
    StreamInfo {
        width,
        height,
        frame_size,
        stride,
    }
}

// ---------------------------------------------------------------------------------------------
// Worker protocol
// ---------------------------------------------------------------------------------------------

enum CameraCommand {
    /// Reconfigure. Synchronous: the reply carries the geometry the device needs to size buffers.
    Configure {
        fourcc: u32,
        width: u32,
        height: u32,
        reply: Sender<Result<StreamInfo, i32>>,
    },
    Start {
        notify: EventFd,
    },
    /// Synchronous, per STREAMOFF semantics: no frame from the old stream may surface after it
    /// returns.
    Stop {
        reply: Sender<()>,
    },
    Shutdown,
}

enum WorkerEvent {
    Cmd(CameraCommand),
    Completed(Request),
}

/// libcamera-backed capture backend.
///
/// Holds no libcamera types, only channel endpoints, so it is freely storable, `Send`, and
/// `Sync`. The frame receiver is wrapped in a `Mutex` because `mpsc::Receiver` is not `Sync`;
/// only the device thread receives frames, so the lock is uncontended.
pub struct LibcameraBackend {
    cmd_tx: Sender<WorkerEvent>,
    frame_rx: Mutex<Receiver<CapturedFrame>>,
    caps: CaptureCaps,
    /// Exponential moving average of the observed frame interval, in nanoseconds. Written by the
    /// worker, read by the device thread through `frame_interval_ns`.
    interval_ns: Arc<AtomicU64>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl LibcameraBackend {
    /// Spawn the worker for the camera at `camera_index` and block until it reports capabilities.
    pub fn new(camera_index: usize) -> anyhow::Result<Self> {
        let (cmd_tx, event_rx) = channel::<WorkerEvent>();
        let (frame_tx, frame_rx) = sync_channel::<CapturedFrame>(FRAME_QUEUE_DEPTH);
        let (caps_tx, caps_rx) = channel::<Result<CaptureCaps, String>>();

        let interval_ns = Arc::new(AtomicU64::new(0));
        let thread_interval = Arc::clone(&interval_ns);
        let completion_tx = cmd_tx.clone();

        let join = std::thread::Builder::new()
            .name("virtio-media-libcamera".into())
            .spawn(move || {
                if let Err(e) = worker_main(
                    camera_index,
                    event_rx,
                    completion_tx,
                    frame_tx,
                    caps_tx.clone(),
                    thread_interval,
                ) {
                    log::error!("camera worker exiting: {e}");
                    // Unblock new() if we failed before reporting capabilities.
                    let _ = caps_tx.send(Err(e));
                }
            })?;

        let caps = caps_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| anyhow::anyhow!("camera worker did not report capabilities"))?
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(Self {
            cmd_tx,
            frame_rx: Mutex::new(frame_rx),
            caps,
            interval_ns,
            join: Some(join),
        })
    }

    fn send(&self, cmd: CameraCommand) -> Result<(), i32> {
        self.cmd_tx
            .send(WorkerEvent::Cmd(cmd))
            .map_err(|_| libc::EIO)
    }
}

impl Drop for LibcameraBackend {
    fn drop(&mut self) {
        let _ = self.send(CameraCommand::Shutdown);
        // The worker can block on a full frame queue, so keep draining while it observes Shutdown.
        while self.frame_rx.lock().unwrap().try_recv().is_ok() {}
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl CaptureBackend for LibcameraBackend {
    fn caps(&self) -> &CaptureCaps {
        &self.caps
    }

    fn configure(&mut self, fourcc: u32, width: u32, height: u32) -> Result<StreamInfo, i32> {
        let (reply, reply_rx) = channel();
        self.send(CameraCommand::Configure {
            fourcc,
            width,
            height,
            reply,
        })?;
        reply_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| libc::EIO)?
    }

    fn start(&mut self, notify: EventFd) -> Result<(), i32> {
        self.send(CameraCommand::Start { notify })
    }

    fn stop(&mut self) -> Result<(), i32> {
        let (reply, reply_rx) = channel();
        self.send(CameraCommand::Stop { reply })?;
        // A disconnected reply means the worker is gone; the frames are moot either way.
        let _ = reply_rx.recv_timeout(Duration::from_secs(2));
        while self.frame_rx.lock().unwrap().try_recv().is_ok() {}
        Ok(())
    }

    fn try_next_frame(&mut self) -> Option<CapturedFrame> {
        self.frame_rx.lock().unwrap().try_recv().ok()
    }

    fn frame_interval_ns(&self) -> Option<u64> {
        // libcamera's UVC pipeline handler exposes no FrameDurationLimits and the true rate varies
        // with auto-exposure, so we report a measured interval: V4L2 defines timeperframe as the
        // current frame period, and omitting it makes applications guess (ffmpeg assumes 10 fps).
        // Before any frames have been seen, report a conventional 30 fps.
        let measured = self.interval_ns.load(Ordering::Relaxed);
        Some(if measured == 0 {
            default_frame_interval_ns()
        } else {
            measured
        })
    }

    fn estimate(&self, fourcc: u32, width: u32, height: u32) -> StreamInfo {
        estimate_geometry(fourcc, width, height)
    }
}

// ---------------------------------------------------------------------------------------------
// Worker internals
// ---------------------------------------------------------------------------------------------

/// Owned state for one configured stream. None of these borrow the camera.
struct StreamState {
    /// Kept alive because `Stream` points into it.
    _config: CameraConfiguration,
    stream: Stream,
    /// Holds the allocator alive via the `Arc` inside each `FrameBuffer`.
    _alloc: FrameBufferAllocator,
    /// Requests not currently owned by libcamera.
    idle: Vec<Request>,
    /// Requests handed to libcamera and not yet returned.
    outstanding: usize,
    /// Incremented on every reconfiguration and encoded in each request's cookie, so completions
    /// from a previous stream (which reference dropped buffers) can be discarded.
    generation: u64,
    info: StreamInfo,
}

fn worker_main(
    camera_index: usize,
    event_rx: Receiver<WorkerEvent>,
    completion_tx: Sender<WorkerEvent>,
    frame_tx: SyncSender<CapturedFrame>,
    caps_tx: Sender<Result<CaptureCaps, String>>,
    interval_ns: Arc<AtomicU64>,
) -> Result<(), String> {
    let mgr = CameraManager::new().map_err(|e| format!("camera manager: {e}"))?;
    mgr.log_set_level("Camera", LoggingLevel::Error);

    let cameras = mgr.cameras();
    let cam = cameras
        .get(camera_index)
        .ok_or_else(|| format!("no camera at index {camera_index}"))?;

    // generate_configuration lives on Camera, not ActiveCamera, so the snapshot needs no exclusive
    // access and can happen before acquire().
    let caps = snapshot_caps(&cam)?;

    // Acquire before reporting capabilities, so a failed acquire is a construction error rather
    // than an opaque EIO on the first ioctl.
    let mut cam = cam.acquire().map_err(|e| format!("acquire: {e}"))?;

    caps_tx
        .send(Ok(caps))
        .map_err(|_| "caps receiver gone".to_string())?;

    // Completions are funnelled into the same channel as commands so the loop has one wait point.
    // This closure runs on libcamera's thread.
    cam.on_request_completed(move |req| {
        let _ = completion_tx.send(WorkerEvent::Completed(req));
    });

    let mut state: Option<StreamState> = None;
    let mut streaming = false;
    let mut notify: Option<EventFd> = None;
    // Set if a Shutdown is seen while draining inside stop_stream, where it cannot be acted on.
    let mut shutdown = false;
    let mut generation: u64 = 0;
    let mut last_timestamp: Option<u64> = None;

    while let Ok(event) = event_rx.recv() {
        match event {
            WorkerEvent::Cmd(CameraCommand::Configure {
                fourcc,
                width,
                height,
                reply,
            }) => {
                if streaming {
                    shutdown |= stop_stream(&mut cam, &mut state, &event_rx).unwrap_or(false);
                    streaming = false;
                }
                // Drop the old configuration before reallocating: alloc() refuses a stream that
                // already has buffers, and the old requests hold those buffers alive.
                state = None;
                last_timestamp = None;

                generation = generation.wrapping_add(1);
                match configure_stream(&mut cam, fourcc, width, height, generation) {
                    Ok(new_state) => {
                        let info = new_state.info;
                        state = Some(new_state);
                        let _ = reply.send(Ok(info));
                    }
                    Err(e) => {
                        log::error!("configure failed: {e}");
                        let _ = reply.send(Err(libc::EINVAL));
                    }
                }
            }

            WorkerEvent::Cmd(CameraCommand::Start { notify: fd }) => {
                let Some(st) = state.as_mut() else {
                    log::error!("Start without a configured stream");
                    continue;
                };
                if streaming {
                    continue;
                }
                if let Err(e) = cam.start(None) {
                    log::error!("camera start: {e}");
                    continue;
                }
                notify = Some(fd);
                last_timestamp = None;

                // Take ownership of the pool so a failed request can be returned without holding a
                // borrow across the loop. Draining in place would also discard the untried
                // remainder on `break`, shrinking the pool on every failed Start.
                let mut pending = std::mem::take(&mut st.idle).into_iter();
                while let Some(req) = pending.next() {
                    match cam.queue_request(req) {
                        Ok(()) => st.outstanding += 1,
                        Err((req, e)) => {
                            log::error!("queue_request: {e}");
                            st.idle.push(req);
                            st.idle.extend(pending);
                            break;
                        }
                    }
                }
                streaming = true;
            }

            WorkerEvent::Cmd(CameraCommand::Stop { reply }) => {
                if streaming {
                    shutdown |= stop_stream(&mut cam, &mut state, &event_rx).unwrap_or(false);
                    streaming = false;
                    notify = None;
                    last_timestamp = None;
                }
                // Always answer, including a redundant Stop, or the caller waits out its timeout.
                let _ = reply.send(());
            }

            WorkerEvent::Cmd(CameraCommand::Shutdown) => {
                if streaming {
                    let _ = stop_stream(&mut cam, &mut state, &event_rx);
                }
                break;
            }

            WorkerEvent::Completed(mut req) => {
                let cookie_generation = req.cookie() >> 32;
                let Some(st) = state.as_mut() else {
                    // Stream was torn down; let the request drop.
                    continue;
                };
                if cookie_generation != st.generation {
                    log::debug!(
                        "discarding request from generation {cookie_generation}, current is {}",
                        st.generation
                    );
                    continue;
                }
                st.outstanding = st.outstanding.saturating_sub(1);

                if !streaming {
                    // Cancelled after stop(). Park it for the next Start.
                    req.reuse(ReuseFlag::REUSE_BUFFERS);
                    st.idle.push(req);
                    continue;
                }

                match extract_frame(&req, &st.stream) {
                    Ok(Some(frame)) => {
                        update_interval(&interval_ns, &mut last_timestamp, frame.timestamp_ns);
                        match frame_tx.try_send(frame) {
                            Ok(()) => {
                                if let Some(fd) = notify.as_ref() {
                                    if let Err(e) = fd.signal() {
                                        log::error!("eventfd signal: {e}");
                                    }
                                }
                            }
                            // The consumer is behind. Dropping the newest frame is what a camera
                            // does; blocking would stall the recycle and starve libcamera.
                            Err(TrySendError::Full(_)) => {
                                log::debug!("frame queue full, dropping frame");
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                log::warn!("frame consumer gone, stopping");
                                let _ = cam.stop();
                                break;
                            }
                        }
                    }
                    // Non-Success frames are dropped rather than forwarded.
                    Ok(None) => {}
                    Err(e) => log::error!("frame extraction: {e}"),
                }

                req.reuse(ReuseFlag::REUSE_BUFFERS);
                match cam.queue_request(req) {
                    Ok(()) => st.outstanding += 1,
                    Err((req, e)) => {
                        log::error!("requeue: {e}");
                        st.idle.push(req);
                    }
                }
            }
        }

        // A Shutdown observed during a drain is acted on here. Streaming was already stopped by the
        // stop_stream call that saw it.
        if shutdown {
            break;
        }
    }

    Ok(())
}

/// Fold a frame timestamp into the interval EMA.
fn update_interval(interval_ns: &AtomicU64, last: &mut Option<u64>, timestamp_ns: u64) {
    if let Some(prev) = *last {
        let sample = timestamp_ns.saturating_sub(prev);
        if (MIN_PLAUSIBLE_INTERVAL_NS..=MAX_PLAUSIBLE_INTERVAL_NS).contains(&sample) {
            let current = interval_ns.load(Ordering::Relaxed);
            let next = if current == 0 {
                sample
            } else {
                current - (current >> INTERVAL_EMA_SHIFT) + (sample >> INTERVAL_EMA_SHIFT)
            };
            interval_ns.store(next, Ordering::Relaxed);
        }
    }
    *last = Some(timestamp_ns);
}

fn snapshot_caps(cam: &libcamera::camera::Camera<'_>) -> Result<CaptureCaps, String> {
    let card = cam
        .properties()
        .get::<properties::Model>()
        .map(|m| (*m).to_string())
        .unwrap_or_else(|_| "libcamera".to_string());

    let cfg = cam
        .generate_configuration(&[StreamRole::VideoRecording])
        .ok_or("could not generate configuration")?;
    let stream_cfg = cfg.get(0).ok_or("no stream in configuration")?;
    let formats = stream_cfg.formats();
    let pixel_formats = formats.pixel_formats();

    let mut caps = CaptureCaps {
        card,
        ..Default::default()
    };

    // The unmodified configuration is what libcamera would pick on its own, and is the right default
    // for a freshly opened device. Falling back to the first or last enumerated entry gives
    // something arbitrary: on a camera enumerating MJPEG before YUYV, the last entry is a small YUYV
    // mode while libcamera would have chosen MJPEG at full resolution.
    if let Some((fourcc, _)) = libcamera_to_v4l2(stream_cfg.get_pixel_format()) {
        let size = stream_cfg.get_size();
        caps.default = Some(FormatEntry {
            fourcc,
            width: size.width,
            height: size.height,
        });
    }

    for pf in &*pixel_formats {
        let Some((fourcc, compressed)) = libcamera_to_v4l2(pf) else {
            log::debug!("skipping unmapped libcamera format {pf}");
            continue;
        };
        caps.formats.push(FormatDesc { fourcc, compressed });
        // Sizes are per-format, never a global list.
        for size in formats.sizes(pf) {
            caps.entries.push(FormatEntry {
                fourcc,
                width: size.width,
                height: size.height,
            });
        }
    }

    if caps.entries.is_empty() {
        return Err("camera exposes no formats mappable to V4L2".into());
    }
    Ok(caps)
}

fn configure_stream(
    cam: &mut ActiveCamera<'_>,
    fourcc: u32,
    width: u32,
    height: u32,
    generation: u64,
) -> Result<StreamState, String> {
    let pixel_format = v4l2_to_libcamera(fourcc).ok_or("unsupported fourcc")?;

    let mut config = cam
        .generate_configuration(&[StreamRole::VideoRecording])
        .ok_or("could not generate configuration")?;

    if let Some(mut cfg) = config.get_mut(0) {
        cfg.set_pixel_format(pixel_format);
        cfg.set_size(Size::new(width, height));
    }

    // validate() adjusts rather than rejecting, matching V4L2's S_FMT semantics.
    match config.validate() {
        CameraConfigurationStatus::Valid => {}
        CameraConfigurationStatus::Adjusted => {
            log::info!("libcamera adjusted the requested configuration");
        }
        CameraConfigurationStatus::Invalid => return Err("configuration invalid".into()),
    }

    cam.configure(&mut config)
        .map_err(|e| format!("configure: {e}"))?;

    let (stream, info) = {
        let cfg = config.get(0).ok_or("no stream after configure")?;
        let size = cfg.get_size();
        let info = StreamInfo {
            width: size.width,
            height: size.height,
            // Authoritative; not computable from the format. See the crate README.
            frame_size: cfg.get_frame_size(),
            stride: cfg.get_stride(),
        };
        (cfg.stream().ok_or("no stream handle")?, info)
    };

    let mut alloc = FrameBufferAllocator::new(cam);
    let buffers = alloc
        .alloc(&stream)
        .map_err(|e| format!("alloc buffers: {e}"))?;

    let mut idle = Vec::with_capacity(buffers.len());
    for (i, buf) in buffers.into_iter().enumerate() {
        let mapped = MemoryMappedFrameBuffer::new(buf).map_err(|e| format!("map buffer: {e:?}"))?;
        // Generation in the high 32 bits, buffer index in the low 32, so a completion can be matched
        // against the configuration that created it.
        let cookie = (generation << 32) | (i as u64 & 0xffff_ffff);
        let mut req = cam
            .create_request(Some(cookie))
            .ok_or("create_request failed")?;
        req.add_buffer(&stream, mapped)
            .map_err(|e| format!("add_buffer: {e}"))?;
        idle.push(req);
    }

    Ok(StreamState {
        _config: config,
        stream,
        _alloc: alloc,
        idle,
        outstanding: 0,
        generation,
        info,
    })
}

/// Stop the camera and drain the cancelled requests libcamera hands back, reclaiming them for the
/// next start.
///
/// Returns whether a `Shutdown` was observed while draining; swallowing one would leave `Drop`'s
/// join waiting on a loop that never saw it.
fn stop_stream(
    cam: &mut ActiveCamera<'_>,
    state: &mut Option<StreamState>,
    event_rx: &Receiver<WorkerEvent>,
) -> Result<bool, String> {
    cam.stop().map_err(|e| format!("stop: {e}"))?;

    let Some(st) = state.as_mut() else {
        return Ok(false);
    };

    let mut saw_shutdown = false;
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    while st.outstanding > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            log::warn!("{} requests never returned after stop", st.outstanding);
            break;
        }
        match event_rx.recv_timeout(remaining) {
            Ok(WorkerEvent::Completed(mut req)) => {
                if req.cookie() >> 32 != st.generation {
                    // Stale request from an earlier configuration; it was never counted in
                    // `outstanding`, so drop it without decrementing.
                    continue;
                }
                st.outstanding -= 1;
                req.reuse(ReuseFlag::REUSE_BUFFERS);
                st.idle.push(req);
            }
            Ok(WorkerEvent::Cmd(CameraCommand::Shutdown)) => saw_shutdown = true,
            // Answer a racing Stop rather than dropping its reply sender, so the caller does not sit
            // out its timeout.
            Ok(WorkerEvent::Cmd(CameraCommand::Stop { reply })) => {
                let _ = reply.send(());
            }
            Ok(WorkerEvent::Cmd(_)) => {}
            Err(_) => break,
        }
    }

    // Anything still unaccounted for was cancelled and will either never arrive or arrive with a
    // stale generation, so clear the count. Leaving it non-zero would make every later stop wait out
    // the full drain timeout.
    st.outstanding = 0;
    Ok(saw_shutdown)
}

/// Pull frame data and metadata out of a completed request.
///
/// Returns `Ok(None)` for frames that must not reach the guest: UVC cameras emit junk flagged
/// `Startup` or `Error` for the first few requests after `start()`.
fn extract_frame(req: &Request, stream: &Stream) -> Result<Option<CapturedFrame>, String> {
    let fb: &MemoryMappedFrameBuffer<FrameBuffer> =
        req.buffer(stream).ok_or("request has no buffer")?;
    let meta = fb.metadata().ok_or("no frame metadata")?;

    match meta.status() {
        FrameMetadataStatus::Success => {}
        other => {
            log::debug!("dropping frame with status {other:?}");
            return Ok(None);
        }
    }

    let plane_meta = meta.planes().get(0).ok_or("no plane metadata")?;
    let bytes_used = plane_meta.bytes_used;

    let planes = fb.data();
    let plane = planes.first().ok_or("no data plane")?;
    let end = (bytes_used as usize).min(plane.len());

    Ok(Some(CapturedFrame {
        // TODO: this allocates per frame. Fine for ~80 KB MJPEG at 10-15 fps; worth revisiting for
        // 1280x720 YUYV, which is 1.8 MB per frame. The alternative is sharing the session's memfds
        // with the worker so it can write into them directly.
        data: plane[..end].to_vec(),
        bytes_used,
        sequence: meta.sequence(),
        timestamp_ns: meta.timestamp(),
    }))
}
