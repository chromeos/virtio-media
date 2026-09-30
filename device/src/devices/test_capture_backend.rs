// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A [`CaptureBackend`] that synthesises frames in software, so
//! [`crate::devices::capture_device::CaptureDevice`] can be exercised (including under
//! `v4l2-compliance`) with no camera and no native dependencies. It deliberately exposes two
//! formats with different size lists to exercise per-format size enumeration.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::devices::capture_device::CaptureBackend;
use crate::devices::capture_device::CaptureCaps;
use crate::devices::capture_device::CapturedFrame;
use crate::devices::capture_device::EventFd;
use crate::devices::capture_device::FormatDesc;
use crate::devices::capture_device::FormatEntry;
use crate::devices::capture_device::StreamInfo;

/// `V4L2_PIX_FMT_GREY`. The V4L2 fourcc macro is little-endian byte packing.
const FOURCC_GREY: u32 = u32::from_le_bytes(*b"GREY");
/// `V4L2_PIX_FMT_YUYV`.
const FOURCC_YUYV: u32 = u32::from_le_bytes(*b"YUYV");

/// Matches a real backend's queue depth, so consumers see the same drop behavior.
const FRAME_QUEUE_DEPTH: usize = 4;

/// Frames per second the generator aims for.
const DEFAULT_FPS: u64 = 30;

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: writing into a valid timespec with a valid clock id.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn geometry(fourcc: u32, width: u32, height: u32) -> StreamInfo {
    let (stride, frame_size) = match fourcc {
        FOURCC_YUYV => (
            width.saturating_mul(2),
            width.saturating_mul(height).saturating_mul(2),
        ),
        // GREY and anything unexpected.
        _ => (width, width.saturating_mul(height)),
    };
    StreamInfo {
        width,
        height,
        frame_size,
        stride,
    }
}

/// Fill `buf` with a frame that changes visibly from one `sequence` to the next, so repeated
/// delivery of one frame is distinguishable from delivery of successive frames.
fn draw(buf: &mut [u8], fourcc: u32, width: u32, height: u32, sequence: u32) {
    let w = width as usize;
    let h = height as usize;
    let phase = (sequence as usize).wrapping_mul(4);

    match fourcc {
        FOURCC_YUYV => {
            // Packed 4:2:2, two pixels per four bytes: Y0 Cb Y1 Cr.
            for y in 0..h {
                let row = y * w * 2;
                for x in (0..w).step_by(2) {
                    let bar = ((x + phase) * 8 / w.max(1)) % 8;
                    // Rough colour bars: luma descends across the bars, chroma alternates.
                    let luma = (235 - bar * 26) as u8;
                    let cb = if bar.is_multiple_of(2) { 90 } else { 200 } as u8;
                    let cr = if bar.is_multiple_of(3) { 200 } else { 90 } as u8;
                    let i = row + x * 2;
                    if i + 3 < buf.len() {
                        buf[i] = luma;
                        buf[i + 1] = cb;
                        buf[i + 2] = luma;
                        buf[i + 3] = cr;
                    }
                }
            }
        }
        _ => {
            // 8-bit greyscale: a diagonal gradient that slides one bar per frame.
            for y in 0..h {
                let row = y * w;
                for x in 0..w {
                    let i = row + x;
                    if i < buf.len() {
                        buf[i] = ((x + y + phase) & 0xff) as u8;
                    }
                }
            }
        }
    }
}

/// Configuration knobs, mainly so tests can run the generator faster than real time.
#[derive(Debug, Clone, Copy)]
pub struct TestBackendConfig {
    pub fps: u64,
}

impl Default for TestBackendConfig {
    fn default() -> Self {
        Self { fps: DEFAULT_FPS }
    }
}

/// State shared with the generator thread.
struct Generator {
    handle: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

pub struct TestCaptureBackend {
    caps: CaptureCaps,
    config: TestBackendConfig,
    current: FormatEntry,
    info: StreamInfo,
    frame_rx: Receiver<CapturedFrame>,
    frame_tx: SyncSender<CapturedFrame>,
    generator: Option<Generator>,
}

impl TestCaptureBackend {
    pub fn new(config: TestBackendConfig) -> Self {
        // Two formats with deliberately different size lists.
        let grey_sizes = [(320u32, 240u32), (640, 480)];
        let yuyv_sizes = [(320u32, 240u32), (640, 480), (1280, 720)];

        let mut entries = Vec::new();
        for (w, h) in grey_sizes {
            entries.push(FormatEntry {
                fourcc: FOURCC_GREY,
                width: w,
                height: h,
            });
        }
        for (w, h) in yuyv_sizes {
            entries.push(FormatEntry {
                fourcc: FOURCC_YUYV,
                width: w,
                height: h,
            });
        }

        let default = FormatEntry {
            fourcc: FOURCC_YUYV,
            width: 640,
            height: 480,
        };

        let caps = CaptureCaps {
            card: "test-pattern".to_string(),
            formats: vec![
                FormatDesc {
                    fourcc: FOURCC_GREY,
                    compressed: false,
                },
                FormatDesc {
                    fourcc: FOURCC_YUYV,
                    compressed: false,
                },
            ],
            entries,
            default: Some(default),
        };

        let (frame_tx, frame_rx) = sync_channel(FRAME_QUEUE_DEPTH);

        Self {
            caps,
            config,
            current: default,
            info: geometry(default.fourcc, default.width, default.height),
            frame_rx,
            frame_tx,
            generator: None,
        }
    }

    fn halt(&mut self) {
        if let Some(gen) = self.generator.take() {
            gen.stop.store(true, Ordering::Relaxed);
            let _ = gen.handle.join();
        }
        // Drop anything queued so it cannot surface in the next stream.
        while self.frame_rx.try_recv().is_ok() {}
    }
}

impl Default for TestCaptureBackend {
    fn default() -> Self {
        Self::new(TestBackendConfig::default())
    }
}

impl Drop for TestCaptureBackend {
    fn drop(&mut self) {
        self.halt();
    }
}

impl CaptureBackend for TestCaptureBackend {
    fn caps(&self) -> &CaptureCaps {
        &self.caps
    }

    fn configure(&mut self, fourcc: u32, width: u32, height: u32) -> Result<StreamInfo, i32> {
        if self.generator.is_some() {
            return Err(libc::EBUSY);
        }
        if !self.caps.supports(fourcc, width, height) {
            return Err(libc::EINVAL);
        }
        self.current = FormatEntry {
            fourcc,
            width,
            height,
        };
        self.info = geometry(fourcc, width, height);
        Ok(self.info)
    }

    fn start(&mut self, notify: EventFd) -> Result<(), i32> {
        if self.generator.is_some() {
            return Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let tx = self.frame_tx.clone();
        let entry = self.current;
        let frame_size = self.info.frame_size as usize;
        let interval = Duration::from_nanos(1_000_000_000 / self.config.fps.max(1));

        let handle = std::thread::Builder::new()
            .name("virtio-media-testpat".into())
            .spawn(move || {
                // Sequence restarts at zero on each stream, which is what V4L2 expects.
                let mut sequence: u32 = 0;
                while !thread_stop.load(Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    if thread_stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let mut data = vec![0u8; frame_size];
                    draw(&mut data, entry.fourcc, entry.width, entry.height, sequence);

                    let frame = CapturedFrame {
                        bytes_used: frame_size as u32,
                        sequence,
                        timestamp_ns: monotonic_ns(),
                        data,
                    };
                    sequence = sequence.wrapping_add(1);

                    match tx.try_send(frame) {
                        Ok(()) => {
                            if let Err(e) = notify.signal() {
                                log::error!("test backend eventfd signal: {e}");
                                break;
                            }
                        }
                        // The consumer is behind. Dropping the newest frame is what a camera does.
                        Err(TrySendError::Full(_)) => {
                            log::debug!("test backend frame queue full, dropping frame")
                        }
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
            })
            .map_err(|e| {
                log::error!("spawning test pattern generator: {e}");
                libc::EIO
            })?;

        self.generator = Some(Generator { handle, stop });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), i32> {
        self.halt();
        Ok(())
    }

    fn try_next_frame(&mut self) -> Option<CapturedFrame> {
        self.frame_rx.try_recv().ok()
    }

    fn frame_interval_ns(&self) -> Option<u64> {
        // This backend genuinely controls its own rate, so it can report one honestly even before
        // streaming has begun.
        Some(1_000_000_000 / self.config.fps.max(1))
    }

    fn estimate(&self, fourcc: u32, width: u32, height: u32) -> StreamInfo {
        geometry(fourcc, width, height)
    }
}
