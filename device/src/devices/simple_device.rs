// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Simple example virtio-media CAPTURE device with no dependency.
//!
//! This module illustrates how to write a device for virtio-media. It exposes a capture device
//! that generates a RGB pattern on the buffers queued by the guest.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::BufWriter;
use std::io::Result as IoResult;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::rc::Rc;

use memfd::Memfd;
use v4l2r::bindings;
use v4l2r::bindings::v4l2_fmtdesc;
use v4l2r::bindings::v4l2_format;
use v4l2r::bindings::v4l2_pix_format;
use v4l2r::bindings::v4l2_requestbuffers;
use v4l2r::ioctl::BufferCapabilities;
use v4l2r::ioctl::BufferFlags;
use v4l2r::ioctl::QueryBuf;
use v4l2r::ioctl::V4l2Buffer;
use v4l2r::memory::MemoryType;
use v4l2r::PixelFormat;
use v4l2r::QueueType;

use crate::ioctl::virtio_media_dispatch_ioctl;
use crate::ioctl::IoctlResult;
use crate::ioctl::VirtioMediaIoctlHandler;
use crate::protocol::DequeueBufferEvent;
use crate::protocol::MmapResp;
use crate::protocol::MunmapResp;
use crate::protocol::SgEntry;
use crate::protocol::V4l2Event;
use crate::protocol::V4l2Ioctl;
use crate::protocol::VIRTIO_MEDIA_MMAP_FLAG_RW;
use crate::VirtioMediaDevice;
use crate::VirtioMediaEventQueue;
use crate::VirtioMediaHostMemoryMapper;
use crate::WriteDescriptorChain;

/// Current status of a buffer.
#[derive(Debug, PartialEq, Eq)]
enum BufferState {
    /// Buffer has just been created (or streamed off) and not been used yet.
    New,
    /// Buffer has been QBUF'd by the driver but not yet processed.
    Incoming,
    /// Buffer has been processed and is ready for dequeue.
    Outgoing {
        /// Sequence of the generated frame.
        sequence: u32,
    },
}

/// Information about a MMAP buffer being mapped into the guest.
struct BufferMmap {
    /// Address the buffer has been mapped to inside the guest.
    guest_addr: u64,
    /// Number of times mmap has been performed for this buffer. The mapping remains alive until
    /// this reaches zero.
    num_mappings: usize,
}

/// Information about a single buffer.
struct Buffer {
    /// Current state of the buffer.
    state: BufferState,
    /// Queue of the buffer.
    queue: QueueType,
    /// Index of the buffer.
    index: u32,
    /// Backing storage for the buffer.
    fd: Memfd,
    /// Size in bytes of the buffer.
    size: u64,
    /// Offset that can be used to map the buffer.
    offset: u64,
    /// Set to (guest address, num of mappings) if the buffer is of MMAP type and is currently
    /// mapped into the guest address space.
    ///
    /// We use a shared reference here because `munmap` might need to reset this to `None`.
    mmap: Rc<RefCell<Option<BufferMmap>>>,
}

impl Buffer {
    /// Generate a `V4l2Buffer` from the current information in this buffer. Useful as a reply to
    /// the `QUERYBUF` and `QBUF` commands, and to `DQBUF` events.
    fn to_v4l2_buffer(&self) -> V4l2Buffer {
        // TODO add V4l2Buffer builder type.
        let buffer = bindings::v4l2_buffer {
            index: self.index,
            type_: self.queue as u32,
            // TODO if the buffer is dequeuable, fill this.
            bytesused: if let BufferState::Outgoing { .. } = &self.state {
                BUFFER_SIZE
            } else {
                0
            },
            flags: (match self.state {
                BufferState::New => BufferFlags::empty(),
                BufferState::Incoming => BufferFlags::QUEUED,
                BufferState::Outgoing { .. } => BufferFlags::empty(),
            } | if self.mmap.borrow().is_some() {
                BufferFlags::MAPPED
            } else {
                BufferFlags::empty()
            } | BufferFlags::TIMESTAMP_MONOTONIC)
                .bits(),
            field: bindings::v4l2_field_V4L2_FIELD_NONE,
            timestamp: if let BufferState::Outgoing { sequence } = &self.state {
                bindings::timeval {
                    tv_sec: (*sequence + 1) as i64 / 1000,
                    tv_usec: (*sequence + 1) as i64 % 1000,
                }
            } else {
                bindings::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                }
            },
            timecode: Default::default(),
            sequence: if let BufferState::Outgoing { sequence } = &self.state {
                *sequence
            } else {
                0
            },
            memory: MemoryType::Mmap as u32,
            m: bindings::v4l2_buffer__bindgen_ty_1 {
                offset: self.offset as u32,
            },
            length: self.size as u32,
            ..unsafe { std::mem::zeroed() }
        };

        V4l2Buffer::try_from_v4l2_buffer(buffer, None).unwrap()
    }
}

/// Session data of [`SimpleCaptureDevice`].
pub struct SimpleCaptureDeviceSession {
    /// Id of the session.
    id: u32,
    /// Current iteration of the pattern generation cycle.
    iteration: u64,
    /// Buffers currently allocated for this session.
    buffers: Vec<Buffer>,
    /// FIFO of queued buffers awaiting processing.
    queued_buffers: VecDeque<usize>,
    /// Is the session currently streaming?
    streaming: bool,
}

impl SimpleCaptureDeviceSession {
    /// Generate the data pattern on all queued buffers and send the corresponding
    /// [`DequeueBufferEvent`] to the driver.
    fn process_queued_buffers<Q: VirtioMediaEventQueue>(
        &mut self,
        evt_queue: &mut Q,
    ) -> IoctlResult<()> {
        while let Some(buf_id) = self.queued_buffers.pop_front() {
            let buffer = self.buffers.get_mut(buf_id).ok_or(libc::EIO)?;
            let sequence = self.iteration as u32;

            buffer
                .fd
                .as_file()
                .seek(SeekFrom::Start(0))
                .map_err(|_| libc::EIO)?;
            let mut writer = BufWriter::new(buffer.fd.as_file());
            let color = [
                0xffu8 * (sequence as u8 % 2),
                0x55u8 * (sequence as u8 % 3),
                0x10u8 * (sequence as u8 % 16),
            ];
            for _ in 0..(WIDTH * HEIGHT) {
                let _ = writer.write(&color).map_err(|_| libc::EIO)?;
            }

            buffer.state = BufferState::Outgoing { sequence };
            self.iteration += 1;

            let v4l2_buffer = buffer.to_v4l2_buffer();

            evt_queue.send_event(V4l2Event::DequeueBuffer(DequeueBufferEvent::new(
                self.id,
                v4l2_buffer,
            )));
        }

        Ok(())
    }
}

/// A simplistic video capture device, used to demonstrate how device code can be written, or for
/// testing VMMs and guests without dedicated hardware support.
///
/// This device supports a single pixel format (`RGB3`) and a single resolution, and generates
/// frames of varying uniform color. The only buffer type supported is `MMAP`
pub struct SimpleCaptureDevice<Q: VirtioMediaEventQueue> {
    /// Queue used to send events to the guest.
    #[allow(dead_code)]
    evt_queue: Q,
    /// Addresses at which MMAP buffers are mapped into the guest.
    ///
    /// [`BufferMmap`]s are shared with the [`Buffer`] they originated from.
    mmap_mappings: BTreeMap<u64, Rc<RefCell<Option<BufferMmap>>>>,
    /// ID of the session with allocated buffers, if any.
    ///
    /// v4l2-compliance checks that only a single session can have allocated buffers at a given
    /// time, since that's how actual hardware works - no two sessions can access a camera at the
    /// same time. It will fails if we allow simultaneous sessions to be active, so we need this
    /// artificial limitation to make it pass fully.
    active_session: Option<u32>,
}

impl<Q> SimpleCaptureDevice<Q>
where
    Q: VirtioMediaEventQueue,
{
    pub fn new(evt_queue: Q) -> Self {
        Self {
            evt_queue,
            mmap_mappings: Default::default(),
            active_session: None,
        }
    }
}

impl<Q, Reader, Writer> VirtioMediaDevice<Reader, Writer> for SimpleCaptureDevice<Q>
where
    Q: VirtioMediaEventQueue,
    Reader: std::io::Read,
    Writer: std::io::Write,
{
    type Session = SimpleCaptureDeviceSession;

    fn new_session(&mut self, session_id: u32) -> Result<Self::Session, i32> {
        Ok(SimpleCaptureDeviceSession {
            id: session_id,
            iteration: 0,
            buffers: Default::default(),
            queued_buffers: Default::default(),
            streaming: false,
        })
    }

    fn close_session(&mut self, session: Self::Session) {
        if self.active_session == Some(session.id) {
            self.active_session = None;
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

    fn do_mmap<M: VirtioMediaHostMemoryMapper>(
        &mut self,
        session: &mut Self::Session,
        flags: u32,
        offset: u64,
        mapper: &mut M,
        writer: &mut Writer,
    ) -> IoResult<()> {
        let buffer = match session.buffers.iter_mut().find(|b| b.offset == offset) {
            Some(buffer) => buffer,
            None => return writer.write_err_response(libc::EINVAL),
        };
        let rw = (flags & VIRTIO_MEDIA_MMAP_FLAG_RW) != 0;

        let mut mmap = buffer.mmap.borrow_mut();

        let guest_addr = match *mmap {
            Some(BufferMmap {
                guest_addr,
                ref mut num_mappings,
            }) => {
                *num_mappings += 1;
                guest_addr
            }
            None => {
                let guest_addr = mapper
                    .add_mapping(
                        buffer.fd.as_file().try_clone().unwrap(),
                        buffer.size,
                        offset,
                        rw,
                    )
                    .unwrap();
                *mmap = Some(BufferMmap {
                    guest_addr,
                    num_mappings: 1,
                });
                self.mmap_mappings.insert(offset, buffer.mmap.clone());
                guest_addr
            }
        };

        writer.write_response(MmapResp::ok(guest_addr, buffer.size))
    }

    fn do_munmap<M: VirtioMediaHostMemoryMapper>(
        &mut self,
        offset: u64,
        mapper: &mut M,
        writer: &mut Writer,
    ) -> IoResult<()> {
        if let Some(mapping) = self.mmap_mappings.remove(&offset) {
            let mut mmap = mapping.borrow_mut();
            if let Some(BufferMmap {
                ref mut num_mappings,
                ..
            }) = *mmap
            {
                *num_mappings -= 1;
                if *num_mappings == 0 {
                    // If this was the last mapping, remove it.
                    *mmap = None;

                    match mapper.remove_mapping(offset) {
                        Ok(()) => return writer.write_response(MunmapResp::ok()),
                        Err(e) => {
                            log::warn!(
                                "could not unmap host buffer with offset 0x{:x}: {:#}",
                                offset,
                                e
                            );
                            return writer.write_err_response(libc::EINVAL);
                        }
                    }
                } else {
                    // Otherwise, put it back.
                    drop(mmap);
                    self.mmap_mappings.insert(offset, mapping);
                    return writer.write_response(MunmapResp::ok());
                }
            }
        }

        writer.write_err_response(libc::EINVAL)
    }
}

const PIXELFORMAT: u32 = PixelFormat::from_fourcc(b"RGB3").to_u32();
const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const BYTES_PER_LINE: u32 = WIDTH * 3;
const BUFFER_SIZE: u32 = BYTES_PER_LINE * HEIGHT;

fn default_fmtdesc(queue: QueueType) -> v4l2_fmtdesc {
    v4l2_fmtdesc {
        index: 0,
        type_: queue as u32,
        pixelformat: PIXELFORMAT,
        ..Default::default()
    }
}

fn default_fmt(queue: QueueType) -> v4l2_format {
    let pix = v4l2_pix_format {
        width: WIDTH,
        height: HEIGHT,
        pixelformat: PIXELFORMAT,
        field: bindings::v4l2_field_V4L2_FIELD_NONE,
        bytesperline: BYTES_PER_LINE,
        sizeimage: BUFFER_SIZE,
        colorspace: bindings::v4l2_colorspace_V4L2_COLORSPACE_SRGB,
        ..Default::default()
    };

    v4l2_format {
        type_: queue as u32,
        fmt: bindings::v4l2_format__bindgen_ty_1 { pix },
    }
}

/// Implementations of the ioctls required by a CAPTURE device.
impl<Q> VirtioMediaIoctlHandler for SimpleCaptureDevice<Q>
where
    Q: VirtioMediaEventQueue,
{
    type Session = SimpleCaptureDeviceSession;

    fn enum_fmt(
        &mut self,
        _session: &mut Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<v4l2_fmtdesc> {
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }
        if index > 0 {
            return Err(libc::EINVAL);
        }

        Ok(default_fmtdesc(queue))
    }

    fn g_fmt(
        &mut self,
        _session: &mut Self::Session,
        queue: QueueType,
    ) -> IoctlResult<v4l2_format> {
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }

        Ok(default_fmt(queue))
    }

    fn s_fmt(
        &mut self,
        _session: &mut Self::Session,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        let queue = QueueType::n(format.type_).ok_or(libc::EINVAL)?;
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }

        Ok(default_fmt(queue))
    }

    fn try_fmt(
        &mut self,
        _session: &mut Self::Session,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        // TODO pass the validated queue to these hooks?
        let queue = QueueType::n(format.type_).ok_or(libc::EINVAL)?;
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }

        Ok(default_fmt(queue))
    }

    fn reqbufs(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        memory: MemoryType,
        count: u32,
    ) -> IoctlResult<v4l2_requestbuffers> {
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }
        if memory != MemoryType::Mmap {
            return Err(libc::EINVAL);
        }
        if session.streaming {
            return Err(libc::EBUSY);
        }
        // Buffers cannot be requested on a session if there is already another session with
        // allocated buffers.
        match self.active_session {
            Some(id) if id != session.id => return Err(libc::EBUSY),
            _ => (),
        }

        // Reqbufs(0) is an implicit streamoff.
        if count == 0 {
            self.active_session = None;
            self.streamoff(session, queue)?;
        } else {
            // TODO factorize with streamoff.
            session.queued_buffers.clear();
            for buffer in session.buffers.iter_mut() {
                buffer.state = BufferState::New;
            }
            self.active_session = Some(session.id);
        }

        let count = std::cmp::min(count, 32);

        session.buffers = (0..count)
            .map(|i| {
                let fd = memfd::MemfdOptions::default()
                    .create(format!("simple device buffer {}", i))
                    .unwrap();
                fd.as_file().set_len(BUFFER_SIZE as u64).unwrap();

                Buffer {
                    state: BufferState::New,
                    queue: QueueType::VideoCapture,
                    index: i,
                    fd,
                    size: BUFFER_SIZE as u64,
                    offset: i as u64 * BUFFER_SIZE as u64,
                    mmap: Rc::new(RefCell::new(None)),
                }
            })
            .collect();

        Ok(v4l2_requestbuffers {
            count,
            type_: queue as u32,
            memory: memory as u32,
            capabilities: (BufferCapabilities::SUPPORTS_MMAP
                | BufferCapabilities::SUPPORTS_ORPHANED_BUFS)
                .bits(),
            ..Default::default()
        })
    }

    fn querybuf(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<v4l2r::ioctl::V4l2Buffer> {
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }
        let buffer = session.buffers.get(index as usize).ok_or(libc::EINVAL)?;

        Ok(buffer.to_v4l2_buffer())
    }

    fn qbuf(
        &mut self,
        session: &mut Self::Session,
        buffer: v4l2r::ioctl::V4l2Buffer,
        _guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<v4l2r::ioctl::V4l2Buffer> {
        let host_buffer = session
            .buffers
            .get_mut(buffer.index() as usize)
            .ok_or(libc::EINVAL)?;
        // Attempt to queue already queued buffer.
        if host_buffer.state == BufferState::Incoming {
            return Err(libc::EINVAL);
        }

        host_buffer.state = BufferState::Incoming;
        session.queued_buffers.push_back(buffer.index() as usize);

        let buffer = host_buffer.to_v4l2_buffer();

        if session.streaming {
            session.process_queued_buffers(&mut self.evt_queue)?;
        }

        Ok(buffer)
    }

    fn streamon(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        if queue != QueueType::VideoCapture || session.buffers.is_empty() {
            return Err(libc::EINVAL);
        }
        session.streaming = true;

        session.process_queued_buffers(&mut self.evt_queue)?;

        Ok(())
    }

    fn streamoff(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        if queue != QueueType::VideoCapture {
            return Err(libc::EINVAL);
        }
        session.streaming = false;
        session.queued_buffers.clear();
        for buffer in session.buffers.iter_mut() {
            buffer.state = BufferState::New;
        }

        Ok(())
    }

    fn g_input(&mut self, _session: &mut Self::Session) -> IoctlResult<i32> {
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
        _session: &mut Self::Session,
        index: u32,
    ) -> IoctlResult<bindings::v4l2_input> {
        if index != 0 {
            Err(libc::EINVAL)
        } else {
            Ok(bindings::v4l2_input {
                index: 0,
                name: *b"Default\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                type_: bindings::V4L2_INPUT_TYPE_CAMERA,
                ..Default::default()
            })
        }
    }
}
