// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module uses `v4l2r` to proxy a host V4L2 device into the guest.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Result as IoResult;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use log::error;
use log::warn;
use v4l2r::bindings::v4l2_audio;
use v4l2r::bindings::v4l2_audioout;
use v4l2r::bindings::v4l2_control;
use v4l2r::bindings::v4l2_create_buffers;
use v4l2r::bindings::v4l2_decoder_cmd;
use v4l2r::bindings::v4l2_dv_timings;
use v4l2r::bindings::v4l2_dv_timings_cap;
use v4l2r::bindings::v4l2_enc_idx;
use v4l2r::bindings::v4l2_encoder_cmd;
use v4l2r::bindings::v4l2_event;
use v4l2r::bindings::v4l2_event_subscription;
use v4l2r::bindings::v4l2_ext_control;
use v4l2r::bindings::v4l2_ext_controls;
use v4l2r::bindings::v4l2_fmtdesc;
use v4l2r::bindings::v4l2_format;
use v4l2r::bindings::v4l2_frequency;
use v4l2r::bindings::v4l2_frequency_band;
use v4l2r::bindings::v4l2_frmivalenum;
use v4l2r::bindings::v4l2_frmsizeenum;
use v4l2r::bindings::v4l2_input;
use v4l2r::bindings::v4l2_modulator;
use v4l2r::bindings::v4l2_output;
use v4l2r::bindings::v4l2_query_ext_ctrl;
use v4l2r::bindings::v4l2_queryctrl;
use v4l2r::bindings::v4l2_querymenu;
use v4l2r::bindings::v4l2_rect;
use v4l2r::bindings::v4l2_requestbuffers;
use v4l2r::bindings::v4l2_standard;
use v4l2r::bindings::v4l2_std_id;
use v4l2r::bindings::v4l2_streamparm;
use v4l2r::bindings::v4l2_tuner;
pub use v4l2r::device::Device as V4l2Device;
use v4l2r::device::DeviceConfig;
use v4l2r::device::DeviceOpenError;
use v4l2r::ioctl::AudioMode;
use v4l2r::ioctl::BufferFlags;
use v4l2r::ioctl::CtrlId;
use v4l2r::ioctl::CtrlWhich;
use v4l2r::ioctl::DqBufError;
use v4l2r::ioctl::DqEventError;
use v4l2r::ioctl::EventType as V4l2EventType;
use v4l2r::ioctl::ExpbufFlags;
use v4l2r::ioctl::ExtControlError;
use v4l2r::ioctl::IntoErrno;
use v4l2r::ioctl::QueryBuf;
use v4l2r::ioctl::QueryCapError;
use v4l2r::ioctl::QueryCtrlFlags;
use v4l2r::ioctl::SelectionFlags;
use v4l2r::ioctl::SelectionTarget;
use v4l2r::ioctl::SelectionType;
use v4l2r::ioctl::SubscribeEventFlags;
use v4l2r::ioctl::TunerMode;
use v4l2r::ioctl::TunerTransmissionFlags;
use v4l2r::ioctl::TunerType;
use v4l2r::ioctl::V4l2Buffer;
use v4l2r::memory::MemoryType;
use v4l2r::QueueType;

use crate::ioctl::virtio_media_dispatch_ioctl;
use crate::ioctl::IoctlResult;
use crate::ioctl::VirtioMediaIoctlHandler;
use crate::mmap::MmapMappingManager;
use crate::protocol::DequeueBufferEvent;
use crate::protocol::MmapResp;
use crate::protocol::MunmapResp;
use crate::protocol::SessionEvent;
use crate::protocol::SgEntry;
use crate::protocol::V4l2Event;
use crate::protocol::V4l2Ioctl;
use crate::protocol::VIRTIO_MEDIA_MMAP_FLAG_RW;
use crate::VirtioMediaDevice;
use crate::VirtioMediaEventQueue;
use crate::VirtioMediaGuestMemoryMapper;
use crate::VirtioMediaHostMemoryMapper;
use crate::WriteDescriptorChain;

fn guest_v4l2_buffer_to_host<M: VirtioMediaGuestMemoryMapper>(
    v4l2_buffer: &V4l2Buffer,
    mut guest_regions: Vec<Vec<SgEntry>>,
    m: &M,
) -> anyhow::Result<(V4l2Buffer, Vec<M::GuestMemoryMapping>)> {
    if v4l2_buffer.memory() == MemoryType::UserPtr && v4l2_buffer.v4l2_buffer().length > 0 {
        let mut resources = vec![];
        let mut host_buffer = *v4l2_buffer.v4l2_buffer();
        let queue = v4l2_buffer.queue_type();

        if queue.is_multiplanar() {
            let mut host_planes = v4l2_buffer.v4l2_plane_iter().cloned().collect::<Vec<_>>();

            for (plane, mem_regions) in host_planes
                .iter_mut()
                .filter(|p| p.length > 0)
                .zip(guest_regions)
            {
                let mut mapping = m.new_mapping(mem_regions)?;

                plane.m.userptr = mapping.as_mut().as_ptr() as u64;
                resources.push(mapping);
            }

            let host_planes: [_; v4l2r::bindings::VIDEO_MAX_PLANES as usize] = host_planes
                .into_iter()
                .chain(std::iter::repeat(Default::default()))
                .take(v4l2r::bindings::VIDEO_MAX_PLANES as usize)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!("could not convert vector of v4l2_planes into array")
                })?;

            Ok((
                V4l2Buffer::try_from_v4l2_buffer(host_buffer, Some(host_planes))?,
                resources,
            ))
        } else {
            let mem_regions = guest_regions.remove(0);
            let mut mapping = m.new_mapping(mem_regions)?;

            host_buffer.m.userptr = mapping.as_mut().as_ptr() as u64;
            resources.push(mapping);

            Ok((
                V4l2Buffer::try_from_v4l2_buffer(host_buffer, None)?,
                resources,
            ))
        }
    } else {
        Ok((v4l2_buffer.clone(), Default::default()))
    }
}

/// Restore the user pointers of `host_buffer` using the values in `initial_guest_buffer`, if the buffer's
/// memory type is `USERPTR`. This allows a buffer processed on the host to be passed back to the
/// guest with the correct values.
fn host_v4l2_buffer_to_guest<R>(
    host_buffer: &V4l2Buffer,
    userptr_buffers: &BTreeMap<u64, V4l2UserPlaneInfo<R>>,
) -> anyhow::Result<V4l2Buffer> {
    if host_buffer.memory() == MemoryType::UserPtr {
        let mut guest_buffer = *host_buffer.v4l2_buffer();
        let guest_planes = if host_buffer.queue_type().is_multiplanar() {
            let mut guest_planes: [v4l2r::bindings::v4l2_plane;
                v4l2r::bindings::VIDEO_MAX_PLANES as usize] = Default::default();
            for (guest_plane, host_plane) in
                guest_planes.iter_mut().zip(host_buffer.v4l2_plane_iter())
            {
                // Safe because we checked that the memory type is USERPTR.
                let host_userptr = unsafe { host_plane.m.userptr };
                *guest_plane = *host_plane;
                if host_userptr != 0 {
                    guest_plane.m.userptr = userptr_buffers
                        .get(&host_userptr)
                        .map(|p| p.guest_addr)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "host buffer address 0x{:x} not registered!",
                                host_userptr
                            )
                        })?;
                }
            }

            Some(guest_planes)
        } else {
            // Safe because we checked that the memory type is USERPTR.
            let host_userptr = unsafe { host_buffer.v4l2_buffer().m.userptr };
            if host_userptr != 0 {
                guest_buffer.m.userptr = userptr_buffers
                    .get(&host_userptr)
                    .map(|p| p.guest_addr)
                    .ok_or_else(|| {
                    anyhow::anyhow!("host buffer address 0x{:x} not registered!", host_userptr)
                })?;
            }
            None
        };
        V4l2Buffer::try_from_v4l2_buffer(guest_buffer, guest_planes)
            .context("while patching guest memory addresses into host V4L2 buffer")
    } else {
        Ok(host_buffer.clone())
    }
}

#[derive(Clone, Copy, Debug)]
enum ExtCtrlIoctl {
    Get,
    Set,
    Try,
}

fn perform_ext_ctrls_ioctl<M: VirtioMediaGuestMemoryMapper>(
    ioctl: ExtCtrlIoctl,
    device: &V4l2Device,
    mem: &M,
    which: CtrlWhich,
    ctrls: (
        &mut v4l2_ext_controls,
        &mut Vec<v4l2_ext_control>,
        Vec<Vec<SgEntry>>,
    ),
) -> Result<(), ExtControlError> {
    let (ctrls, ctrl_array, mem_regions) = ctrls;
    // TODO only backup the addresses of controls which size of > 0 for efficiency? Also keep track
    // of the control index so we don't make a mistake if the host changes the control size.
    let ctrl_array_backup = ctrl_array.clone();

    // Read the payloads for all the controls with one.
    let mut payloads = ctrl_array
        .iter()
        .filter(|ctrl| ctrl.size > 0)
        .zip(mem_regions)
        .map(|(_, sgs)| mem.new_mapping(sgs))
        // TODO remove unwrap
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();

    // Patch the pointers to the payloads.
    for (ctrl, payload) in ctrl_array
        .iter_mut()
        .filter(|ctrl| ctrl.size > 0)
        .zip(payloads.iter_mut())
    {
        ctrl.__bindgen_anon_1.ptr = payload.as_mut().as_mut_ptr() as *mut libc::c_void;
    }

    let res = match ioctl {
        ExtCtrlIoctl::Get => v4l2r::ioctl::g_ext_ctrls(device, which, ctrl_array.as_mut_slice()),
        ExtCtrlIoctl::Set => v4l2r::ioctl::s_ext_ctrls(device, which, ctrl_array.as_mut_slice()),
        ExtCtrlIoctl::Try => v4l2r::ioctl::try_ext_ctrls(device, which, ctrl_array.as_mut_slice()),
    };

    // Restore guest addresses in the controls array.
    for (ctrl, ctrl_backup) in ctrl_array
        .iter_mut()
        .zip(ctrl_array_backup.iter())
        .filter(|(_, ctrl)| ctrl.size > 0)
    {
        ctrl.__bindgen_anon_1.ptr = unsafe { ctrl_backup.__bindgen_anon_1.ptr };
    }

    if let Err(e) = &res {
        ctrls.error_idx = e.error_idx;
    }

    res
}

/// Information about a given USERPTR memory plane.
struct V4l2UserPlaneInfo<R> {
    /// Queue the buffer belongs to.
    queue: QueueType,
    /// Buffer index.
    index: u8,

    guest_addr: u64,
    _guest_resource: R,
}

pub struct V4l2Session<M: VirtioMediaGuestMemoryMapper> {
    id: u32,
    device: Arc<V4l2Device>,

    /// Type of the capture queue, if one has been set up.
    capture_queue_type: Option<QueueType>,
    /// Type of the output queue, if one has been set up.
    output_queue_type: Option<QueueType>,

    capture_streaming: bool,
    capture_num_queued: usize,

    output_streaming: bool,
    output_num_queued: usize,

    /// Map of host USERPTR addresses to guest USERPTR addresses. Only used for queues which memory
    /// type is USERPTR.
    ///
    /// TODO this is not properly cleared. We should probably record the session ID and queue in
    /// order to remove the records upon REQBUFS or session deletion?
    userptr_buffers: BTreeMap<u64, V4l2UserPlaneInfo<M::GuestMemoryMapping>>,
}

impl<M> V4l2Session<M>
where
    M: VirtioMediaGuestMemoryMapper,
{
    fn new(id: u32, device: Arc<V4l2Device>) -> Self {
        Self {
            id,
            device,
            capture_queue_type: None,
            output_queue_type: None,
            capture_streaming: false,
            capture_num_queued: 0,
            output_streaming: false,
            output_num_queued: 0,
            userptr_buffers: Default::default(),
        }
    }

    /// Returns whether this session should be polling for CAPTURE buffers in its current state.
    fn should_poll_capture(&self) -> bool {
        self.capture_streaming && self.capture_num_queued > 0
    }

    fn register_userptr_addresses(
        &mut self,
        host_buffer: &V4l2Buffer,
        guest_buffer: &V4l2Buffer,
        mut guest_resources: Vec<M::GuestMemoryMapping>,
    ) {
        let memory = host_buffer.memory();

        if memory == MemoryType::UserPtr {
            let queue = host_buffer.queue_type();

            if queue.is_multiplanar() && host_buffer.v4l2_buffer().length > 0 {
                // Safe because we have tested that the memory type is USERPTR.
                unsafe {
                    for ((host_plane, guest_plane), guest_resource) in host_buffer
                        .v4l2_plane_iter()
                        .zip(guest_buffer.v4l2_plane_iter())
                        .filter(|(h, _)| h.m.userptr != 0)
                        .zip(guest_resources.into_iter())
                    {
                        let plane_info = {
                            V4l2UserPlaneInfo {
                                queue: guest_buffer.queue_type(),
                                index: guest_buffer.index() as u8,
                                guest_addr: guest_plane.m.userptr,
                                _guest_resource: guest_resource,
                            }
                        };
                        self.userptr_buffers
                            .insert(host_plane.m.userptr, plane_info);
                    }
                }
            } else if !queue.is_multiplanar() && host_buffer.v4l2_buffer().length > 0 {
                let host_addr = unsafe { host_buffer.v4l2_buffer().m.userptr };
                let guest_addr = unsafe { guest_buffer.v4l2_buffer().m.userptr };
                let plane_info = V4l2UserPlaneInfo {
                    queue: guest_buffer.queue_type(),
                    index: guest_buffer.index() as u8,
                    guest_addr,
                    _guest_resource: guest_resources.remove(0),
                };

                self.userptr_buffers.insert(host_addr, plane_info);
            }
        }
    }
}

/// Trait allowing a session to be polled for events and capture buffers.
///
/// The worker that runs a `V4l2ProxyDevice` typically polls on file descriptors for available
/// CAPTURE buffers and outstanding session events. However V4L2's poll logic returns with the
/// `POLLERR` flag if a CAPTURE queue is polled while not streaming or if zero CAPTURE buffers have
/// been queued. To avoid this, the device needs to disable polling when this would happen, and
/// re-enable it when conditions are adequate.
///
/// If the worker does not need such a feature, `()` can be passed as a no-op type that implements
/// this interface.
pub trait SessionPoller {
    /// Add a newly created `session` to be polled for events (not capture buffers).
    fn add_session(&self, session: &V4l2Device, session_id: u32) -> Result<(), i32>;
    /// Stop polling all activity on `session`.
    fn remove_session(&self, session: &V4l2Device);

    /// Start or stop polling for available CAPTURE buffers on `session`, on which `add_session`
    /// has been previously invoked. Events are always polled regardless of the value of `poll`.
    fn poll_capture_buffers(
        &self,
        session: &V4l2Device,
        session_id: u32,
        poll: bool,
    ) -> Result<(), i32>;
}

/// No-op implementation of `SessionPoller`. This is here for convenience but should probably not
/// be used.
impl SessionPoller for () {
    fn add_session(&self, _session: &V4l2Device, _session_id: u32) -> Result<(), i32> {
        Ok(())
    }

    fn remove_session(&self, _session: &V4l2Device) {}

    fn poll_capture_buffers(
        &self,
        _session: &V4l2Device,
        _session_id: u32,
        _poll: bool,
    ) -> Result<(), i32> {
        Ok(())
    }
}

/// Information about a given MMAP memory plane.
///
/// We keep these around indexed by the memory offset in order to service MMAP commands. Only used
/// if the memory type of the queue is MMAP.
struct V4l2MmapPlaneInfo {
    /// ID of the session the buffer belongs to.
    session_id: u32,
    /// Queue the buffer belongs to.
    queue: QueueType,
    /// Buffer index.
    index: u8,
    /// Plane index.
    plane: u8,
    /// Length of the plane in bytes.
    length: u32,
    /// Exported file descriptor, if a map into the guest has been requested.
    exported_fd: Option<File>,
    /// Guest address at which the buffer has been mapped.
    map_address: u64,
    /// Whether the buffer is still active from the device's point of view.
    active: bool,
}

/// A host V4L2 device that can be proxied into a virtio-media guest.
pub struct V4l2ProxyDevice<
    Q: VirtioMediaEventQueue,
    M: VirtioMediaGuestMemoryMapper,
    HM: VirtioMediaHostMemoryMapper,
    P: SessionPoller = (),
> {
    /// `/dev/videoX` host device path.
    device_path: PathBuf,

    mem: M,
    evt_queue: Q,
    session_poller: P,

    /// Map of memory offsets to detailed buffer information. Only used for queues which memory
    /// type is MMAP.
    mmap_buffers: BTreeMap<u64, V4l2MmapPlaneInfo>,

    mmap_manager: MmapMappingManager<HM>,
}

pub struct DequeueEventError(i32);
pub struct DequeueBufferError(i32);

impl<Q, M, HM, P> V4l2ProxyDevice<Q, M, HM, P>
where
    Q: VirtioMediaEventQueue,
    M: VirtioMediaGuestMemoryMapper,
    HM: VirtioMediaHostMemoryMapper,
    P: SessionPoller,
{
    pub fn new(device_path: PathBuf, evt_queue: Q, mem: M, mapper: HM, session_poller: P) -> Self {
        Self {
            mem,
            evt_queue,
            session_poller,
            device_path,
            mmap_buffers: Default::default(),
            mmap_manager: MmapMappingManager::new(mapper),
        }
    }

    fn delete_session(&mut self, session: &V4l2Session<M>) {
        // Mark all buffers from this session as being inactive.
        for (&offset, buffer) in self.mmap_buffers.iter_mut() {
            if buffer.session_id == session.id {
                self.mmap_manager.unregister_buffer(offset);
                buffer.active = false;
            }
        }
        // Garbage-collect buffers that can be deleted.
        self.mmap_buffers.retain(|_, b| b.active);

        self.session_poller.remove_session(&session.device);
    }

    /// Clear all the previous buffer information for this queue, and insert new information if the
    /// memory type is MMAP.
    fn update_mmap_offsets(
        &mut self,
        session: &mut V4l2Session<M>,
        queue: QueueType,
        memory: MemoryType,
        range: std::ops::Range<u32>,
    ) {
        // Remove buffers that have been deallocated.
        self.mmap_buffers
            .iter_mut()
            .filter(|(_, b)| b.session_id == session.id && b.queue == queue)
            .filter(|(_, b)| range.is_empty() || b.index as u32 >= range.start)
            .for_each(|(&offset, b)| {
                self.mmap_manager.unregister_buffer(offset);
                b.active = false;
            });
        // Garbage-collect buffers that can be deleted.
        self.mmap_buffers.retain(|_, b| b.active);

        if memory == MemoryType::Mmap {
            for i in range {
                let buffer = match v4l2r::ioctl::querybuf::<V4l2Buffer>(
                    &session.device,
                    queue,
                    i as usize,
                ) {
                    Ok(buffer) => buffer,
                    Err(e) => {
                        warn!("failed to query newly allocated buffer: {:#}", e);
                        continue;
                    }
                };
                // TODO(v4l2r) have an iterator instead?
                for j in 0..buffer.num_planes() {
                    let plane = buffer.get_plane(j).unwrap();
                    let offset = match plane.mem_offset() {
                        Some(offset) => offset,
                        None => {
                            warn!("expected a plane memory offset but none present");
                            continue;
                        }
                    };

                    self.mmap_manager
                        .register_buffer(offset as u64, plane.length() as u64)
                        .unwrap();

                    self.mmap_buffers.insert(
                        offset as u64,
                        V4l2MmapPlaneInfo {
                            session_id: session.id,
                            queue,
                            index: buffer.index() as u8,
                            plane: j as u8,
                            length: plane.length(),
                            map_address: 0,
                            exported_fd: None,
                            active: true,
                        },
                    );
                }
            }
        }

        // If we allocated on the capture or output queue successfully, remember its type.
        // TODO this should be somewhere else?
        match queue {
            QueueType::VideoCapture | QueueType::VideoCaptureMplane => {
                session.capture_queue_type = Some(queue);
            }
            QueueType::VideoOutput | QueueType::VideoOutputMplane => {
                session.output_queue_type = Some(queue);
            }
            _ => (),
        }
    }

    /// Dequeue all pending events for `session` and send them to the guest.
    ///
    /// In case of error, the session should be considered invalid and destroyed.
    pub fn dequeue_events(
        &mut self,
        session: &mut V4l2Session<M>,
    ) -> Result<(), DequeueEventError> {
        loop {
            match v4l2r::ioctl::dqevent::<v4l2_event>(&session.device) {
                Ok(event) => self
                    .evt_queue
                    .send_event(V4l2Event::Event(SessionEvent::new(session.id, event))),
                Err(DqEventError::NotReady) => return Ok(()),
                Err(e) => {
                    let err = e.into_errno();
                    self.evt_queue.send_error(session.id, err);
                    return Err(DequeueEventError(err));
                }
            }
        }
    }

    /// Attempt to dequeue all processed OUTPUT buffers and send the corresponding events to
    /// `evt_queue`.
    ///
    /// In case of error, the session should be considered invalid and destroyed.
    pub fn dequeue_output_buffers(
        &mut self,
        session: &mut V4l2Session<M>,
    ) -> Result<(), DequeueBufferError> {
        let output_queue_type = match session.output_queue_type {
            Some(queue_type) => queue_type,
            None => return Ok(()),
        };

        if !session.output_streaming || session.output_num_queued == 0 {
            return Ok(());
        }

        loop {
            match v4l2r::ioctl::dqbuf::<V4l2Buffer>(&session.device, output_queue_type) {
                Ok(buffer) => {
                    // Drop buffer information. This also syncs the buffer content if it has been shadowed.
                    session.userptr_buffers.retain(|_, v| {
                        Some(v.queue) != session.output_queue_type
                            || v.index != buffer.index() as u8
                    });
                    self.evt_queue
                        .send_event(V4l2Event::DequeueBuffer(DequeueBufferEvent::new(
                            session.id, buffer,
                        )))
                }
                Err(DqBufError::Eos) | Err(DqBufError::NotReady) => return Ok(()),
                Err(e) => {
                    let err = e.into_errno();
                    self.evt_queue.send_error(session.id, err);
                    return Err(DequeueBufferError(err));
                }
            };
        }
    }

    /// Attempt to dequeue a single CAPTURE buffer and send the corresponding event to `evt_queue`.
    ///
    /// In case of error, the session should be considered invalid and destroyed.
    pub fn dequeue_capture_buffer(
        &mut self,
        session: &mut V4l2Session<M>,
        wait_ctx: &P,
    ) -> Result<(), DequeueBufferError> {
        let capture_queue_type = match session.capture_queue_type {
            Some(queue_type) => queue_type,
            None => return Ok(()),
        };

        let v4l2_buffer =
            match v4l2r::ioctl::dqbuf::<V4l2Buffer>(&session.device, capture_queue_type) {
                Ok(buffer) => buffer,
                Err(DqBufError::Eos) => return Ok(()),
                Err(DqBufError::NotReady) => return Ok(()),
                Err(e) => {
                    let err = e.into_errno();
                    self.evt_queue.send_error(session.id, err);
                    return Err(DequeueBufferError(err));
                }
            };

        // Drop buffer information. This also syncs the buffer content if it has been shadowed.
        session.userptr_buffers.retain(|_, v| {
            Some(v.queue) != session.capture_queue_type || v.index != v4l2_buffer.index() as u8
        });

        let capture_polling_active = session.should_poll_capture();
        session.capture_num_queued -= 1;
        if (capture_polling_active && session.capture_num_queued == 0) ||
            // This may or may not be needed...
            v4l2_buffer.flags().contains(BufferFlags::LAST)
        {
            if let Err(e) = wait_ctx.poll_capture_buffers(&session.device, session.id, false) {
                error!("cannot disable CAPTURE polling after last buffer: {}", e);
            }
        }

        self.evt_queue
            .send_event(V4l2Event::DequeueBuffer(DequeueBufferEvent::new(
                session.id,
                v4l2_buffer,
            )));

        Ok(())
    }
}

impl<Q, M, HM, P> VirtioMediaIoctlHandler for V4l2ProxyDevice<Q, M, HM, P>
where
    Q: VirtioMediaEventQueue,
    M: VirtioMediaGuestMemoryMapper,
    HM: VirtioMediaHostMemoryMapper,
    P: SessionPoller,
{
    type Session = V4l2Session<M>;

    fn enum_fmt(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<v4l2_fmtdesc> {
        v4l2r::ioctl::enum_fmt(&session.device, queue, index).map_err(IntoErrno::into_errno)
    }

    fn g_fmt(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<v4l2_format> {
        v4l2r::ioctl::g_fmt(&session.device, queue).map_err(IntoErrno::into_errno)
    }

    fn s_fmt(
        &mut self,
        session: &mut Self::Session,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        v4l2r::ioctl::s_fmt(&mut session.device, format).map_err(IntoErrno::into_errno)
    }

    fn reqbufs(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        memory: MemoryType,
        count: u32,
    ) -> IoctlResult<v4l2_requestbuffers> {
        let mut reqbufs: v4l2_requestbuffers =
            v4l2r::ioctl::reqbufs(&session.device, queue, memory, count)
                .map_err(IntoErrno::into_errno)?;

        // We do not support requests at the moment, so do not advertize them.
        reqbufs.capabilities &= !v4l2r::bindings::V4L2_BUF_CAP_SUPPORTS_REQUESTS;

        self.update_mmap_offsets(session, queue, memory, 0..reqbufs.count);

        match queue {
            QueueType::VideoCapture | QueueType::VideoCaptureMplane => {
                // REQBUFS(0) is an implicit STREAMOFF.
                if reqbufs.count == 0 {
                    let was_polling_capture = session.should_poll_capture();
                    session.capture_streaming = false;
                    session.capture_num_queued = 0;
                    if was_polling_capture {
                        if let Err(e) = self.session_poller.poll_capture_buffers(
                            &session.device,
                            session.id,
                            false,
                        ) {
                            error!(
                                "cannot disable CAPTURE polling after REQBUFS(0) ioctl: {}",
                                e
                            );
                        }
                    }
                }
            }
            QueueType::VideoOutput | QueueType::VideoOutputMplane => {
                // REQBUFS(0) is an implicit STREAMOFF.
                if reqbufs.count == 0 {
                    session.output_streaming = false;
                    session.output_num_queued = 0;
                }
            }
            _ => (),
        }

        Ok(reqbufs)
    }

    fn querybuf(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<V4l2Buffer> {
        v4l2r::ioctl::querybuf(&session.device, queue, index as usize)
            .map_err(IntoErrno::into_errno)
            .and_then(|host_buffer| {
                host_v4l2_buffer_to_guest(&host_buffer, &session.userptr_buffers).map_err(|e| {
                    error!("{:#}", e.context("while performing QUERYBUF ioctl"));
                    libc::EINVAL
                })
            })
    }

    fn streamon(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        v4l2r::ioctl::streamon(&session.device, queue).map_err(IntoErrno::into_errno)?;

        match queue {
            QueueType::VideoCapture | QueueType::VideoCaptureMplane
                if !session.capture_streaming =>
            {
                session.capture_streaming = true;
                if session.should_poll_capture() {
                    if let Err(e) =
                        self.session_poller
                            .poll_capture_buffers(&session.device, session.id, true)
                    {
                        error!("cannot enable CAPTURE polling after STREAMON ioctl: {}", e);
                    }
                }
            }
            QueueType::VideoOutput | QueueType::VideoOutputMplane if !session.output_streaming => {
                session.output_streaming = true;
            }
            _ => (),
        }

        Ok(())
    }

    fn streamoff(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        v4l2r::ioctl::streamoff(&session.device, queue).map_err(IntoErrno::into_errno)?;

        match queue {
            QueueType::VideoCapture | QueueType::VideoCaptureMplane => {
                let was_polling_capture = session.should_poll_capture();
                session.capture_streaming = false;
                session.capture_num_queued = 0;
                if was_polling_capture {
                    if let Err(e) =
                        self.session_poller
                            .poll_capture_buffers(&session.device, session.id, false)
                    {
                        error!(
                            "cannot disable CAPTURE polling after STREAMOFF ioctl: {}",
                            e
                        );
                    }
                }
            }
            QueueType::VideoOutput | QueueType::VideoOutputMplane => {
                session.output_streaming = false;
                session.output_num_queued = 0;
            }
            _ => (),
        }

        Ok(())
    }

    fn qbuf(
        &mut self,
        session: &mut Self::Session,
        guest_buffer: V4l2Buffer,
        guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<V4l2Buffer> {
        // Proactively dequeue output buffers we are done with. Errors can be ignored in
        // this context.
        let _ = self.dequeue_output_buffers(session);

        let (host_buffer, guest_resources) =
            guest_v4l2_buffer_to_host(&guest_buffer, guest_regions, &self.mem)
                .map_err(|_| libc::EINVAL)?;
        session.register_userptr_addresses(&host_buffer, &guest_buffer, guest_resources);
        let queue = host_buffer.queue_type();
        let index = host_buffer.index() as usize;
        let out_buffer = v4l2r::ioctl::qbuf(&session.device, queue, index, host_buffer)
            .map_err(|e| e.into_errno())
            .and_then(|host_out_buffer| {
                // TODO if we had a PREPARE_BUF before, do we need to patch the addresses
                // from the buffer given at that time?
                host_v4l2_buffer_to_guest(&host_out_buffer, &session.userptr_buffers).map_err(|e| {
                    error!("{:#}", e.context("while processing QBUF"));
                    libc::EINVAL
                })
            })?;

        match queue {
            QueueType::VideoCapture | QueueType::VideoCaptureMplane => {
                let was_polling_capture = session.should_poll_capture();
                session.capture_num_queued += 1;
                if !was_polling_capture && session.should_poll_capture() {
                    if let Err(e) =
                        self.session_poller
                            .poll_capture_buffers(&session.device, session.id, true)
                    {
                        error!("cannot enable CAPTURE polling after QBUF ioctl: {}", e);
                    }
                }
            }
            QueueType::VideoOutput | QueueType::VideoOutputMplane => {
                session.output_num_queued += 1;
            }
            _ => (),
        }

        Ok(out_buffer)
    }

    fn g_parm(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
    ) -> IoctlResult<v4l2_streamparm> {
        v4l2r::ioctl::g_parm(&session.device, queue).map_err(|e| e.into_errno())
    }

    fn s_parm(
        &mut self,
        session: &mut Self::Session,
        parm: v4l2_streamparm,
    ) -> IoctlResult<v4l2_streamparm> {
        v4l2r::ioctl::s_parm(&session.device, parm).map_err(|e| e.into_errno())
    }

    fn g_std(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_std_id> {
        v4l2r::ioctl::g_std(&session.device).map_err(|e| e.into_errno())
    }

    fn s_std(&mut self, session: &mut Self::Session, std: v4l2_std_id) -> IoctlResult<()> {
        v4l2r::ioctl::s_std(&session.device, std).map_err(|e| e.into_errno())
    }

    fn enumstd(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<v4l2_standard> {
        v4l2r::ioctl::enumstd(&session.device, index).map_err(|e| e.into_errno())
    }

    fn enuminput(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<v4l2_input> {
        v4l2r::ioctl::enuminput(&session.device, index as usize).map_err(|e| e.into_errno())
    }

    fn g_ctrl(&mut self, session: &mut Self::Session, id: u32) -> IoctlResult<v4l2_control> {
        v4l2r::ioctl::g_ctrl(&session.device, id)
            .map(|value| v4l2_control { id, value })
            .map_err(|e| e.into_errno())
    }

    fn s_ctrl(
        &mut self,
        session: &mut Self::Session,
        id: u32,
        value: i32,
    ) -> IoctlResult<v4l2_control> {
        v4l2r::ioctl::s_ctrl(&session.device, id, value)
            .map(|value| v4l2_control { id, value })
            .map_err(|e| e.into_errno())
    }

    fn g_tuner(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<v4l2_tuner> {
        v4l2r::ioctl::g_tuner(&session.device, index).map_err(|e| e.into_errno())
    }

    fn s_tuner(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        mode: TunerMode,
    ) -> IoctlResult<()> {
        v4l2r::ioctl::s_tuner(&session.device, index, mode).map_err(|e| e.into_errno())
    }

    fn g_audio(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_audio> {
        v4l2r::ioctl::g_audio(&session.device).map_err(|e| e.into_errno())
    }

    fn s_audio(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        mode: Option<AudioMode>,
    ) -> IoctlResult<()> {
        v4l2r::ioctl::s_audio(&session.device, index, mode).map_err(|e| e.into_errno())
    }

    fn queryctrl(
        &mut self,
        session: &mut Self::Session,
        id: v4l2r::ioctl::CtrlId,
        flags: v4l2r::ioctl::QueryCtrlFlags,
    ) -> IoctlResult<v4l2_queryctrl> {
        v4l2r::ioctl::queryctrl(&session.device, id, flags).map_err(|e| e.into_errno())
    }

    fn querymenu(
        &mut self,
        session: &mut Self::Session,
        id: u32,
        index: u32,
    ) -> IoctlResult<v4l2_querymenu> {
        v4l2r::ioctl::querymenu(&session.device, id, index).map_err(|e| e.into_errno())
    }

    fn g_input(&mut self, session: &mut Self::Session) -> IoctlResult<i32> {
        v4l2r::ioctl::g_input(&session.device)
            .map(|i| i as i32)
            .map_err(|e| e.into_errno())
    }

    fn s_input(&mut self, session: &mut Self::Session, input: i32) -> IoctlResult<i32> {
        v4l2r::ioctl::s_input(&session.device, input as usize)
            .map(|i| i as i32)
            .map_err(|e| e.into_errno())
    }

    fn g_output(&mut self, session: &mut Self::Session) -> IoctlResult<i32> {
        v4l2r::ioctl::g_output(&session.device)
            .map(|o| o as i32)
            .map_err(|e| e.into_errno())
    }

    fn s_output(&mut self, session: &mut Self::Session, output: i32) -> IoctlResult<i32> {
        v4l2r::ioctl::s_output(&session.device, output as usize)
            .map(|()| output)
            .map_err(|e| e.into_errno())
    }

    fn enumoutput(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<v4l2_output> {
        v4l2r::ioctl::enumoutput(&session.device, index as usize).map_err(|e| e.into_errno())
    }

    fn g_audout(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_audioout> {
        v4l2r::ioctl::g_audout(&session.device).map_err(|e| e.into_errno())
    }

    fn s_audout(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<()> {
        v4l2r::ioctl::s_audout(&session.device, index).map_err(|e| e.into_errno())
    }

    fn g_modulator(
        &mut self,
        session: &mut Self::Session,
        index: u32,
    ) -> IoctlResult<v4l2_modulator> {
        v4l2r::ioctl::g_modulator(&session.device, index).map_err(|e| e.into_errno())
    }

    fn s_modulator(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        flags: TunerTransmissionFlags,
    ) -> IoctlResult<()> {
        v4l2r::ioctl::s_modulator(&session.device, index, flags).map_err(|e| e.into_errno())
    }

    fn g_frequency(
        &mut self,
        session: &mut Self::Session,
        tuner: u32,
    ) -> IoctlResult<v4l2_frequency> {
        v4l2r::ioctl::g_frequency(&session.device, tuner).map_err(|e| e.into_errno())
    }

    fn s_frequency(
        &mut self,
        session: &mut Self::Session,
        tuner: u32,
        type_: TunerType,
        frequency: u32,
    ) -> IoctlResult<()> {
        v4l2r::ioctl::s_frequency(&session.device, tuner, type_, frequency)
            .map_err(|e| e.into_errno())
    }

    fn querystd(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_std_id> {
        v4l2r::ioctl::querystd::<v4l2_std_id>(&session.device).map_err(|e| e.into_errno())
    }

    fn try_fmt(
        &mut self,
        session: &mut Self::Session,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        v4l2r::ioctl::try_fmt::<_, v4l2_format>(&session.device, format).map_err(|e| e.into_errno())
    }

    fn enumaudio(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<v4l2_audio> {
        v4l2r::ioctl::enumaudio::<v4l2_audio>(&session.device, index).map_err(|e| e.into_errno())
    }

    fn enumaudout(
        &mut self,
        session: &mut Self::Session,
        index: u32,
    ) -> IoctlResult<v4l2_audioout> {
        v4l2r::ioctl::enumaudout::<v4l2_audioout>(&session.device, index)
            .map_err(|e| e.into_errno())
    }

    fn g_ext_ctrls(
        &mut self,
        session: &mut Self::Session,
        which: CtrlWhich,
        ctrls: &mut v4l2_ext_controls,
        ctrl_array: &mut Vec<v4l2_ext_control>,
        user_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<()> {
        perform_ext_ctrls_ioctl(
            ExtCtrlIoctl::Get,
            &session.device,
            &self.mem,
            which,
            (ctrls, ctrl_array, user_regions),
        )
        .map_err(|e| e.into_errno())
    }

    fn s_ext_ctrls(
        &mut self,
        session: &mut Self::Session,
        which: CtrlWhich,
        ctrls: &mut v4l2_ext_controls,
        ctrl_array: &mut Vec<v4l2_ext_control>,
        user_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<()> {
        perform_ext_ctrls_ioctl(
            ExtCtrlIoctl::Set,
            &session.device,
            &self.mem,
            which,
            (ctrls, ctrl_array, user_regions),
        )
        .map_err(|e| e.into_errno())
    }

    fn try_ext_ctrls(
        &mut self,
        session: &mut Self::Session,
        which: CtrlWhich,
        ctrls: &mut v4l2_ext_controls,
        ctrl_array: &mut Vec<v4l2_ext_control>,
        user_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<()> {
        perform_ext_ctrls_ioctl(
            ExtCtrlIoctl::Try,
            &session.device,
            &self.mem,
            which,
            (ctrls, ctrl_array, user_regions),
        )
        .map_err(|e| e.into_errno())
    }

    fn enum_framesizes(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        pixel_format: u32,
    ) -> IoctlResult<v4l2_frmsizeenum> {
        v4l2r::ioctl::enum_frame_sizes(&session.device, index, pixel_format.into())
            .map_err(|e| e.into_errno())
    }

    fn enum_frameintervals(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        pixel_format: u32,
        width: u32,
        height: u32,
    ) -> IoctlResult<v4l2_frmivalenum> {
        v4l2r::ioctl::enum_frame_intervals(
            &session.device,
            index,
            pixel_format.into(),
            width,
            height,
        )
        .map_err(|e| e.into_errno())
    }

    fn g_enc_index(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_enc_idx> {
        v4l2r::ioctl::g_enc_index(&session.device).map_err(|e| e.into_errno())
    }

    fn encoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: v4l2_encoder_cmd,
    ) -> IoctlResult<v4l2_encoder_cmd> {
        v4l2r::ioctl::encoder_cmd(&session.device, cmd).map_err(|e| e.into_errno())
    }

    fn try_encoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: v4l2_encoder_cmd,
    ) -> IoctlResult<v4l2_encoder_cmd> {
        v4l2r::ioctl::try_encoder_cmd(&session.device, cmd).map_err(|e| e.into_errno())
    }

    fn s_dv_timings(
        &mut self,
        session: &mut Self::Session,
        timings: v4l2_dv_timings,
    ) -> IoctlResult<v4l2_dv_timings> {
        v4l2r::ioctl::s_dv_timings(&session.device, timings).map_err(|e| e.into_errno())
    }

    fn g_dv_timings(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_dv_timings> {
        v4l2r::ioctl::g_dv_timings(&session.device).map_err(|e| e.into_errno())
    }

    fn subscribe_event(
        &mut self,
        session: &mut Self::Session,
        event: V4l2EventType,
        flags: SubscribeEventFlags,
    ) -> IoctlResult<()> {
        v4l2r::ioctl::subscribe_event(&session.device, event, flags).map_err(|e| e.into_errno())?;

        // Make sure the initial event it put into the eventq before we return.
        if flags.contains(SubscribeEventFlags::SEND_INITIAL) {
            // This sends the potential events before the command response,
            // ensuring the guest will be able to see them alongside the response.
            let _ = self.dequeue_events(session).err();
        }

        Ok(())
    }

    fn unsubscribe_event(
        &mut self,
        session: &mut Self::Session,
        event: v4l2_event_subscription,
    ) -> IoctlResult<()> {
        if event.type_ == v4l2r::bindings::V4L2_EVENT_ALL {
            v4l2r::ioctl::unsubscribe_all_events(&session.device)
        } else {
            let event = V4l2EventType::try_from(&event).map_err(|_| libc::EINVAL)?;

            v4l2r::ioctl::unsubscribe_event(&session.device, event)
        }
        .map_err(|e| e.into_errno())
    }

    fn create_bufs(
        &mut self,
        session: &mut Self::Session,
        count: u32,
        queue: QueueType,
        memory: MemoryType,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_create_buffers> {
        let create_bufs = v4l2r::ioctl::create_bufs::<_, v4l2_create_buffers>(
            &session.device,
            count,
            memory,
            format,
        )
        .map_err(|e| (e.into_errno()))?;

        let bufs_range = create_bufs.index..(create_bufs.index + create_bufs.count);
        self.update_mmap_offsets(session, queue, memory, bufs_range);

        Ok(create_bufs)
    }

    fn prepare_buf(
        &mut self,
        session: &mut Self::Session,
        guest_buffer: V4l2Buffer,
        guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<V4l2Buffer> {
        let (host_buffer, guest_resources) =
            guest_v4l2_buffer_to_host(&guest_buffer, guest_regions, &self.mem)
                .map_err(|_| libc::EINVAL)?;
        session.register_userptr_addresses(&host_buffer, &guest_buffer, guest_resources);
        let queue = host_buffer.queue_type();
        let index = host_buffer.index() as usize;
        v4l2r::ioctl::prepare_buf(&session.device, queue, index, host_buffer)
            .map_err(|e| e.into_errno())
            .and_then(|host_out_buffer| {
                host_v4l2_buffer_to_guest(&host_out_buffer, &session.userptr_buffers).map_err(|e| {
                    error!("{:#}", e.context("while processing PREPARE_BUF"));
                    libc::EINVAL
                })
            })
    }

    fn g_selection(
        &mut self,
        session: &mut Self::Session,
        sel_type: SelectionType,
        sel_target: SelectionTarget,
    ) -> IoctlResult<v4l2_rect> {
        v4l2r::ioctl::g_selection(&session.device, sel_type, sel_target).map_err(|e| e.into_errno())
    }

    fn s_selection(
        &mut self,
        session: &mut Self::Session,
        sel_type: SelectionType,
        sel_target: SelectionTarget,
        sel_rect: v4l2_rect,
        sel_flags: SelectionFlags,
    ) -> IoctlResult<v4l2_rect> {
        v4l2r::ioctl::s_selection(&session.device, sel_type, sel_target, sel_rect, sel_flags)
            .map_err(|e| e.into_errno())
    }

    fn decoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: v4l2_decoder_cmd,
    ) -> IoctlResult<v4l2_decoder_cmd> {
        v4l2r::ioctl::decoder_cmd(&session.device, cmd).map_err(|e| e.into_errno())
    }

    fn try_decoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: v4l2_decoder_cmd,
    ) -> IoctlResult<v4l2_decoder_cmd> {
        v4l2r::ioctl::try_decoder_cmd(&session.device, cmd).map_err(|e| e.into_errno())
    }

    fn enum_dv_timings(
        &mut self,
        session: &mut Self::Session,
        index: u32,
    ) -> IoctlResult<v4l2_dv_timings> {
        v4l2r::ioctl::enum_dv_timings(&session.device, index).map_err(|e| e.into_errno())
    }

    fn query_dv_timings(&mut self, session: &mut Self::Session) -> IoctlResult<v4l2_dv_timings> {
        v4l2r::ioctl::query_dv_timings(&session.device).map_err(|e| e.into_errno())
    }

    fn dv_timings_cap(&self, session: &mut Self::Session) -> IoctlResult<v4l2_dv_timings_cap> {
        v4l2r::ioctl::dv_timings_cap(&session.device).map_err(|e| e.into_errno())
    }

    fn enum_freq_bands(
        &self,
        session: &mut Self::Session,
        tuner: u32,
        type_: TunerType,
        index: u32,
    ) -> IoctlResult<v4l2_frequency_band> {
        v4l2r::ioctl::enum_freq_bands(&session.device, tuner, type_, index)
            .map_err(|e| e.into_errno())
    }

    fn query_ext_ctrl(
        &mut self,
        session: &mut Self::Session,
        id: CtrlId,
        flags: QueryCtrlFlags,
    ) -> IoctlResult<v4l2_query_ext_ctrl> {
        v4l2r::ioctl::query_ext_ctrl::<v4l2_query_ext_ctrl>(&session.device, id, flags)
            .map_err(|e| e.into_errno())
    }
}

impl<Q, M, HM, P, Reader, Writer> VirtioMediaDevice<Reader, Writer> for V4l2ProxyDevice<Q, M, HM, P>
where
    Q: VirtioMediaEventQueue,
    M: VirtioMediaGuestMemoryMapper,
    HM: VirtioMediaHostMemoryMapper,
    P: SessionPoller,
    Reader: std::io::Read,
    Writer: std::io::Write,
{
    type Session = V4l2Session<M>;

    fn new_session(&mut self, session_id: u32) -> Result<Self::Session, i32> {
        match V4l2Device::open(&self.device_path, DeviceConfig::new().non_blocking_dqbuf()) {
            Ok(device) => {
                let session = V4l2Session::new(session_id, Arc::new(device));
                match self.session_poller.add_session(&session.device, session.id) {
                    Ok(()) => Ok(session),
                    Err(e) => {
                        error!("failed to add FD of new V4L2 session for polling: {}", e);
                        Err(e)
                    }
                }
            }
            Err(DeviceOpenError::OpenError(e)) => Err(e as i32),
            Err(DeviceOpenError::QueryCapError(QueryCapError::IoctlError(e))) => Err(e as i32),
        }
    }

    fn close_session(&mut self, session: Self::Session) {
        self.delete_session(&session)
    }

    fn do_mmap(
        &mut self,
        session: &mut Self::Session,
        flags: u32,
        offset: u64,
        writer: &mut Writer,
    ) -> IoResult<()> {
        let rw = (flags & VIRTIO_MEDIA_MMAP_FLAG_RW) != 0;

        let plane_info = match self.mmap_buffers.get_mut(&offset) {
            Some(plane_info) => plane_info,
            None => return writer.write_err_response(libc::EINVAL),
        };

        // Export the FD for the plane and cache it if needed.
        let exported_fd = match &mut plane_info.exported_fd {
            Some(fd) => fd,
            None => {
                let fd = match v4l2r::ioctl::expbuf::<File>(
                    &session.device,
                    plane_info.queue,
                    plane_info.index as usize,
                    plane_info.plane as usize,
                    if rw {
                        ExpbufFlags::RDWR
                    } else {
                        ExpbufFlags::RDONLY
                    },
                ) {
                    Ok(desc) => desc,
                    Err(e) => return writer.write_err_response(e.into_errno()),
                };

                plane_info.exported_fd.get_or_insert(fd)
            }
        };

        plane_info.map_address = match self.mmap_manager.create_mapping(
            offset,
            exported_fd,
            plane_info.length as u64,
            rw,
        ) {
            Ok(guest_addr) => guest_addr,
            Err(e) => return writer.write_err_response(e),
        };

        writer.write_response(MmapResp::ok(
            plane_info.map_address,
            plane_info.length as u64,
        ))
    }

    fn do_munmap(&mut self, guest_addr: u64, writer: &mut Writer) -> IoResult<()> {
        match self.mmap_manager.remove_mapping(guest_addr) {
            Ok(has_mappings) => {
                // Free the exported handle if this was the last mapping.
                if !has_mappings {
                    if let Some(entry) = self
                        .mmap_buffers
                        .iter_mut()
                        .map(|(_, entry)| entry)
                        .find(|entry| entry.map_address == guest_addr)
                    {
                        entry.exported_fd = None
                    };
                }

                writer.write_response(MunmapResp::ok())
            }
            Err(e) => writer.write_err_response(e),
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
}
