// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This crate contains host-side helpers to write virtio-media devices and full devices
//! implementations.
//!
//! Both helpers and devices are VMM-independent and rely on a handful of traits being implemented
//! to operate on a given VMM. This means that implementing a specific device, and adding support
//! for all virtio-media devices on a given VMM, are two completely orthogonal tasks. Adding
//! support for a VMM makes all the devices relying on this crate available. Conversely, writing a
//! new device using this crate makes it available to all supported VMMs.
//!
//! # Traits to implement by the VMM
//!
//! * Descriptor chains must implement `Read` and `Write` on their device-readable and
//! device-writable parts, respectively. This allows devices to read commands and writes responses.
//! * The event queue must implement the `VirtioMediaEventQueue` trait to allow devices to send
//! events to the guest.
//! * The guest memory must be made accessible through an implementation of
//! `VirtioMediaGuestMemoryMapper`.
//! * Optionally, .... can be implemented if the host supports mapping MMAP buffers into the guest
//! address space.
//!
//! These traits allow any device that implements `VirtioMediaDevice` to run on any VMM that
//! implements them.
//!
//! # Anatomy of a device
//!
//! Devices implement `VirtioMediaDevice` to provide ways to create and close sessions, and to make
//! MMAP buffers visible to the guest (if supported). They also typically implement
//! `VirtioMediaIoctlHandler` and make use of `virtio_media_dispatch_ioctl` to handle ioctls
//! simply.
//!
//! The VMM then uses `VirtioMediaDeviceRunner` in order to ask it to process a command whenever
//! one arrives on the command queue.
//!
//! By following this pattern, devices never need to care about deserializing and validating the
//! virtio-media protocol. Instead, their relevant methods are invoked when needed, on validated
//! input, while protocol errors are handled upstream in a way that is consistent for all devices.
//!
//! The devices currently in this crate are:
//!
//! * A device that proxies any host V4L2 device into the guest, in the `crate::v4l2_device_proxy`
//! module.

pub mod devices;
pub mod ioctl;
pub mod mmap;
pub mod protocol;

use std::collections::HashMap;
use std::fs::File;
use std::io::Result as IoResult;

use anyhow::Context;
use log::error;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use protocol::*;

/// Extension trait for reading objects from the device-readable section of a descriptor chain.
pub trait ReadDescriptorChain {
    fn read_obj<T: FromBytes>(&mut self) -> std::io::Result<T>;
}

/// Any implementor of `Read` can be used to read virtio-media commands.
impl<R> ReadDescriptorChain for R
where
    R: std::io::Read,
{
    fn read_obj<T: FromBytes>(&mut self) -> std::io::Result<T> {
        let mut obj = std::mem::MaybeUninit::uninit();
        // Safe because the slice boundaries cover `obj`, and the slice doesn't outlive it.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, std::mem::size_of::<T>())
        };

        self.read_exact(slice)?;

        // Safe because obj can be initialized from an array of bytes.
        Ok(unsafe { obj.assume_init() })
    }
}

/// Extension trait for writing objects and responses into the device-writable section of a
/// descriptor chain.
pub trait WriteDescriptorChain {
    /// Write an arbitrary object to the guest.
    fn write_obj<T: AsBytes>(&mut self, obj: &T) -> IoResult<()>;

    /// Write a command response to the guest.
    fn write_response<T: AsBytes>(&mut self, response: T) -> IoResult<()> {
        self.write_obj(&response)
    }

    /// Send `code` as the error code of an error response.
    fn write_err_response(&mut self, code: libc::c_int) -> IoResult<()> {
        self.write_response(RespHeader::err(code))
    }
}

/// Any implementor of `Write` can be used to write virtio-media responses.
impl<W> WriteDescriptorChain for W
where
    W: std::io::Write,
{
    fn write_obj<T: AsBytes>(&mut self, obj: &T) -> IoResult<()> {
        self.write_all(obj.as_bytes())
    }
}

/// Trait for reading objects from a reader, e.g. the device-readable section of a descriptor
/// chain.
pub trait FromDescriptorChain {
    fn read_from_chain<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>
    where
        Self: Sized;
}

/// Trait for writing objects to a writer, e.g. the device-writable section of a descriptor chain.
pub trait ToDescriptorChain {
    fn write_to_chain<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

/// Trait for sending V4L2 events to the driver.
pub trait VirtioMediaEventQueue {
    /// Wait until an event descriptor becomes available and send `event` to the guest.
    fn send_event(&mut self, event: V4l2Event);

    /// Wait until an event descriptor becomes available and send `errno` as an error event to the
    /// guest.
    fn send_error(&mut self, session_id: u32, errno: i32) {
        self.send_event(V4l2Event::Error(ErrorEvent::new(session_id, errno)));
    }
}

/// Trait enabling guest memory linear access for the device.
///
/// Although the host can access the guest memory, it sometimes need to have a linear view of
/// sparse areas. This trait provides a way to perform such mappings.
///
/// Note to devices: [`VirtioMediaGuestMemoryMapper::GuestMemoryMapping`] instances must be held
/// for as long as the device might access the memory to avoid race conditions, as some
/// implementations might e.g. write back into the guest memory at destruction time.
pub trait VirtioMediaGuestMemoryMapper {
    /// Host-side linear mapping of sparse guest memory.
    type GuestMemoryMapping: AsRef<[u8]> + AsMut<[u8]>;

    /// Maps `sgs`, which contains a list of guest-physical SG entries into a linear mapping on the
    /// host.
    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyhow::Result<Self::GuestMemoryMapping>;
}

/// Trait for mapping host buffers into the guest physical address space.
///
/// An VMM-side implementation of this trait is needed in order to map `MMAP` buffers into the
/// guest.
///
/// If the functionality is not needed, `()` can be passed in place of an implementor of this
/// trait. It will return `ENOTTY` to each `mmap` attempt, effectively disabling the ability to
/// map `MMAP` buffers into the guest.
pub trait VirtioMediaHostMemoryMapper {
    /// Maps `length` bytes of host memory starting at `offset` and backed by `buffer` into the
    /// guest address space.
    ///
    /// Returns the guest physical address of the start of the mapped memory on success, or a
    /// `libc` error code in case of failure.
    fn add_mapping(&mut self, buffer: File, length: u64, offset: u64, rw: bool)
        -> Result<u64, i32>;

    /// Removes a guest mapping previously created at guest physical memory address `guest_addr`.
    fn remove_mapping(&mut self, guest_addr: u64) -> Result<(), i32>;
}

/// No-op implementation of `VirtioMediaHostMemoryMapper`. Can be used for testing purposes or when
/// it is not needed to map `MMAP` buffers into the guest.
impl VirtioMediaHostMemoryMapper for () {
    fn add_mapping(&mut self, _: File, _: u64, _: u64, _: bool) -> Result<u64, i32> {
        Err(libc::ENOTTY)
    }

    fn remove_mapping(&mut self, _: u64) -> Result<(), i32> {
        Err(libc::ENOTTY)
    }
}

/// Trait for implementing virtio-media devices.
///
/// The preferred way to use this trait is to wrap implementations in a
/// [`VirtioMediaDeviceRunner`], which takes care of reading and dispatching commands. In addition,
/// [`ioctl::VirtioMediaIoctlHandler`] should also be used to automatically parse and dispatch
/// ioctls.
pub trait VirtioMediaDevice<Reader: std::io::Read, Writer: std::io::Write> {
    type Session;

    /// Create a new session which ID is `session_id`.
    ///
    /// The error value returned is the error code to send back to the guest.
    fn new_session(&mut self, session_id: u32) -> Result<Self::Session, i32>;
    /// Close the passed session.
    fn close_session(&mut self, session: Self::Session);

    /// Perform the IOCTL command and write the response into `writer`.
    ///
    /// The flow for performing a given `ioctl` is to read the parameters from `reader`, perform
    /// the operation, and then write the result on `writer`. Events triggered by a given ioctl can
    /// be queued on `evt_queue`.
    ///
    /// Only returns an error if the response could not be properly written ; all other errors are
    /// propagated to the guest and considered normal operation from the host's point of view.
    ///
    /// The recommended implementation of this method is to just invoke
    /// `virtio_media_dispatch_ioctl` on an implementation of `VirtioMediaIoctlHandler`, so all the
    /// details of ioctl parsing and validation are taken care of by this crate.
    fn do_ioctl(
        &mut self,
        session: &mut Self::Session,
        ioctl: V4l2Ioctl,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> IoResult<()>;

    /// Performs the MMAP command and write the response into `writer`.
    ///
    /// Only returns an error if the response could not be properly written ; all other errors are
    /// propagated to the guest.
    //
    // TODO flags should be a dedicated enum?
    fn do_mmap(
        &mut self,
        session: &mut Self::Session,
        flags: u32,
        offset: u64,
        writer: &mut Writer,
    ) -> IoResult<()>;
    /// Performs the MUNMAP command and write the response into `writer`.
    ///
    /// Only returns an error if the response could not be properly written ; all other errors are
    /// propagated to the guest.
    fn do_munmap(&mut self, guest_addr: u64, writer: &mut Writer) -> IoResult<()>;
}

/// Wrapping structure for a `VirtioMediaDevice` managing its sessions and providing methods for
/// processing its commands.
pub struct VirtioMediaDeviceRunner<Reader, Writer, Device>
where
    Reader: std::io::Read,
    Writer: std::io::Write,
    Device: VirtioMediaDevice<Reader, Writer>,
{
    pub device: Device,
    pub sessions: HashMap<u32, Device::Session>,
    session_id_counter: u32,
}

impl<Reader, Writer, Device> From<Device> for VirtioMediaDeviceRunner<Reader, Writer, Device>
where
    Reader: std::io::Read,
    Writer: std::io::Write,
    Device: VirtioMediaDevice<Reader, Writer>,
{
    fn from(device: Device) -> Self {
        Self {
            device,
            sessions: Default::default(),
            session_id_counter: 0,
        }
    }
}

impl<Reader, Writer, Device> VirtioMediaDeviceRunner<Reader, Writer, Device>
where
    Reader: std::io::Read,
    Writer: std::io::Write,
    Device: VirtioMediaDevice<Reader, Writer>,
{
    /// Handle a single command from the virtio queue.
    ///
    /// `reader` and `writer` are the device-readable and device-writable sections of the
    /// descriptor chain containing the command. After this method has returned, the caller is
    /// responsible for returning the used descriptor chain to the guest.
    ///
    /// This method never returns an error, as doing so would halt the worker thread. All errors
    /// are propagated to the guest, with the exception of errors triggered while writing the
    /// response which are logged on the host side.
    pub fn handle_command(&mut self, reader: &mut Reader, writer: &mut Writer) {
        let hdr: CmdHeader = match reader.read_obj() {
            Ok(hdr) => hdr,
            Err(e) => {
                error!("error while reading command header: {:#}", e);
                let _ = writer.write_err_response(libc::EINVAL);
                return;
            }
        };

        let res = match hdr.cmd {
            VIRTIO_MEDIA_CMD_OPEN => {
                let session_id = self.session_id_counter;

                match self.device.new_session(session_id) {
                    Ok(session) => {
                        self.session_id_counter += 1;
                        self.sessions.insert(session_id, session);
                        writer.write_response(OpenResp::ok(session_id))
                    }
                    Err(e) => writer.write_err_response(e),
                }
                .context("while writing response for OPEN command")
            }
            .context("while writing response for OPEN command"),
            VIRTIO_MEDIA_CMD_CLOSE => reader
                .read_obj()
                .context("while reading CLOSE command")
                .map(|CloseCmd { session_id, .. }| {
                    if let Some(session) = self.sessions.remove(&session_id) {
                        self.device.close_session(session);
                    }
                }),
            VIRTIO_MEDIA_CMD_IOCTL => reader
                .read_obj()
                .context("while reading IOCTL command")
                .and_then(|IoctlCmd { session_id, code }| {
                    match self.sessions.get_mut(&session_id) {
                        Some(session) => match V4l2Ioctl::n(code) {
                            Some(ioctl) => self.device.do_ioctl(session, ioctl, reader, writer),
                            None => {
                                error!("unknown ioctl code {}", code);
                                writer.write_err_response(libc::ENOTTY)
                            }
                        },
                        None => writer.write_err_response(libc::EINVAL),
                    }
                    .context("while writing response for IOCTL command")
                }),
            VIRTIO_MEDIA_CMD_MMAP => reader
                .read_obj()
                .context("while reading MMAP command")
                .and_then(
                    |MmapCmd {
                         session_id,
                         flags,
                         offset,
                     }| {
                        match self.sessions.get_mut(&session_id) {
                            Some(session) => self.device.do_mmap(session, flags, offset, writer),

                            None => writer.write_err_response(libc::EINVAL),
                        }
                        .context("while writing response for MMAP command")
                    },
                ),
            VIRTIO_MEDIA_CMD_MUNMAP => reader
                .read_obj()
                .context("while reading UNMMAP command")
                .and_then(|MunmapCmd { guest_addr }| {
                    self.device
                        .do_munmap(guest_addr, writer)
                        .context("while writing response for MUNMAP command")
                }),
            _ => writer
                .write_err_response(libc::ENOTTY)
                .context("while writing error response for invalid command"),
        };

        if let Err(e) = res {
            error!("error while processing command: {:#}", e);
            let _ = writer.write_err_response(libc::EINVAL);
        }
    }

    /// Returns the device this runner has been created from.
    pub fn into_device(self) -> Device {
        self.device
    }
}
