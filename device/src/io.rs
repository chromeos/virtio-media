// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Traits and implementations for reading virtio-media commands from and writing responses to
//! virtio descriptors.
//!
//! Virtio-media requires data send through virtqueues to be in little-endian order, but there is
//! no guarantee that the host also uses the same endianness. The [`VmediaType`] trait needs to be
//! implemented for all types transiting through virtio in order to ensure they are converted
//! from/to the correct representation if needed.
//!
//! Commands and responses can be read and written from any type implementing [`std::io::Read`] or
//! [`std::io::Write`] respectively. The [`ReadFromDescriptorChain`] and [`WriteToDescriptorChain`]
//! sealed extension traits are the only way to write or read data from virtio descriptors. They
//! ensure that transiting data is always in little-endian representation by using [`VmediaType`]
//! to wrap it into [`LeWrapper`].

use std::io::Result as IoResult;
use std::mem::MaybeUninit;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

#[cfg(target_endian = "little")]
mod le;
#[cfg(target_endian = "little")]
pub use le::*;

#[cfg(target_endian = "big")]
mod be;
#[cfg(target_endian = "big")]
pub use be::*;

use crate::RespHeader;

/// Seals for [`ReadFromDescriptorChain`] and [`WriteToDescriptorChain`] so no new implementations can
/// be created outside of this crate.
mod private {
    pub trait RSealed {}
    impl<R> RSealed for R where R: std::io::Read {}

    pub trait WSealed {}
    impl<W> WSealed for W where W: std::io::Write {}
}

/// Extension trait for reading objects from the device-readable section of a descriptor chain,
/// converting them from little-endian to the native endianness of the system.
pub trait ReadFromDescriptorChain: private::RSealed {
    fn read_obj<T: VmediaType>(&mut self) -> std::io::Result<T>;
}

/// Any implementor of [`std::io::Read`] can be used to read virtio-media commands.
impl<R> ReadFromDescriptorChain for R
where
    R: std::io::Read,
{
    fn read_obj<T: VmediaType>(&mut self) -> std::io::Result<T> {
        // We use `zeroed` instead of `uninit` because `read_exact` cannot be called with
        // uninitialized memory. Since `T` implements `FromBytes`, its zeroed form is valid and
        // initialized.
        let mut obj: MaybeUninit<LeWrapper<T>> = std::mem::MaybeUninit::zeroed();
        // Safe because the slice boundaries cover `obj`, and the slice doesn't outlive it.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, std::mem::size_of::<T>())
        };

        self.read_exact(slice)?;

        // Safe because obj can be initialized from an array of bytes.
        Ok(unsafe { obj.assume_init() }.into_native())
    }
}

/// Extension trait for writing objects and responses into the device-writable section of a
/// descriptor chain, after converting them to little-endian representation.
pub trait WriteToDescriptorChain: private::WSealed {
    /// Write an arbitrary object to the guest.
    fn write_obj<T: VmediaType>(&mut self, obj: T) -> IoResult<()>;

    /// Write a command response to the guest.
    fn write_response<T: VmediaType>(&mut self, response: T) -> IoResult<()> {
        self.write_obj(response)
    }

    /// Send `code` as the error code of an error response.
    fn write_err_response(&mut self, code: libc::c_int) -> IoResult<()> {
        self.write_response(RespHeader::err(code))
    }
}

/// Any implementor of [`std::io::Write`] can be used to write virtio-media responses.
impl<W> WriteToDescriptorChain for W
where
    W: std::io::Write,
{
    fn write_obj<T: VmediaType>(&mut self, obj: T) -> IoResult<()> {
        self.write_all(obj.to_le().as_bytes())
    }
}

/// Private wrapper for all types that can be sent/received over virtio. Wrapped objects are
/// guaranteed to use little-endian representation.
///
/// Wrapped objects are inaccessible and can only be passed to methods writing to virtio
/// descriptors. [`Self::into_native`] can be used to retrieve the object in its native ordering.
#[repr(transparent)]
pub struct LeWrapper<T: VmediaType>(T);

impl<T: VmediaType> LeWrapper<T> {
    /// Convert the wrapped object back to native ordering and return it.
    pub fn into_native(self) -> T {
        T::from_le(self)
    }
}

unsafe impl<T: VmediaType> FromZeroes for LeWrapper<T> {
    fn only_derive_is_allowed_to_implement_this_trait() {}
}

unsafe impl<T: VmediaType> FromBytes for LeWrapper<T> {
    fn only_derive_is_allowed_to_implement_this_trait() {}
}

unsafe impl<T: VmediaType> AsBytes for LeWrapper<T> {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}
