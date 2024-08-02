// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a simple memory allocator using `memfd`. The `MemFd` crate provides the same
//! functionality, but also pulls some unwanted dependencies in, so we use this simple
//! implementation instead.

use core::slice;
use std::fs::File;
use std::io;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::RawFd;
use std::ptr::NonNull;

use nix::errno::Errno;
use nix::sys::memfd::memfd_create;
use nix::sys::memfd::MemFdCreateFlag;
use nix::sys::mman;
use thiserror::Error;

/// A chunk of memory allocated through `memfd`.
///
/// Buffers allocated this way are of fixed size, and can be manipulated as files.
pub struct MemFdBuffer {
    file: File,
    size: NonZeroU64,
}

#[derive(Debug, Error)]
pub enum NewMemFdBufferError {
    #[error("MemFdBuffer size cannot be zero")]
    ZeroSize,
    #[error("call to memfd_create failed: {0}")]
    FailedToCreate(#[from] Errno),
    #[error("failed to set size of memfd: {0}")]
    FailedToSetSize(io::Error),
    #[error("failed to seal memfd: {0}")]
    FailedToSeal(io::Error),
}

#[derive(Debug, Error)]
pub enum MemFdMmapError {
    #[error("buffer size {0} larger than usize")]
    BufferTooLarge(u64),
    #[error("mmap call returned error: {0}")]
    Mmap(#[from] Errno),
}

impl MemFdBuffer {
    pub fn new(size: u64) -> Result<Self, NewMemFdBufferError> {
        let size = NonZeroU64::new(size).ok_or(NewMemFdBufferError::ZeroSize)?;

        // Dummy name, we may want to support names for debugging purposes.
        let fd = memfd_create(c"", MemFdCreateFlag::MFD_ALLOW_SEALING)?;

        let file: File = fd.into();

        // Allocate requested size.
        file.set_len(size.into())
            .map_err(NewMemFdBufferError::FailedToSetSize)?;

        // Seal so the memory size cannot be changed.
        //
        // SAFETY: `file` is a valid file.
        if unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(NewMemFdBufferError::FailedToSeal(io::Error::last_os_error()));
        }

        Ok(Self { file, size })
    }

    pub fn as_file(&self) -> &File {
        &self.file
    }

    pub fn mmap(&self) -> Result<MemFdMapping, MemFdMmapError> {
        let size = NonZeroUsize::try_from(self.size)
            .map_err(|_| MemFdMmapError::BufferTooLarge(self.size.into()))?;

        // SAFETY: `self.file` is a valid file.
        let data = unsafe {
            mman::mmap(
                None,
                size,
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED,
                &self.file,
                0,
            )?
        };

        Ok(MemFdMapping {
            // SAFETY: `data` is non-null and obtained through a `mmap` of size `self.size`.
            data: unsafe { slice::from_raw_parts_mut(data.as_ptr().cast(), size.into()) },
        })
    }
}

impl AsFd for MemFdBuffer {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl AsRawFd for MemFdBuffer {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl From<MemFdBuffer> for File {
    fn from(memfd: MemFdBuffer) -> Self {
        memfd.file
    }
}

/// A CPU mapping of a `MemFdBuffer`.
pub struct MemFdMapping {
    // A mapping remains valid until we munmap it, that is, until the
    // PlaneMapping object is deleted. Hence the static lifetime.
    data: &'static mut [u8],
}

impl MemFdMapping {
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl Drop for MemFdMapping {
    fn drop(&mut self) {
        // Safe because the pointer and length were constructed in mmap() and
        // are always valid.
        unsafe {
            mman::munmap(
                NonNull::new_unchecked(self.data.as_mut_ptr().cast()),
                self.data.len(),
            )
        }
        .unwrap_or_else(|e| {
            log::error!("error while unmapping MemFdBuffer: {:#}", e);
        });
    }
}

impl AsRef<[u8]> for MemFdMapping {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

impl AsMut<[u8]> for MemFdMapping {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data
    }
}
