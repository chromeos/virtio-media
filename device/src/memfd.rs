// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a simple memory allocator using `memfd`. The `MemFd` crate provides the same
//! functionality, but also pulls some unwanted dependencies in, so we use this simple
//! implementation instead.

use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::RawFd;

use nix::errno::Errno;
use nix::sys::memfd::memfd_create;
use nix::sys::memfd::MemFdCreateFlag;
use thiserror::Error;

/// A chunk of memory allocated through `memfd`.
///
/// Buffers allocated this way are of fixed size, and can be manipulated as files.
pub struct MemFdBuffer {
    file: File,
}

#[derive(Debug, Error)]
pub enum NewMemFdBufferError {
    #[error("call to memfd_create failed: {0}")]
    FailedToCreate(#[from] Errno),
    #[error("failed to set size of memfd: {0}")]
    FailedToSetSize(io::Error),
    #[error("failed to seal memfd: {0}")]
    FailedToSeal(io::Error),
}

impl MemFdBuffer {
    pub fn new(size: u64) -> Result<Self, NewMemFdBufferError> {
        // Dummy name, we may want to support names for debugging purposes.
        let fd = memfd_create(c"", MemFdCreateFlag::MFD_ALLOW_SEALING)?;

        let file: File = fd.into();

        // Allocate requested size.
        file.set_len(size)
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

        Ok(Self { file })
    }

    pub const fn as_file(&self) -> &File {
        &self.file
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
