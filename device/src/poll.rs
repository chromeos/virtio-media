// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::fd::BorrowedFd;

/// Trait allowing sessions of a device to signal when they have an event pending.
///
/// The worker that runs a `V4l2ProxyDevice` typically polls on file descriptors for available
/// CAPTURE buffers and outstanding session events. However V4L2's poll logic returns with the
/// `POLLERR` flag if a CAPTURE queue is polled while not streaming or if zero CAPTURE buffers have
/// been queued. To avoid this, the device needs to disable polling when this would happen, and
/// re-enable it when conditions are adequate.
///
/// If the worker does not need such a feature, `()` can be passed as a no-op type that implements
/// this interface.
pub trait SessionPoller: Clone {
    /// Add a newly created `session` to be polled.
    ///
    /// The `session` FD must signal that it is readable if there are events pending for the
    /// session.
    fn add_session(&self, session: BorrowedFd, session_id: u32) -> Result<(), i32>;
    /// Stop polling all activity on `session`.
    fn remove_session(&self, session: BorrowedFd);
}

/// No-op implementation of `SessionPoller`. This should only be used when using
/// `VirtioMediaDeviceRunner` with a device that doesn't need to be polled, otherwise the methods
/// might be called, which will make the program panic.
impl SessionPoller for () {
    fn add_session(&self, _session: BorrowedFd, _session_id: u32) -> Result<(), i32> {
        panic!("this device needs a proper SessionPoller - aborting")
    }

    fn remove_session(&self, _session: BorrowedFd) {
        panic!("this device needs a proper SessionPoller - aborting")
    }
}
