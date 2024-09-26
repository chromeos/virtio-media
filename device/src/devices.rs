// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio-media host devices.
//!
//! This module contains some host-side devices implementations that any VMM can use as long as it
//! provides implementations of the required traits.
//!
//! The conditions for using these devices are as follows:
//!
//! * [`std::io::Read`] and [`std::io::Write`] implementations for the device-readable and
//!   device-writable sections of the descriptor chain,
//! * An implementation of [`crate::VirtioMediaEventQueue`], so devices can send events to the guest,
//! * For devices that need to access guest memory linearly, an implementation of
//!   [`crate::VirtioMediaGuestMemoryMapper`].
//! * For devices that need to map host memory into the guest, an implementation of
//!   [`crate::VirtioMediaHostMemoryMapper`].
//!
//! [simple_device] implements a simple capture device that generates frames in software. It can be
//! used as a reference for how to write devices, or as a way to test the guest without any
//! specific hardware on the host.
//!
//! [v4l2_device_proxy] proxies any host V4L2 device to the guest, making its functionality
//! available to the guest with minimal overhead.

#[cfg(feature = "simple-device")]
pub mod simple_device;
#[cfg(feature = "simple-device")]
pub use simple_device::SimpleCaptureDevice;

pub mod v4l2_device_proxy;
pub use v4l2_device_proxy::V4l2ProxyDevice;

pub mod video_decoder;
