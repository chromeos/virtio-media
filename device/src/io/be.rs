// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

std::compile_error!("Big-endian hosts are not supported yet");

pub trait VmediaType: Sized {
    fn to_le(self) -> LeWrapper<Self>;

    fn from_le(le: LeWrapper<Self>) -> Self {
        // Assume endianness conversion is symmetrical, which is should be.
        self.0.to_le().0
    }
}
