// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Since the wire format of virtio-media uses little-endian, a host using the same ordering does
//! not need to perform any swapping - hence the definitions here are no-ops.

use v4l2r::bindings;

use crate::io::LeWrapper;
use crate::CloseCmd;
use crate::CmdHeader;
use crate::DequeueBufferEvent;
use crate::ErrorEvent;
use crate::IoctlCmd;
use crate::MmapCmd;
use crate::MmapResp;
use crate::MunmapCmd;
use crate::MunmapResp;
use crate::OpenCmd;
use crate::OpenResp;
use crate::RespHeader;
use crate::SessionEvent;
use crate::SgEntry;

/// Trait for types that can be sent as part of the virtio-media protocol.
pub trait VmediaType: Sized {
    fn to_le(self) -> LeWrapper<Self> {
        LeWrapper(self)
    }
    fn from_le(le: LeWrapper<Self>) -> Self {
        le.0
    }
}

impl VmediaType for () {}
impl VmediaType for u32 {}
impl VmediaType for i32 {}

impl VmediaType for CmdHeader {}
impl VmediaType for RespHeader {}
impl VmediaType for OpenCmd {}
impl VmediaType for OpenResp {}
impl VmediaType for CloseCmd {}
impl VmediaType for IoctlCmd {}
impl VmediaType for SgEntry {}
impl VmediaType for MmapCmd {}
impl VmediaType for MmapResp {}
impl VmediaType for MunmapCmd {}
impl VmediaType for MunmapResp {}
impl VmediaType for DequeueBufferEvent {}
impl VmediaType for SessionEvent {}
impl VmediaType for ErrorEvent {}

impl VmediaType for bindings::v4l2_buffer {}
impl VmediaType for bindings::v4l2_standard {}
impl VmediaType for bindings::v4l2_input {}
impl VmediaType for bindings::v4l2_control {}
impl VmediaType for bindings::v4l2_std_id {}
impl VmediaType for bindings::v4l2_tuner {}
impl VmediaType for bindings::v4l2_audio {}
impl VmediaType for bindings::v4l2_plane {}
impl VmediaType for bindings::v4l2_format {}
impl VmediaType for bindings::v4l2_enc_idx {}
impl VmediaType for bindings::v4l2_output {}
impl VmediaType for bindings::v4l2_audioout {}
impl VmediaType for bindings::v4l2_modulator {}
impl VmediaType for bindings::v4l2_frequency {}
impl VmediaType for bindings::v4l2_frmsizeenum {}
impl VmediaType for bindings::v4l2_frmivalenum {}
impl VmediaType for bindings::v4l2_encoder_cmd {}
impl VmediaType for bindings::v4l2_decoder_cmd {}
impl VmediaType for bindings::v4l2_dv_timings {}
impl VmediaType for bindings::v4l2_event_subscription {}
impl VmediaType for bindings::v4l2_create_buffers {}
impl VmediaType for bindings::v4l2_selection {}
impl VmediaType for bindings::v4l2_enum_dv_timings {}
impl VmediaType for bindings::v4l2_dv_timings_cap {}
impl VmediaType for bindings::v4l2_frequency_band {}
impl VmediaType for bindings::v4l2_query_ext_ctrl {}
impl VmediaType for bindings::v4l2_queryctrl {}
impl VmediaType for bindings::v4l2_querymenu {}
impl VmediaType for bindings::v4l2_ext_control {}
impl VmediaType for bindings::v4l2_ext_controls {}
impl VmediaType for bindings::v4l2_fmtdesc {}
impl VmediaType for bindings::v4l2_requestbuffers {}
impl VmediaType for bindings::v4l2_streamparm {}
