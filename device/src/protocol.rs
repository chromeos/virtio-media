// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use enumn::N;
use v4l2r::bindings::v4l2_event;
use v4l2r::ioctl::V4l2Buffer;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

pub const VIRTIO_ID_MEDIA: u32 = 48;

const VIRTIO_MEDIA_CARD_NAME_LEN: usize = 32;
#[derive(Debug, AsBytes)]
#[repr(C)]
pub struct VirtioMediaDeviceConfig {
    /// The device_caps field of struct video_device.
    pub device_caps: u32,
    /// The vfl_devnode_type of the device.
    pub device_type: u32,
    /// The `card` field of v4l2_capability.
    pub card: [u8; VIRTIO_MEDIA_CARD_NAME_LEN],
}

impl AsRef<[u8]> for VirtioMediaDeviceConfig {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub const VIRTIO_MEDIA_CMD_OPEN: u32 = 1;
pub const VIRTIO_MEDIA_CMD_CLOSE: u32 = 2;
pub const VIRTIO_MEDIA_CMD_IOCTL: u32 = 3;
pub const VIRTIO_MEDIA_CMD_MMAP: u32 = 4;
pub const VIRTIO_MEDIA_CMD_MUNMAP: u32 = 5;

pub const VIRTIO_MEDIA_MMAP_FLAG_RW: u32 = 1 << 0;

#[derive(PartialEq, Eq, PartialOrd, Ord, N, Clone, Copy, Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum V4l2Ioctl {
    VIDIOC_QUERYCAP = 0,
    VIDIOC_ENUM_FMT = 2,
    VIDIOC_G_FMT = 4,
    VIDIOC_S_FMT = 5,
    VIDIOC_REQBUFS = 8,
    VIDIOC_QUERYBUF = 9,
    VIDIOC_G_FBUF = 10,
    VIDIOC_S_FBUF = 11,
    VIDIOC_OVERLAY = 14,
    VIDIOC_QBUF = 15,
    VIDIOC_EXPBUF = 16,
    VIDIOC_DQBUF = 17,
    VIDIOC_STREAMON = 18,
    VIDIOC_STREAMOFF = 19,
    VIDIOC_G_PARM = 21,
    VIDIOC_S_PARM = 22,
    VIDIOC_G_STD = 23,
    VIDIOC_S_STD = 24,
    VIDIOC_ENUMSTD = 25,
    VIDIOC_ENUMINPUT = 26,
    VIDIOC_G_CTRL = 27,
    VIDIOC_S_CTRL = 28,
    VIDIOC_G_TUNER = 29,
    VIDIOC_S_TUNER = 30,
    VIDIOC_G_AUDIO = 33,
    VIDIOC_S_AUDIO = 34,
    VIDIOC_QUERYCTRL = 36,
    VIDIOC_QUERYMENU = 37,
    VIDIOC_G_INPUT = 38,
    VIDIOC_S_INPUT = 39,
    VIDIOC_G_EDID = 40,
    VIDIOC_S_EDID = 41,
    VIDIOC_G_OUTPUT = 46,
    VIDIOC_S_OUTPUT = 47,
    VIDIOC_ENUMOUTPUT = 48,
    VIDIOC_G_AUDOUT = 49,
    VIDIOC_S_AUDOUT = 50,
    VIDIOC_G_MODULATOR = 54,
    VIDIOC_S_MODULATOR = 55,
    VIDIOC_G_FREQUENCY = 56,
    VIDIOC_S_FREQUENCY = 57,
    VIDIOC_CROPCAP = 58,
    VIDIOC_G_CROP = 59,
    VIDIOC_S_CROP = 60,
    VIDIOC_G_JPEGCOMP = 61,
    VIDIOC_S_JPEGCOMP = 62,
    VIDIOC_QUERYSTD = 63,
    VIDIOC_TRY_FMT = 64,
    VIDIOC_ENUMAUDIO = 65,
    VIDIOC_ENUMAUDOUT = 66,
    VIDIOC_G_PRIORITY = 67,
    VIDIOC_S_PRIORITY = 68,
    VIDIOC_G_SLICED_VBI_CAP = 69,
    VIDIOC_LOG_STATUS = 70,
    VIDIOC_G_EXT_CTRLS = 71,
    VIDIOC_S_EXT_CTRLS = 72,
    VIDIOC_TRY_EXT_CTRLS = 73,
    VIDIOC_ENUM_FRAMESIZES = 74,
    VIDIOC_ENUM_FRAMEINTERVALS = 75,
    VIDIOC_G_ENC_INDEX = 76,
    VIDIOC_ENCODER_CMD = 77,
    VIDIOC_TRY_ENCODER_CMD = 78,
    VIDIOC_DBG_S_REGISTER = 79,
    VIDIOC_DBG_G_REGISTER = 80,
    VIDIOC_S_HW_FREQ_SEEK = 82,
    VIDIOC_S_DV_TIMINGS = 87,
    VIDIOC_G_DV_TIMINGS = 88,
    VIDIOC_DQEVENT = 89,
    VIDIOC_SUBSCRIBE_EVENT = 90,
    VIDIOC_UNSUBSCRIBE_EVENT = 91,
    VIDIOC_CREATE_BUFS = 92,
    VIDIOC_PREPARE_BUF = 93,
    VIDIOC_G_SELECTION = 94,
    VIDIOC_S_SELECTION = 95,
    VIDIOC_DECODER_CMD = 96,
    VIDIOC_TRY_DECODER_CMD = 97,
    VIDIOC_ENUM_DV_TIMINGS = 98,
    VIDIOC_QUERY_DV_TIMINGS = 99,
    VIDIOC_DV_TIMINGS_CAP = 100,
    VIDIOC_ENUM_FREQ_BANDS = 101,
    VIDIOC_DBG_G_CHIP_INFO = 102,
    VIDIOC_QUERY_EXT_CTRL = 103,
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct SgEntry {
    pub start: u64,
    pub len: u32,
    __padding: u32,
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct CmdHeader {
    pub cmd: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, AsBytes)]
pub struct RespHeader {
    pub errno: i32,
    _padding: u32,
}

impl RespHeader {
    pub fn ok() -> Self {
        Self {
            errno: 0,
            _padding: 0,
        }
    }

    pub fn err(errno: i32) -> Self {
        Self { errno, _padding: 0 }
    }
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct OpenCmd {}

#[repr(C)]
#[derive(Debug, AsBytes)]
pub struct OpenResp {
    hdr: RespHeader,
    session_id: u32,
    _padding: u32,
}

impl OpenResp {
    pub fn ok(session_id: u32) -> Self {
        Self {
            hdr: RespHeader::ok(),
            session_id,
            _padding: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct CloseCmd {
    pub session_id: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct IoctlCmd {
    pub session_id: u32,
    pub code: u32,
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct MmapCmd {
    pub session_id: u32,
    pub flags: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Debug, AsBytes)]
pub struct MmapResp {
    hdr: RespHeader,
    driver_addr: u64,
    len: u64,
}

impl MmapResp {
    pub fn ok(addr: u64, len: u64) -> Self {
        Self {
            hdr: RespHeader::ok(),
            driver_addr: addr,
            len,
        }
    }
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct MunmapCmd {
    pub driver_addr: u64,
}

#[repr(C)]
#[derive(Debug, AsBytes)]
pub struct MunmapResp {
    hdr: RespHeader,
}

impl MunmapResp {
    pub fn ok() -> Self {
        Self {
            hdr: RespHeader::ok(),
        }
    }
}

pub const VIRTIO_MEDIA_EVENT_ERROR: u32 = 0;
pub const VIRTIO_MEDIA_EVENT_DQBUF: u32 = 1;
pub const VIRTIO_MEDIA_EVENT_EVENT: u32 = 2;

#[repr(C)]
#[derive(Debug, AsBytes)]
pub struct EventHeader {
    event: u32,
    session_id: u32,
}

impl EventHeader {
    pub fn new(event: u32, session_id: u32) -> Self {
        Self { event, session_id }
    }
}

#[repr(C)]
#[derive(Debug, AsBytes)]
pub struct ErrorEvent {
    hdr: EventHeader,
    errno: i32,
    _padding: u32,
}

impl ErrorEvent {
    pub fn new(session_id: u32, errno: i32) -> Self {
        Self {
            hdr: EventHeader::new(VIRTIO_MEDIA_EVENT_ERROR, session_id),
            errno,
            _padding: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DequeueBufferEvent {
    hdr: EventHeader,
    v4l2_buffer: V4l2Buffer,
}

impl DequeueBufferEvent {
    pub fn new(session_id: u32, v4l2_buffer: V4l2Buffer) -> Self {
        Self {
            hdr: EventHeader::new(VIRTIO_MEDIA_EVENT_DQBUF, session_id),
            v4l2_buffer,
        }
    }
}

#[repr(C)]
pub struct SessionEvent {
    pub hdr: EventHeader,
    v4l2_event: v4l2_event,
}

impl SessionEvent {
    pub fn new(session_id: u32, v4l2_event: v4l2_event) -> Self {
        Self {
            hdr: EventHeader::new(VIRTIO_MEDIA_EVENT_EVENT, session_id),
            v4l2_event,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum V4l2Event {
    Error(ErrorEvent),
    DequeueBuffer(DequeueBufferEvent),
    Event(SessionEvent),
}
