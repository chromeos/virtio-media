// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Result as IoResult;

use v4l2r::bindings::v4l2_audio;
use v4l2r::bindings::v4l2_audioout;
use v4l2r::bindings::v4l2_buffer;
use v4l2r::bindings::v4l2_control;
use v4l2r::bindings::v4l2_create_buffers;
use v4l2r::bindings::v4l2_decoder_cmd;
use v4l2r::bindings::v4l2_dv_timings;
use v4l2r::bindings::v4l2_dv_timings_cap;
use v4l2r::bindings::v4l2_enc_idx;
use v4l2r::bindings::v4l2_encoder_cmd;
use v4l2r::bindings::v4l2_enum_dv_timings;
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
use v4l2r::bindings::v4l2_plane;
use v4l2r::bindings::v4l2_query_ext_ctrl;
use v4l2r::bindings::v4l2_queryctrl;
use v4l2r::bindings::v4l2_querymenu;
use v4l2r::bindings::v4l2_rect;
use v4l2r::bindings::v4l2_requestbuffers;
use v4l2r::bindings::v4l2_selection;
use v4l2r::bindings::v4l2_standard;
use v4l2r::bindings::v4l2_std_id;
use v4l2r::bindings::v4l2_streamparm;
use v4l2r::bindings::v4l2_tuner;
use v4l2r::ioctl::AudioMode;
use v4l2r::ioctl::CtrlId;
use v4l2r::ioctl::CtrlWhich;
use v4l2r::ioctl::EventType as V4l2EventType;
use v4l2r::ioctl::QueryCtrlFlags;
use v4l2r::ioctl::SelectionFlags;
use v4l2r::ioctl::SelectionTarget;
use v4l2r::ioctl::SelectionType;
use v4l2r::ioctl::SubscribeEventFlags;
use v4l2r::ioctl::TunerMode;
use v4l2r::ioctl::TunerTransmissionFlags;
use v4l2r::ioctl::TunerType;
use v4l2r::ioctl::UncheckedV4l2Buffer;
use v4l2r::ioctl::V4l2Buffer;
use v4l2r::ioctl::V4l2PlanesWithBacking;
use v4l2r::memory::MemoryType;
use v4l2r::QueueDirection;
use v4l2r::QueueType;

use crate::io::ReadFromDescriptorChain;
use crate::io::VmediaType;
use crate::io::WriteToDescriptorChain;
use crate::protocol::RespHeader;
use crate::protocol::SgEntry;
use crate::protocol::V4l2Ioctl;

/// Reads a SG list of guest physical addresses passed from the driver and returns it.
fn get_userptr_regions<R: ReadFromDescriptorChain>(
    r: &mut R,
    size: usize,
) -> anyhow::Result<Vec<SgEntry>> {
    let mut bytes_taken = 0;
    let mut res = Vec::new();

    while bytes_taken < size {
        let sg_entry = r.read_obj::<SgEntry>()?;
        bytes_taken += sg_entry.len as usize;
        res.push(sg_entry);
    }

    Ok(res)
}

/// Local trait for reading simple or complex objects from a reader, e.g. the device-readable
/// section of a descriptor chain.
trait FromDescriptorChain {
    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> std::io::Result<Self>
    where
        Self: Sized;
}

/// Implementation for simple objects that can be returned as-is after their endianness is
/// fixed.
impl<T> FromDescriptorChain for T
where
    T: VmediaType,
{
    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> std::io::Result<Self> {
        reader.read_obj()
    }
}

/// Implementation to easily read a `v4l2_buffer` of `USERPTR` memory type and its associated
/// guest-side buffers from a descriptor chain.
impl FromDescriptorChain for (V4l2Buffer, Vec<Vec<SgEntry>>) {
    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> IoResult<Self>
    where
        Self: Sized,
    {
        let v4l2_buffer = reader.read_obj::<v4l2_buffer>()?;
        let queue = match QueueType::n(v4l2_buffer.type_) {
            Some(queue) => queue,
            None => return Err(std::io::ErrorKind::InvalidData.into()),
        };

        let v4l2_planes = if queue.is_multiplanar() && v4l2_buffer.length > 0 {
            if v4l2_buffer.length > v4l2r::bindings::VIDEO_MAX_PLANES {
                return Err(std::io::ErrorKind::InvalidData.into());
            }

            let planes: [v4l2r::bindings::v4l2_plane; v4l2r::bindings::VIDEO_MAX_PLANES as usize] =
                (0..v4l2_buffer.length as usize)
                    .map(|_| reader.read_obj::<v4l2_plane>())
                    .collect::<IoResult<Vec<_>>>()?
                    .into_iter()
                    .chain(std::iter::repeat(Default::default()))
                    .take(v4l2r::bindings::VIDEO_MAX_PLANES as usize)
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            Some(planes)
        } else {
            None
        };

        let v4l2_buffer = V4l2Buffer::try_from(UncheckedV4l2Buffer(v4l2_buffer, v4l2_planes))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;

        // Read the `MemRegion`s of all planes if the buffer is `USERPTR`.
        let guest_regions = if let V4l2PlanesWithBacking::UserPtr(planes) =
            v4l2_buffer.planes_with_backing_iter()
        {
            planes
                .filter(|p| *p.length > 0)
                .map(|p| {
                    get_userptr_regions(reader, *p.length as usize)
                        .map_err(|_| std::io::ErrorKind::InvalidData.into())
                })
                .collect::<IoResult<Vec<_>>>()?
        } else {
            vec![]
        };

        Ok((v4l2_buffer, guest_regions))
    }
}

/// Implementation to easily read a `v4l2_ext_controls` struct, its array of controls, and the SG
/// list of the buffers pointed to by the controls from a descriptor chain.
impl FromDescriptorChain for (v4l2_ext_controls, Vec<v4l2_ext_control>, Vec<Vec<SgEntry>>) {
    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        let ctrls = reader.read_obj::<v4l2_ext_controls>()?;

        let ctrl_array = (0..ctrls.count)
            .map(|_| reader.read_obj::<v4l2_ext_control>())
            .collect::<IoResult<Vec<_>>>()?;

        // Read all the payloads.
        let mem_regions = ctrl_array
            .iter()
            .filter(|ctrl| ctrl.size > 0)
            .map(|ctrl| {
                get_userptr_regions(reader, ctrl.size as usize)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
            })
            .collect::<IoResult<Vec<_>>>()?;

        Ok((ctrls, ctrl_array, mem_regions))
    }
}

/// Local trait for writing simple or complex objects to a writer, e.g. the device-writable section
/// of a descriptor chain.
trait ToDescriptorChain {
    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()>;
}

/// Implementation for simple objects that can be written as-is after their endianness is
/// fixed.
impl<T> ToDescriptorChain for T
where
    T: VmediaType,
{
    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()> {
        writer.write_obj(self)
    }
}

/// Implementation to easily write a `v4l2_buffer` to a descriptor chain, while ensuring the number
/// of planes written is not larger than a limit (i.e. the maximum number of planes that the
/// descriptor chain can receive).
impl ToDescriptorChain for (V4l2Buffer, usize) {
    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()> {
        let mut v4l2_buffer = *self.0.as_v4l2_buffer();
        // If the buffer is multiplanar, nullify the `planes` pointer to avoid leaking host
        // addresses.
        if self.0.queue().is_multiplanar() {
            v4l2_buffer.m.planes = std::ptr::null_mut();
        }
        writer.write_obj(v4l2_buffer)?;

        // Write plane information if the buffer is multiplanar. Limit the number of planes to the
        // upper bound we were given.
        for plane in self.0.as_v4l2_planes().iter().take(self.1) {
            writer.write_obj(*plane)?;
        }

        Ok(())
    }
}

/// Implementation to easily write a `v4l2_ext_controls` struct and its array of controls to a
/// descriptor chain.
impl ToDescriptorChain for (v4l2_ext_controls, Vec<v4l2_ext_control>) {
    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()> {
        let (ctrls, ctrl_array) = self;
        let mut ctrls = ctrls;

        // Nullify the control pointer to avoid leaking host addresses.
        ctrls.controls = std::ptr::null_mut();
        writer.write_obj(ctrls)?;

        for ctrl in ctrl_array {
            writer.write_obj(ctrl)?;
        }

        Ok(())
    }
}

/// Returns `ENOTTY` to signal that an ioctl is not handled by this device.
macro_rules! unhandled_ioctl {
    () => {
        Err(libc::ENOTTY)
    };
}

pub type IoctlResult<T> = Result<T, i32>;

/// Trait for implementing ioctls supported by a device.
///
/// It provides a default implementation for all ioctls that returns the error code for an
/// unsupported ioctl (`ENOTTY`) to the driver. This means that a device just needs to implement
/// this trait and override the ioctls it supports in order to provide the expected behavior. All
/// parsing and input validation is done by the companion function [`virtio_media_dispatch_ioctl`].
#[allow(unused_variables)]
pub trait VirtioMediaIoctlHandler {
    type Session;

    fn enum_fmt(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<v4l2_fmtdesc> {
        unhandled_ioctl!()
    }
    fn g_fmt(&mut self, session: &Self::Session, queue: QueueType) -> IoctlResult<v4l2_format> {
        unhandled_ioctl!()
    }
    /// Hook for the `VIDIOC_S_FMT` ioctl.
    ///
    /// `queue` is guaranteed to match `format.type_`.
    fn s_fmt(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        unhandled_ioctl!()
    }
    fn reqbufs(
        &mut self,
        session: &mut Self::Session,
        queue: QueueType,
        memory: MemoryType,
        count: u32,
    ) -> IoctlResult<v4l2_requestbuffers> {
        unhandled_ioctl!()
    }
    fn querybuf(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        index: u32,
    ) -> IoctlResult<V4l2Buffer> {
        unhandled_ioctl!()
    }

    // TODO qbuf needs a better structure to represent a buffer and its potential guest buffers.
    fn qbuf(
        &mut self,
        session: &mut Self::Session,
        buffer: V4l2Buffer,
        guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<V4l2Buffer> {
        unhandled_ioctl!()
    }

    // TODO expbuf

    fn streamon(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        unhandled_ioctl!()
    }
    fn streamoff(&mut self, session: &mut Self::Session, queue: QueueType) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn g_parm(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
    ) -> IoctlResult<v4l2_streamparm> {
        unhandled_ioctl!()
    }
    fn s_parm(
        &mut self,
        session: &mut Self::Session,
        parm: v4l2_streamparm,
    ) -> IoctlResult<v4l2_streamparm> {
        unhandled_ioctl!()
    }

    fn g_std(&mut self, session: &Self::Session) -> IoctlResult<v4l2_std_id> {
        unhandled_ioctl!()
    }

    fn s_std(&mut self, session: &mut Self::Session, std: v4l2_std_id) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn enumstd(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_standard> {
        unhandled_ioctl!()
    }

    fn enuminput(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_input> {
        unhandled_ioctl!()
    }

    fn g_ctrl(&mut self, session: &Self::Session, id: u32) -> IoctlResult<v4l2_control> {
        unhandled_ioctl!()
    }

    fn s_ctrl(
        &mut self,
        session: &mut Self::Session,
        id: u32,
        value: i32,
    ) -> IoctlResult<v4l2_control> {
        unhandled_ioctl!()
    }

    fn g_tuner(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_tuner> {
        unhandled_ioctl!()
    }

    fn s_tuner(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        mode: TunerMode,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn g_audio(&mut self, session: &Self::Session) -> IoctlResult<v4l2_audio> {
        unhandled_ioctl!()
    }

    fn s_audio(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        mode: Option<AudioMode>,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn queryctrl(
        &mut self,
        session: &Self::Session,
        id: CtrlId,
        flags: QueryCtrlFlags,
    ) -> IoctlResult<v4l2_queryctrl> {
        unhandled_ioctl!()
    }

    fn querymenu(
        &mut self,
        session: &Self::Session,
        id: u32,
        index: u32,
    ) -> IoctlResult<v4l2_querymenu> {
        unhandled_ioctl!()
    }

    fn g_input(&mut self, session: &Self::Session) -> IoctlResult<i32> {
        unhandled_ioctl!()
    }

    fn s_input(&mut self, session: &mut Self::Session, input: i32) -> IoctlResult<i32> {
        unhandled_ioctl!()
    }

    fn g_output(&mut self, session: &Self::Session) -> IoctlResult<i32> {
        unhandled_ioctl!()
    }

    fn s_output(&mut self, session: &mut Self::Session, output: i32) -> IoctlResult<i32> {
        unhandled_ioctl!()
    }

    fn enumoutput(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_output> {
        unhandled_ioctl!()
    }

    fn g_audout(&mut self, session: &Self::Session) -> IoctlResult<v4l2_audioout> {
        unhandled_ioctl!()
    }

    fn s_audout(&mut self, session: &mut Self::Session, index: u32) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn g_modulator(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_modulator> {
        unhandled_ioctl!()
    }

    fn s_modulator(
        &mut self,
        session: &mut Self::Session,
        index: u32,
        flags: TunerTransmissionFlags,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn g_frequency(&mut self, session: &Self::Session, tuner: u32) -> IoctlResult<v4l2_frequency> {
        unhandled_ioctl!()
    }

    fn s_frequency(
        &mut self,
        session: &mut Self::Session,
        tuner: u32,
        type_: TunerType,
        frequency: u32,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn querystd(&mut self, session: &Self::Session) -> IoctlResult<v4l2_std_id> {
        unhandled_ioctl!()
    }

    /// Hook for the `VIDIOC_TRY_FMT` ioctl.
    ///
    /// `queue` is guaranteed to match `format.type_`.
    fn try_fmt(
        &mut self,
        session: &Self::Session,
        queue: QueueType,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_format> {
        unhandled_ioctl!()
    }

    fn enumaudio(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_audio> {
        unhandled_ioctl!()
    }

    fn enumaudout(&mut self, session: &Self::Session, index: u32) -> IoctlResult<v4l2_audioout> {
        unhandled_ioctl!()
    }

    /// Ext control ioctls modify `ctrls` and `ctrl_array` in place instead of returning them.
    fn g_ext_ctrls(
        &mut self,
        session: &Self::Session,
        which: CtrlWhich,
        ctrls: &mut v4l2_ext_controls,
        ctrl_array: &mut Vec<v4l2_ext_control>,
        user_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }
    /// Ext control ioctls modify `ctrls` and `ctrl_array` in place instead of returning them.
    fn s_ext_ctrls(
        &mut self,
        session: &mut Self::Session,
        which: CtrlWhich,
        ctrls: &mut v4l2_ext_controls,
        ctrl_array: &mut Vec<v4l2_ext_control>,
        user_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }
    /// Ext control ioctls modify `ctrls` and `ctrl_array` in place instead of returning them.
    fn try_ext_ctrls(
        &mut self,
        session: &Self::Session,
        which: CtrlWhich,
        ctrls: &mut v4l2_ext_controls,
        ctrl_array: &mut Vec<v4l2_ext_control>,
        user_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn enum_framesizes(
        &mut self,
        session: &Self::Session,
        index: u32,
        pixel_format: u32,
    ) -> IoctlResult<v4l2_frmsizeenum> {
        unhandled_ioctl!()
    }

    fn enum_frameintervals(
        &mut self,
        session: &Self::Session,
        index: u32,
        pixel_format: u32,
        width: u32,
        height: u32,
    ) -> IoctlResult<v4l2_frmivalenum> {
        unhandled_ioctl!()
    }

    fn g_enc_index(&mut self, session: &Self::Session) -> IoctlResult<v4l2_enc_idx> {
        unhandled_ioctl!()
    }

    fn encoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: v4l2_encoder_cmd,
    ) -> IoctlResult<v4l2_encoder_cmd> {
        unhandled_ioctl!()
    }

    fn try_encoder_cmd(
        &mut self,
        session: &Self::Session,
        cmd: v4l2_encoder_cmd,
    ) -> IoctlResult<v4l2_encoder_cmd> {
        unhandled_ioctl!()
    }

    fn s_dv_timings(
        &mut self,
        session: &mut Self::Session,
        timings: v4l2_dv_timings,
    ) -> IoctlResult<v4l2_dv_timings> {
        unhandled_ioctl!()
    }

    fn g_dv_timings(&mut self, session: &Self::Session) -> IoctlResult<v4l2_dv_timings> {
        unhandled_ioctl!()
    }

    fn subscribe_event(
        &mut self,
        session: &mut Self::Session,
        event: V4l2EventType,
        flags: SubscribeEventFlags,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    fn unsubscribe_event(
        &mut self,
        session: &mut Self::Session,
        event: v4l2_event_subscription,
    ) -> IoctlResult<()> {
        unhandled_ioctl!()
    }

    /// `queue` and `memory` are validated versions of the information in `create_buffers`.
    ///
    /// `create_buffers` is modified in place and returned to the guest event in case of error.
    fn create_bufs(
        &mut self,
        session: &mut Self::Session,
        count: u32,
        queue: QueueType,
        memory: MemoryType,
        format: v4l2_format,
    ) -> IoctlResult<v4l2_create_buffers> {
        unhandled_ioctl!()
    }

    // TODO like qbuf, this needs a better structure to represent a buffer and its potential guest
    // buffers.
    fn prepare_buf(
        &mut self,
        session: &mut Self::Session,
        buffer: V4l2Buffer,
        guest_regions: Vec<Vec<SgEntry>>,
    ) -> IoctlResult<V4l2Buffer> {
        unhandled_ioctl!()
    }

    fn g_selection(
        &mut self,
        session: &Self::Session,
        sel_type: SelectionType,
        sel_target: SelectionTarget,
    ) -> IoctlResult<v4l2_rect> {
        unhandled_ioctl!()
    }

    fn s_selection(
        &mut self,
        session: &mut Self::Session,
        sel_type: SelectionType,
        sel_target: SelectionTarget,
        sel_rect: v4l2_rect,
        sel_flags: SelectionFlags,
    ) -> IoctlResult<v4l2_rect> {
        unhandled_ioctl!()
    }

    fn decoder_cmd(
        &mut self,
        session: &mut Self::Session,
        cmd: v4l2_decoder_cmd,
    ) -> IoctlResult<v4l2_decoder_cmd> {
        unhandled_ioctl!()
    }

    fn try_decoder_cmd(
        &mut self,
        session: &Self::Session,
        cmd: v4l2_decoder_cmd,
    ) -> IoctlResult<v4l2_decoder_cmd> {
        unhandled_ioctl!()
    }

    fn enum_dv_timings(
        &mut self,
        session: &Self::Session,
        index: u32,
    ) -> IoctlResult<v4l2_dv_timings> {
        unhandled_ioctl!()
    }

    fn query_dv_timings(&mut self, session: &Self::Session) -> IoctlResult<v4l2_dv_timings> {
        unhandled_ioctl!()
    }

    fn dv_timings_cap(&self, session: &Self::Session) -> IoctlResult<v4l2_dv_timings_cap> {
        unhandled_ioctl!()
    }

    fn enum_freq_bands(
        &self,
        session: &Self::Session,
        tuner: u32,
        type_: TunerType,
        index: u32,
    ) -> IoctlResult<v4l2_frequency_band> {
        unhandled_ioctl!()
    }

    fn query_ext_ctrl(
        &mut self,
        session: &Self::Session,
        id: CtrlId,
        flags: QueryCtrlFlags,
    ) -> IoctlResult<v4l2_query_ext_ctrl> {
        unhandled_ioctl!()
    }
}

/// Writes a `ENOTTY` error response into `writer` to signal that an ioctl is not implemented by
/// the device.
fn invalid_ioctl<W: WriteToDescriptorChain>(code: V4l2Ioctl, writer: &mut W) -> IoResult<()> {
    writer.write_err_response(libc::ENOTTY).map_err(|e| {
        log::error!(
            "failed to write error response for invalid ioctl {:?}: {:#}",
            code,
            e
        );
        e
    })
}

/// Implements a `WR` ioctl for which errors may also carry a payload.
///
/// * `Reader` is the reader to the device-readable part of the descriptor chain,
/// * `Writer` is the writer to the device-writable part of the descriptor chain,
/// * `I` is the data to be read from the descriptor chain,
/// * `O` is the type of response to be written to the descriptor chain for both success and
///   failure,
/// * `X` processes the input and produces a result. In case of failure, an error code and optional
///   payload to write along with it are returned.
fn wr_ioctl_with_err_payload<Reader, Writer, I, O, X>(
    ioctl: V4l2Ioctl,
    reader: &mut Reader,
    writer: &mut Writer,
    process: X,
) -> IoResult<()>
where
    Reader: ReadFromDescriptorChain,
    Writer: WriteToDescriptorChain,
    I: FromDescriptorChain,
    O: ToDescriptorChain,
    X: FnOnce(I) -> Result<O, (i32, Option<O>)>,
{
    let input = match I::read_from_chain(reader) {
        Ok(input) => input,
        Err(e) => {
            log::error!("error while reading input for {:?} ioctl: {:#}", ioctl, e);
            return writer.write_err_response(libc::EINVAL);
        }
    };

    let (resp_header, output) = match process(input) {
        Ok(output) => (RespHeader::ok(), Some(output)),
        Err((errno, output)) => (RespHeader::err(errno), output),
    };

    writer.write_response(resp_header)?;
    if let Some(output) = output {
        output.write_to_chain(writer)?;
    }

    Ok(())
}

/// Implements a `WR` ioctl for which errors do not carry a payload.
///
/// * `Reader` is the reader to the device-readable part of the descriptor chain,
/// * `Writer` is the writer to the device-writable part of the descriptor chain,
/// * `I` is the data to be read from the descriptor chain,
/// * `O` is the type of response to be written to the descriptor chain in case of success,
/// * `X` processes the input and produces a result. In case of failure, an error code to transmit
///   to the guest is returned.
fn wr_ioctl<Reader, Writer, I, O, X>(
    ioctl: V4l2Ioctl,
    reader: &mut Reader,
    writer: &mut Writer,
    process: X,
) -> IoResult<()>
where
    Reader: ReadFromDescriptorChain,
    Writer: WriteToDescriptorChain,
    I: FromDescriptorChain,
    O: ToDescriptorChain,
    X: FnOnce(I) -> Result<O, i32>,
{
    wr_ioctl_with_err_payload(ioctl, reader, writer, |input| {
        process(input).map_err(|err| (err, None))
    })
}

/// Implements a `W` ioctl.
///
/// * `Reader` is the reader to the device-readable part of the descriptor chain,
/// * `I` is the data to be read from the descriptor chain,
/// * `X` processes the input. In case of failure, an error code to transmit to the guest is
///   returned.
fn w_ioctl<Reader, Writer, I, X>(
    ioctl: V4l2Ioctl,
    reader: &mut Reader,
    writer: &mut Writer,
    process: X,
) -> IoResult<()>
where
    I: FromDescriptorChain,
    Reader: ReadFromDescriptorChain,
    Writer: WriteToDescriptorChain,
    X: FnOnce(I) -> Result<(), i32>,
{
    wr_ioctl(ioctl, reader, writer, process)
}

/// Implements a `R` ioctl.
///
/// * `Writer` is the writer to the device-writable part of the descriptor chain,
/// * `O` is the type of response to be written to the descriptor chain in case of success,
/// * `X` runs the ioctl and produces a result. In case of failure, an error code to transmit to
///   the guest is returned.
fn r_ioctl<Writer, O, X>(ioctl: V4l2Ioctl, writer: &mut Writer, process: X) -> IoResult<()>
where
    Writer: WriteToDescriptorChain,
    O: ToDescriptorChain,
    X: FnOnce() -> Result<O, i32>,
{
    wr_ioctl(ioctl, &mut std::io::empty(), writer, |()| process())
}

/// Ensures that the `readbuffers` and `writebuffers` members of a `v4l2_streamparm` are zero since
/// we do not expose the `READWRITE` capability.
fn patch_streamparm(mut parm: v4l2_streamparm) -> v4l2_streamparm {
    match QueueType::n(parm.type_)
        .unwrap_or(QueueType::VideoCapture)
        .direction()
    {
        QueueDirection::Output => parm.parm.output.writebuffers = 0,
        QueueDirection::Capture => parm.parm.capture.readbuffers = 0,
    }

    parm
}

/// IOCTL dispatcher for implementors of [`VirtioMediaIoctlHandler`].
///
/// This function takes care of reading and validating IOCTL inputs and writing outputs or errors
/// back to the driver, invoking the relevant method of the handler in the middle.
///
/// Implementors of [`VirtioMediaIoctlHandler`] can thus just focus on writing the desired behavior
/// for their device, and let the more tedious parsing and validation to this function.
pub fn virtio_media_dispatch_ioctl<S, H, Reader, Writer>(
    handler: &mut H,
    session: &mut S,
    ioctl: V4l2Ioctl,
    reader: &mut Reader,
    writer: &mut Writer,
) -> IoResult<()>
where
    H: VirtioMediaIoctlHandler<Session = S>,
    Reader: ReadFromDescriptorChain,
    Writer: WriteToDescriptorChain,
{
    use V4l2Ioctl::*;

    match ioctl {
        VIDIOC_QUERYCAP => invalid_ioctl(ioctl, writer),
        VIDIOC_ENUM_FMT => wr_ioctl(ioctl, reader, writer, |format: v4l2_fmtdesc| {
            let queue = QueueType::n(format.type_).ok_or(libc::EINVAL)?;
            handler.enum_fmt(session, queue, format.index)
        }),
        VIDIOC_G_FMT => wr_ioctl(ioctl, reader, writer, |format: v4l2_format| {
            let queue = QueueType::n(format.type_).ok_or(libc::EINVAL)?;
            handler.g_fmt(session, queue)
        }),
        VIDIOC_S_FMT => wr_ioctl(ioctl, reader, writer, |format: v4l2_format| {
            let queue = QueueType::n(format.type_).ok_or(libc::EINVAL)?;
            handler.s_fmt(session, queue, format)
        }),
        VIDIOC_REQBUFS => wr_ioctl(ioctl, reader, writer, |reqbufs: v4l2_requestbuffers| {
            let queue = QueueType::n(reqbufs.type_).ok_or(libc::EINVAL)?;
            let memory = MemoryType::n(reqbufs.memory).ok_or(libc::EINVAL)?;

            match memory {
                MemoryType::Mmap | MemoryType::UserPtr => (),
                t => {
                    log::error!(
                        "VIDIOC_REQBUFS: memory type {:?} is currently unsupported",
                        t
                    );
                    return Err(libc::EINVAL);
                }
            }

            handler.reqbufs(session, queue, memory, reqbufs.count)
        }),
        VIDIOC_QUERYBUF => {
            wr_ioctl(ioctl, reader, writer, |buffer: v4l2_buffer| {
                let queue = QueueType::n(buffer.type_).ok_or(libc::EINVAL)?;
                // Maximum number of planes we can write back to the driver.
                let num_planes = if queue.is_multiplanar() {
                    buffer.length as usize
                } else {
                    0
                };

                handler
                    .querybuf(session, queue, buffer.index)
                    .map(|guest_buffer| (guest_buffer, num_planes))
            })
        }
        VIDIOC_G_FBUF => invalid_ioctl(ioctl, writer),
        VIDIOC_S_FBUF => invalid_ioctl(ioctl, writer),
        VIDIOC_OVERLAY => invalid_ioctl(ioctl, writer),
        VIDIOC_QBUF => wr_ioctl(ioctl, reader, writer, |(guest_buffer, guest_regions)| {
            let num_planes = guest_buffer.num_planes();

            handler
                .qbuf(session, guest_buffer, guest_regions)
                .map(|guest_buffer| (guest_buffer, num_planes))
        }),
        // TODO implement EXPBUF.
        VIDIOC_EXPBUF => invalid_ioctl(ioctl, writer),
        VIDIOC_DQBUF => invalid_ioctl(ioctl, writer),
        VIDIOC_STREAMON => w_ioctl(ioctl, reader, writer, |input: u32| {
            let queue = QueueType::n(input).ok_or(libc::EINVAL)?;

            handler.streamon(session, queue)
        }),
        VIDIOC_STREAMOFF => w_ioctl(ioctl, reader, writer, |input: u32| {
            let queue = QueueType::n(input).ok_or(libc::EINVAL)?;

            handler.streamoff(session, queue)
        }),
        VIDIOC_G_PARM => wr_ioctl(ioctl, reader, writer, |parm: v4l2_streamparm| {
            let queue = QueueType::n(parm.type_).ok_or(libc::EINVAL)?;

            handler.g_parm(session, queue).map(patch_streamparm)
        }),
        VIDIOC_S_PARM => wr_ioctl(ioctl, reader, writer, |parm: v4l2_streamparm| {
            handler
                .s_parm(session, patch_streamparm(parm))
                .map(patch_streamparm)
        }),
        VIDIOC_G_STD => r_ioctl(ioctl, writer, || handler.g_std(session)),
        VIDIOC_S_STD => w_ioctl(ioctl, reader, writer, |id: v4l2_std_id| {
            handler.s_std(session, id)
        }),
        VIDIOC_ENUMSTD => wr_ioctl(ioctl, reader, writer, |std: v4l2_standard| {
            handler.enumstd(session, std.index)
        }),
        VIDIOC_ENUMINPUT => wr_ioctl(ioctl, reader, writer, |input: v4l2_input| {
            handler.enuminput(session, input.index)
        }),
        VIDIOC_G_CTRL => wr_ioctl(ioctl, reader, writer, |ctrl: v4l2_control| {
            handler.g_ctrl(session, ctrl.id)
        }),
        VIDIOC_S_CTRL => wr_ioctl(ioctl, reader, writer, |ctrl: v4l2_control| {
            handler.s_ctrl(session, ctrl.id, ctrl.value)
        }),
        VIDIOC_G_TUNER => wr_ioctl(ioctl, reader, writer, |tuner: v4l2_tuner| {
            handler.g_tuner(session, tuner.index)
        }),
        VIDIOC_S_TUNER => w_ioctl(ioctl, reader, writer, |tuner: v4l2_tuner| {
            let mode = TunerMode::n(tuner.audmode).ok_or(libc::EINVAL)?;
            handler.s_tuner(session, tuner.index, mode)
        }),
        VIDIOC_G_AUDIO => r_ioctl(ioctl, writer, || handler.g_audio(session)),
        VIDIOC_S_AUDIO => w_ioctl(ioctl, reader, writer, |input: v4l2_audio| {
            handler.s_audio(session, input.index, AudioMode::n(input.mode))
        }),
        VIDIOC_QUERYCTRL => wr_ioctl(ioctl, reader, writer, |input: v4l2_queryctrl| {
            let (id, flags) = v4l2r::ioctl::parse_ctrl_id_and_flags(input.id);

            handler.queryctrl(session, id, flags)
        }),
        VIDIOC_QUERYMENU => wr_ioctl(ioctl, reader, writer, |input: v4l2_querymenu| {
            handler.querymenu(session, input.id, input.index)
        }),
        VIDIOC_G_INPUT => r_ioctl(ioctl, writer, || handler.g_input(session)),
        VIDIOC_S_INPUT => wr_ioctl(ioctl, reader, writer, |input: i32| {
            handler.s_input(session, input)
        }),
        VIDIOC_G_EDID => invalid_ioctl(ioctl, writer),
        VIDIOC_S_EDID => invalid_ioctl(ioctl, writer),
        VIDIOC_G_OUTPUT => r_ioctl(ioctl, writer, || handler.g_output(session)),
        VIDIOC_S_OUTPUT => wr_ioctl(ioctl, reader, writer, |output: i32| {
            handler.s_output(session, output)
        }),
        VIDIOC_ENUMOUTPUT => wr_ioctl(ioctl, reader, writer, |output: v4l2_output| {
            handler.enumoutput(session, output.index)
        }),
        VIDIOC_G_AUDOUT => r_ioctl(ioctl, writer, || handler.g_audout(session)),
        VIDIOC_S_AUDOUT => w_ioctl(ioctl, reader, writer, |audout: v4l2_audioout| {
            handler.s_audout(session, audout.index)
        }),
        VIDIOC_G_MODULATOR => wr_ioctl(ioctl, reader, writer, |modulator: v4l2_modulator| {
            handler.g_modulator(session, modulator.index)
        }),
        VIDIOC_S_MODULATOR => w_ioctl(ioctl, reader, writer, |modulator: v4l2_modulator| {
            let flags =
                TunerTransmissionFlags::from_bits(modulator.txsubchans).ok_or(libc::EINVAL)?;
            handler.s_modulator(session, modulator.index, flags)
        }),
        VIDIOC_G_FREQUENCY => wr_ioctl(ioctl, reader, writer, |freq: v4l2_frequency| {
            handler.g_frequency(session, freq.tuner)
        }),
        VIDIOC_S_FREQUENCY => w_ioctl(ioctl, reader, writer, |freq: v4l2_frequency| {
            let type_ = TunerType::n(freq.type_).ok_or(libc::EINVAL)?;

            handler.s_frequency(session, freq.tuner, type_, freq.frequency)
        }),
        // TODO do these 3 need to be supported?
        VIDIOC_CROPCAP => invalid_ioctl(ioctl, writer),
        VIDIOC_G_CROP => invalid_ioctl(ioctl, writer),
        VIDIOC_S_CROP => invalid_ioctl(ioctl, writer),
        // Deprecated in V4L2.
        VIDIOC_G_JPEGCOMP => invalid_ioctl(ioctl, writer),
        // Deprecated in V4L2.
        VIDIOC_S_JPEGCOMP => invalid_ioctl(ioctl, writer),
        VIDIOC_QUERYSTD => r_ioctl(ioctl, writer, || handler.querystd(session)),
        VIDIOC_TRY_FMT => wr_ioctl(ioctl, reader, writer, |format: v4l2_format| {
            let queue = QueueType::n(format.type_).ok_or(libc::EINVAL)?;
            handler.try_fmt(session, queue, format)
        }),
        VIDIOC_ENUMAUDIO => wr_ioctl(ioctl, reader, writer, |audio: v4l2_audio| {
            handler.enumaudio(session, audio.index)
        }),
        VIDIOC_ENUMAUDOUT => wr_ioctl(ioctl, reader, writer, |audio: v4l2_audioout| {
            handler.enumaudout(session, audio.index)
        }),
        VIDIOC_G_PRIORITY => invalid_ioctl(ioctl, writer),
        VIDIOC_S_PRIORITY => invalid_ioctl(ioctl, writer),
        // TODO support this, although it's marginal.
        VIDIOC_G_SLICED_VBI_CAP => invalid_ioctl(ioctl, writer),
        // Doesn't make sense in a virtual context.
        VIDIOC_LOG_STATUS => invalid_ioctl(ioctl, writer),
        VIDIOC_G_EXT_CTRLS => wr_ioctl_with_err_payload(
            ioctl,
            reader,
            writer,
            |(mut ctrls, mut ctrl_array, user_regions)| {
                let which = CtrlWhich::try_from(&ctrls).map_err(|()| (libc::EINVAL, None))?;

                match handler.g_ext_ctrls(session, which, &mut ctrls, &mut ctrl_array, user_regions)
                {
                    Ok(()) => Ok((ctrls, ctrl_array)),
                    // It is very important what we write back the updated input in case
                    // of error as it contains extra information.
                    Err(e) => Err((e, Some((ctrls, ctrl_array)))),
                }
            },
        ),
        VIDIOC_S_EXT_CTRLS => wr_ioctl_with_err_payload(
            ioctl,
            reader,
            writer,
            |(mut ctrls, mut ctrl_array, user_regions)| {
                let which = CtrlWhich::try_from(&ctrls).map_err(|()| (libc::EINVAL, None))?;

                match handler.s_ext_ctrls(session, which, &mut ctrls, &mut ctrl_array, user_regions)
                {
                    Ok(()) => Ok((ctrls, ctrl_array)),
                    // It is very important what we write back the updated input in case
                    // of error as it contains extra information.
                    Err(e) => Err((e, Some((ctrls, ctrl_array)))),
                }
            },
        ),
        VIDIOC_TRY_EXT_CTRLS => wr_ioctl_with_err_payload(
            ioctl,
            reader,
            writer,
            |(mut ctrls, mut ctrl_array, user_regions)| {
                let which = CtrlWhich::try_from(&ctrls).map_err(|()| (libc::EINVAL, None))?;

                match handler.try_ext_ctrls(
                    session,
                    which,
                    &mut ctrls,
                    &mut ctrl_array,
                    user_regions,
                ) {
                    Ok(()) => Ok((ctrls, ctrl_array)),
                    // It is very important what we write back the updated input in case
                    // of error as it contains extra information.
                    Err(e) => Err((e, Some((ctrls, ctrl_array)))),
                }
            },
        ),
        VIDIOC_ENUM_FRAMESIZES => {
            wr_ioctl(ioctl, reader, writer, |frmsizeenum: v4l2_frmsizeenum| {
                handler.enum_framesizes(session, frmsizeenum.index, frmsizeenum.pixel_format)
            })
        }
        VIDIOC_ENUM_FRAMEINTERVALS => {
            wr_ioctl(ioctl, reader, writer, |frmivalenum: v4l2_frmivalenum| {
                handler.enum_frameintervals(
                    session,
                    frmivalenum.index,
                    frmivalenum.pixel_format,
                    frmivalenum.width,
                    frmivalenum.height,
                )
            })
        }
        VIDIOC_G_ENC_INDEX => r_ioctl(ioctl, writer, || handler.g_enc_index(session)),
        VIDIOC_ENCODER_CMD => wr_ioctl(ioctl, reader, writer, |cmd: v4l2_encoder_cmd| {
            handler.encoder_cmd(session, cmd)
        }),
        VIDIOC_TRY_ENCODER_CMD => wr_ioctl(ioctl, reader, writer, |cmd: v4l2_encoder_cmd| {
            handler.try_encoder_cmd(session, cmd)
        }),
        // Doesn't make sense in a virtual context.
        VIDIOC_DBG_G_REGISTER => invalid_ioctl(ioctl, writer),
        // Doesn't make sense in a virtual context.
        VIDIOC_DBG_S_REGISTER => invalid_ioctl(ioctl, writer),
        VIDIOC_S_HW_FREQ_SEEK => invalid_ioctl(ioctl, writer),
        VIDIOC_S_DV_TIMINGS => wr_ioctl(ioctl, reader, writer, |timings: v4l2_dv_timings| {
            handler.s_dv_timings(session, timings)
        }),
        VIDIOC_G_DV_TIMINGS => wr_ioctl(
            ioctl,
            reader,
            writer,
            // We are not using the input - this should probably have been a R ioctl?
            |_: v4l2_dv_timings| handler.g_dv_timings(session),
        ),
        // Supported by an event.
        VIDIOC_DQEVENT => invalid_ioctl(ioctl, writer),
        VIDIOC_SUBSCRIBE_EVENT => {
            w_ioctl(ioctl, reader, writer, |input: v4l2_event_subscription| {
                let event = V4l2EventType::try_from(&input).unwrap();
                let flags = SubscribeEventFlags::from_bits(input.flags).unwrap();

                handler.subscribe_event(session, event, flags)
            })?;

            Ok(())
        }
        VIDIOC_UNSUBSCRIBE_EVENT => {
            w_ioctl(ioctl, reader, writer, |event: v4l2_event_subscription| {
                handler.unsubscribe_event(session, event)
            })
        }
        VIDIOC_CREATE_BUFS => wr_ioctl(ioctl, reader, writer, |input: v4l2_create_buffers| {
            let queue = QueueType::n(input.format.type_).ok_or(libc::EINVAL)?;
            let memory = MemoryType::n(input.memory).ok_or(libc::EINVAL)?;

            handler.create_bufs(session, input.count, queue, memory, input.format)
        }),
        VIDIOC_PREPARE_BUF => wr_ioctl(ioctl, reader, writer, |(guest_buffer, guest_regions)| {
            let num_planes = guest_buffer.num_planes();

            handler
                .prepare_buf(session, guest_buffer, guest_regions)
                .map(|out_buffer| (out_buffer, num_planes))
        }),
        VIDIOC_G_SELECTION => wr_ioctl(ioctl, reader, writer, |mut selection: v4l2_selection| {
            let sel_type = SelectionType::n(selection.type_).ok_or(libc::EINVAL)?;
            let sel_target = SelectionTarget::n(selection.target).ok_or(libc::EINVAL)?;

            handler
                .g_selection(session, sel_type, sel_target)
                .map(|rect| {
                    selection.r = rect;
                    selection
                })
        }),
        VIDIOC_S_SELECTION => wr_ioctl(ioctl, reader, writer, |mut selection: v4l2_selection| {
            let sel_type = SelectionType::n(selection.type_).ok_or(libc::EINVAL)?;
            let sel_target = SelectionTarget::n(selection.target).ok_or(libc::EINVAL)?;
            let sel_flags = SelectionFlags::from_bits(selection.flags).ok_or(libc::EINVAL)?;

            handler
                .s_selection(session, sel_type, sel_target, selection.r, sel_flags)
                .map(|rect| {
                    selection.r = rect;
                    selection
                })
        }),
        VIDIOC_DECODER_CMD => wr_ioctl(ioctl, reader, writer, |cmd: v4l2_decoder_cmd| {
            handler.decoder_cmd(session, cmd)
        }),
        VIDIOC_TRY_DECODER_CMD => wr_ioctl(ioctl, reader, writer, |cmd: v4l2_decoder_cmd| {
            handler.try_decoder_cmd(session, cmd)
        }),
        VIDIOC_ENUM_DV_TIMINGS => wr_ioctl(
            ioctl,
            reader,
            writer,
            |mut enum_timings: v4l2_enum_dv_timings| {
                handler
                    .enum_dv_timings(session, enum_timings.index)
                    .map(|timings| {
                        enum_timings.timings = timings;
                        enum_timings
                    })
            },
        ),
        VIDIOC_QUERY_DV_TIMINGS => r_ioctl(ioctl, writer, || handler.query_dv_timings(session)),
        VIDIOC_DV_TIMINGS_CAP => wr_ioctl(ioctl, reader, writer, |_: v4l2_dv_timings_cap| {
            handler.dv_timings_cap(session)
        }),
        VIDIOC_ENUM_FREQ_BANDS => {
            wr_ioctl(ioctl, reader, writer, |freq_band: v4l2_frequency_band| {
                let type_ = TunerType::n(freq_band.type_).ok_or(libc::EINVAL)?;

                handler.enum_freq_bands(session, freq_band.tuner, type_, freq_band.index)
            })
        }
        // Doesn't make sense in a virtual context.
        VIDIOC_DBG_G_CHIP_INFO => invalid_ioctl(ioctl, writer),
        VIDIOC_QUERY_EXT_CTRL => wr_ioctl(ioctl, reader, writer, |ctrl: v4l2_query_ext_ctrl| {
            let (id, flags) = v4l2r::ioctl::parse_ctrl_id_and_flags(ctrl.id);
            handler.query_ext_ctrl(session, id, flags)
        }),
    }
}
