# FFmpeg software decoder device for virtio-media

This crate contains a virtio-media decoder device implementation that performs
decoding in software using the host's FFmpeg library. It provides an easy way to
try virtio-media without any specific hardware, as well as an example
implementation for a decoder device.

## Features

- Decoding of H.264, VP8, VP9, HEVC.
- Supported output formats: NV12.

## Building

The device should be added to your VMM like any other virtio-media device. At
build time, the `build.rs` script will attempt to detect the host's FFmpeg
libraries, run `bindgen` on then to create its wrapper, and link against them.

This crate provides its own FFmpeg bindings - 3rdparty ones were considered, but
unfortunately I could not get any to build reliably.

## Limitations

This is still a bit of a work-in-progress, although FFmpeg in the guest works
reliably using the `v4l2m2m` series of codecs. Support for more output formats
and a code cleanup are in order.
