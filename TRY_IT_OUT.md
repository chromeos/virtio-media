# Trying out virtio-media

This document demonstrates how to quickly try virtio-media by controlling a
virtual host device through a Debian guest image using the
[crosvm](https://crosvm.dev/book/) VMM.

Through this document, we will build and run the following components:

- A guest Linux kernel with virtio-media support enabled
- A Debian guest image with v4l-utils installed
- Crosvm with virtio-media support

## Prerequisites

- A C compiler toolchain
- The [Rust toolchain](https://rustup.rs/) version 1.75 or later
- The `virt-builder` utility (usually available in the `guestfs-tools` package)
- The `virt-copy-out` and `virt-copy-in` tools (usually available in the
  `libguestfs` package)

## Directory Setup

Create a workspace directory and get into it:

```sh
mkdir virtio_media_playground
cd virtio_media_playground
```

This directory can be erased in order to remove everything we will build here.

## Guest Kernel Image with virtio-media Built-in

1. Clone the kernel repository on the right branch:

   ```sh
   git clone --branch b4/virtio-media --depth=2 https://github.com/Gnurou/linux
   cd linux
   ```

   This branch is just a regular Linux mainline release with a few commits on
   top that adds the configuration we will use, and the virtio-media driver.

2. Build the kernel:

   ```sh
   make virtio_media_defconfig
   make -j16 bzImage
   ```

   (Adjust `-j16` to match your number of CPU cores)

## Guest System Image

Create the Debian image:

```sh
cd ..  # Back to the workspace root
virt-builder debian-12 \
  --install v4l-utils \
  --root-password password:""
```

This command does the following:

- Download a Debian 12 image,
- Install the `v4l-utils` package into it,
- Set the root password to be empty,

## Crosvm

1. Clone and checkout the crosvm branch containing the work-in-progress
   virtio-media support:

   ```sh
   git clone --depth=1 https://chromium.googlesource.com/crosvm/crosvm
   cd crosvm
   git submodule update --init
   ```

2. Build the crosvm binary:

   ```sh
   cargo build --release --features "media"
   ```

If everything goes well, the binary should be in `target/release/crosvm`, and we
now are ready to run our VM and try out some virtual media devices!

## Start the VM

```sh
cd ..  # Back to the workspace root
./crosvm/target/release/crosvm run \
  linux/arch/x86/boot/bzImage \
  --disable-sandbox \
  --rwdisk debian-12.img \
  -p "root=/dev/vda1" \
  --simple-media-device
```

This command does the following:

- Boot the kernel image we built,
- Add the Debian guest image as a virtual disk,
- Pass the kernel parameter to use this virtual disk as root partition,
- Add a simple, dummy virtio-media test device that is entirely emulated in
  crosvm.

You should see the system booting. After a few seconds, press `<enter>` to get
the login prompt. Login as `root` with an empty password.

## Test the Virtual Device

The simple virtio-media device should have been detected and become visible as
`/dev/video0` in the guest. Let's see if it works:

```sh
v4l2-compliance -d0 -s
```

This should display a long list of tests ending with:

```console
...
Total for virtio_media device /dev/video0: 54, Succeeded: 54, Failed: 0, Warnings: 1
```

We can also check its supported capture formats:

```sh
v4l2-ctl -d0 --list-formats
```

Which informs us that our device only supports `RGB3`:

```console
ioctl: VIDIOC_ENUM_FMT
        Type: Video Capture

        [0]: 'RGB3' (24-bit RGB 8-8-8)
```

And we can also capture frames from it:

```sh
v4l2-ctl -d0 --stream-mmap --stream-count 30 --stream-to simple.rgb
```

This writes 30 640x480 RGB frames (all filled with a single color) into the
`simple.rgb` file.

That's enough for this simple example. Next we will see how to proxy a V4L2
device on the host into the guest. Let's exit the guest:

```sh
poweroff
```

If you want to visualize the file we generated, copy it out of the disk image:

```sh
virt-copy-out -a debian-12.img /root/simple.rgb .
```

You can then view it using a dedicated tool like
[YUView](https://github.com/IENT/YUView).

## Proxy a host V4L2 device into a guest

This next example uses virtio-media's V4L2 proxy device to make a host V4L2
device visible almost as-is into a guest. We will need a working V4L2 device on
the host, for this example we will assume a regular USB camera using the
`uvcvideo` driver. With the camera plugged, use `v4l2-ctl` on the host to find
out the number of the device:

```sh
v4l2-ctl -d0 --info
```

If the output lines look something like

```console
Driver Info:
        Driver name      : uvcvideo
        Card type        : <Camera name>
```

Then you have found the correct device. If not, replace `-d0` with `-d1`, `-d2`,
... until you find a device which driver name is `uvcvideo`.

Now that we have found the device, we can start `crosvm` with a proxy device for
it:

```sh
./crosvm/target/release/crosvm run \
  linux/arch/x86/boot/bzImage \
  --disable-sandbox \
  --rwdisk debian-12.img \
  -p "root=/dev/vda1" \
  --v4l2-proxy /dev/video0
```

The `/dev/video0` assumes that the `-d0` argument of `v4l2-ctl` returned the
right device - adjust the argument for the actual device on your host.

With the guest booted, we can check that our device is indeed recognized:

```sh
v4l2-ctl -d0 --info
```

This should return sensibly the same output as when the command was run on the
host, with the exception that the driver name is now `virtio_media`.

Most USB cameras support streaming into motion-JPEG, so let's try to capture a
stream:

```sh
v4l2-ctl -d0 --stream-mmap --set-fmt-video pixelformat=MJPG --stream-to out.mpg
```

Use `Ctrl-C` to stop the capture. The stream has been recorded into the
directory shared with the host, so let's exit the guest in order to check it
out:

```sh
poweroff
```

Then on the host, copy the file out of the guest image:

```sh
virt-copy-out -a debian-12.img /root/out.mpg .
```

And use your media player of choice to play it, e.g.:

```sh
ffplay out.mpg
```
