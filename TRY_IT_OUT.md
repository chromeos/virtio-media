# Trying out virtio-media

This document demonstrates how to quickly try virtio-media by controlling a
virtual host device through a Debian guest image using the
[crosvm](https://crosvm.dev/book/) VMM.

Through this document, we will build and run the following components:

- A guest Linux kernel with virtio-media support enabled
- The virtio-media guest kernel module
- A Debian guest image with v4l-utils installed
- Crosvm with virtio-media support

## Prerequisites

- A C compiler toolchain
- The [Rust toolchain](https://rustup.rs/) version 1.75 or later
- The `virt-builder utility` (usually available in the `libguestfs-tools`
  package)

## Directory Setup

Create a workspace directory and get into it:

```console
mkdir virtio_media_playground
cd virtio_media_playground
```

This directory can be erased in order to remove everything we will build here.

## Guest Kernel Image

The virtio-media guest driver works with a regular mainline Linux kernel, as
long as the required virtio and V4L2 options are enabled.

1. Clone the kernel repository:

   ```console
   git clone --branch virtio-media --depth=2 https://github.com/Gnurou/linux
   cd linux
   ```

   This branch is just a regular Linux mainline release with a commit on top
   that adds the configuration we will use.

2. Build the kernel:

   ```console
   mkdir build_virtio_media
   make O=build_virtio_media virtio_crosvm_defconfig
   make O=build_virtio_media -j16 bzImage modules
   ```

   (Adjust `-j16` to match your number of CPU cores)

## Virtio-media Guest Kernel Module

1. Clone the virtio-media repository:

   ```console
   cd ..  # Back to the workspace root
   git clone https://github.com/chromeos/virtio-media
   cd virtio-media/driver
   ```

2. Build the module:

   ```console
   make -C ../../linux/build_virtio_media/ M=$PWD
   ```

## Guest System Image

Create the Debian image:

```console
cd ../..  # Back to the workspace root
virt-builder debian-12 \
  --install v4l-utils \
  --root-password password:"" \
  --mkdir /root/vmedia \
  --append-line '/etc/fstab:vmedia /root/vmedia virtiofs'
```

This command does the following:

- Download a Debian 12 image,
- Install the `v4l-utils` package into it,
- Set the root password to be empty,
- Ensures that the shared virtiofs filesystem labeled `vmedia` (that we will use
  to share the host directory containing the virtio-media kernel module) is
  mounted into `/root/vmedia`.

## Crosvm

1. Clone and checkout the crosvm branch containing the work-in-progress
   virtio-media support:

   ```console
   git clone --depth=1 https://chromium.googlesource.com/crosvm/crosvm
   cd crosvm
   git fetch --depth=10 origin refs/changes/29/5065329/9
   git checkout FETCH_HEAD
   git submodule update --init
   ```

2. Build the crosvm binary:

   ```console
   cargo build --release --features "media"
   ```

If everything goes well, the binary should be in `target/release/crosvm`, and we
now are ready to run our VM and try out some virtual media devices!

## Start the VM

```console
cd ..  # Back to the workspace root
./crosvm/target/release/crosvm run \
  linux/build_virtio_media/arch/x86/boot/bzImage \
  --rwdisk debian-12.img \
  -p "root=/dev/vda1" \
  --shared-dir "$PWD/virtio-media:vmedia:type=fs" \
  --simple-media
```

This command does the following:

- Start the kernel image we built,
- Adds the Debian guest image as a virtual disk,
- Passes the kernel parameter to use this virtual disk as root partition,
- Shares the folder containing the virtio-media kernel module as a virtiofs
  filesystem labeled `vmedia`,
- Adds a simple, dummy virtio-media test device that is entirely emulated in
  crosvm.

You should see the system booting. After a few seconds, press `<enter>` to get
the login prompt. Login as `root` with an empty password.

We will now want to insert the `virtio-media` kernel module:

```console
insmod /root/vmedia/driver/virtio-media.ko
```

## Test the Virtual Device

The simple virtio-media device should have been detected and become visible as
`/dev/video0`. Let's see if it works:

```console
v4l2-compliance -d0 -s
```

This should display a long list of tests ending with:

```console
...
Total for virtio_media device /dev/video0: 54, Succeeded: 54, Failed: 0, Warnings: 1
```

We can also check its supported capture formats:

```console
v4l2-ctl -d0 --list-formats
```

Which informs us that our device only supports `RGB3`:

```console
ioctl: VIDIOC_ENUM_FMT
        Type: Video Capture

        [0]: 'RGB3' (24-bit RGB 8-8-8)
```

And we can also capture frames from it:

```console
v4l2-ctl -d0 --stream-mmap --stream-count 30 --stream-to /root/vmedia/simple.rgb
```

This writes 30 640x480 RGB frames (all filled with a single color) into the
`simple.rgb` file of our `virtio-media` directory on the host. You can visualize
the output using a dedicated tool like [YUView](https://github.com/IENT/YUView).

That's enough for this simple example. Next we will see how to proxy a V4L2
device on the host into the guest. Let's exit the guest:

```console
poweroff
```

## Proxy a host V4L2 device into a guest

This next example uses virtio-media's V4L2 proxy device to make a host V4L2
device visible almost as-is into a guest. We will need a working V4L2 device on
the host, for this example we will assume a regular USB camera using the
`uvcvideo` driver. With the camera plugged, use `v4l2-ctl` on the host to find
out the number of the device:

```console
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

```console
./crosvm/target/release/crosvm run \
  linux/build_virtio_media/arch/x86/boot/bzImage \
  --rwdisk debian-12.img \
  -p "root=/dev/vda1" \
  --shared-dir "$PWD/virtio-media:vmedia:type=fs" \
  --v4l2-proxy /dev/video0
```

The `/dev/video0` assumes that the `-d0` argument of `v4l2-ctl` returned the
right device - adjust the argument for the actual device on your host.

With the guest booted, we can insert the `v4l2-media` module again:

```console
insmod /root/vmedia/driver/virtio-media.ko
```

And check that our device is indeed recognized:

```console
v4l2-ctl -d0 --info
```

This should return sensibly the same output as when the command was run on the
host, with the exception that the driver name is now `virtio_media`.

Most USB cameras support streaming into motion-JPEG, so let's try to capture a
stream:

```console
v4l2-ctl -d0 --stream-mmap --set-fmt-video pixelformat=MJPG --stream-to /root/vmedia/out.mpg
```

Use `Ctrl-C` to stop the capture. The stream has been recorded into the
directory shared with the host, so let's exit the guest in order to check it
out:

```console
poweroff
```

Then on the host, use your media player of choice to view the captured file:

```console
ffplay virtio-media/out.mpg
```
