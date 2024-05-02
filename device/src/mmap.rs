// Copyright 2024 The ChromiumOS Authors

use std::os::fd::BorrowedFd;

use thiserror::Error;

use crate::VirtioMediaHostMemoryMapper;

#[derive(Debug, PartialEq, Eq)]
pub struct MmapBufferMapping {
    /// Number of times `mmap` has been performed for this buffer.
    num_mappings: usize,
    /// Guest address at which the buffer is currently mapped.
    guest_addr: u64,
    /// Whether the mapping of this buffer is read-only or read-write.
    rw: bool,
}

/// Information about a MMAP buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct MmapBuffer {
    /// Start offset in the MMAP range of this buffer.
    offset: u32,
    /// Size of the buffer.
    size: u32,
    /// Whether this buffer is still registered, i.e. hasn't been deleted by the driver.
    /// Unregistered buffers can still have active mappings, and are kept alive until their mapping
    /// count reaches zero. However such buffers cannot be mapped anymore and take no space in the
    /// MMAP range.
    registered: bool,
    /// Mapping information about this buffer, if the buffer is currently mapped into the guest.
    mapping: Option<MmapBufferMapping>,
}

impl MmapBuffer {
    /// Returns a new instance of `MmapBuffer` with the given parameters, zero mappings and
    /// a registered status.
    fn new(offset: u32, size: u32) -> Self {
        Self {
            offset,
            size,
            registered: true,
            mapping: None,
        }
    }
}

/// Range manager for MMAP buffers, using a host memory mapper.
///
/// Devices that allocate MMAP buffers can register a buffer using [`Self::register_buffer`] and
/// unregister them with [`Self::unregister_buffer`]. Registered buffers can then be mapped into the
/// guest address space by calling [`Self::create_mapping`] on their offset. This will return the address
/// of their guest mapping, which can then be accessed or used to unmap them with [`Self::remove_mapping`].
pub struct MmapMappingManager<M: VirtioMediaHostMemoryMapper> {
    /// Sorted MMAP space of the device. Each registered MMAP buffer takes the `[offset, size - 1]`
    /// range in this space, which is sorted in order to be binary-searchable.
    ///
    /// Buffers that are unregistered but still mapped are still kept here, but do not take space
    /// in the MMAP range (i.e. they are skipped during the binary search).
    buffers: Vec<MmapBuffer>,
    /// Memory mapper used to create buffer mappings.
    mapper: M,
}

impl<M: VirtioMediaHostMemoryMapper> From<M> for MmapMappingManager<M> {
    fn from(mapper: M) -> Self {
        Self {
            buffers: Vec::new(),
            mapper,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegisterBufferError {
    #[error("insufficient free space in the MMAP range")]
    NoFreeSpace,
    #[error("requested range is already occupied")]
    RangeOccupied,
    #[error("buffers of size 0 cannot be registered")]
    EmptyBuffer,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CreateMappingError {
    #[error("no buffer registered at the requested offset")]
    InvalidOffset,
    #[error("cannot create new mappings for unregistered buffers")]
    UnregisteredBuffer,
    #[error("requested mapping range goes outside the buffer")]
    SizeOutOfBounds,
    #[error("error while cloning the FD for the buffer")]
    FdCloneFailure(std::io::ErrorKind),
    #[error("error while mapping the buffer: {0}")]
    MappingFailure(i32),
    #[error("mapping requested with different permission from the old one")]
    NonMatchingPermissions,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoveMappingError {
    #[error("no buffer registered at the requested offset")]
    InvalidOffset,
}

impl<M: VirtioMediaHostMemoryMapper> MmapMappingManager<M> {
    /// Registers a new buffer of `size` at `offset`. If `offset` if `None`, then a free space of
    /// `size` is allocated and the offset of the buffer is returned.
    ///
    /// This method fails if there is no free space of `size` in the range, or if `offset` is
    /// `Some` and the requested space if already used by some other buffer. If `offset` is `Some`
    /// and the function succeed, then the returned value is guaranteed to be the passed offset.
    pub fn register_buffer(
        &mut self,
        offset: Option<u64>,
        size: u64,
    ) -> Result<u64, RegisterBufferError> {
        let offset = offset.unwrap_or_else(|| {
            // TODO: we should also look for free space inside the range if the upper bound has
            // insufficient space.
            self.buffers
                .last()
                .map(|b| b.offset as u64 + b.size as u64)
                .unwrap_or(0)
        });

        self.register_buffer_by_offset(offset, size)
            .map(|()| offset)
    }

    /// Unregisters the buffer previously registered at `offset`. Returns `true` if a buffer was
    /// indeed registered as starting at `offset`, `false` otherwise.
    pub fn unregister_buffer(&mut self, offset: u64) -> bool {
        let Ok(offset) = u32::try_from(offset) else {
            return false;
        };

        match self.buffers.binary_search_by_key(&offset, |b| b.offset) {
            Err(_) => false,
            Ok(index) => {
                let buffer = &mut self.buffers[index];

                buffer.registered = false;
                // If there is no mapping then the buffer can be removed from the MMAP range.
                if buffer.mapping.is_none() {
                    self.buffers.remove(index);
                }

                true
            }
        }
    }

    // Register a new buffer of `size` at `offset`. Returns an error if the [offset..size[ area is
    // already occupied by another buffer.
    fn register_buffer_by_offset(
        &mut self,
        offset: u64,
        size: u64,
    ) -> Result<(), RegisterBufferError> {
        let size = u32::try_from(size).map_err(|_| RegisterBufferError::NoFreeSpace)?;
        if size == 0 {
            return Err(RegisterBufferError::EmptyBuffer);
        }

        let last_buffer_address = u32::try_from(offset + (size as u64 - 1))
            .map_err(|_| RegisterBufferError::NoFreeSpace)?;
        let offset = offset as u32;

        // Check that the range starting at `offset` can indeed contain our buffer.
        let index = match self.buffers.binary_search_by_key(&offset, |b| b.offset) {
            // Already have a registered buffer at that very offset.
            Ok(_) => return Err(RegisterBufferError::RangeOccupied),
            Err(index) => index,
        };

        // Check that the buffer wouldn't overlap with the next buffer.
        let last_permitted_address = self
            .buffers
            .get(index)
            .map(|b| b.offset - 1)
            .unwrap_or(u32::MAX);
        if last_buffer_address > last_permitted_address {
            return Err(RegisterBufferError::RangeOccupied);
        }

        // Also check that it doesn't overlap with the previous one.
        if index > 0 {
            let prev_buffer = &self.buffers[index - 1];
            let first_permitted_address = prev_buffer
                .offset
                .checked_add(prev_buffer.size)
                .ok_or(RegisterBufferError::NoFreeSpace)?;
            if offset < first_permitted_address {
                return Err(RegisterBufferError::RangeOccupied);
            }
        }

        self.buffers.insert(index, MmapBuffer::new(offset, size));

        Ok(())
    }

    /// Create a new mapping for the buffer registered at `offset`. `rw` indicates whether the
    /// mapping is read-only or read-write. Returns the guest address at which the buffer is
    /// mapped, and the size of the mapping, which should be equal to the size of the buffer.
    ///
    /// This method can be called several times and will reuse the prior mapping if it exists. The
    /// mapping will also persist until an identical number of calls to [`Self::remove_mapping`]
    /// are performed.
    ///
    /// Note however that requiring the same active mapping with different `rw` permissions will
    /// result in a `EPERM` error.
    pub fn create_mapping(
        &mut self,
        offset: u64,
        fd: BorrowedFd,
        rw: bool,
    ) -> Result<(u64, u64), CreateMappingError> {
        let offset = u32::try_from(offset).map_err(|_| CreateMappingError::InvalidOffset)?;
        // TODO: should be we able to map from the middle of a buffer?
        let buffer = self
            .buffers
            .binary_search_by_key(&offset, |b| b.offset)
            .map(|i| &mut self.buffers[i])
            .map_err(|_| CreateMappingError::InvalidOffset)?;
        let last_buffer_address = buffer
            .offset
            .checked_add(buffer.size - 1)
            .ok_or(CreateMappingError::InvalidOffset)?;

        // Cannot create additional mappings for buffers that have been destroyed on the guest side.
        if !buffer.registered {
            return Err(CreateMappingError::UnregisteredBuffer);
        }

        // Check that we are not requiring more mapping than the buffer can cover.
        if last_buffer_address > buffer.offset + (buffer.size - 1) {
            return Err(CreateMappingError::SizeOutOfBounds);
        }

        let guest_addr = match &mut buffer.mapping {
            None => {
                let guest_addr = self
                    .mapper
                    .add_mapping(
                        fd,
                        // Always map the full buffer so we can reuse the mapping even with different
                        // sizes.
                        buffer.size as u64,
                        buffer.offset as u64,
                        rw,
                    )
                    .map_err(CreateMappingError::MappingFailure)?;

                buffer.mapping = Some(MmapBufferMapping {
                    num_mappings: 1,
                    rw,
                    guest_addr,
                });

                // TODO: need to be able to lookup the buffer back by guest address - add a
                // guest_addr -> offset table?
                guest_addr
            }
            Some(mapping) => {
                if mapping.rw != rw {
                    return Err(CreateMappingError::NonMatchingPermissions);
                }
                mapping.num_mappings += 1;
                mapping.guest_addr
            }
        };

        Ok((guest_addr, buffer.size as u64))
    }

    /// Returns `true` if the buffer still has other mappings, `false` if this was the last mapping.
    pub fn remove_mapping(&mut self, guest_addr: u64) -> Result<bool, RemoveMappingError> {
        // TODO: use a guest_addr -> offset table to avoid O(n) here?
        for (i, buffer) in self.buffers.iter_mut().enumerate() {
            match &mut buffer.mapping {
                Some(mapping) if mapping.guest_addr == guest_addr => {
                    mapping.num_mappings -= 1;
                    if mapping.num_mappings == 0 {
                        if let Err(e) = self.mapper.remove_mapping(guest_addr) {
                            log::error!("error while unmapping MMAP buffer: {:#}", e);
                        }
                        buffer.mapping = None;
                        // If this was the last dangling mapping then the buffer can be removed
                        // from the MMAP range.
                        if !buffer.registered {
                            self.buffers.remove(i);
                        }
                        return Ok(false);
                    } else {
                        return Ok(true);
                    }
                }
                _ => (),
            }
        }

        Err(RemoveMappingError::InvalidOffset)
    }
    /// Returns `true` if the buffer registered at `offset` is already mapped.
    pub fn is_mapped(&self, offset: u64) -> bool {
        let Ok(offset) = u32::try_from(offset) else {
            return false;
        };

        match self.buffers.binary_search_by_key(&offset, |b| b.offset) {
            Err(_) => false,
            Ok(index) => self.buffers[index].mapping.is_some(),
        }
    }

    /// Consume the mapping manager and return the mapper it has been constructed from.
    pub fn into_mapper(self) -> M {
        self.mapper
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsFd;
    use std::os::fd::BorrowedFd;
    use std::os::fd::FromRawFd;

    use crate::VirtioMediaHostMemoryMapper;

    use super::CreateMappingError;
    use super::MmapBuffer;
    use super::MmapBufferMapping;
    use super::MmapMappingManager;
    use super::RegisterBufferError;
    use super::RemoveMappingError;

    struct DummyHostMemoryMapper;

    impl VirtioMediaHostMemoryMapper for DummyHostMemoryMapper {
        fn add_mapping(
            &mut self,
            _buffer: BorrowedFd,
            _length: u64,
            offset: u64,
            _rw: bool,
        ) -> Result<u64, i32> {
            Ok(offset | 0x8000_0000)
        }

        fn remove_mapping(&mut self, _guest_addr: u64) -> Result<(), i32> {
            Ok(())
        }
    }

    #[test]
    fn mmap_manager_register_by_offset() {
        let mut mm = MmapMappingManager::from(DummyHostMemoryMapper);
        assert_eq!(mm.buffers, vec![]);

        assert_eq!(mm.register_buffer_by_offset(0x0, 0x1000), Ok(()));
        assert_eq!(mm.buffers, vec![MmapBuffer::new(0x0, 0x1000)]);

        assert_eq!(mm.register_buffer_by_offset(0x1000, 0x5000), Ok(()));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
            ]
        );

        assert_eq!(mm.register_buffer_by_offset(0xa000, 0x1000), Ok(()));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert_eq!(mm.register_buffer_by_offset(0x6000, 0x2000), Ok(()));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x6000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert_eq!(
            mm.register_buffer_by_offset(0x8000, 0x0),
            Err(RegisterBufferError::EmptyBuffer)
        );

        assert_eq!(
            mm.register_buffer_by_offset(0x1000, 0x1000),
            Err(RegisterBufferError::RangeOccupied)
        );

        assert_eq!(
            mm.register_buffer_by_offset(0x0, 0x1000),
            Err(RegisterBufferError::RangeOccupied)
        );

        assert_eq!(
            mm.register_buffer_by_offset(0x2000, 0x1000),
            Err(RegisterBufferError::RangeOccupied)
        );

        assert_eq!(
            mm.register_buffer_by_offset(0x7000, 0x2000),
            Err(RegisterBufferError::RangeOccupied)
        );

        assert_eq!(
            mm.register_buffer_by_offset(0x8000, 0x2100),
            Err(RegisterBufferError::RangeOccupied)
        );

        assert_eq!(mm.register_buffer_by_offset(0x8000, 0x2000), Ok(()));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x6000, 0x2000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert_eq!(mm.register_buffer_by_offset(0xffff_f000, 0x1000), Ok(()));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x6000, 0x2000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
                MmapBuffer::new(0xffff_f000, 0x1000),
            ]
        );

        assert!(mm.unregister_buffer(0xffff_f000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x6000, 0x2000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert!(mm.unregister_buffer(0x6000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert!(!mm.unregister_buffer(0x6000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert!(!mm.unregister_buffer(0x8100));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert!(mm.unregister_buffer(0x0));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x8000, 0x2000),
                MmapBuffer::new(0xa000, 0x1000),
            ]
        );

        assert!(mm.unregister_buffer(0xa000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x8000, 0x2000),
            ]
        );

        assert!(mm.unregister_buffer(0x1000));
        assert_eq!(mm.buffers, vec![MmapBuffer::new(0x8000, 0x2000),]);

        assert!(mm.unregister_buffer(0x8000));
        assert_eq!(mm.buffers, vec![]);

        assert_eq!(
            mm.register_buffer_by_offset(0x0, 0x1_0000_0000),
            Err(RegisterBufferError::NoFreeSpace)
        );
        assert_eq!(mm.buffers, vec![]);
    }

    #[test]
    fn mmap_manager_register() {
        let mut mm = MmapMappingManager::from(DummyHostMemoryMapper);

        assert_eq!(mm.register_buffer(None, 0x1000), Ok(0x0));
        assert_eq!(mm.buffers, vec![MmapBuffer::new(0x0, 0x1000)]);

        assert_eq!(mm.register_buffer(None, 0x5000), Ok(0x1000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
            ]
        );

        assert_eq!(mm.register_buffer(None, 0xffff_a000), Ok(0x6000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
                MmapBuffer::new(0x6000, 0xffff_a000),
            ]
        );

        assert!(mm.unregister_buffer(0x6000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
            ]
        );

        assert_eq!(
            mm.register_buffer(None, 0xffff_b000),
            Err(RegisterBufferError::NoFreeSpace)
        );
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
            ]
        );
    }

    #[test]
    fn mmap_manager_mapping() {
        let mut mm = MmapMappingManager::from(DummyHostMemoryMapper);

        assert_eq!(mm.register_buffer(None, 0x1000), Ok(0x0));
        assert_eq!(mm.register_buffer(None, 0x5000), Ok(0x1000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer::new(0x1000, 0x5000),
            ]
        );

        let file = unsafe { File::from_raw_fd(0) };

        // Single mapping
        assert_eq!(
            mm.create_mapping(0x1000, file.as_fd(), false),
            Ok((0x8000_1000, 0x5000))
        );
        assert_eq!(mm.remove_mapping(0x8000_1000), Ok(false));
        assert_eq!(
            mm.remove_mapping(0x8000_1000),
            Err(RemoveMappingError::InvalidOffset)
        );

        // Multiple mappings
        assert_eq!(
            mm.create_mapping(0x1000, file.as_fd(), false),
            Ok((0x8000_1000, 0x5000))
        );
        assert_eq!(
            mm.create_mapping(0x1000, file.as_fd(), false),
            Ok((0x8000_1000, 0x5000))
        );
        assert_eq!(mm.remove_mapping(0x8000_1000), Ok(true));
        assert_eq!(mm.remove_mapping(0x8000_1000), Ok(false));
        assert_eq!(
            mm.remove_mapping(0x8000_1000),
            Err(RemoveMappingError::InvalidOffset)
        );

        // Mapping at non-existing offset
        assert_eq!(
            mm.create_mapping(0x2000, file.as_fd(), false),
            Err(CreateMappingError::InvalidOffset)
        );

        // Requesting same mapping with different access
        assert_eq!(
            mm.create_mapping(0x1000, file.as_fd(), false),
            Ok((0x8000_1000, 0x5000))
        );
        assert_eq!(
            mm.create_mapping(0x1000, file.as_fd(), true),
            Err(CreateMappingError::NonMatchingPermissions)
        );
        assert_eq!(mm.remove_mapping(0x8000_1000), Ok(false));

        // Mappings must survive a buffer's deregistration
        assert_eq!(
            mm.create_mapping(0x1000, file.as_fd(), false),
            Ok((0x8000_1000, 0x5000))
        );
        assert!(mm.unregister_buffer(0x1000));
        assert_eq!(
            mm.buffers,
            vec![
                MmapBuffer::new(0x0, 0x1000),
                MmapBuffer {
                    offset: 0x1000,
                    size: 0x5000,
                    registered: false,
                    mapping: Some(MmapBufferMapping {
                        num_mappings: 1,
                        guest_addr: 0x8000_1000,
                        rw: false
                    })
                }
            ]
        );
        // ... but un-registered buffers are removed alongside their last mapping.
        assert_eq!(mm.remove_mapping(0x8000_1000), Ok(false));
        assert_eq!(mm.buffers, vec![MmapBuffer::new(0x0, 0x1000),])
    }
}
