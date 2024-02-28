// Copyright 2024 The ChromiumOS Authors

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::rc::Rc;

use crate::ioctl::IoctlResult;
use crate::VirtioMediaHostMemoryMapper;

/// Information about a MMAP buffer being mapped into the guest.
#[derive(Default)]
pub struct MmapMapping {
    /// Number of times mmap has been performed for this buffer. The mapping remains alive until
    /// this reaches zero.
    num_mappings: usize,
    /// Whether the mapping of this buffer is read-only or read-write. Only valid if `num_mappings
    /// >= 1`.
    rw: bool,
}

/// Range mananger for MMAP buffers, using a host memory mapper.
///
/// Devices that allocate MMAP buffers can register their offset using [`register_offset`] and
/// unregister then with [`unregister_buffer`]. Registered buffers can then be mapped into the
/// guest address space by calling [`create_mapping`] on their offset. This will return the address
/// of their guest mapping, which can then be accessed or used to unmap them with [`remove_mapping`].
pub struct MmapMappingManager<M: VirtioMediaHostMemoryMapper> {
    /// Maps V4L2 buffers offsets to their guest mapping, if they are mapped.
    buffers: BTreeMap<u64, Rc<RefCell<MmapMapping>>>,
    /// Maps guest addresses of mapped buffers to their buffer information.
    mappings: BTreeMap<u64, Rc<RefCell<MmapMapping>>>,
    mapper: M,
}

// Rcs in this struct are never leaving and will thus all be moved to the target thread.
unsafe impl<M: VirtioMediaHostMemoryMapper> Send for MmapMappingManager<M> {}

impl<M: VirtioMediaHostMemoryMapper> From<M> for MmapMappingManager<M> {
    fn from(mapper: M) -> Self {
        Self {
            buffers: Default::default(),
            mappings: Default::default(),
            mapper,
        }
    }
}

impl<M: VirtioMediaHostMemoryMapper> MmapMappingManager<M> {
    /// Registers a new buffer at `offset`. The buffer has no mapping initially.
    pub fn register_buffer(&mut self, offset: u64, _length: u64) -> IoctlResult<()> {
        if let std::collections::btree_map::Entry::Vacant(e) = self.buffers.entry(offset) {
            e.insert(Rc::new(Default::default()));
            Ok(())
        } else {
            Err(libc::EINVAL)
        }
    }

    pub fn unregister_buffer(&mut self, offset: u64) {
        let _ = self.buffers.remove(&offset);
    }

    /// Create a new mapping of length [`size`] for the buffer registered at [`offset`]. [`rw`]
    /// indicates whether the mapping is read-only or read-write.
    ///
    /// This method can be called several times and will reuse the prior mapping if it exists. The
    /// mapping will also persist until an identical number of calls to [`remove_mapping`] are
    /// performed.
    ///
    /// Note however that requiring the same active mapping with different [`rw`] permissions will
    /// result in a `EPERM` error.
    pub fn create_mapping(
        &mut self,
        offset: u64,
        fd: &File,
        size: u64,
        rw: bool,
    ) -> IoctlResult<u64> {
        let entry = match self.buffers.get_mut(&offset) {
            Some(entry) => entry,
            None => return Err(libc::EINVAL),
        };

        let mut mapping = entry.borrow_mut();

        // First time we are mapping.
        if mapping.num_mappings == 0 {
            let guest_addr = self.mapper.add_mapping(
                fd.try_clone().map_err(|_| libc::EINVAL)?,
                size,
                offset,
                rw,
            )?;

            mapping.num_mappings = 1;
            mapping.rw = rw;

            self.mappings.insert(guest_addr, entry.clone());

            Ok(guest_addr)
        } else {
            if mapping.rw != rw {
                return Err(libc::EPERM);
            }

            mapping.num_mappings += 1;

            Ok(self
                .mappings
                .iter()
                .find(|(_, m)| m.as_ptr() == entry.as_ptr())
                .map(|(guest_addr, _)| *guest_addr)
                .expect("inconsistent state: mapped buffer not found in mappings list!"))
        }
    }

    /// Returns `true` if the buffer still has other mappings, `false` if this was the last mapping.
    pub fn remove_mapping(&mut self, guest_addr: u64) -> IoctlResult<bool> {
        let entry = match self.mappings.get(&guest_addr) {
            Some(mapping) => mapping,
            None => return Err(libc::EINVAL),
        };

        let mut mapping = entry.borrow_mut();

        mapping.num_mappings -= 1;

        // Last mapping, remove it.
        if mapping.num_mappings == 0 {
            self.mapper.remove_mapping(guest_addr)?;

            drop(mapping);
            let _ = self.mappings.remove(&guest_addr);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Returns `true` if the buffer registered at `offset` is already mapped.
    pub fn is_mapped(&self, offset: u64) -> bool {
        self.buffers
            .get(&offset)
            .map(|m| m.borrow().num_mappings > 0)
            .unwrap_or(false)
    }

    /// Consume the mapping manager and return the mapper it has been constructed from.
    pub fn into_mapper(self) -> M {
        self.mapper
    }
}
