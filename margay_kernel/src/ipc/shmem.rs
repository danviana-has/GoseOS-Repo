//! Zero-Copy Shared Memory IPC (`SharedMemory`)
//!
//! Capability-controlled physical page pools that can be mapped simultaneously
//! into two or more isolated `AddressSpace`s for high-throughput, zero-copy
//! bulk data transfer between Ring 3 servers.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::object::SharedMemId;
use crate::cap::CapRights;
use crate::ipc::IpcError;
use crate::mm::frame::{frame_flags, frame_meta, frame_ref_inc, PAGE_SIZE};
use crate::mm::paging::PageFlags;
use crate::mm::vspace::{AddressSpace, VmaKind, VmaRegion};
use crate::mm::{pmm, PhysAddr, VirtAddr};
use crate::sched::sync::IrqSpinlock;

pub struct SharedMemoryRegion {
    pub id: SharedMemId,
    pub frames: Vec<PhysAddr>,
    pub sealed: bool,
}

impl SharedMemoryRegion {
    pub fn size_bytes(&self) -> usize {
        self.frames.len() * PAGE_SIZE
    }
}

static NEXT_SHMEM_ID: AtomicU64 = AtomicU64::new(1);
static SHMEM_TABLE: IrqSpinlock<BTreeMap<SharedMemId, SharedMemoryRegion>> =
    IrqSpinlock::new(BTreeMap::new());

/// Allocate a new zero-filled Shared Memory region of `num_pages` 4 KiB frames.
pub fn create_shared_memory(num_pages: usize) -> Result<SharedMemId, IpcError> {
    if num_pages == 0 || num_pages > 4096 {
        return Err(IpcError::InvalidAddress);
    }

    let mut frames = Vec::with_capacity(num_pages);
    for _ in 0..num_pages {
        match pmm::alloc_frame_zeroed() {
            Some(pa) => {
                if let Some(meta) = frame_meta(pa.as_u64()) {
                    meta.set_flags(frame_flags::SHARED);
                }
                frames.push(pa);
            }
            None => {
                for pa in frames {
                    pmm::release_frame(pa);
                }
                return Err(IpcError::OutOfMemory);
            }
        }
    }

    let id = NEXT_SHMEM_ID.fetch_add(1, Ordering::Relaxed);
    SHMEM_TABLE.lock().insert(
        id,
        SharedMemoryRegion {
            id,
            frames,
            sealed: false,
        },
    );
    Ok(id)
}

/// Map a `SharedMemory` object into `vspace` at `base_vaddr` with permissions
/// bounded by the caller's `CapRights` (enforcing W^X).
pub fn map_into_vspace(
    id: SharedMemId,
    vspace: &mut AddressSpace,
    base_vaddr: u64,
    rights: CapRights,
) -> Result<usize, IpcError> {
    if (base_vaddr & (PAGE_SIZE as u64 - 1)) != 0 || base_vaddr == 0 {
        return Err(IpcError::InvalidAddress);
    }
    if !rights.contains(CapRights::READ) {
        return Err(IpcError::PermissionDenied);
    }

    let mut flags = PageFlags::PRESENT
        .union(PageFlags::USER)
        .union(PageFlags::SHARED)
        .union(PageFlags::NO_EXECUTE);
    if rights.contains(CapRights::WRITE) {
        flags = flags.union(PageFlags::WRITABLE);
    }

    let frames: Vec<PhysAddr> = {
        let table = SHMEM_TABLE.lock();
        let region = table.get(&id).ok_or(IpcError::InvalidSharedMem)?;
        region.frames.clone()
    };

    let length = (frames.len() * PAGE_SIZE) as u64;
    vspace
        .register_vma(VmaRegion {
            start: base_vaddr,
            length,
            flags,
            kind: VmaKind::SharedMemory,
        })
        .map_err(|_| IpcError::InvalidAddress)?;

    for (i, &pa) in frames.iter().enumerate() {
        let va = VirtAddr::new(base_vaddr + (i * PAGE_SIZE) as u64);
        frame_ref_inc(pa.as_u64());
        if vspace.map_page(va, pa, flags).is_err() {
            pmm::release_frame(pa);
            return Err(IpcError::InvalidAddress);
        }
    }

    Ok(frames.len() * PAGE_SIZE)
}

/// Release the Shared Memory object's own frame references (pages remain alive
/// in any VSpace that still maps them until unmapped).
pub fn destroy_shared_memory(id: SharedMemId) {
    if let Some(region) = SHMEM_TABLE.lock().remove(&id) {
        for pa in region.frames {
            pmm::release_frame(pa);
        }
    }
}
