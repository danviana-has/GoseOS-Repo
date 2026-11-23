//! Slab / Object Cache Allocator
//!
//! Provides O(1) allocation and deallocation for fixed-size kernel objects
//! across 8 power-of-two size classes (16, 32, 64, 128, 256, 512, 1024, 2048
//! bytes). Each slab is a 4 KiB physical page backed by the Buddy PMM with an
//! intrusive freelist embedded inside free object slots and a compact header
//! at the start of the page.

use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use crate::debug::telemetry::TELEMETRY;
use crate::mm::frame::{frame_flags, frame_meta, PAGE_SIZE};
use crate::mm::{phys_to_virt, pmm, virt_to_phys, PhysAddr};
use crate::sched::sync::IrqSpinlock;

/// Size classes managed by the kernel Slab allocator.
pub const SLAB_SIZES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

const SLAB_MAGIC: u32 = 0x534C_4142; // "SLAB"

/// Header placed at offset 0 of every 4 KiB slab page (64 bytes, 64-byte aligned).
#[repr(C, align(64))]
struct SlabPageHeader {
    magic: u32,
    class_idx: u16,
    in_use: u16,
    capacity: u16,
    _pad: u16,
    free_head: *mut FreeSlot,
    next_slab: *mut SlabPageHeader,
    prev_slab: *mut SlabPageHeader,
}

#[repr(C)]
struct FreeSlot {
    next: *mut FreeSlot,
}

/// Per-size-class slab cache maintaining partial and full slab lists.
pub struct SlabCache {
    class_idx: usize,
    obj_size: usize,
    partial_head: *mut SlabPageHeader,
    full_head: *mut SlabPageHeader,
    total_slabs: usize,
    total_allocated: usize,
}

unsafe impl Send for SlabCache {}

impl SlabCache {
    pub const fn new(class_idx: usize, obj_size: usize) -> Self {
        Self {
            class_idx,
            obj_size,
            partial_head: core::ptr::null_mut(),
            full_head: core::ptr::null_mut(),
            total_slabs: 0,
            total_allocated: 0,
        }
    }

    /// Grow this cache by allocating a fresh 4 KiB page from the Buddy PMM
    /// and carving it into `obj_size` slots linked into `free_head`.
    unsafe fn grow(&mut self) -> Option<*mut SlabPageHeader> {
        let pa = pmm::alloc_frame()?;
        if let Some(meta) = frame_meta(pa.as_u64()) {
            meta.set_flags(frame_flags::SLAB);
        }
        let page_va = phys_to_virt(pa.as_u64()) as usize;
        let hdr = page_va as *mut SlabPageHeader;

        let hdr_size = core::mem::size_of::<SlabPageHeader>();
        let start_off = (hdr_size + self.obj_size - 1) & !(self.obj_size - 1);
        let usable = PAGE_SIZE.saturating_sub(start_off);
        let capacity = (usable / self.obj_size) as u16;
        debug_assert!(capacity > 0);

        // Build intrusive freelist from back to front so first alloc is at lowest offset
        let mut head: *mut FreeSlot = core::ptr::null_mut();
        for i in (0..capacity as usize).rev() {
            let slot = (page_va + start_off + i * self.obj_size) as *mut FreeSlot;
            (*slot).next = head;
            head = slot;
        }

        hdr.write(SlabPageHeader {
            magic: SLAB_MAGIC,
            class_idx: self.class_idx as u16,
            in_use: 0,
            capacity,
            _pad: 0,
            free_head: head,
            next_slab: self.partial_head,
            prev_slab: core::ptr::null_mut(),
        });

        if !self.partial_head.is_null() {
            (*self.partial_head).prev_slab = hdr;
        }
        self.partial_head = hdr;
        self.total_slabs += 1;
        Some(hdr)
    }

    unsafe fn unlink_from(head: &mut *mut SlabPageHeader, slab: *mut SlabPageHeader) {
        let prev = (*slab).prev_slab;
        let next = (*slab).next_slab;
        if !prev.is_null() {
            (*prev).next_slab = next;
        } else {
            *head = next;
        }
        if !next.is_null() {
            (*next).prev_slab = prev;
        }
        (*slab).prev_slab = core::ptr::null_mut();
        (*slab).next_slab = core::ptr::null_mut();
    }

    unsafe fn push_front(head: &mut *mut SlabPageHeader, slab: *mut SlabPageHeader) {
        (*slab).prev_slab = core::ptr::null_mut();
        (*slab).next_slab = *head;
        if !(*head).is_null() {
            (**head).prev_slab = slab;
        }
        *head = slab;
    }

    /// Allocate one object from this slab cache in O(1).
    pub unsafe fn alloc(&mut self) -> Option<NonNull<u8>> {
        let slab = if !self.partial_head.is_null() {
            self.partial_head
        } else {
            self.grow()?
        };

        let slot = (*slab).free_head;
        debug_assert!(!slot.is_null());
        (*slab).free_head = (*slot).next;
        (*slab).in_use += 1;
        self.total_allocated += 1;

        if (*slab).free_head.is_null() {
            Self::unlink_from(&mut self.partial_head, slab);
            Self::push_front(&mut self.full_head, slab);
        }

        TELEMETRY.slab_allocs.fetch_add(1, Ordering::Relaxed);
        NonNull::new(slot as *mut u8)
    }

    /// Return an object pointer belonging to this cache.
    pub unsafe fn free(&mut self, ptr: *mut u8) {
        let page_va = (ptr as usize) & !(PAGE_SIZE - 1);
        let slab = page_va as *mut SlabPageHeader;
        debug_assert_eq!((*slab).magic, SLAB_MAGIC, "Corrupt slab header magic");
        debug_assert_eq!((*slab).class_idx as usize, self.class_idx);

        let was_full = (*slab).free_head.is_null();
        let slot = ptr as *mut FreeSlot;
        (*slot).next = (*slab).free_head;
        (*slab).free_head = slot;
        (*slab).in_use -= 1;
        self.total_allocated -= 1;

        if was_full {
            Self::unlink_from(&mut self.full_head, slab);
            Self::push_front(&mut self.partial_head, slab);
        } else if (*slab).in_use == 0 && self.total_slabs > 1 {
            // Reclaim completely empty slab back to Buddy PMM (keep 1 warm slab)
            Self::unlink_from(&mut self.partial_head, slab);
            self.total_slabs -= 1;
            let pa = PhysAddr::new(virt_to_phys(page_va as u64));
            pmm::free_frame(pa);
        }

        TELEMETRY.slab_frees.fetch_add(1, Ordering::Relaxed);
    }
}

/// Global Slab Allocator array protected by per-cache `IrqSpinlock`s to minimize
/// contention across SMP cores.
pub struct SlabAllocator {
    caches: [IrqSpinlock<SlabCache>; 8],
}

impl SlabAllocator {
    pub const fn new() -> Self {
        Self {
            caches: [
                IrqSpinlock::new(SlabCache::new(0, SLAB_SIZES[0])),
                IrqSpinlock::new(SlabCache::new(1, SLAB_SIZES[1])),
                IrqSpinlock::new(SlabCache::new(2, SLAB_SIZES[2])),
                IrqSpinlock::new(SlabCache::new(3, SLAB_SIZES[3])),
                IrqSpinlock::new(SlabCache::new(4, SLAB_SIZES[4])),
                IrqSpinlock::new(SlabCache::new(5, SLAB_SIZES[5])),
                IrqSpinlock::new(SlabCache::new(6, SLAB_SIZES[6])),
                IrqSpinlock::new(SlabCache::new(7, SLAB_SIZES[7])),
            ],
        }
    }

    #[inline]
    pub fn class_for(size: usize, align: usize) -> Option<usize> {
        let eff = size.max(align);
        for (i, &cls) in SLAB_SIZES.iter().enumerate() {
            if eff <= cls {
                return Some(i);
            }
        }
        None
    }

    pub fn alloc(&self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let idx = Self::class_for(size, align)?;
        unsafe { self.caches[idx].lock().alloc() }
    }

    pub unsafe fn free(&self, ptr: *mut u8, size: usize, align: usize) -> bool {
        if let Some(idx) = Self::class_for(size, align) {
            self.caches[idx].lock().free(ptr);
            true
        } else {
            false
        }
    }

    pub fn log_stats(&self) {
        let mut total_slabs = 0usize;
        let mut total_objs = 0usize;
        for c in &self.caches {
            let guard = c.lock();
            total_slabs += guard.total_slabs;
            total_objs += guard.total_allocated;
        }
        crate::kinfo!(
            "SLAB",
            "Object Caches ready: 8 classes (16B..2048B), active_slabs={}, live_objs={}",
            total_slabs,
            total_objs
        );
    }
}

pub static SLAB_ALLOCATOR: SlabAllocator = SlabAllocator::new();
