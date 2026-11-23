//! Physical Memory Manager (PMM) — Multi-Zone Buddy Allocator
//!
//! Manages physical RAM in power-of-two blocks from order 0 (4 KiB) up to
//! order 10 (4 MiB, covering 4 KiB standard pages and 2 MiB Huge Pages) with
//! intrusive free lists stored directly inside free physical frames via the
//! HHDM direct map, O(log N) split/coalesce via XOR buddy calculation, DMA
//! zone support, and `PageFrame` reference counting integration.

use core::sync::atomic::Ordering;

use crate::arch::x86_64::limine::{self, MemoryMapType};
use crate::debug::telemetry::TELEMETRY;
use crate::mm::frame::{
    frame_flags, frame_meta, MemoryZone, MAX_TRACKED_FRAMES, PAGE_SHIFT, PAGE_SIZE,
};
use crate::mm::{phys_to_virt, PhysAddr};
use crate::sched::sync::IrqSpinlock;

/// Maximum buddy order: order 10 = 1024 pages = 4 MiB (order 9 = 2 MiB Huge Page).
pub const MAX_ORDER: usize = 11;
/// Order corresponding to a 2 MiB Huge Page (512 * 4 KiB).
pub const ORDER_2M: usize = 9;

/// Intrusive doubly-linked free-list node stored at the start of every free block
/// (accessed via HHDM).
#[repr(C)]
struct FreeNode {
    prev_pfn: u32,
    next_pfn: u32,
}

const INVALID_PFN: u32 = u32::MAX;

struct BuddyZone {
    free_heads: [u32; MAX_ORDER],
    free_counts: [usize; MAX_ORDER],
    total_pages: usize,
    free_pages: usize,
}

impl BuddyZone {
    const fn new() -> Self {
        Self {
            free_heads: [INVALID_PFN; MAX_ORDER],
            free_counts: [0; MAX_ORDER],
            total_pages: 0,
            free_pages: 0,
        }
    }

    #[inline]
    unsafe fn node_mut(pfn: u32) -> &'static mut FreeNode {
        let vaddr = phys_to_virt((pfn as u64) << PAGE_SHIFT);
        &mut *(vaddr as *mut FreeNode)
    }

    /// Push a free block of `order` onto this zone's free list.
    unsafe fn list_push(&mut self, pfn: u32, order: usize) {
        let old_head = self.free_heads[order];
        let node = Self::node_mut(pfn);
        node.prev_pfn = INVALID_PFN;
        node.next_pfn = old_head;
        if old_head != INVALID_PFN {
            Self::node_mut(old_head).prev_pfn = pfn;
        }
        self.free_heads[order] = pfn;
        self.free_counts[order] += 1;

        if let Some(meta) = frame_meta((pfn as u64) << PAGE_SHIFT) {
            meta.order.store(order as u8, Ordering::Release);
            meta.flags.store(frame_flags::FREE, Ordering::Release);
            meta.refcount.store(0, Ordering::Release);
        }
    }

    /// Pop the head block of `order` from this zone's free list.
    unsafe fn list_pop(&mut self, order: usize) -> Option<u32> {
        let head = self.free_heads[order];
        if head == INVALID_PFN {
            return None;
        }
        let next = Self::node_mut(head).next_pfn;
        if next != INVALID_PFN {
            Self::node_mut(next).prev_pfn = INVALID_PFN;
        }
        self.free_heads[order] = next;
        self.free_counts[order] -= 1;
        Some(head)
    }

    /// Unlink an arbitrary `pfn` from `order`'s doubly-linked free list in O(1).
    unsafe fn list_remove(&mut self, pfn: u32, order: usize) {
        let node = Self::node_mut(pfn);
        let prev = node.prev_pfn;
        let next = node.next_pfn;

        if prev != INVALID_PFN {
            Self::node_mut(prev).next_pfn = next;
        } else {
            self.free_heads[order] = next;
        }
        if next != INVALID_PFN {
            Self::node_mut(next).prev_pfn = prev;
        }
        self.free_counts[order] -= 1;
    }

    /// Allocate a block of `req_order`, splitting larger blocks if necessary.
    unsafe fn alloc_order(&mut self, req_order: usize) -> Option<u32> {
        if req_order >= MAX_ORDER {
            return None;
        }
        for cur_order in req_order..MAX_ORDER {
            if let Some(pfn) = self.list_pop(cur_order) {
                // Split down to `req_order`, returning right-hand buddies to lower lists
                let mut o = cur_order;
                while o > req_order {
                    o -= 1;
                    let buddy_pfn = pfn + (1u32 << o);
                    self.list_push(buddy_pfn, o);
                }
                let pages = 1usize << req_order;
                self.free_pages -= pages;

                // Mark allocated metadata
                if let Some(meta) = frame_meta((pfn as u64) << PAGE_SHIFT) {
                    meta.flags.store(frame_flags::KERNEL, Ordering::Release);
                    meta.order.store(req_order as u8, Ordering::Release);
                    meta.refcount.store(1, Ordering::Release);
                }
                return Some(pfn);
            }
        }
        None
    }

    /// Free a block of `order` and coalesce iteratively with its XOR buddy.
    unsafe fn free_order(&mut self, mut pfn: u32, mut order: usize) {
        let orig_pages = 1usize << order;
        let my_zone = MemoryZone::from_paddr((pfn as u64) << PAGE_SHIFT) as u8;

        while order + 1 < MAX_ORDER {
            let buddy_pfn = pfn ^ (1u32 << order);
            if (buddy_pfn as usize) >= MAX_TRACKED_FRAMES {
                break;
            }
            let Some(buddy_meta) = frame_meta((buddy_pfn as u64) << PAGE_SHIFT) else {
                break;
            };
            // Coalesce only if buddy is FREE, same order, and same zone
            if !buddy_meta.has_flag(frame_flags::FREE)
                || buddy_meta.order.load(Ordering::Acquire) as usize != order
                || buddy_meta.zone.load(Ordering::Acquire) != my_zone
            {
                break;
            }
            self.list_remove(buddy_pfn, order);
            pfn = pfn.min(buddy_pfn);
            order += 1;
        }

        self.list_push(pfn, order);
        self.free_pages += orig_pages;
    }
}

struct PmmState {
    zones: [BuddyZone; 3], // 0=DMA, 1=DMA32, 2=Normal
    total_usable_bytes: u64,
    initialized: bool,
}

impl PmmState {
    const fn new() -> Self {
        Self {
            zones: [BuddyZone::new(), BuddyZone::new(), BuddyZone::new()],
            total_usable_bytes: 0,
            initialized: false,
        }
    }

    fn ingest_usable_range(&mut self, start: u64, length: u64) {
        // Reserve the first 1 MiB (real-mode IVT, BIOS, VGA, legacy tables)
        let mut cur = start.max(0x10_0000);
        let end = (start + length).min((MAX_TRACKED_FRAMES as u64) << PAGE_SHIFT);

        // Align start up and end down to 4 KiB boundaries
        cur = (cur + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
        let end = end & !(PAGE_SIZE as u64 - 1);
        if cur >= end {
            return;
        }

        while cur < end {
            let pfn = (cur >> PAGE_SHIFT) as u32;
            let zone = MemoryZone::from_paddr(cur);
            let zone_idx = zone as usize;

            // Find largest aligned power-of-two order that fits within [cur, end) and stays in the same zone
            let mut order = MAX_ORDER - 1;
            while order > 0 {
                let block_pages = 1u64 << order;
                let block_bytes = block_pages << PAGE_SHIFT;
                let aligned = (pfn & ((1u32 << order) - 1)) == 0;
                let fits = cur + block_bytes <= end;
                let same_zone = MemoryZone::from_paddr(cur + block_bytes - PAGE_SIZE as u64) == zone;
                if aligned && fits && same_zone {
                    break;
                }
                order -= 1;
            }

            let pages = 1usize << order;
            for i in 0..pages {
                if let Some(meta) = frame_meta(cur + ((i as u64) << PAGE_SHIFT)) {
                    meta.zone.store(zone_idx as u8, Ordering::Release);
                    meta.flags.store(0, Ordering::Release);
                    meta.refcount.store(0, Ordering::Release);
                    meta.order.store(0, Ordering::Release);
                }
            }

            unsafe {
                self.zones[zone_idx].list_push(pfn, order);
            }
            self.zones[zone_idx].total_pages += pages;
            self.zones[zone_idx].free_pages += pages;
            self.total_usable_bytes += (pages as u64) << PAGE_SHIFT;
            cur += (pages as u64) << PAGE_SHIFT;
        }
    }
}

static PMM: IrqSpinlock<PmmState> = IrqSpinlock::new(PmmState::new());

/// Initialize the Physical Memory Manager from the Limine memory map.
pub fn init() {
    let entries = limine::memory_map_entries();
    let mut pmm = PMM.lock();

    for &entry_ptr in entries {
        if entry_ptr.is_null() {
            continue;
        }
        let entry = unsafe { *entry_ptr };
        if entry.kind() == MemoryMapType::Usable {
            pmm.ingest_usable_range(entry.base, entry.length);
        }
    }

    pmm.initialized = true;

    let total_mb = pmm.total_usable_bytes / (1024 * 1024);
    let dma_pages = pmm.zones[0].free_pages;
    let dma32_pages = pmm.zones[1].free_pages;
    let normal_pages = pmm.zones[2].free_pages;
    drop(pmm);

    crate::kinfo!(
        "PMM",
        "Buddy Allocator online: {} MiB usable (DMA={}p, DMA32={}p, Normal={}p)",
        total_mb,
        dma_pages,
        dma32_pages,
        normal_pages
    );
}

/// Allocate `2^order` contiguous physical frames (order 0 = 4 KiB, order 9 = 2 MiB).
pub fn alloc_order(order: usize) -> Option<PhysAddr> {
    let mut pmm = PMM.lock();
    // Prefer Normal -> DMA32 -> DMA so low DMA memory is preserved for devices.
    for z in [2usize, 1, 0] {
        if let Some(pfn) = unsafe { pmm.zones[z].alloc_order(order) } {
            TELEMETRY
                .frames_allocated
                .fetch_add(1u64 << order, Ordering::Relaxed);
            return Some(PhysAddr::new((pfn as u64) << PAGE_SHIFT));
        }
    }
    None
}

/// Allocate `2^order` contiguous physical frames strictly from the DMA (<16 MiB)
/// or DMA32 (<4 GiB) zone.
pub fn alloc_dma(order: usize, require_low_16m: bool) -> Option<PhysAddr> {
    let mut pmm = PMM.lock();
    let zones: &[usize] = if require_low_16m { &[0] } else { &[1, 0] };
    for &z in zones {
        if let Some(pfn) = unsafe { pmm.zones[z].alloc_order(order) } {
            if let Some(meta) = frame_meta((pfn as u64) << PAGE_SHIFT) {
                meta.set_flags(frame_flags::DMA);
            }
            TELEMETRY
                .frames_allocated
                .fetch_add(1u64 << order, Ordering::Relaxed);
            return Some(PhysAddr::new((pfn as u64) << PAGE_SHIFT));
        }
    }
    None
}

/// Allocate a single 4 KiB physical page frame.
#[inline]
pub fn alloc_frame() -> Option<PhysAddr> {
    alloc_order(0)
}

/// Allocate a single zero-filled 4 KiB physical page frame.
pub fn alloc_frame_zeroed() -> Option<PhysAddr> {
    let pa = alloc_frame()?;
    unsafe {
        core::ptr::write_bytes(phys_to_virt(pa.as_u64()) as *mut u8, 0, PAGE_SIZE);
    }
    Some(pa)
}

/// Allocate a 2 MiB physically contiguous Huge Page (order 9).
#[inline]
pub fn alloc_huge_2m() -> Option<PhysAddr> {
    alloc_order(ORDER_2M)
}

/// Free a previously allocated block of `2^order` physical frames.
pub fn free_order(paddr: PhysAddr, order: usize) {
    let raw = paddr.as_u64();
    if raw == 0 || (raw >> PAGE_SHIFT) as usize >= MAX_TRACKED_FRAMES {
        return;
    }
    let zone = MemoryZone::from_paddr(raw) as usize;
    let pfn = (raw >> PAGE_SHIFT) as u32;
    let mut pmm = PMM.lock();
    unsafe {
        pmm.zones[zone].free_order(pfn, order);
    }
    TELEMETRY
        .frames_freed
        .fetch_add(1u64 << order, Ordering::Relaxed);
}

/// Free a single 4 KiB physical frame (only after its refcount reaches 0).
#[inline]
pub fn free_frame(paddr: PhysAddr) {
    free_order(paddr, 0);
}

/// Decrement a frame's reference count and return it to the Buddy allocator
/// if the count drops to 0.
pub fn release_frame(paddr: PhysAddr) {
    if let Some(meta) = frame_meta(paddr.as_u64()) {
        if meta.refs() > 0 && meta.ref_dec() == 0 {
            free_frame(paddr);
        }
    }
}

/// Snapshot of PMM memory availability.
#[derive(Debug, Clone, Copy)]
pub struct PmmStats {
    pub total_pages: usize,
    pub free_pages: usize,
    pub used_pages: usize,
    pub free_bytes: u64,
}

pub fn stats() -> PmmStats {
    let pmm = PMM.lock();
    let total: usize = pmm.zones.iter().map(|z| z.total_pages).sum();
    let free: usize = pmm.zones.iter().map(|z| z.free_pages).sum();
    PmmStats {
        total_pages: total,
        free_pages: free,
        used_pages: total.saturating_sub(free),
        free_bytes: (free as u64) << PAGE_SHIFT,
    }
}
