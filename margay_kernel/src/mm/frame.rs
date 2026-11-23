//! Physical Page Frame Metadata & Reference Counting (`PageFrame`)
//!
//! Every 4 KiB physical page frame tracked by the PMM has a compact metadata
//! descriptor recording its reference count (for Copy-on-Write and Shared
//! Memory), buddy allocation order, memory zone (DMA / DMA32 / Normal), and
//! semantic usage flags.

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU8, Ordering};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;
pub const HUGE_PAGE_2M: usize = 2 * 1024 * 1024;
pub const HUGE_PAGE_1G: usize = 1024 * 1024 * 1024;

/// Maximum physical memory supported by the static frame metadata table (1 GiB = 262,144 frames).
/// Each `PageFrame` is 8 bytes -> 2 MiB BSS table, zero dynamic bootstrap hazard.
pub const MAX_TRACKED_FRAMES: usize = 262_144;

/// Physical memory zones for DMA and general allocation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryZone {
    /// Legacy ISA / low DMA (< 16 MiB)
    Dma = 0,
    /// 32-bit PCI DMA (< 4 GiB)
    Dma32 = 1,
    /// General 64-bit RAM (>= 4 GiB)
    Normal = 2,
}

impl MemoryZone {
    #[inline]
    pub const fn from_paddr(paddr: u64) -> Self {
        if paddr < 16 * 1024 * 1024 {
            Self::Dma
        } else if paddr < 4 * 1024 * 1024 * 1024 {
            Self::Dma32
        } else {
            Self::Normal
        }
    }
}

/// Bitflags describing the role and state of a physical page frame.
pub mod frame_flags {
    pub const FREE: u16 = 1 << 0;
    pub const KERNEL: u16 = 1 << 1;
    pub const USER: u16 = 1 << 2;
    pub const PAGETABLE: u16 = 1 << 3;
    pub const SLAB: u16 = 1 << 4;
    pub const COW: u16 = 1 << 5;
    pub const SHARED: u16 = 1 << 6;
    pub const DMA: u16 = 1 << 7;
    pub const PINNED: u16 = 1 << 8;
    pub const RESERVED: u16 = 1 << 9;
}

/// Compact 8-byte descriptor for a single 4 KiB physical page frame.
#[repr(C)]
pub struct PageFrame {
    pub refcount: AtomicU32,
    pub flags: AtomicU16,
    pub order: AtomicU8,
    pub zone: AtomicU8,
}

impl PageFrame {
    pub const fn new_reserved() -> Self {
        Self {
            refcount: AtomicU32::new(0),
            flags: AtomicU16::new(frame_flags::RESERVED),
            order: AtomicU8::new(0),
            zone: AtomicU8::new(MemoryZone::Normal as u8),
        }
    }

    #[inline]
    pub fn ref_inc(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::AcqRel) + 1
    }

    #[inline]
    pub fn ref_dec(&self) -> u32 {
        let prev = self.refcount.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "PageFrame refcount underflow");
        prev - 1
    }

    #[inline]
    pub fn refs(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_flags(&self, bits: u16) {
        self.flags.fetch_or(bits, Ordering::AcqRel);
    }

    #[inline]
    pub fn clear_flags(&self, bits: u16) {
        self.flags.fetch_and(!bits, Ordering::AcqRel);
    }

    #[inline]
    pub fn has_flag(&self, bit: u16) -> bool {
        (self.flags.load(Ordering::Acquire) & bit) != 0
    }
}

/// Global Page Frame Database (PFN -> `PageFrame`).
static FRAME_DB: [PageFrame; MAX_TRACKED_FRAMES] = [const { PageFrame::new_reserved() }; MAX_TRACKED_FRAMES];

/// Retrieve the `PageFrame` descriptor for a physical address (if within tracked RAM).
#[inline]
pub fn frame_meta(paddr: u64) -> Option<&'static PageFrame> {
    let pfn = (paddr >> PAGE_SHIFT) as usize;
    if pfn < MAX_TRACKED_FRAMES {
        Some(&FRAME_DB[pfn])
    } else {
        None
    }
}

/// Increment reference count on a physical frame (e.g. CoW fork or SharedMemory map).
#[inline]
pub fn frame_ref_inc(paddr: u64) -> u32 {
    if let Some(f) = frame_meta(paddr) {
        f.ref_inc()
    } else {
        1
    }
}

/// Decrement reference count on a physical frame; returns the new count.
/// Caller should free the frame via `pmm::free_frame(paddr)` when count hits 0.
#[inline]
pub fn frame_ref_dec(paddr: u64) -> u32 {
    if let Some(f) = frame_meta(paddr) {
        f.ref_dec()
    } else {
        0
    }
}

/// Query current reference count on a physical frame.
#[inline]
pub fn frame_refs(paddr: u64) -> u32 {
    if let Some(f) = frame_meta(paddr) {
        f.refs()
    } else {
        0
    }
}
