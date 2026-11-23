//! Memory Management Subsystem (PMM, VMM, 4-Level Paging, Slab & Heap)

pub mod frame;
pub mod heap;
pub mod paging;
pub mod pmm;
pub mod slab;
pub mod vspace;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::{self, limine};
use crate::mm::frame::PAGE_SIZE;

static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Strong newtype for a 64-bit physical memory address.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        (self.0 & (PAGE_SIZE as u64 - 1)) == 0
    }

    #[inline]
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE as u64 - 1))
    }

    #[inline]
    pub const fn align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1))
    }
}

/// Strong newtype for a 64-bit canonical virtual memory address.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        (self.0 & (PAGE_SIZE as u64 - 1)) == 0
    }

    #[inline]
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE as u64 - 1))
    }

    #[inline]
    pub const fn align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1))
    }
}

/// Initialize the HHDM offset, Kernel PML4 anchor, Buddy PMM, and Slab caches.
pub fn init() {
    let hhdm = limine::hhdm_offset();
    HHDM_OFFSET.store(hhdm, Ordering::Release);

    let cr3 = x86_64::read_cr3();
    vspace::set_kernel_pml4(cr3);

    pmm::init();
    slab::SLAB_ALLOCATOR.log_stats();

    crate::kinfo!(
        "MM",
        "HHDM={:#018x} KernelCR3={:#018x} W^X=enforced CoW=enabled",
        hhdm,
        cr3 & paging::PageFlags::ADDR_MASK
    );
}

/// Convert a physical address to its Higher Half Direct Map (HHDM) virtual address.
#[inline(always)]
pub fn phys_to_virt(paddr: u64) -> u64 {
    paddr.wrapping_add(HHDM_OFFSET.load(Ordering::Relaxed))
}

/// Convert an HHDM virtual address back to its physical address.
#[inline(always)]
pub fn virt_to_phys(vaddr: u64) -> u64 {
    vaddr.wrapping_sub(HHDM_OFFSET.load(Ordering::Relaxed))
}

/// Return the HHDM base virtual offset.
#[inline(always)]
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Relaxed)
}
