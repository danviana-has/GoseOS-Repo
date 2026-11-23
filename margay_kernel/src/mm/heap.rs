//! Kernel Global Heap Allocator (`#[global_allocator]`)
//!
//! Routes allocations <= 2048 bytes directly through the lock-sharded
//! `SLAB_ALLOCATOR`, and allocations > 2048 bytes directly to power-of-two
//! Buddy PMM blocks mapped via the Higher Half Direct Map (HHDM).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use crate::mm::frame::PAGE_SIZE;
use crate::mm::slab::SLAB_ALLOCATOR;
use crate::mm::{phys_to_virt, pmm, virt_to_phys, PhysAddr};

pub struct MargayHeapAllocator;

/// Compute the smallest Buddy order `k` such that `(1 << k) * PAGE_SIZE >= bytes`.
#[inline]
fn buddy_order_for_bytes(bytes: usize) -> usize {
    let pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut order = 0usize;
    while (1usize << order) < pages {
        order += 1;
    }
    order
}

unsafe impl GlobalAlloc for MargayHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        let align = layout.align().max(1);

        // Fast path: Slab Object Cache (<= 2048 bytes)
        if let Some(nn) = SLAB_ALLOCATOR.alloc(size, align) {
            return nn.as_ptr();
        }

        // Large allocation path: Buddy PMM contiguous frames via HHDM
        let req_bytes = size.max(align);
        let order = buddy_order_for_bytes(req_bytes);
        match pmm::alloc_order(order) {
            Some(pa) => phys_to_virt(pa.as_u64()) as *mut u8,
            None => null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let size = layout.size().max(1);
        let align = layout.align().max(1);

        if SLAB_ALLOCATOR.free(ptr, size, align) {
            return;
        }

        let req_bytes = size.max(align);
        let order = buddy_order_for_bytes(req_bytes);
        let pa = PhysAddr::new(virt_to_phys(ptr as u64));
        pmm::free_order(pa, order);
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: MargayHeapAllocator = MargayHeapAllocator;

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!(
        "Kernel Heap OOM: failed to allocate {} bytes (align={})",
        layout.size(),
        layout.align()
    );
}
