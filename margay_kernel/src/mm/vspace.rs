//! Virtual Address Spaces (`AddressSpace` / VSpace), VMA Tracking,
//! Copy-on-Write (CoW), and Cross-CPU TLB Shootdown via IPI.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::{self, apic, smp};
use crate::debug::telemetry::TELEMETRY;
use crate::mm::frame::{frame_ref_inc, frame_refs, PAGE_SIZE};
use crate::mm::paging::{self, MapError, PageFlags, PageTable};
use crate::mm::{phys_to_virt, pmm, PhysAddr, VirtAddr};
use crate::sched::sync::IrqSpinlock;

/// Maximum canonical user-space address (lower half: `0x0000_7FFF_FFFF_F000`).
pub const USER_SPACE_LIMIT: u64 = 0x0000_7FFF_FFFF_F000;

/// Semantic kind of a Virtual Memory Area (VMA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaKind {
    Anonymous,
    Code,
    Stack,
    IpcBuffer,
    SharedMemory,
    MmioDevice,
}

/// Tracked contiguous virtual memory region inside a user `AddressSpace`.
#[derive(Debug, Clone, Copy)]
pub struct VmaRegion {
    pub start: u64,
    pub length: u64,
    pub flags: PageFlags,
    pub kind: VmaKind,
}

impl VmaRegion {
    #[inline]
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }

    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    #[inline]
    pub fn overlaps(&self, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        self.start < end && start < self.end()
    }
}

/// Unique AddressSpace (VSpace) identifier.
pub type VSpaceId = u64;

static NEXT_VSPACE_ID: AtomicU64 = AtomicU64::new(1);
static KERNEL_PML4_PA: AtomicU64 = AtomicU64::new(0);

/// Record the kernel's initial higher-half PML4 physical address during boot.
pub fn set_kernel_pml4(cr3_phys: u64) {
    KERNEL_PML4_PA.store(cr3_phys & PageFlags::ADDR_MASK, Ordering::Release);
}

pub fn kernel_pml4() -> PhysAddr {
    PhysAddr::new(KERNEL_PML4_PA.load(Ordering::Acquire))
}

/// Isolated virtual address space belonging to a Process / Ring 3 Server.
pub struct AddressSpace {
    pub id: VSpaceId,
    pub pml4_pa: PhysAddr,
    pub vmas: Vec<VmaRegion>,
    pub mapped_pages: usize,
}

impl AddressSpace {
    /// Allocate a new isolated user `AddressSpace` with kernel higher-half mapped.
    pub fn new_user() -> Result<Self, MapError> {
        let pml4_pa = paging::create_user_pml4(kernel_pml4())?;
        Ok(Self {
            id: NEXT_VSPACE_ID.fetch_add(1, Ordering::Relaxed),
            pml4_pa,
            vmas: Vec::new(),
            mapped_pages: 0,
        })
    }

    /// Physical CR3 value for activating this address space.
    #[inline]
    pub fn cr3(&self) -> u64 {
        self.pml4_pa.as_u64()
    }

    /// Activate this address space on the current CPU if not already active.
    #[inline]
    pub fn activate(&self) {
        let target = self.cr3();
        if x86_64::read_cr3() != target {
            unsafe {
                x86_64::write_cr3(target);
            }
        }
    }

    /// Register a VMA descriptor after verifying bounds and non-overlap.
    pub fn register_vma(&mut self, region: VmaRegion) -> Result<(), MapError> {
        if region.start == 0 || region.end() > USER_SPACE_LIMIT || region.length == 0 {
            return Err(MapError::UnalignedAddress);
        }
        if region.flags.violates_wx() {
            return Err(MapError::WxViolation);
        }
        for existing in &self.vmas {
            if existing.overlaps(region.start, region.length) {
                return Err(MapError::AlreadyMapped);
            }
        }
        self.vmas.push(region);
        Ok(())
    }

    /// Map a single 4 KiB physical frame at `vaddr` with W^X enforcement.
    pub fn map_page(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        if vaddr.as_u64() >= USER_SPACE_LIMIT {
            return Err(MapError::UnalignedAddress);
        }
        paging::map_4k(self.pml4_pa, vaddr, paddr, flags)?;
        self.mapped_pages += 1;
        Ok(())
    }

    /// Allocate and map `num_pages` fresh zeroed 4 KiB pages starting at `base_vaddr`.
    pub fn map_anonymous_region(
        &mut self,
        base_vaddr: u64,
        num_pages: usize,
        flags: PageFlags,
        kind: VmaKind,
    ) -> Result<(), MapError> {
        let length = (num_pages * PAGE_SIZE) as u64;
        self.register_vma(VmaRegion {
            start: base_vaddr,
            length,
            flags,
            kind,
        })?;

        for i in 0..num_pages {
            let va = VirtAddr::new(base_vaddr + (i * PAGE_SIZE) as u64);
            let pa = pmm::alloc_frame_zeroed().ok_or(MapError::OutOfMemory)?;
            if let Err(e) = self.map_page(va, pa, flags) {
                pmm::free_frame(pa);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Unmap a single 4 KiB page, release its physical frame refcount, and perform
    /// a cross-CPU TLB shootdown.
    pub fn unmap_page(&mut self, vaddr: VirtAddr) -> Result<(), MapError> {
        let old_pa = paging::unmap_4k(self.pml4_pa, vaddr)?;
        self.mapped_pages = self.mapped_pages.saturating_sub(1);
        tlb_shootdown_page(vaddr.as_u64());
        pmm::release_frame(old_pa);
        Ok(())
    }

    /// Update page protection flags (enforcing W^X) and shoot down TLB.
    pub fn protect_page(&mut self, vaddr: VirtAddr, new_flags: PageFlags) -> Result<(), MapError> {
        if new_flags.violates_wx() {
            return Err(MapError::WxViolation);
        }
        let pte = paging::get_pte_4k_mut(self.pml4_pa, vaddr).ok_or(MapError::NotMapped)?;
        let pa = pte.addr();
        pte.set(pa, new_flags.union(PageFlags::PRESENT));
        tlb_shootdown_page(vaddr.as_u64());
        Ok(())
    }

    /// Clone this AddressSpace using Copy-on-Write (CoW):
    /// Writable private user pages are marked read-only + `PageFlags::COW` in
    /// both parent and child, incrementing physical frame reference counts.
    pub fn clone_cow(&mut self) -> Result<Self, MapError> {
        let mut child = Self::new_user()?;
        child.vmas = self.vmas.clone();

        unsafe {
            let pml4 = PageTable::from_paddr(self.pml4_pa);
            for i4 in 0..256usize {
                let e4 = pml4.entries[i4];
                if !e4.is_present() {
                    continue;
                }
                let pdpt = PageTable::from_paddr(e4.addr());
                for i3 in 0..512usize {
                    let e3 = pdpt.entries[i3];
                    if !e3.is_present() || e3.is_huge() {
                        continue;
                    }
                    let pd = PageTable::from_paddr(e3.addr());
                    for i2 in 0..512usize {
                        let e2 = pd.entries[i2];
                        if !e2.is_present() || e2.is_huge() {
                            continue;
                        }
                        let pt = PageTable::from_paddr_mut(e2.addr());
                        for i1 in 0..512usize {
                            let e1 = &mut pt.entries[i1];
                            if !e1.is_present() {
                                continue;
                            }
                            let va_raw = ((i4 as u64) << 39)
                                | ((i3 as u64) << 30)
                                | ((i2 as u64) << 21)
                                | ((i1 as u64) << 12);
                            let pa = e1.addr();
                            let mut flags = e1.flags();

                            // Mark private writable pages CoW (read-only) in both parent & child
                            if flags.contains(PageFlags::WRITABLE)
                                && !flags.contains(PageFlags::SHARED)
                            {
                                flags = flags.remove(PageFlags::WRITABLE).union(PageFlags::COW);
                                e1.set(pa, flags);
                            }

                            frame_ref_inc(pa.as_u64());
                            child.map_page(VirtAddr::new(va_raw), pa, flags)?;
                        }
                    }
                }
            }
        }

        // Flush TLBs since parent writable entries were downgraded to CoW read-only
        tlb_shootdown_all();
        Ok(child)
    }

    /// Translate a virtual address in this VSpace.
    #[inline]
    pub fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        paging::translate(self.pml4_pa, vaddr)
    }

    /// Validate that a user buffer `[ptr, ptr + len)` is fully within user space
    /// and mapped present (and optionally writable).
    pub fn validate_user_range(&self, ptr: u64, len: usize, require_write: bool) -> bool {
        if len == 0 {
            return true;
        }
        let Some(end) = ptr.checked_add(len as u64) else {
            return false;
        };
        if ptr == 0 || end > USER_SPACE_LIMIT {
            return false;
        }
        let mut cur = ptr & !(PAGE_SIZE as u64 - 1);
        while cur < end {
            let Some((_, flags)) = self.translate(VirtAddr::new(cur)) else {
                return false;
            };
            if !flags.contains(PageFlags::USER) {
                return false;
            }
            if require_write && !flags.contains(PageFlags::WRITABLE) && !flags.contains(PageFlags::COW)
            {
                return false;
            }
            cur += PAGE_SIZE as u64;
        }
        true
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        if self.pml4_pa.as_u64() != 0 && self.pml4_pa != kernel_pml4() {
            paging::destroy_user_pml4(self.pml4_pa);
        }
    }
}

// ---------------------------------------------------------------------------
// Copy-on-Write Page Fault Handler
// ---------------------------------------------------------------------------

/// Attempt to resolve a `#PF` page fault (e.g. Copy-on-Write write fault) on the
/// currently active CR3. Returns `true` if handled and execution can resume.
pub fn handle_page_fault(cr2: u64, error_code: u64, _from_user: bool) -> bool {
    // Only handle Present + Write protection faults on lower-half user addresses
    let is_present = (error_code & 1) != 0;
    let is_write = (error_code & 2) != 0;
    if !is_present || !is_write || cr2 >= USER_SPACE_LIMIT {
        return false;
    }

    let cr3_pa = PhysAddr::new(x86_64::read_cr3() & PageFlags::ADDR_MASK);
    let page_va = VirtAddr::new(cr2 & !(PAGE_SIZE as u64 - 1));

    let Some(pte) = paging::get_pte_4k_mut(cr3_pa, page_va) else {
        return false;
    };

    let flags = pte.flags();
    if !flags.contains(PageFlags::COW) {
        return false;
    }

    let old_pa = pte.addr();
    let new_flags = flags.remove(PageFlags::COW).union(PageFlags::WRITABLE);
    if new_flags.violates_wx() {
        return false;
    }

    if frame_refs(old_pa.as_u64()) <= 1 {
        // Sole owner remaining: promote page directly to writable without copying.
        pte.set(old_pa, new_flags);
    } else {
        // Shared CoW page: allocate a private copy and decrement old frame refcount.
        let Some(new_pa) = pmm::alloc_frame() else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(old_pa.as_u64()) as *const u8,
                phys_to_virt(new_pa.as_u64()) as *mut u8,
                PAGE_SIZE,
            );
        }
        pte.set(new_pa, new_flags);
        pmm::release_frame(old_pa);
    }

    x86_64::invlpg(page_va.as_u64());
    TELEMETRY.cow_faults.fetch_add(1, Ordering::Relaxed);
    true
}

// ---------------------------------------------------------------------------
// Cross-CPU TLB Shootdown Protocol via IPI
// ---------------------------------------------------------------------------

struct TlbShootdownRequest {
    /// Target virtual address, or `u64::MAX` for full TLB flush.
    target_vaddr: u64,
}

static TLB_LOCK: IrqSpinlock<TlbShootdownRequest> =
    IrqSpinlock::new(TlbShootdownRequest { target_vaddr: 0 });
static TLB_TARGET_VADDR: AtomicU64 = AtomicU64::new(0);
static TLB_PENDING_ACKS: AtomicU32 = AtomicU32::new(0);

/// Shoot down a single virtual page across all online CPUs.
pub fn tlb_shootdown_page(vaddr: u64) {
    x86_64::invlpg(vaddr);
    broadcast_shootdown(vaddr);
}

/// Shoot down all non-global TLB entries across all online CPUs.
pub fn tlb_shootdown_all() {
    x86_64::flush_tlb_all();
    broadcast_shootdown(u64::MAX);
}

fn broadcast_shootdown(vaddr: u64) {
    let online = smp::online_cpus();
    if online <= 1 || !apic::is_ready() {
        return;
    }

    let mut req = TLB_LOCK.lock();
    req.target_vaddr = vaddr;
    TLB_TARGET_VADDR.store(vaddr, Ordering::Release);
    TLB_PENDING_ACKS.store(online - 1, Ordering::Release);

    apic::broadcast_ipi_excluding_self(apic::VECTOR_IPI_TLB_SHOOTDOWN);
    TELEMETRY.tlb_shootdowns.fetch_add(1, Ordering::Relaxed);

    // Wait for peer CPUs to acknowledge (bounded spin for safety)
    let mut spins = 0u32;
    while TLB_PENDING_ACKS.load(Ordering::Acquire) > 0 && spins < 5_000_000 {
        core::hint::spin_loop();
        spins += 1;
    }
}

/// Executed on peer CPUs inside `VECTOR_IPI_TLB_SHOOTDOWN` ISR.
pub fn handle_tlb_shootdown_ipi() {
    let target = TLB_TARGET_VADDR.load(Ordering::Acquire);
    if target == u64::MAX {
        x86_64::flush_tlb_all();
    } else {
        x86_64::invlpg(target);
    }
    let _ = TLB_PENDING_ACKS.try_update(Ordering::AcqRel, Ordering::Relaxed, |v| {
        if v > 0 { Some(v - 1) } else { Some(0) }
    });
}
