//! x86_64 4-Level Paging Engine (PML4 -> PDPT -> PD -> PT)
//!
//! Supports 4 KiB, 2 MiB, and 1 GiB mappings, strict W^X (Write XOR Execute)
//! validation, Copy-on-Write (CoW) software flag tracking, kernel higher-half
//! sharing into every user AddressSpace, and safe recursive page table teardown.

use crate::mm::frame::{frame_flags, frame_meta, PAGE_SIZE};
use crate::mm::{phys_to_virt, pmm, PhysAddr, VirtAddr};

/// Architectural and software-defined x86_64 Page Table Entry flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags(pub u64);

impl PageFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const NO_CACHE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const HUGE: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);
    /// Software bit 9: Copy-on-Write shared page (mapped read-only until write fault).
    pub const COW: Self = Self(1 << 9);
    /// Software bit 10: SharedMemory zero-copy page.
    pub const SHARED: Self = Self(1 << 10);
    /// Bit 63: No-Execute (NX / XD).
    pub const NO_EXECUTE: Self = Self(1 << 63);

    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Strict W^X check: a mapping must never be simultaneously WRITABLE and
    /// executable (i.e. missing NO_EXECUTE).
    #[inline]
    pub const fn violates_wx(self) -> bool {
        self.contains(Self::WRITABLE) && !self.contains(Self::NO_EXECUTE)
    }

    /// Preset: Kernel read/write data (NX).
    pub const fn kernel_rw() -> Self {
        Self::PRESENT
            .union(Self::WRITABLE)
            .union(Self::NO_EXECUTE)
            .union(Self::GLOBAL)
    }

    /// Preset: User code (R-X, no write).
    pub const fn user_rx() -> Self {
        Self::PRESENT.union(Self::USER)
    }

    /// Preset: User data / stack (RW-, NX).
    pub const fn user_rw() -> Self {
        Self::PRESENT
            .union(Self::USER)
            .union(Self::WRITABLE)
            .union(Self::NO_EXECUTE)
    }

    /// Preset: User read-only data (R--, NX).
    pub const fn user_ro() -> Self {
        Self::PRESENT.union(Self::USER).union(Self::NO_EXECUTE)
    }

    /// Preset: User MMIO device mapping (RW-, NX, Uncacheable + WriteThrough).
    pub const fn user_mmio() -> Self {
        Self::PRESENT
            .union(Self::USER)
            .union(Self::WRITABLE)
            .union(Self::NO_EXECUTE)
            .union(Self::NO_CACHE)
            .union(Self::WRITE_THROUGH)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    pub fn is_present(self) -> bool {
        (self.0 & PageFlags::PRESENT.0) != 0
    }

    #[inline]
    pub fn is_huge(self) -> bool {
        (self.0 & PageFlags::HUGE.0) != 0
    }

    #[inline]
    pub fn flags(self) -> PageFlags {
        PageFlags(self.0 & !PageFlags::ADDR_MASK)
    }

    #[inline]
    pub fn addr(self) -> PhysAddr {
        PhysAddr::new(self.0 & PageFlags::ADDR_MASK)
    }

    #[inline]
    pub fn set(&mut self, paddr: PhysAddr, flags: PageFlags) {
        self.0 = (paddr.as_u64() & PageFlags::ADDR_MASK) | flags.bits();
    }

    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    #[inline]
    pub unsafe fn from_paddr_mut(paddr: PhysAddr) -> &'static mut Self {
        &mut *(phys_to_virt(paddr.as_u64()) as *mut Self)
    }

    #[inline]
    pub unsafe fn from_paddr(paddr: PhysAddr) -> &'static Self {
        &*(phys_to_virt(paddr.as_u64()) as *const Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    OutOfMemory,
    AlreadyMapped,
    NotMapped,
    WxViolation,
    UnalignedAddress,
    HugePageConflict,
}

/// Extract 9-bit page table indices (pml4, pdpt, pd, pt) from a canonical virtual address.
#[inline]
pub const fn table_indices(vaddr: VirtAddr) -> (usize, usize, usize, usize) {
    let a = vaddr.as_u64();
    let pml4 = ((a >> 39) & 0x1FF) as usize;
    let pdpt = ((a >> 30) & 0x1FF) as usize;
    let pd = ((a >> 21) & 0x1FF) as usize;
    let pt = ((a >> 12) & 0x1FF) as usize;
    (pml4, pdpt, pd, pt)
}

/// Allocate a fresh zeroed page table frame and mark its `PageFrame` metadata.
fn alloc_table_frame() -> Result<PhysAddr, MapError> {
    let pa = pmm::alloc_frame_zeroed().ok_or(MapError::OutOfMemory)?;
    if let Some(meta) = frame_meta(pa.as_u64()) {
        meta.set_flags(frame_flags::PAGETABLE);
    }
    Ok(pa)
}

/// Ensure an intermediate page table entry exists, allocating a child table if needed.
unsafe fn ensure_next_table(
    entry: &mut PageTableEntry,
    user_accessible: bool,
) -> Result<&'static mut PageTable, MapError> {
    if entry.is_present() {
        if entry.is_huge() {
            return Err(MapError::HugePageConflict);
        }
        // Propagate USER bit upward if a user mapping traverses an existing table
        if user_accessible && !entry.flags().contains(PageFlags::USER) {
            entry.0 |= PageFlags::USER.0;
        }
        return Ok(PageTable::from_paddr_mut(entry.addr()));
    }

    let child_pa = alloc_table_frame()?;
    let mut flags = PageFlags::PRESENT.union(PageFlags::WRITABLE);
    if user_accessible {
        flags = flags.union(PageFlags::USER);
    }
    entry.set(child_pa, flags);
    Ok(PageTable::from_paddr_mut(child_pa))
}

/// Map a 4 KiB virtual page to a 4 KiB physical frame in `pml4_pa`, enforcing W^X.
pub fn map_4k(
    pml4_pa: PhysAddr,
    vaddr: VirtAddr,
    paddr: PhysAddr,
    flags: PageFlags,
) -> Result<(), MapError> {
    if !vaddr.is_page_aligned() || !paddr.is_page_aligned() {
        return Err(MapError::UnalignedAddress);
    }
    if flags.violates_wx() {
        return Err(MapError::WxViolation);
    }

    let (i4, i3, i2, i1) = table_indices(vaddr);
    let is_user = flags.contains(PageFlags::USER);

    unsafe {
        let pml4 = PageTable::from_paddr_mut(pml4_pa);
        let pdpt = ensure_next_table(&mut pml4.entries[i4], is_user)?;
        let pd = ensure_next_table(&mut pdpt.entries[i3], is_user)?;
        let pt = ensure_next_table(&mut pd.entries[i2], is_user)?;

        if pt.entries[i1].is_present() {
            return Err(MapError::AlreadyMapped);
        }
        pt.entries[i1].set(paddr, flags.union(PageFlags::PRESENT));
    }
    Ok(())
}

/// Map a 2 MiB Huge Page in `pml4_pa`, enforcing W^X.
pub fn map_2m(
    pml4_pa: PhysAddr,
    vaddr: VirtAddr,
    paddr: PhysAddr,
    flags: PageFlags,
) -> Result<(), MapError> {
    const MASK_2M: u64 = (2 * 1024 * 1024) - 1;
    if (vaddr.as_u64() & MASK_2M) != 0 || (paddr.as_u64() & MASK_2M) != 0 {
        return Err(MapError::UnalignedAddress);
    }
    if flags.violates_wx() {
        return Err(MapError::WxViolation);
    }

    let (i4, i3, i2, _) = table_indices(vaddr);
    let is_user = flags.contains(PageFlags::USER);

    unsafe {
        let pml4 = PageTable::from_paddr_mut(pml4_pa);
        let pdpt = ensure_next_table(&mut pml4.entries[i4], is_user)?;
        let pd = ensure_next_table(&mut pdpt.entries[i3], is_user)?;

        if pd.entries[i2].is_present() {
            return Err(MapError::AlreadyMapped);
        }
        pd.entries[i2].set(paddr, flags.union(PageFlags::PRESENT).union(PageFlags::HUGE));
    }
    Ok(())
}

/// Unmap a 4 KiB virtual page and return its previously mapped physical address.
pub fn unmap_4k(pml4_pa: PhysAddr, vaddr: VirtAddr) -> Result<PhysAddr, MapError> {
    let (i4, i3, i2, i1) = table_indices(vaddr);
    unsafe {
        let pml4 = PageTable::from_paddr(pml4_pa);
        if !pml4.entries[i4].is_present() {
            return Err(MapError::NotMapped);
        }
        let pdpt = PageTable::from_paddr(pml4.entries[i4].addr());
        if !pdpt.entries[i3].is_present() || pdpt.entries[i3].is_huge() {
            return Err(MapError::NotMapped);
        }
        let pd = PageTable::from_paddr(pdpt.entries[i3].addr());
        if !pd.entries[i2].is_present() || pd.entries[i2].is_huge() {
            return Err(MapError::NotMapped);
        }
        let pt = PageTable::from_paddr_mut(pd.entries[i2].addr());
        if !pt.entries[i1].is_present() {
            return Err(MapError::NotMapped);
        }
        let old_pa = pt.entries[i1].addr();
        pt.entries[i1].clear();
        Ok(old_pa)
    }
}

/// Translate a virtual address through `pml4_pa`, returning `(PhysAddr, PageFlags)`.
pub fn translate(pml4_pa: PhysAddr, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
    let (i4, i3, i2, i1) = table_indices(vaddr);
    unsafe {
        let pml4 = PageTable::from_paddr(pml4_pa);
        let e4 = pml4.entries[i4];
        if !e4.is_present() {
            return None;
        }
        let pdpt = PageTable::from_paddr(e4.addr());
        let e3 = pdpt.entries[i3];
        if !e3.is_present() {
            return None;
        }
        if e3.is_huge() {
            let offset = vaddr.as_u64() & 0x3FFF_FFFF;
            return Some((PhysAddr::new(e3.addr().as_u64() + offset), e3.flags()));
        }
        let pd = PageTable::from_paddr(e3.addr());
        let e2 = pd.entries[i2];
        if !e2.is_present() {
            return None;
        }
        if e2.is_huge() {
            let offset = vaddr.as_u64() & 0x1F_FFFF;
            return Some((PhysAddr::new(e2.addr().as_u64() + offset), e2.flags()));
        }
        let pt = PageTable::from_paddr(e2.addr());
        let e1 = pt.entries[i1];
        if !e1.is_present() {
            return None;
        }
        let offset = vaddr.as_u64() & (PAGE_SIZE as u64 - 1);
        Some((PhysAddr::new(e1.addr().as_u64() + offset), e1.flags()))
    }
}

/// Mutable lookup of a leaf 4 KiB PTE (for CoW / permission updates).
pub fn get_pte_4k_mut(pml4_pa: PhysAddr, vaddr: VirtAddr) -> Option<&'static mut PageTableEntry> {
    let (i4, i3, i2, i1) = table_indices(vaddr);
    unsafe {
        let pml4 = PageTable::from_paddr(pml4_pa);
        if !pml4.entries[i4].is_present() {
            return None;
        }
        let pdpt = PageTable::from_paddr(pml4.entries[i4].addr());
        if !pdpt.entries[i3].is_present() || pdpt.entries[i3].is_huge() {
            return None;
        }
        let pd = PageTable::from_paddr(pdpt.entries[i3].addr());
        if !pd.entries[i2].is_present() || pd.entries[i2].is_huge() {
            return None;
        }
        let pt = PageTable::from_paddr_mut(pd.entries[i2].addr());
        if !pt.entries[i1].is_present() {
            return None;
        }
        Some(&mut pt.entries[i1])
    }
}

/// Create a fresh user PML4 that clones the kernel higher-half entries (256..512)
/// from `kernel_pml4_pa` while leaving the entire lower user half (0..256) empty.
pub fn create_user_pml4(kernel_pml4_pa: PhysAddr) -> Result<PhysAddr, MapError> {
    let new_pa = alloc_table_frame()?;
    unsafe {
        let src = PageTable::from_paddr(kernel_pml4_pa);
        let dst = PageTable::from_paddr_mut(new_pa);
        for i in 256..512 {
            dst.entries[i] = src.entries[i];
        }
    }
    Ok(new_pa)
}

/// Tear down all lower-half (user) page tables and decrement physical frame
/// refcounts, freeing the PML4 itself. Never touches kernel higher-half entries.
pub fn destroy_user_pml4(pml4_pa: PhysAddr) {
    unsafe {
        let pml4 = PageTable::from_paddr(pml4_pa);
        for i4 in 0..256 {
            let e4 = pml4.entries[i4];
            if !e4.is_present() {
                continue;
            }
            let pdpt = PageTable::from_paddr(e4.addr());
            for i3 in 0..512 {
                let e3 = pdpt.entries[i3];
                if !e3.is_present() || e3.is_huge() {
                    continue;
                }
                let pd = PageTable::from_paddr(e3.addr());
                for i2 in 0..512 {
                    let e2 = pd.entries[i2];
                    if !e2.is_present() || e2.is_huge() {
                        continue;
                    }
                    let pt = PageTable::from_paddr(e2.addr());
                    for i1 in 0..512 {
                        let e1 = pt.entries[i1];
                        if e1.is_present() {
                            pmm::release_frame(e1.addr());
                        }
                    }
                    pmm::free_frame(e2.addr());
                }
                pmm::free_frame(e3.addr());
            }
            pmm::free_frame(e4.addr());
        }
    }
    pmm::free_frame(pml4_pa);
}
