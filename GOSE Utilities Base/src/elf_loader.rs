//! Ring 3 ELF64 Process Loader
//!
//! Used by `goseinit.elf` (to spawn isolated hardware/FS/shell servers) and
//! by `gosebi.elf` (to execute `execbin <NOME.elf>` binaries from FAT32).
//!
//! Creates a new isolated `Process` (`SYS_PROCESS_CREATE`), retypes `Frame4K`s
//! from `UntypedMemory` (`CAP_OP_RETYPE`), maps them into the target VSpace
//! with strict W^X (`SYS_VSPACE_MAP_FRAME`), delegates only the required
//! capabilities (`CAP_OP_COPY_TO_CNODE`), and starts execution (`SYS_THREAD_CREATE_IN`).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::libmargay::{
    self, GoseBootInfo, MAP_RO, MAP_RW, MAP_RX, RETYPE_FRAME_4K, RIGHT_ALL,
};

const PAGE_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// Monotonic scratch virtual address counter in the loader's own VSpace (`0x6000_0000+`)
static NEXT_SCRATCH_VA: AtomicU64 = AtomicU64::new(0x0000_0000_6000_0000);
/// Monotonic CSpace slot allocator in the loader's root CNode (slots 100..499)
static NEXT_LOADER_SLOT: AtomicU64 = AtomicU64::new(100);

fn alloc_loader_slot() -> u64 {
    let s = NEXT_LOADER_SLOT.fetch_add(1, Ordering::Relaxed);
    if s >= 500 {
        NEXT_LOADER_SLOT.store(100, Ordering::Relaxed);
        100
    } else {
        s
    }
}

fn alloc_scratch_va() -> u64 {
    NEXT_SCRATCH_VA.fetch_add(PAGE_SIZE as u64, Ordering::Relaxed)
}

/// Capability delegation entry: `(src_cptr_in_loader, dst_slot_in_child)`.
#[derive(Clone, Copy)]
pub struct CapGrant {
    pub src_slot: u64,
    pub dst_slot: u64,
}

/// Spawn a new isolated Ring 3 Process from an ELF64 byte slice.
/// Returns `(pid, tid)` on success.
pub fn spawn_elf_process(
    elf: &[u8],
    untyped_slot: u64,
    child_bi: &GoseBootInfo,
    grants: &[CapGrant],
) -> Option<(u64, u64)> {
    if elf.len() < core::mem::size_of::<Elf64Ehdr>() || !elf.starts_with(b"\x7FELF") {
        return None;
    }
    let ehdr = unsafe { core::ptr::read_unaligned(elf.as_ptr() as *const Elf64Ehdr) };
    if ehdr.e_machine != 0x3E || ehdr.e_entry == 0 {
        return None;
    }

    let vs_slot = alloc_loader_slot();
    let cn_slot = alloc_loader_slot();
    let pid = libmargay::process_create(8, vs_slot, cn_slot);
    if pid <= 0 {
        return None;
    }

    let frame_slot = alloc_loader_slot();

    // 1. Load all PT_LOAD segments with strict W^X enforcement
    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;

    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + core::mem::size_of::<Elf64Phdr>() > elf.len() {
            break;
        }
        let ph = unsafe { core::ptr::read_unaligned(elf.as_ptr().add(off) as *const Elf64Phdr) };
        if ph.p_type != 1 || ph.p_memsz == 0 {
            continue;
        }

        let seg_start = ph.p_vaddr & !(PAGE_SIZE as u64 - 1);
        let seg_end = (ph.p_vaddr + ph.p_memsz + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
        let num_pages = ((seg_end - seg_start) / PAGE_SIZE as u64) as usize;

        let is_exec = (ph.p_flags & 1) != 0;
        let is_write = (ph.p_flags & 2) != 0;
        let perm = if is_exec && !is_write {
            MAP_RX
        } else if is_write {
            MAP_RW
        } else {
            MAP_RO
        };

        for p in 0..num_pages {
            let page_va = seg_start + (p * PAGE_SIZE) as u64;
            let fslot = 99u64;
            let _ = libmargay::cap_delete(fslot);
            if !libmargay::cap_retype(untyped_slot, fslot, RETYPE_FRAME_4K, 0) {
                return None;
            }
            let scratch = alloc_scratch_va();
            if !libmargay::vspace_map_frame(2, fslot, scratch, MAP_RW) {
                return None;
            }

            // Copy overlapping ELF bytes into the freshly zeroed Frame4K
            let page_end = page_va + PAGE_SIZE as u64;
            let file_start = ph.p_vaddr;
            let file_end = ph.p_vaddr + ph.p_filesz;
            let ov_start = page_va.max(file_start);
            let ov_end = page_end.min(file_end);
            if ov_start < ov_end {
                let len = (ov_end - ov_start) as usize;
                let dst_off = (ov_start - page_va) as usize;
                let src_off = ph.p_offset as usize + (ov_start - file_start) as usize;
                if src_off + len <= elf.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            elf.as_ptr().add(src_off),
                            (scratch as *mut u8).add(dst_off),
                            len,
                        );
                    }
                }
            }

            let mapped = libmargay::vspace_map_frame(vs_slot, fslot, page_va, perm);
            let _ = libmargay::cap_delete(fslot);
            if !mapped {
                return None;
            }
        }
    }

    // 2. Map 32 KiB user stack (8 pages) at 0x1000_0000
    const CHILD_STACK_VA: u64 = 0x0000_0000_1000_0000;
    const CHILD_STACK_PAGES: usize = 8;
    for p in 0..CHILD_STACK_PAGES {
        let fslot = 99u64;
        let _ = libmargay::cap_delete(fslot);
        if !libmargay::cap_retype(untyped_slot, fslot, RETYPE_FRAME_4K, 0) {
            return None;
        }
        let mapped = libmargay::vspace_map_frame(
            vs_slot,
            fslot,
            CHILD_STACK_VA + (p * PAGE_SIZE) as u64,
            MAP_RW,
        );
        let _ = libmargay::cap_delete(fslot);
        if !mapped {
            return None;
        }
    }

    // 3. Map GoseBootInfo page at 0x0030_0000
    const BOOTINFO_VA: u64 = 0x0000_0000_0030_0000;
    let _ = libmargay::cap_delete(frame_slot);
    if !libmargay::cap_retype(untyped_slot, frame_slot, RETYPE_FRAME_4K, 0) {
        return None;
    }
    let bi_scratch = alloc_scratch_va();
    if !libmargay::vspace_map_frame(2, frame_slot, bi_scratch, MAP_RW) {
        return None;
    }
    unsafe {
        core::ptr::write(bi_scratch as *mut GoseBootInfo, *child_bi);
    }
    let mapped_bi = libmargay::vspace_map_frame(vs_slot, frame_slot, BOOTINFO_VA, MAP_RO);
    let _ = libmargay::cap_delete(frame_slot);
    if !mapped_bi {
        return None;
    }

    // 4. Delegate least-privilege capabilities into child's CNode
    let _ = libmargay::cap_copy_to_cnode(vs_slot, cn_slot, 2, RIGHT_ALL, 0);
    for g in grants {
        if g.src_slot != 0 && g.dst_slot != 0 {
            let _ = libmargay::cap_copy_to_cnode(g.src_slot, cn_slot, g.dst_slot, RIGHT_ALL, 0);
        }
    }

    // 5. Spawn child's main Ring 3 thread
    let child_rsp = CHILD_STACK_VA + (CHILD_STACK_PAGES * PAGE_SIZE) as u64 - 8;
    let tid = libmargay::thread_create_in(vs_slot, ehdr.e_entry, child_rsp, BOOTINFO_VA);
    if tid <= 0 {
        return None;
    }

    Some((pid as u64, tid as u64))
}
