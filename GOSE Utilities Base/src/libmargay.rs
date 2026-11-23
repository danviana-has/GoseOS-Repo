//! `libmargay` — Ring 3 User-Space Syscall ABI & Hardware Access SDK for Margay Microkernel

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

// Syscall Numbers (must match `margay_kernel/src/syscall/mod.rs`)
pub const SYS_DEBUG_PRINT: u64 = 0;
pub const SYS_YIELD: u64 = 1;
pub const SYS_THREAD_EXIT: u64 = 2;
pub const SYS_GET_TID: u64 = 3;
pub const SYS_IPC_SEND: u64 = 4;
pub const SYS_IPC_RECV: u64 = 5;
pub const SYS_IPC_CALL: u64 = 6;
pub const SYS_IPC_REPLY: u64 = 7;
pub const SYS_IPC_REPLY_WAIT: u64 = 8;
pub const SYS_NOTIFY_SIGNAL: u64 = 9;
pub const SYS_NOTIFY_WAIT: u64 = 10;
pub const SYS_NOTIFY_POLL: u64 = 11;
pub const SYS_CAP_INVOKE: u64 = 12;
pub const SYS_SHMEM_CREATE: u64 = 13;
pub const SYS_SHMEM_MAP: u64 = 14;
pub const SYS_THREAD_SPAWN: u64 = 15;
pub const SYS_SYSINFO: u64 = 16;
pub const SYS_PROCESS_CREATE: u64 = 17;
pub const SYS_VSPACE_MAP_FRAME: u64 = 18;
pub const SYS_THREAD_CREATE_IN: u64 = 19;

// Capability invocation sub-operations
pub const CAP_OP_MINT: u64 = 1;
pub const CAP_OP_COPY: u64 = 2;
pub const CAP_OP_MOVE: u64 = 3;
pub const CAP_OP_DELETE: u64 = 4;
pub const CAP_OP_REVOKE: u64 = 5;
pub const CAP_OP_IOPORT_GRANT: u64 = 6;
pub const CAP_OP_IRQ_BIND: u64 = 7;
pub const CAP_OP_IRQ_ACK: u64 = 8;
pub const CAP_OP_MMIO_MAP: u64 = 9;
pub const CAP_OP_RETYPE: u64 = 10;
pub const CAP_OP_COPY_TO_CNODE: u64 = 11;

// Retype object kinds
pub const RETYPE_FRAME_4K: u64 = 1;
pub const RETYPE_ENDPOINT: u64 = 2;
pub const RETYPE_NOTIFICATION: u64 = 3;
pub const RETYPE_CNODE: u64 = 4;
pub const RETYPE_VSPACE: u64 = 5;

// CapRights bits
pub const RIGHT_READ: u64 = 1 << 0;
pub const RIGHT_WRITE: u64 = 1 << 1;
pub const RIGHT_GRANT: u64 = 1 << 2;
pub const RIGHT_EXECUTE: u64 = 1 << 5;
pub const RIGHT_ALL: u64 = 0x7F;

// W^X permissions for SYS_VSPACE_MAP_FRAME
pub const MAP_RO: u64 = 0x1;
pub const MAP_RW: u64 = 0x3;
pub const MAP_RX: u64 = 0x5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootModuleDesc {
    pub vaddr: u64,
    pub size: u64,
    pub name: [u8; 32],
}

impl BootModuleDesc {
    pub fn name_str(&self) -> &str {
        cstr_slice(&self.name)
    }
}

/// Boot hand-off structure mapped read-only at `0x0000_0000_0030_0000`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GoseBootInfo {
    pub magic: u64,
    pub kernel_version: [u8; 32],
    pub fb_phys: u64,
    pub fb_width: u64,
    pub fb_height: u64,
    pub fb_pitch: u64,
    pub fb_bpp: u32,
    pub cpu_count: u32,
    pub total_mem_pages: u64,
    pub free_mem_pages: u64,
    pub cpu_vendor: [u8; 16],
    pub cpu_brand: [u8; 48],
    pub fb_cap_slot: u64,
    pub ps2_ioport_slot: u64,
    pub ata_pri_ioport_slot: u64,
    pub ata_ctl_ioport_slot: u64,
    pub com1_ioport_slot: u64,
    pub irq_ctrl_slot: u64,
    pub untyped_slot: u64,
    pub untyped2_slot: u64,
    pub ep_gop_slot: u64,
    pub ep_ps2_slot: u64,
    pub ep_fs_slot: u64,
    pub shm_gop_slot: u64,
    pub shm_fs_slot: u64,
    pub exit_notif_slot: u64,
    pub module_count: u32,
    pub _pad: u32,
    pub modules: [BootModuleDesc; 8],
}

impl GoseBootInfo {
    pub fn kernel_ver_str(&self) -> &str {
        cstr_slice(&self.kernel_version)
    }

    pub fn cpu_vendor_str(&self) -> &str {
        cstr_slice(&self.cpu_vendor)
    }

    pub fn cpu_brand_str(&self) -> &str {
        cstr_slice(&self.cpu_brand).trim()
    }
}

fn cstr_slice(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("")
}

#[inline(always)]
pub unsafe fn syscall6(
    num: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inout("rax") num => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        in("r8") a4,
        in("r9") a5,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IpcRegs {
    pub tag: u64,
    pub r0: u64,
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub badge: u64,
}

#[inline]
pub fn ipc_call(ep_cptr: u64, tag: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> IpcRegs {
    let out_tag: u64;
    let out_r0: u64;
    let out_r1: u64;
    let out_r2: u64;
    let out_r3: u64;
    let out_badge: u64;
    unsafe {
        asm!(
            "syscall",
            inout("rax") SYS_IPC_CALL => out_tag,
            inout("rdi") ep_cptr => out_r0,
            inout("rsi") tag => out_r1,
            inout("rdx") r0 => out_r2,
            inout("r10") r1 => out_r3,
            inout("r8") r2 => out_badge,
            in("r9") r3,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    IpcRegs {
        tag: out_tag,
        r0: out_r0,
        r1: out_r1,
        r2: out_r2,
        r3: out_r3,
        badge: out_badge,
    }
}

#[inline]
pub fn ipc_recv(ep_cptr: u64) -> IpcRegs {
    let out_tag: u64;
    let out_r0: u64;
    let out_r1: u64;
    let out_r2: u64;
    let out_r3: u64;
    let out_badge: u64;
    unsafe {
        asm!(
            "syscall",
            inout("rax") SYS_IPC_RECV => out_tag,
            inout("rdi") ep_cptr => out_r0,
            out("rsi") out_r1,
            out("rdx") out_r2,
            out("r10") out_r3,
            out("r8") out_badge,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    IpcRegs {
        tag: out_tag,
        r0: out_r0,
        r1: out_r1,
        r2: out_r2,
        r3: out_r3,
        badge: out_badge,
    }
}

#[inline]
pub fn ipc_reply(tag: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> i64 {
    unsafe { syscall6(SYS_IPC_REPLY, tag, r0, r1, r2, r3, 0) }
}

#[inline]
pub fn notify_signal(notif_cptr: u64, bits: u64) -> i64 {
    unsafe { syscall6(SYS_NOTIFY_SIGNAL, notif_cptr, bits, 0, 0, 0, 0) }
}

#[inline]
pub fn notify_wait(notif_cptr: u64) -> u64 {
    unsafe { syscall6(SYS_NOTIFY_WAIT, notif_cptr, 0, 0, 0, 0, 0) as u64 }
}

#[inline]
pub fn debug_print(s: &str) {
    unsafe {
        let _ = syscall6(SYS_DEBUG_PRINT, s.as_ptr() as u64, s.len() as u64, 0, 0, 0, 0);
    }
}

#[inline]
pub fn yield_now() {
    unsafe {
        let _ = syscall6(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

#[inline]
pub fn sysinfo(query: u64) -> u64 {
    unsafe { syscall6(SYS_SYSINFO, query, 0, 0, 0, 0, 0) as u64 }
}

#[inline]
pub fn grant_ioport(cap_slot: u64) -> bool {
    unsafe { syscall6(SYS_CAP_INVOKE, CAP_OP_IOPORT_GRANT, cap_slot, 0, 0, 0, 0) == 0 }
}

#[inline]
pub fn map_mmio(frame_slot: u64, target_vaddr: u64, num_pages: usize) -> bool {
    unsafe {
        syscall6(
            SYS_CAP_INVOKE,
            CAP_OP_MMIO_MAP,
            frame_slot,
            target_vaddr,
            num_pages as u64,
            0,
            0,
        ) == 0
    }
}

#[inline]
pub fn cap_retype(untyped_cptr: u64, dst_cptr: u64, kind: u64, size_param: u64) -> bool {
    unsafe {
        syscall6(
            SYS_CAP_INVOKE,
            CAP_OP_RETYPE,
            untyped_cptr,
            dst_cptr,
            kind,
            size_param,
            0,
        ) == 0
    }
}

#[inline]
pub fn cap_delete(target_cptr: u64) -> bool {
    unsafe { syscall6(SYS_CAP_INVOKE, CAP_OP_DELETE, target_cptr, 0, 0, 0, 0) == 0 }
}

#[inline]
pub fn cap_copy_to_cnode(
    src_cptr: u64,
    dst_cnode_cptr: u64,
    dst_slot: u64,
    rights: u64,
    badge: u64,
) -> bool {
    unsafe {
        syscall6(
            SYS_CAP_INVOKE,
            CAP_OP_COPY_TO_CNODE,
            src_cptr,
            dst_cnode_cptr,
            dst_slot,
            rights,
            badge,
        ) == 0
    }
}

#[inline]
pub fn process_create(cnode_radix: u64, vspace_dst: u64, cnode_dst: u64) -> i64 {
    unsafe { syscall6(SYS_PROCESS_CREATE, cnode_radix, vspace_dst, cnode_dst, 0, 0, 0) }
}

#[inline]
pub fn vspace_map_frame(vspace_cptr: u64, frame_cptr: u64, vaddr: u64, perm: u64) -> bool {
    unsafe { syscall6(SYS_VSPACE_MAP_FRAME, vspace_cptr, frame_cptr, vaddr, perm, 0, 0) == 0 }
}

#[inline]
pub fn thread_create_in(vspace_cptr: u64, entry_rip: u64, user_rsp: u64, arg0: u64) -> i64 {
    unsafe { syscall6(SYS_THREAD_CREATE_IN, vspace_cptr, entry_rip, user_rsp, arg0, 0, 0) }
}

#[inline]
pub fn shmem_create(num_pages: u64) -> i64 {
    unsafe { syscall6(SYS_SHMEM_CREATE, num_pages, 0, 0, 0, 0, 0) }
}

#[inline]
pub fn shmem_map(shmem_cptr: u64, target_vaddr: u64) -> i64 {
    unsafe { syscall6(SYS_SHMEM_MAP, shmem_cptr, target_vaddr, 0, 0, 0, 0) }
}

#[inline]
pub fn thread_exit() -> ! {
    unsafe {
        let _ = syscall6(SYS_THREAD_EXIT, 0, 0, 0, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Cleanly exit a child process spawned via `execbin`, signaling `exit_notif_slot` if present.
pub fn exit_process(bi: &GoseBootInfo) -> ! {
    if bi.exit_notif_slot != 0 {
        let _ = notify_signal(bi.exit_notif_slot, 1);
    }
    thread_exit();
}

// ---------------------------------------------------------------------------
// Ring 3 Direct I/O Port Primitives (Authorized by Kernel TSS IOPB)
// ---------------------------------------------------------------------------

#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

#[inline(always)]
pub unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

#[inline(always)]
pub unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
}

// ---------------------------------------------------------------------------
// User-Space Heap Allocator (512 KiB Arena per ELF process)
// ---------------------------------------------------------------------------

const USER_HEAP_SIZE: usize = 512 * 1024;

#[repr(C, align(16))]
struct UserHeapArena([u8; USER_HEAP_SIZE]);

static mut USER_HEAP: UserHeapArena = UserHeapArena([0; USER_HEAP_SIZE]);
static HEAP_CURSOR: AtomicUsize = AtomicUsize::new(0);

pub struct UserBumpAllocator;

unsafe impl GlobalAlloc for UserBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(16);
        let size = layout.size().max(1);
        let base = core::ptr::addr_of_mut!(USER_HEAP.0) as usize;

        loop {
            let cur = HEAP_CURSOR.load(Ordering::Relaxed);
            let abs = base + cur;
            let aligned_abs = (abs + align - 1) & !(align - 1);
            let next_cur = (aligned_abs - base) + size;
            if next_cur > USER_HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if HEAP_CURSOR
                .compare_exchange_weak(cur, next_cur, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return aligned_abs as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static USER_ALLOCATOR: UserBumpAllocator = UserBumpAllocator;
