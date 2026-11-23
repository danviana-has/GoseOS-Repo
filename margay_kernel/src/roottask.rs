//! Embedded Initial Root Task Stub (Ring 3 User-Space Boot Validation)
//!
//! Assembles a self-contained, position-independent x86_64 Ring 3 program
//! into `.roottask`, maps it into PID 1's isolated `AddressSpace` with strict
//! W^X (`USER | PRESENT | EXECUTE` for code, `USER | PRESENT | WRITABLE | NX`
//! for stacks), populates PID 1's root CSpace with initial capabilities, and
//! verifies live Ring 3 execution of:
//!   1. `SYS_DEBUG_PRINT`, `SYS_GET_TID`, `SYS_SYSINFO`
//!   2. `SYS_THREAD_SPAWN` + Synchronous Fastpath IPC (`SYS_IPC_CALL` / `RECV` / `REPLY`)
//!   3. Asynchronous Notification (`SYS_NOTIFY_SIGNAL` -> `SYS_NOTIFY_WAIT`)
//!   4. Capability Mint + Iterative CDT Revocation (`SYS_CAP_INVOKE`)
//!   5. Zero-Copy Shared Memory (`SYS_SHMEM_CREATE` + `SYS_SHMEM_MAP` + RW)
//!   6. `UntypedMemory` Retype (`CAP_OP_RETYPE`) + Hierarchical Multi-Level CPtr (`depth = 12`)
//!   7. Cross-Process Creation (`SYS_PROCESS_CREATE`, `SYS_VSPACE_MAP_FRAME`,
//!      `SYS_THREAD_CREATE_IN`, `CAP_OP_COPY_TO_CNODE`) + Cross-PID IPC (PID 1 <-> PID 2)
//!   8. Real Hardware Delegation in Ring 3: TSS IOPB (`out` to 8254 PIT ports `0x40..0x43`)
//!      + ACPI MADT ISO (`ISA IRQ 0 -> GSI 2`) + I/O APIC -> Notification wakeup!

use core::arch::global_asm;

use crate::arch::x86_64::cpuid::CpuFeatures;
use crate::arch::x86_64::{limine, smp};
use crate::cap::object::{CapObject, Capability, FrameSize};
use crate::cap::{self, CapRights};
use crate::ipc::{endpoint, notification};
use crate::mm::frame::PAGE_SIZE;
use crate::mm::paging::PageFlags;
use crate::mm::vspace::{VmaKind, VmaRegion};
use crate::mm::{phys_to_virt, pmm, virt_to_phys, PhysAddr, VirtAddr};
use crate::sched::process::Process;
use crate::sched::{self, DEFAULT_PRIORITY};

/// Virtual addresses mapped inside the Root Task's isolated Ring 3 AddressSpace.
const ROOTTASK_CODE_VA: u64 = 0x0000_0000_0040_0000;
const ROOTTASK_MAIN_STACK_VA: u64 = 0x0000_0000_0080_0000;
const ROOTTASK_WORKER_STACK_VA: u64 = 0x0000_0000_0081_0000;
const ROOTTASK_STACK_PAGES: usize = 4; // 16 KiB per thread stack

// Initial Root Task CSpace slot indices:
const CAP_SLOT_CNODE: usize = 1;
const CAP_SLOT_VSPACE: usize = 2;
const CAP_SLOT_ENDPOINT: usize = 3;
const CAP_SLOT_NOTIF: usize = 4;
const CAP_SLOT_IRQ_CTRL: usize = 5;
const CAP_SLOT_IOPORT_PIT: usize = 6;
const CAP_SLOT_UNTYPED: usize = 7;

// Position-independent Ring 3 x86_64 assembly test binary.
global_asm!(
    r#"
.section .roottask, "a"
.align 16
.global roottask_image_start
roottask_image_start:

// ---------------------------------------------------------------------------
// Root Task Main Thread Entry (PID 1, Ring 3, CPL=3)
// ---------------------------------------------------------------------------
roottask_main:
    // 1. Announce Ring 3 execution via SYS_DEBUG_PRINT (0)
    lea rdi, [rip + msg_banner]
    lea rsi, [rip + msg_banner_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 2. Verify SYS_GET_TID (3) and SYS_SYSINFO (16)
    mov rax, 3
    syscall
    test rax, rax
    jz roottask_fail

    mov rax, 16
    xor rdi, rdi
    syscall
    test rax, rax
    jz roottask_fail

    // 3. Spawn secondary Ring 3 worker thread via SYS_THREAD_SPAWN (15)
    lea rdi, [rip + roottask_worker]
    mov rsi, 0x0000000000813FF8
    mov rdx, 3
    mov rax, 15
    syscall
    test rax, rax
    js roottask_fail

    // 4. Synchronous Fastpath IPC Call to worker on Endpoint CPtr=3
    mov rax, 6
    mov rdi, 3
    mov rsi, 1
    mov rdx, 0xCAFEBABE13370001
    mov r10, 0x42
    xor r8, r8
    xor r9, r9
    syscall

    mov rbx, 0xCAFEBABE13371001
    cmp rdi, rbx
    jne roottask_fail

    lea rdi, [rip + msg_ipc_ok]
    lea rsi, [rip + msg_ipc_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 5. Wait for worker's Asynchronous Notification signal on CPtr=4
    mov rax, 10
    mov rdi, 4
    syscall
    cmp rax, 0xA5
    jne roottask_fail

    lea rdi, [rip + msg_notif_ok]
    lea rsi, [rip + msg_notif_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 6. Test Capability Mint + CDT Revoke via SYS_CAP_INVOKE (12)
    mov rax, 12
    mov rdi, 1                    // CAP_OP_MINT
    mov rsi, 3                    // src = Endpoint 3
    mov rdx, 10                   // dst = slot 10
    mov r10, 1                    // rights = READ
    mov r8, 0x77                  // badge = 0x77
    syscall
    test rax, rax
    jnz roottask_fail

    mov rax, 12
    mov rdi, 5                    // CAP_OP_REVOKE
    mov rsi, 3                    // target = Endpoint 3
    syscall
    cmp rax, 1
    jne roottask_fail

    lea rdi, [rip + msg_cap_ok]
    lea rsi, [rip + msg_cap_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 7. Test Zero-Copy Shared Memory: SYS_SHMEM_CREATE (13) + SYS_SHMEM_MAP (14)
    mov rax, 13
    mov rdi, 2                    // 2 pages = 8 KiB
    syscall
    test rax, rax
    js roottask_fail
    mov r12, rax

    mov rax, 14
    mov rdi, r12
    mov rsi, 0x0000000000900000
    syscall
    cmp rax, 8192
    jne roottask_fail

    mov rbx, 0x0000000000900000
    mov rcx, 0x123456789ABCDEF0
    mov [rbx], rcx
    mov rdx, [rbx]
    cmp rdx, rcx
    jne roottask_fail

    lea rdi, [rip + msg_shmem_ok]
    lea rsi, [rip + msg_shmem_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 8. Test UntypedMemory Retype (CAP_OP_RETYPE=10) + Hierarchical CPtr (depth=12)
    //    8a. Retype child CNode (kind=4, radix=4 -> 16 slots) from Untyped(7) into slot 12
    mov rax, 12
    mov rdi, 10                   // CAP_OP_RETYPE
    mov rsi, 7                    // untyped_cptr = 7
    mov rdx, 12                   // dst = root slot 12
    mov r10, 4                    // RetypeKind::CNode
    mov r8, 4                     // radix_bits = 4
    syscall
    test rax, rax
    jnz roottask_fail

    //    8b. Retype Notification (kind=3) into hierarchical CPtr:
    //        depth=12 (8b root=12, 4b child=3) -> (12 << 56) | (12 << 4) | 3 = 0x0C000000000000C3
    mov r13, 0x0C000000000000C3
    mov rax, 12
    mov rdi, 10                   // CAP_OP_RETYPE
    mov rsi, 7                    // untyped_cptr = 7
    mov rdx, r13                  // hierarchical dst CPtr!
    mov r10, 3                    // RetypeKind::Notification
    xor r8, r8
    syscall
    test rax, rax
    jnz roottask_fail

    //    8c. Signal & Wait using the hierarchical CPtr directly!
    mov rax, 9                    // SYS_NOTIFY_SIGNAL
    mov rdi, r13
    mov rsi, 0x3C
    syscall
    test rax, rax
    jnz roottask_fail

    mov rax, 10                   // SYS_NOTIFY_WAIT
    mov rdi, r13
    syscall
    cmp rax, 0x3C
    jne roottask_fail

    lea rdi, [rip + msg_retype_ok]
    lea rsi, [rip + msg_retype_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 9. Test Process Creation (PID 2) + VSpace Frame Map (W^X) + Cross-Process IPC!
    //    9a. Retype 2 Frame4K objects from Untyped(7) into slot 13 (code) & slot 14 (stack)
    mov rax, 12
    mov rdi, 10                   // CAP_OP_RETYPE
    mov rsi, 7
    mov rdx, 13
    mov r10, 1                    // RetypeKind::Frame4K
    xor r8, r8
    syscall
    test rax, rax
    jnz roottask_fail

    mov rax, 12
    mov rdi, 10
    mov rsi, 7
    mov rdx, 14
    mov r10, 1                    // RetypeKind::Frame4K
    xor r8, r8
    syscall
    test rax, rax
    jnz roottask_fail

    //    9b. Map Frame 13 RW (perm=3) into Root VSpace(2) at 0xA00000 to copy PID 2 code
    mov rax, 18                   // SYS_VSPACE_MAP_FRAME
    mov rdi, 2                    // Root VSpace cap
    mov rsi, 13                   // code Frame cap
    mov rdx, 0x0000000000A00000
    mov r10, 3                    // READ | WRITE (NX)
    syscall
    test rax, rax
    jnz roottask_fail

    //    Copy child_server_entry machine code into 0xA00000
    lea rsi, [rip + child_server_entry]
    lea rcx, [rip + child_server_end]
    sub rcx, rsi
    mov rdi, 0x0000000000A00000
    rep movsb

    //    9c. Create isolated PID 2 via SYS_PROCESS_CREATE(17): radix=6, vspace->15, cnode->16
    mov rax, 17
    mov rdi, 6
    mov rsi, 15
    mov rdx, 16
    syscall
    cmp rax, 2
    jb roottask_fail

    //    9d. Map Frame 13 into PID 2 VSpace(15) at 0x500000 as R-X (perm=5, strict W^X!)
    mov rax, 18                   // SYS_VSPACE_MAP_FRAME
    mov rdi, 15                   // PID 2 VSpace cap
    mov rsi, 13                   // code Frame cap
    mov rdx, 0x0000000000500000
    mov r10, 5                    // READ | EXECUTE (no WRITE -> W^X!)
    syscall
    test rax, rax
    jnz roottask_fail

    //    9e. Map Frame 14 into PID 2 VSpace(15) at 0x600000 as RW- (perm=3, strict W^X!)
    mov rax, 18
    mov rdi, 15
    mov rsi, 14                   // stack Frame cap
    mov rdx, 0x0000000000600000
    mov r10, 3                    // READ | WRITE (NX)
    syscall
    test rax, rax
    jnz roottask_fail

    //    9f. Delegate Endpoint(3) into PID 2's CNode(16) at slot 1 via CAP_OP_COPY_TO_CNODE(11)
    mov rax, 12
    mov rdi, 11                   // CAP_OP_COPY_TO_CNODE
    mov rsi, 3                    // src Endpoint cap
    mov rdx, 16                   // dst CNode cap (PID 2's root CNode)
    mov r10, 1                    // target slot index = 1
    mov r8, 0                     // 0 -> CapRights::ALL
    mov r9, 0x2002                // badge
    syscall
    test rax, rax
    jnz roottask_fail

    //    9g. Spawn Ring 3 thread inside PID 2 via SYS_THREAD_CREATE_IN(19)
    mov rax, 19
    mov rdi, 15                   // PID 2 VSpace cap
    mov rsi, 0x0000000000500000   // PID 2 entry RIP
    mov rdx, 0x0000000000600FF8   // PID 2 user RSP
    xor r10, r10
    syscall
    test rax, rax
    js roottask_fail

    //    9h. Cross-Process IPC Call (PID 1 -> PID 2 -> PID 1) on Endpoint(3)
    mov rax, 6                    // SYS_IPC_CALL
    mov rdi, 3
    mov rsi, 7
    mov rdx, 0xBEEF0000
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    mov rbx, 0xBEEF0042
    cmp rdi, rbx
    jne roottask_fail

    lea rdi, [rip + msg_proc_ok]
    lea rsi, [rip + msg_proc_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 10. Real Hardware Delegation Test in Ring 3:
    //     TSS IOPB (ports 0x40..0x43) + Real 8254 PIT ISA IRQ 0 (GSI 2) -> Notification!
    //     10a. Retype Notification from Untyped(7) into slot 17
    mov rax, 12
    mov rdi, 10                   // CAP_OP_RETYPE
    mov rsi, 7
    mov rdx, 17
    mov r10, 3                    // RetypeKind::Notification
    xor r8, r8
    syscall
    test rax, rax
    jnz roottask_fail

    //     10b. Grant Ring 3 I/O port access (0x40..0x43) in TSS IOPB via CAP_OP_IOPORT_GRANT(6)
    mov rax, 12
    mov rdi, 6                    // CAP_OP_IOPORT_GRANT
    mov rsi, 6                    // CAP_SLOT_IOPORT_PIT
    syscall
    test rax, rax
    jnz roottask_fail

    //     10c. Bind ISA IRQ 0 (PIT -> ACPI MADT ISO GSI 2) to Notification(17) with badge 0x5A
    mov rax, 12
    mov rdi, 7                    // CAP_OP_IRQ_BIND
    mov rsi, 5                    // CAP_SLOT_IRQ_CTRL
    mov rdx, 0                    // ISA IRQ 0 (PIT Channel 0)
    mov r10, 17                   // Notification CPtr
    mov r8, 0x5A                  // badge
    syscall
    test rax, rax
    jnz roottask_fail

    //     10d. Directly from Ring 3 (CPL=3!), arm hardware 8254 PIT Channel 0 in one-shot mode!
    //          Port 0x43 = 0x30 (Ch 0, lobyte/hibyte, mode 0 interrupt on terminal count)
    //          Port 0x40 = 1193 (~1 ms countdown at 1.193182 MHz)
    mov dx, 0x43
    mov al, 0x30
    out dx, al
    mov dx, 0x40
    mov al, 0xA9                  // low byte of 1193 (0x04A9)
    out dx, al
    mov al, 0x04                  // high byte of 1193
    out dx, al

    //     10e. Block waiting for the real hardware PIT IRQ to signal Notification(17)!
    mov rax, 10                   // SYS_NOTIFY_WAIT
    mov rdi, 17
    syscall
    cmp rax, 0x5A
    jne roottask_fail

    //     10f. Acknowledge IRQ via CAP_OP_IRQ_ACK(8)
    mov rax, 12
    mov rdi, 8
    mov rsi, 5
    mov rdx, 0
    syscall
    test rax, rax
    jnz roottask_fail

    lea rdi, [rip + msg_irq_ok]
    lea rsi, [rip + msg_irq_ok_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    // 11. Print final PASS banner and exit cleanly
    lea rdi, [rip + msg_all_pass]
    lea rsi, [rip + msg_all_pass_end]
    sub rsi, rdi
    xor rax, rax
    syscall

    mov rax, 2                    // SYS_THREAD_EXIT
    syscall
1:  jmp 1b

// ---------------------------------------------------------------------------
// Secondary Ring 3 Worker Thread (PID 1 — handles IPC Call + signals Notification)
// ---------------------------------------------------------------------------
.align 16
roottask_worker:
    mov rax, 5                    // SYS_IPC_RECV
    mov rdi, 3
    syscall

    add rdi, 0x1000
    mov rsi, rdi
    mov rdi, 2
    mov rdx, 0x99
    xor r10, r10
    xor r8, r8
    mov rax, 7                    // SYS_IPC_REPLY
    syscall

    mov rax, 9                    // SYS_NOTIFY_SIGNAL
    mov rdi, 4
    mov rsi, 0xA5
    syscall

    mov rax, 2                    // SYS_THREAD_EXIT
    syscall
2:  jmp 2b

// ---------------------------------------------------------------------------
// Isolated Child Server Binary (copied into PID 2's own AddressSpace @ 0x500000!)
// ---------------------------------------------------------------------------
.align 16
child_server_entry:
    // Receives cross-process IPC from PID 1 on delegated Endpoint CPtr=1
    mov rax, 5                    // SYS_IPC_RECV
    mov rdi, 1
    syscall

    add rdi, 0x42                 // 0xBEEF0000 + 0x42 = 0xBEEF0042
    mov rsi, rdi
    mov rdi, 8
    xor rdx, rdx
    xor r10, r10
    xor r8, r8
    mov rax, 7                    // SYS_IPC_REPLY
    syscall

    mov rax, 2                    // SYS_THREAD_EXIT
    syscall
3:  jmp 3b
child_server_end:

roottask_fail:
    lea rdi, [rip + msg_fail]
    lea rsi, [rip + msg_fail_end]
    sub rsi, rdi
    xor rax, rax
    syscall
    mov rax, 2
    syscall
4:  jmp 4b

// ---------------------------------------------------------------------------
// Read-Only String Constants Embedded in .roottask
// ---------------------------------------------------------------------------
msg_banner:
    .ascii "[ROOT TASK] Ring 3 User-Space Server online (CPL=3)!\n"
msg_banner_end:

msg_ipc_ok:
    .ascii "[ROOT TASK] [PASS] Synchronous Fastpath IPC Call/Reply verified\n"
msg_ipc_ok_end:

msg_notif_ok:
    .ascii "[ROOT TASK] [PASS] Asynchronous Notification Signal/Wait verified\n"
msg_notif_ok_end:

msg_cap_ok:
    .ascii "[ROOT TASK] [PASS] Capability Mint + Iterative CDT Revocation verified\n"
msg_cap_ok_end:

msg_shmem_ok:
    .ascii "[ROOT TASK] [PASS] Zero-Copy Shared Memory Create/Map/RW verified\n"
msg_shmem_ok_end:

msg_retype_ok:
    .ascii "[ROOT TASK] [PASS] Untyped Retype + Hierarchical CPtr (depth=12) verified\n"
msg_retype_ok_end:

msg_proc_ok:
    .ascii "[ROOT TASK] [PASS] Process Create (PID 2) + VSpace Map (W^X) + Cross-PID IPC verified\n"
msg_proc_ok_end:

msg_irq_ok:
    .ascii "[ROOT TASK] [PASS] Ring 3 Hardware I/O Port (IOPB) + Real PIT IRQ -> Notification verified\n"
msg_irq_ok_end:

msg_all_pass:
    .ascii "[ROOT TASK] === ALL 7 RING 3 MICROKERNEL TESTS PASSED ===\n"
msg_all_pass_end:

msg_fail:
    .ascii "[ROOT TASK] [FAIL] Ring 3 self-test assertion failed!\n"
msg_fail_end:

.global roottask_image_end
roottask_image_end:
.previous
"#
);

extern "C" {
    static roottask_image_start: u8;
    static roottask_image_end: u8;
}

/// Launch PID 1 (Root Task):
/// - If an external ELF64 module (e.g. `gose_init.elf` from `GOSE Utilities Base`)
///   was loaded by Limine, load its ELF64 segments into PID 1 with strict W^X,
///   delegate hardware capabilities (GOP Framebuffer MMIO, PS/2, ATA IDE, IRQ),
///   and jump to its ELF entry point with `BootInfo` at `0x700000`.
/// - Otherwise (standalone `margay_microkernel.iso`), run the embedded Ring 3
///   microkernel self-test stub.
pub fn launch_root_task() {
    let mods = limine::modules();
    if !mods.is_empty() && !mods[0].is_null() {
        let file = unsafe { &*mods[0] };
        if !file.address.is_null() && file.size >= 64 {
            let elf_bytes = unsafe { core::slice::from_raw_parts(file.address, file.size as usize) };
            if elf_bytes.starts_with(b"\x7FELF") {
                launch_external_elf_root_task(elf_bytes);
                return;
            }
        }
    }
    launch_embedded_selftest_root_task();
}

/// Descriptor for an extra Limine boot module mapped read-only into `goseinit`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BootModuleDesc {
    vaddr: u64,
    size: u64,
    name: [u8; 32],
}

impl BootModuleDesc {
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            size: 0,
            name: [0; 32],
        }
    }
}

/// Hand-off structure mapped read-only at `0x0000_0000_0030_0000` for `GOSE Utilities Base`.
#[repr(C)]
#[derive(Clone, Copy)]
struct GoseBootInfo {
    magic: u64,
    kernel_version: [u8; 32],
    fb_phys: u64,
    fb_width: u64,
    fb_height: u64,
    fb_pitch: u64,
    fb_bpp: u32,
    cpu_count: u32,
    total_mem_pages: u64,
    free_mem_pages: u64,
    cpu_vendor: [u8; 16],
    cpu_brand: [u8; 48],
    fb_cap_slot: u64,
    ps2_ioport_slot: u64,
    ata_pri_ioport_slot: u64,
    ata_ctl_ioport_slot: u64,
    com1_ioport_slot: u64,
    irq_ctrl_slot: u64,
    untyped_slot: u64,
    untyped2_slot: u64,
    ep_gop_slot: u64,
    ep_ps2_slot: u64,
    ep_fs_slot: u64,
    shm_gop_slot: u64,
    shm_fs_slot: u64,
    exit_notif_slot: u64,
    module_count: u32,
    _pad: u32,
    modules: [BootModuleDesc; 8],
}

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

fn launch_external_elf_root_task(elf: &[u8]) {
    let ehdr = unsafe { core::ptr::read_unaligned(elf.as_ptr() as *const Elf64Ehdr) };
    assert_eq!(ehdr.e_machine, 0x3E, "External init module is not x86_64 ELF");
    assert!(ehdr.e_entry != 0, "External init module has null entry");

    let mut proc = Process::new("gose_init", 9).expect("Failed to create gose_init Process");
    let root_cnode = proc.root_cnode;
    let vspace_id = proc.vspace.id;

    // Map all PT_LOAD segments with strict W^X enforcement
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

        // Enforce W^X: if PF_X (1) is set, map R-X; else if PF_W (2) is set, map RW- (NX); else R-- (NX)
        let is_exec = (ph.p_flags & 1) != 0;
        let is_write = (ph.p_flags & 2) != 0;
        let flags = if is_exec && !is_write {
            PageFlags::user_rx()
        } else if is_write {
            PageFlags::user_rw()
        } else {
            PageFlags::user_ro()
        };

        let _ = proc.vspace.register_vma(VmaRegion {
            start: seg_start,
            length: (num_pages * PAGE_SIZE) as u64,
            flags,
            kind: if is_exec { VmaKind::Code } else { VmaKind::Anonymous },
        });

        for p in 0..num_pages {
            let page_va = seg_start + (p * PAGE_SIZE) as u64;
            let (pa, already_mapped) = match proc.vspace.translate(VirtAddr::new(page_va)) {
                Some((existing_pa, _)) => (PhysAddr::new(existing_pa.as_u64() & !0xFFF), true),
                None => (pmm::alloc_frame_zeroed().expect("OOM mapping ELF segment"), false),
            };
            let dst = phys_to_virt(pa.as_u64()) as *mut u8;

            // Copy overlapping bytes from file image
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
                        core::ptr::copy_nonoverlapping(elf.as_ptr().add(src_off), dst.add(dst_off), len);
                    }
                }
            }

            if !already_mapped {
                let _ = proc.vspace.map_page(VirtAddr::new(page_va), pa, flags);
            }
        }
    }

    // Map 64 KiB user stack at 0x0000_0000_1000_0000 (well above any ELF .bss)
    const INIT_STACK_VA: u64 = 0x0000_0000_1000_0000;
    const INIT_STACK_PAGES: usize = 16;
    proc.vspace
        .map_anonymous_region(INIT_STACK_VA, INIT_STACK_PAGES, PageFlags::user_rw(), VmaKind::Stack)
        .expect("Failed to map gose_init stack");

    // Map GoseBootInfo page at 0x0000_0000_0030_0000 (below 0x400000 ELF base, read-only NX)
    const BOOTINFO_VA: u64 = 0x0000_0000_0030_0000;
    let bi_pa = pmm::alloc_frame_zeroed().expect("OOM allocating GoseBootInfo");
    let features = CpuFeatures::detect();
    let stats = pmm::stats();

    let (fb_phys, fb_width, fb_height, fb_pitch, fb_bpp) = match limine::primary_framebuffer() {
        Some(fb) => {
            let vaddr = fb.address as u64;
            let phys = if vaddr >= crate::mm::hhdm_offset() {
                virt_to_phys(vaddr)
            } else {
                vaddr
            };
            (phys, fb.width, fb.height, fb.pitch, fb.bpp as u32)
        }
        None => (0, 0, 0, 0, 0),
    };

    let mut kv = [0u8; 32];
    let ver_bytes = b"Margay-0.1.0-x86_64";
    kv[..ver_bytes.len()].copy_from_slice(ver_bytes);

    let mut cv = [0u8; 16];
    cv[..12].copy_from_slice(&features.vendor);

    // Map extra Limine modules (1..N) read-only into goseinit at 0x5000_0000 + idx * 0x0100_0000
    let mut mod_descs = [BootModuleDesc::empty(); 8];
    let mut mod_count = 0u32;
    let all_mods = limine::modules();
    for (idx, &m_ptr) in all_mods.iter().skip(1).take(8).enumerate() {
        if m_ptr.is_null() {
            continue;
        }
        let m = unsafe { &*m_ptr };
        if m.address.is_null() || m.size == 0 {
            continue;
        }
        let mod_va_base = 0x0000_0000_5000_0000u64 + (idx as u64) * 0x0100_0000;
        let num_pages = ((m.size as usize) + PAGE_SIZE - 1) / PAGE_SIZE;
        let _ = proc.vspace.register_vma(VmaRegion {
            start: mod_va_base,
            length: (num_pages * PAGE_SIZE) as u64,
            flags: PageFlags::user_ro(),
            kind: VmaKind::Anonymous,
        });
        let src_slice = unsafe { core::slice::from_raw_parts(m.address, m.size as usize) };
        for p in 0..num_pages {
            let pa = pmm::alloc_frame_zeroed().expect("OOM mapping boot module");
            let dst = phys_to_virt(pa.as_u64()) as *mut u8;
            let off = p * PAGE_SIZE;
            let copy_len = (src_slice.len() - off).min(PAGE_SIZE);
            unsafe {
                core::ptr::copy_nonoverlapping(src_slice.as_ptr().add(off), dst, copy_len);
            }
            let _ = proc.vspace.map_page(
                VirtAddr::new(mod_va_base + off as u64),
                pa,
                PageFlags::user_ro(),
            );
        }

        let mut desc = BootModuleDesc::empty();
        desc.vaddr = mod_va_base;
        desc.size = m.size;
        if !m.path.is_null() {
            let cstr = unsafe { core::ffi::CStr::from_ptr(m.path) }.to_bytes();
            let n = cstr.len().min(31);
            desc.name[..n].copy_from_slice(&cstr[..n]);
        }
        mod_descs[mod_count as usize] = desc;
        mod_count += 1;
    }

    let bi = GoseBootInfo {
        magic: 0x474F_5345_424F_4F54, // "GOSEBOOT"
        kernel_version: kv,
        fb_phys,
        fb_width,
        fb_height,
        fb_pitch,
        fb_bpp,
        cpu_count: smp::online_cpus(),
        total_mem_pages: stats.total_pages as u64,
        free_mem_pages: stats.free_pages as u64,
        cpu_vendor: cv,
        cpu_brand: features.brand,
        fb_cap_slot: 8,
        ps2_ioport_slot: 9,
        ata_pri_ioport_slot: 10,
        ata_ctl_ioport_slot: 11,
        com1_ioport_slot: 6,
        irq_ctrl_slot: 5,
        untyped_slot: 7,
        untyped2_slot: 12,
        ep_gop_slot: 0,
        ep_ps2_slot: 0,
        ep_fs_slot: 0,
        shm_gop_slot: 0,
        shm_fs_slot: 0,
        exit_notif_slot: 0,
        module_count: mod_count,
        _pad: 0,
        modules: mod_descs,
    };

    unsafe {
        core::ptr::write(phys_to_virt(bi_pa.as_u64()) as *mut GoseBootInfo, bi);
    }
    proc.vspace
        .map_page(VirtAddr::new(BOOTINFO_VA), bi_pa, PageFlags::user_ro())
        .expect("Failed to map GoseBootInfo");

    // Populate Initial Capabilities for GOSE User-Space (2 x 4 MiB UntypedMemory pools)
    let untyped_pa = pmm::alloc_order(10).expect("OOM allocating 4 MiB UntypedMemory");
    let untyped2_pa = pmm::alloc_order(10).expect("OOM allocating 4 MiB UntypedMemory #2");
    let _ = cap::cap_insert_root(
        root_cnode,
        1,
        Capability::new(CapObject::CNode { id: root_cnode, radix_bits: 9 }, CapRights::ALL),
    );
    let _ = cap::cap_insert_root(
        root_cnode,
        2,
        Capability::new(CapObject::VSpace { id: vspace_id }, CapRights::ALL),
    );
    let _ = cap::cap_insert_root(
        root_cnode,
        5,
        Capability::new(CapObject::IrqControl, CapRights::ALL),
    );
    let _ = cap::cap_insert_root(
        root_cnode,
        6,
        Capability::new(CapObject::IoPort { start_port: 0x3F8, end_port: 0x3FF }, CapRights::ALL),
    );
    let _ = cap::cap_insert_root(
        root_cnode,
        7,
        Capability::new(
            CapObject::UntypedMemory {
                paddr: untyped_pa.as_u64(),
                size_bits: 22, // 4 MiB
                watermark: 0,
            },
            CapRights::ALL,
        ),
    );
    let _ = cap::cap_insert_root(
        root_cnode,
        12,
        Capability::new(
            CapObject::UntypedMemory {
                paddr: untyped2_pa.as_u64(),
                size_bits: 22, // 4 MiB
                watermark: 0,
            },
            CapRights::ALL,
        ),
    );
    if fb_phys != 0 {
        let _ = cap::cap_insert_root(
            root_cnode,
            8,
            Capability::new(
                CapObject::Frame {
                    paddr: fb_phys,
                    size: FrameSize::Size4K,
                    is_device: true,
                },
                CapRights::ALL,
            ),
        );
    }
    // PS/2 Controller (0x60..0x64)
    let _ = cap::cap_insert_root(
        root_cnode,
        9,
        Capability::new(CapObject::IoPort { start_port: 0x60, end_port: 0x64 }, CapRights::ALL),
    );
    // Primary ATA IDE Controller (0x1F0..0x1F7 & 0x3F6..0x3F7)
    let _ = cap::cap_insert_root(
        root_cnode,
        10,
        Capability::new(CapObject::IoPort { start_port: 0x1F0, end_port: 0x1F7 }, CapRights::ALL),
    );
    let _ = cap::cap_insert_root(
        root_cnode,
        11,
        Capability::new(CapObject::IoPort { start_port: 0x3F6, end_port: 0x3F7 }, CapRights::ALL),
    );

    let pid = sched::register_process(proc);
    let main_rsp = INIT_STACK_VA + (INIT_STACK_PAGES * PAGE_SIZE) as u64 - 8;
    let tid = sched::spawn_user_thread(pid, ehdr.e_entry, main_rsp, BOOTINFO_VA, DEFAULT_PRIORITY)
        .expect("Failed to spawn gose_init main thread");

    crate::kinfo!(
        "ROOT",
        "Loaded external ELF module 'gose_init' ({}B): pid={} tid={} entry={:#x} fb={}x{}x{}",
        elf.len(),
        pid,
        tid,
        ehdr.e_entry,
        fb_width,
        fb_height,
        fb_bpp
    );
}

fn launch_embedded_selftest_root_task() {
    let img_start = unsafe { &roottask_image_start as *const u8 };
    let img_end = unsafe { &roottask_image_end as *const u8 };
    let img_len = (img_end as usize).saturating_sub(img_start as usize);
    assert!(img_len > 0 && img_len <= 4 * PAGE_SIZE, "Invalid Root Task image size");

    let mut proc = Process::new("root_task", 8).expect("Failed to create Root Task Process");
    let root_cnode = proc.root_cnode;
    let vspace_id = proc.vspace.id;

    // 1. Map Root Task code pages as USER | PRESENT | EXECUTE (strict W^X)
    let code_pages = (img_len + PAGE_SIZE - 1) / PAGE_SIZE;
    proc.vspace
        .register_vma(VmaRegion {
            start: ROOTTASK_CODE_VA,
            length: (code_pages * PAGE_SIZE) as u64,
            flags: PageFlags::user_rx(),
            kind: VmaKind::Code,
        })
        .expect("Failed to register Root Task code VMA");

    for page_idx in 0..code_pages {
        let pa = pmm::alloc_frame_zeroed().expect("OOM allocating Root Task code frame");
        let dst = phys_to_virt(pa.as_u64()) as *mut u8;
        let offset = page_idx * PAGE_SIZE;
        let copy_len = (img_len - offset).min(PAGE_SIZE);
        unsafe {
            core::ptr::copy_nonoverlapping(img_start.add(offset), dst, copy_len);
        }
        let va = VirtAddr::new(ROOTTASK_CODE_VA + offset as u64);
        proc.vspace
            .map_page(va, pa, PageFlags::user_rx())
            .expect("Failed to map Root Task code page");
    }

    // 2. Map Main Thread Stack & Worker Thread Stack as USER | WRITABLE | NO_EXECUTE (strict W^X)
    proc.vspace
        .map_anonymous_region(
            ROOTTASK_MAIN_STACK_VA,
            ROOTTASK_STACK_PAGES,
            PageFlags::user_rw(),
            VmaKind::Stack,
        )
        .expect("Failed to map Root Task main stack");

    proc.vspace
        .map_anonymous_region(
            ROOTTASK_WORKER_STACK_VA,
            ROOTTASK_STACK_PAGES,
            PageFlags::user_rw(),
            VmaKind::Stack,
        )
        .expect("Failed to map Root Task worker stack");

    // 3. Populate Initial Root CSpace Capabilities
    let ep_id = endpoint::create_endpoint();
    let notif_id = notification::create_notification();
    let untyped_pa = pmm::alloc_huge_2m().expect("OOM allocating 2 MiB UntypedMemory pool");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_CNODE,
        Capability::new(CapObject::CNode { id: root_cnode, radix_bits: 8 }, CapRights::ALL),
    )
    .expect("Failed to insert CNode cap");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_VSPACE,
        Capability::new(CapObject::VSpace { id: vspace_id }, CapRights::ALL),
    )
    .expect("Failed to insert VSpace cap");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_ENDPOINT,
        Capability::new(CapObject::Endpoint { id: ep_id }, CapRights::ALL),
    )
    .expect("Failed to insert Endpoint cap");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_NOTIF,
        Capability::new(CapObject::Notification { id: notif_id }, CapRights::ALL),
    )
    .expect("Failed to insert Notification cap");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_IRQ_CTRL,
        Capability::new(CapObject::IrqControl, CapRights::ALL),
    )
    .expect("Failed to insert IrqControl cap");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_IOPORT_PIT,
        Capability::new(
            CapObject::IoPort {
                start_port: 0x40,
                end_port: 0x43,
            },
            CapRights::ALL,
        ),
    )
    .expect("Failed to insert PIT IoPort cap");

    cap::cap_insert_root(
        root_cnode,
        CAP_SLOT_UNTYPED,
        Capability::new(
            CapObject::UntypedMemory {
                paddr: untyped_pa.as_u64(),
                size_bits: 21, // 2 MiB
                watermark: 0,
            },
            CapRights::ALL,
        ),
    )
    .expect("Failed to insert UntypedMemory cap");

    // 4. Register Process & Spawn Initial Ring 3 Main Thread
    let pid = sched::register_process(proc);
    let main_rsp = ROOTTASK_MAIN_STACK_VA + (ROOTTASK_STACK_PAGES * PAGE_SIZE) as u64 - 8;
    let tid = sched::spawn_user_thread(pid, ROOTTASK_CODE_VA, main_rsp, 0, DEFAULT_PRIORITY)
        .expect("Failed to spawn Root Task main thread");

    crate::kinfo!(
        "ROOT",
        "Launched Ring 3 Root Task: pid={} tid={} code={:#x} ({}B) untyped={:#x} (2MiB)",
        pid,
        tid,
        ROOTTASK_CODE_VA,
        img_len,
        untyped_pa.as_u64()
    );
}
