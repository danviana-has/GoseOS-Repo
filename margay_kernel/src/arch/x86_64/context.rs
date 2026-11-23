//! Context Switching, Ring 3 Entry (`iretq`), and Fast `syscall`/`sysret` Entry
//!
//! All register layouts here match the System V AMD64 ABI and the `PerCpu`
//! offsets defined in `smp.rs`:
//!   - `gs:[8]`  -> `PerCpu.kernel_rsp`
//!   - `gs:[16]` -> `PerCpu.user_rsp_scratch`

use core::arch::global_asm;

/// Callee-saved kernel context stored inside each Thread Control Block (TCB).
/// Switched by `margay_context_switch(old: *mut CpuContext, new: *const CpuContext)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub rip: u64,
}

/// Full register frame pushed by `margay_syscall_entry` before calling
/// `crate::syscall::dispatch::margay_syscall_dispatch`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11_rflags: u64, // Saved user RFLAGS (clobbered by syscall into R11)
    pub rcx_rip: u64,    // Saved user RIP    (clobbered by syscall into RCX)
    pub r9: u64,         // arg5
    pub r8: u64,         // arg4
    pub r10: u64,        // arg3 (Linux/x86_64 convention since RCX is clobbered)
    pub rdx: u64,        // arg2
    pub rsi: u64,        // arg1
    pub rdi: u64,        // arg0
    pub rax: u64,        // syscall number -> return value
    pub user_rsp: u64,   // Saved user RSP
}

global_asm!(
    r#"
.section .text
// ---------------------------------------------------------------------------
// Cooperative / Preemptive Kernel Context Switch
//   rdi = old: *mut CpuContext
//   rsi = new: *const CpuContext
// ---------------------------------------------------------------------------
.global margay_context_switch
margay_context_switch:
    // Save callee-saved registers into old CpuContext
    mov [rdi + 0x00], r15
    mov [rdi + 0x08], r14
    mov [rdi + 0x10], r13
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], rbx
    mov [rdi + 0x28], rbp
    pushfq
    pop rax
    mov [rdi + 0x30], rax

    // Save return address and adjusted RSP (as if we returned from this call)
    mov rax, [rsp]
    mov [rdi + 0x40], rax       // old.rip = return address
    lea rax, [rsp + 8]
    mov [rdi + 0x38], rax       // old.rsp = caller's RSP

    // Restore callee-saved registers from new CpuContext
    mov r15, [rsi + 0x00]
    mov r14, [rsi + 0x08]
    mov r13, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov rbx, [rsi + 0x20]
    mov rbp, [rsi + 0x28]
    mov rax, [rsi + 0x30]
    push rax
    popfq

    // Switch stack and jump to new RIP
    mov rsp, [rsi + 0x38]
    jmp qword ptr [rsi + 0x40]

// ---------------------------------------------------------------------------
// Initial Transition to Ring 3 User Mode via `iretq`
//   rdi = user_rip
//   rsi = user_rsp
//   rdx = user_rflags (IF=1, bit 1=1 -> 0x202)
//   rcx = user_arg0 (placed in RDI for user entry)
// ---------------------------------------------------------------------------
.global margay_enter_userspace
margay_enter_userspace:
    cli
    // Switch GS to user GS base before entering Ring 3
    swapgs

    // Build iretq frame: SS, RSP, RFLAGS, CS, RIP
    push 0x1B          // USER_DS (0x18 | 3)
    push rsi           // user RSP
    push rdx           // user RFLAGS
    push 0x23          // USER_CS (0x20 | 3)
    push rdi           // user RIP

    // Pass arg0 in RDI and zero all other GPRs to avoid leaking kernel data
    mov rdi, rcx
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    iretq

// ---------------------------------------------------------------------------
// Fast 64-bit SYSCALL Entry (`IA32_LSTAR`)
//   On entry from Ring 3:
//     RCX = user RIP
//     R11 = user RFLAGS
//     RSP = user RSP (untrusted!)
//     IF  = 0 (masked by IA32_FMASK)
// ---------------------------------------------------------------------------
.global margay_syscall_entry
margay_syscall_entry:
    swapgs
    // Save user RSP into PerCpu.user_rsp_scratch (gs:[16]) and load kernel RSP (gs:[8])
    mov gs:[16], rsp
    mov rsp, gs:[8]

    // Build SyscallFrame on the kernel stack
    push qword ptr gs:[16]   // user_rsp
    push rax                 // syscall number
    push rdi                 // arg0
    push rsi                 // arg1
    push rdx                 // arg2
    push r10                 // arg3
    push r8                  // arg4
    push r9                  // arg5
    push rcx                 // user RIP
    push r11                 // user RFLAGS
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    cld
    sti
    call margay_syscall_dispatch
    cli

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11                  // user RFLAGS
    pop rcx                  // user RIP
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop rax                  // return value
    pop rsp                  // restore user RSP

    swapgs
    sysretq
"#
);

extern "C" {
    /// Switch execution from `old` context to `new` context.
    pub fn margay_context_switch(old: *mut CpuContext, new: *const CpuContext);

    /// Enter Ring 3 user space at `(user_rip, user_rsp)` with `user_rflags` and `arg0`.
    pub fn margay_enter_userspace(
        user_rip: u64,
        user_rsp: u64,
        user_rflags: u64,
        arg0: u64,
    ) -> !;

    /// Fast `syscall` entry symbol programmed into `IA32_LSTAR`.
    pub fn margay_syscall_entry();
}
