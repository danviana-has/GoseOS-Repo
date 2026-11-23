//! Fast `syscall`/`sysret` ABI Configuration & Error Codes
//!
//! Configures `IA32_EFER.SCE`, `IA32_STAR`, `IA32_LSTAR`, and `IA32_FMASK`
//! per CPU core so Ring 3 servers enter Ring 0 in ~30 cycles with zero IDT
//! overhead.

pub mod dispatch;

use crate::arch::x86_64::context::margay_syscall_entry;
use crate::arch::x86_64::gdt::IA32_STAR_VALUE;
use crate::arch::x86_64::msr::{
    self, EFER_SCE, IA32_CSTAR, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR,
};

// ---------------------------------------------------------------------------
// Syscall Numbers (Minimalist Microkernel ABI)
// ---------------------------------------------------------------------------

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

// Capability Invocation Sub-Operations (`SYS_CAP_INVOKE`)
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

// ---------------------------------------------------------------------------
// Typed Syscall Return Codes
// ---------------------------------------------------------------------------

#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    Ok = 0,
    InvalidSyscall = -1,
    InvalidCap = -2,
    InsufficientRights = -3,
    InvalidArg = -4,
    OutOfMemory = -5,
    WouldBlock = -6,
    NotFound = -7,
    PermissionDenied = -8,
    Fault = -9,
    Busy = -10,
}

impl SyscallError {
    #[inline]
    pub const fn as_u64(self) -> u64 {
        (self as i64) as u64
    }
}

/// Mask Interrupt Flag (IF=1<<9), Trap Flag (TF=1<<8), and Direction Flag (DF=1<<10)
/// on `syscall` entry so the kernel always starts with clean flags and IRQs masked.
const SYSCALL_RFLAGS_MASK: u64 = (1 << 8) | (1 << 9) | (1 << 10);

/// Program `IA32_EFER`, `IA32_STAR`, `IA32_LSTAR`, `IA32_CSTAR`, and `IA32_FMASK`
/// on the current CPU core.
pub fn init_for_current_cpu() {
    unsafe {
        msr::msr_set_bits(IA32_EFER, EFER_SCE);
        msr::wrmsr(IA32_STAR, IA32_STAR_VALUE);
        msr::wrmsr(IA32_LSTAR, margay_syscall_entry as *const () as u64);
        msr::wrmsr(IA32_CSTAR, 0);
        msr::wrmsr(IA32_FMASK, SYSCALL_RFLAGS_MASK);
    }
}
