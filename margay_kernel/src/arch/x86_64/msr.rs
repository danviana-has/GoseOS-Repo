//! x86_64 Model-Specific Registers (MSRs)
//!
//! Provides architectural MSR addresses and safe-boundary read/write helpers
//! for `rdmsr` / `wrmsr`, plus bit definitions for EFER, APIC_BASE, PAT,
//! and SYSCALL/SYSRET configuration.

use core::arch::asm;

// ---------------------------------------------------------------------------
// Architectural MSR Addresses
// ---------------------------------------------------------------------------

/// Local APIC base physical address and global enable / x2APIC enable flags.
pub const IA32_APIC_BASE: u32 = 0x0000_001B;

/// Time Stamp Counter MSR.
pub const IA32_TSC: u32 = 0x0000_0010;

/// Feature control (VMX, SMX).
pub const IA32_FEATURE_CONTROL: u32 = 0x0000_003A;

/// Page Attribute Table (PAT) memory type encoding.
pub const IA32_PAT: u32 = 0x0000_0277;

/// MTRR capability and default type MSRs.
pub const IA32_MTRRCAP: u32 = 0x0000_00FE;
pub const IA32_MTRR_DEF_TYPE: u32 = 0x0000_02FF;

/// TSC-Deadline mode target value for the Local APIC timer.
pub const IA32_TSC_DEADLINE: u32 = 0x0000_06E0;

/// Extended Feature Enable Register (SCE, LME, LMA, NXE).
pub const IA32_EFER: u32 = 0xC000_0080;

/// Ring 0 / Ring 3 CS/SS selectors for `syscall` and `sysret`.
pub const IA32_STAR: u32 = 0xC000_0081;

/// 64-bit `syscall` target RIP.
pub const IA32_LSTAR: u32 = 0xC000_0082;

/// 32-bit compatibility mode `syscall` target RIP (unused in pure 64-bit).
pub const IA32_CSTAR: u32 = 0xC000_0083;

/// RFLAGS mask applied on `syscall` entry (bits set here are cleared in RFLAGS).
pub const IA32_FMASK: u32 = 0xC000_0084;

/// 64-bit FS segment base address (user TLS).
pub const IA32_FS_BASE: u32 = 0xC000_0100;

/// 64-bit GS segment base address (active per-CPU pointer in Ring 0).
pub const IA32_GS_BASE: u32 = 0xC000_0101;

/// Swapped GS base address exchanged with `IA32_GS_BASE` via `swapgs`.
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Auxiliary TSC processor ID (read by `rdtscp`).
pub const IA32_TSC_AUX: u32 = 0xC000_0103;

// ---------------------------------------------------------------------------
// x2APIC MSR Block (0x800 .. 0x83F)
// ---------------------------------------------------------------------------

pub const IA32_X2APIC_APICID: u32 = 0x802;
pub const IA32_X2APIC_VERSION: u32 = 0x803;
pub const IA32_X2APIC_TPR: u32 = 0x808;
pub const IA32_X2APIC_PPR: u32 = 0x80A;
pub const IA32_X2APIC_EOI: u32 = 0x80B;
pub const IA32_X2APIC_LDR: u32 = 0x80D;
pub const IA32_X2APIC_SIVR: u32 = 0x80F;
pub const IA32_X2APIC_ISR0: u32 = 0x810;
pub const IA32_X2APIC_TMR0: u32 = 0x818;
pub const IA32_X2APIC_IRR0: u32 = 0x820;
pub const IA32_X2APIC_ESR: u32 = 0x828;
pub const IA32_X2APIC_LVT_CMCI: u32 = 0x82F;
pub const IA32_X2APIC_ICR: u32 = 0x830;
pub const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
pub const IA32_X2APIC_LVT_THERMAL: u32 = 0x833;
pub const IA32_X2APIC_LVT_PMI: u32 = 0x834;
pub const IA32_X2APIC_LVT_LINT0: u32 = 0x835;
pub const IA32_X2APIC_LVT_LINT1: u32 = 0x836;
pub const IA32_X2APIC_LVT_ERROR: u32 = 0x837;
pub const IA32_X2APIC_INIT_COUNT: u32 = 0x838;
pub const IA32_X2APIC_CUR_COUNT: u32 = 0x839;
pub const IA32_X2APIC_DIV_CONF: u32 = 0x83E;
pub const IA32_X2APIC_SELF_IPI: u32 = 0x83F;

// ---------------------------------------------------------------------------
// EFER Bit Flags
// ---------------------------------------------------------------------------

/// System Call Extensions (`syscall` / `sysret` enable).
pub const EFER_SCE: u64 = 1 << 0;
/// Long Mode Enable.
pub const EFER_LME: u64 = 1 << 8;
/// Long Mode Active (read-only status).
pub const EFER_LMA: u64 = 1 << 10;
/// No-Execute Page Protection Enable (NX / XD bit in PTEs).
pub const EFER_NXE: u64 = 1 << 11;

// ---------------------------------------------------------------------------
// IA32_APIC_BASE Bit Flags
// ---------------------------------------------------------------------------

/// Bootstrap Processor flag (1 if BSP, 0 if AP).
pub const APIC_BASE_BSP: u64 = 1 << 8;
/// Enable x2APIC mode.
pub const APIC_BASE_X2APIC_ENABLE: u64 = 1 << 10;
/// Global Local APIC enable.
pub const APIC_BASE_GLOBAL_ENABLE: u64 = 1 << 11;
/// Physical base address mask (bits 12..=51).
pub const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// MSR Access Primitives
// ---------------------------------------------------------------------------

/// Read a 64-bit Model-Specific Register.
#[inline(always)]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Write a 64-bit Model-Specific Register.
#[inline(always)]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

/// Set specific bits in an MSR (read-modify-write).
#[inline(always)]
pub unsafe fn msr_set_bits(msr: u32, bits: u64) {
    let cur = rdmsr(msr);
    wrmsr(msr, cur | bits);
}

/// Clear specific bits in an MSR (read-modify-write).
#[inline(always)]
pub unsafe fn msr_clear_bits(msr: u32, bits: u64) {
    let cur = rdmsr(msr);
    wrmsr(msr, cur & !bits);
}

/// Strongly-typed MSR wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msr(pub u32);

impl Msr {
    #[inline(always)]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    #[inline(always)]
    pub unsafe fn read(&self) -> u64 {
        rdmsr(self.0)
    }

    #[inline(always)]
    pub unsafe fn write(&self, value: u64) {
        wrmsr(self.0, value);
    }
}
