//! x86_64 Architecture Subsystem
//!
//! Encapsulates all processor-specific mechanisms: boot protocol (Limine),
//! ACPI/MADT parsing, GDT/TSS/IST, IDT/ISRs, PIC/Local APIC/IOAPIC, MSRs,
//! CPUID, FPU/XSAVE, SMP per-CPU state, and low-level context switching.

pub mod acpi;
pub mod apic;
pub mod context;
pub mod cpuid;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod limine;
pub mod msr;
pub mod pic;
pub mod port;
pub mod smp;
pub mod tss;

use core::arch::asm;

use crate::arch::x86_64::cpuid::CpuFeatures;
use crate::arch::x86_64::msr::{EFER_NXE, IA32_EFER};

/// Read CR0 control register.
#[inline(always)]
pub fn read_cr0() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write CR0 control register.
#[inline(always)]
pub unsafe fn write_cr0(val: u64) {
    asm!("mov cr0, {}", in(reg) val, options(nomem, nostack, preserves_flags));
}

/// Read CR2 (Page Fault linear address).
#[inline(always)]
pub fn read_cr2() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Read CR3 (PML4 physical address).
#[inline(always)]
pub fn read_cr3() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write CR3 (switch address space and flush non-global TLB entries).
#[inline(always)]
pub unsafe fn write_cr3(val: u64) {
    asm!("mov cr3, {}", in(reg) val, options(nomem, nostack, preserves_flags));
}

/// Read CR4 control register.
#[inline(always)]
pub fn read_cr4() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write CR4 control register.
#[inline(always)]
pub unsafe fn write_cr4(val: u64) {
    asm!("mov cr4, {}", in(reg) val, options(nomem, nostack, preserves_flags));
}

/// Invalidate a single virtual address in the local CPU's TLB.
#[inline(always)]
pub fn invlpg(vaddr: u64) {
    unsafe {
        asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// Flush all non-global TLB entries on the current CPU by reloading CR3.
#[inline(always)]
pub fn flush_tlb_all() {
    unsafe {
        let cr3 = read_cr3();
        write_cr3(cr3);
    }
}

/// Read the 64-bit Time Stamp Counter (`rdtsc`).
#[inline(always)]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read RFLAGS register.
#[inline(always)]
pub fn read_rflags() -> u64 {
    let rflags: u64;
    unsafe {
        asm!("pushfq; pop {}", out(reg) rflags, options(nomem));
    }
    rflags
}

/// Check if maskable interrupts (IF bit 9) are currently enabled.
#[inline(always)]
pub fn interrupts_enabled() -> bool {
    (read_rflags() & (1 << 9)) != 0
}

#[inline(always)]
pub fn disable_interrupts() {
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

#[inline(always)]
pub fn enable_interrupts() {
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

#[inline(always)]
pub fn halt_once() {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
}

/// Enable hardware memory-protection features on the current CPU:
/// - CR0.WP (Write Protect in Ring 0 so CoW and read-only enforcement work)
/// - IA32_EFER.NXE (No-Execute bit in page tables for W^X)
/// - CR4.PGE (Global Pages), CR4.SMEP (Supervisor Mode Execution Prevention),
///   CR4.UMIP (User-Mode Instruction Prevention), CR4.FSGSBASE
pub fn enable_cpu_security_features(features: &CpuFeatures) {
    unsafe {
        // Enable Write Protect (CR0.WP = bit 16)
        let cr0 = read_cr0() | (1 << 16);
        write_cr0(cr0);

        // Enable NXE if supported
        if features.has_nx {
            msr::msr_set_bits(IA32_EFER, EFER_NXE);
        }

        // Enable PGE (bit 7), SMEP (bit 20), UMIP (bit 11), FSGSBASE (bit 16)
        // Note: SMAP is deliberately left off during early kernel user-copy helpers
        // without stac/clac wrappers so sys_debug_print can read validated user slices.
        let mut cr4 = read_cr4() | (1 << 7);
        if features.has_smep {
            cr4 |= 1 << 20;
        }
        if features.has_umip {
            cr4 |= 1 << 11;
        }
        if features.has_fsgsbase {
            cr4 |= 1 << 16;
        }
        write_cr4(cr4);
    }
}
