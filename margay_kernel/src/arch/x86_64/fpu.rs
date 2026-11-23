//! FPU / SSE / AVX State Management (FXSAVE/FXRSTOR & XSAVE/XRSTOR)
//!
//! Configures CR0, CR4, and XCR0 per CPU to support user-space floating-point
//! and SIMD workloads while keeping the kernel itself strictly soft-float.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::arch::x86_64::cpuid::CpuFeatures;

static USE_XSAVE: AtomicBool = AtomicBool::new(false);
static XSAVE_MASK: AtomicU32 = AtomicU32::new(0x3); // x87 + SSE

/// 64-byte aligned FPU/SSE/AVX save buffer stored inside each Thread (TCB).
/// 832 bytes covers legacy FXSAVE (512B) + XSAVE header (64B) + AVX YMM_Hi128 (256B).
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FpuState {
    pub data: [u8; 832],
}

impl FpuState {
    /// Create a clean architectural initial FPU/SSE state:
    /// - FCW = 0x037F (all x87 exceptions masked, double-extended precision)
    /// - MXCSR = 0x1F80 (all SSE exceptions masked, round-to-nearest)
    pub const fn new_clean() -> Self {
        let mut data = [0u8; 832];
        // FCW at offset 0..2 = 0x037F
        data[0] = 0x7F;
        data[1] = 0x03;
        // MXCSR at offset 24..28 = 0x1F80
        data[24] = 0x80;
        data[25] = 0x1F;
        Self { data }
    }

    /// Save the current CPU's FPU/SSE/AVX registers into this buffer.
    #[inline]
    pub unsafe fn save(&mut self) {
        let ptr = self.data.as_mut_ptr();
        if USE_XSAVE.load(Ordering::Relaxed) {
            let mask = XSAVE_MASK.load(Ordering::Relaxed);
            asm!(
                "xsave64 [{}]",
                in(reg) ptr,
                in("eax") mask,
                in("edx") 0u32,
                options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "fxsave64 [{}]",
                in(reg) ptr,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Restore the CPU's FPU/SSE/AVX registers from this buffer.
    #[inline]
    pub unsafe fn restore(&self) {
        let ptr = self.data.as_ptr();
        if USE_XSAVE.load(Ordering::Relaxed) {
            let mask = XSAVE_MASK.load(Ordering::Relaxed);
            asm!(
                "xrstor64 [{}]",
                in(reg) ptr,
                in("eax") mask,
                in("edx") 0u32,
                options(nostack, preserves_flags)
            );
        } else {
            asm!(
                "fxrstor64 [{}]",
                in(reg) ptr,
                options(nostack, preserves_flags)
            );
        }
    }
}

/// Enable FPU, SSE, and (if available) XSAVE/AVX on the current CPU.
pub fn init_for_current_cpu(features: &CpuFeatures, is_bsp: bool) {
    unsafe {
        // CR0: clear EM (bit 2) and TS (bit 3); set MP (bit 1) and NE (bit 5)
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        cr0 &= !((1 << 2) | (1 << 3));
        cr0 |= (1 << 1) | (1 << 5);
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));

        // CR4: set OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        cr4 |= (1 << 9) | (1 << 10);

        if features.has_xsave {
            // Enable OSXSAVE (bit 18)
            cr4 |= 1 << 18;
            asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));

            let mut xcr0: u64 = 0x3; // x87 + SSE
            if features.has_avx && features.xsave_area_size <= 832 {
                xcr0 |= 1 << 2; // AVX
            }
            asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32,
                options(nomem, nostack)
            );

            if is_bsp {
                USE_XSAVE.store(true, Ordering::Release);
                XSAVE_MASK.store(xcr0 as u32, Ordering::Release);
            }
        } else {
            asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));
        }

        // Initialize x87 FPU state
        asm!("fninit", options(nomem, nostack));
    }

    if is_bsp {
        crate::kinfo!(
            "FPU",
            "Initialized ({}, mask={:#x})",
            if USE_XSAVE.load(Ordering::Relaxed) { "XSAVE64" } else { "FXSAVE64" },
            XSAVE_MASK.load(Ordering::Relaxed)
        );
    }
}

/// Clear CR0.TS (Task Switched) flag if lazy FPU switching ever triggers `#NM`.
#[inline]
pub fn clear_ts() {
    unsafe {
        asm!("clts", options(nomem, nostack));
    }
}
