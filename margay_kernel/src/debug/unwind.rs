//! Frame-Pointer Stack Unwinder for x86_64
//!
//! Because Margay compiles with `-C force-frame-pointers=yes`, every kernel
//! stack frame forms a linked list via `[rbp] -> prev_rbp`, `[rbp + 8] -> rip`.
//! The unwinder strictly validates canonical higher-half alignment and monotonic
//! stack growth before dereferencing any pointer so it cannot trigger a cascade
//! page fault during panic or Double Fault dumps.

use core::fmt::Write;

use crate::debug::serial::EmergencySerial;

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __roottask_start: u8;
    static __roottask_end: u8;
}

/// Maximum number of stack frames to unwind.
pub const MAX_UNWIND_FRAMES: usize = 32;

/// Classify a return instruction pointer against kernel linker sections.
fn classify_rip(rip: u64) -> &'static str {
    let text_start = unsafe { &__text_start as *const u8 as u64 };
    let text_end = unsafe { &__text_end as *const u8 as u64 };
    let rt_start = unsafe { &__roottask_start as *const u8 as u64 };
    let rt_end = unsafe { &__roottask_end as *const u8 as u64 };

    if rip >= text_start && rip < text_end {
        "margay_kernel!.text"
    } else if rip >= rt_start && rip < rt_end {
        "margay_kernel!.roottask"
    } else if rip < 0x0000_8000_0000_0000 {
        "userspace"
    } else {
        "unknown"
    }
}

/// Check whether an RBP address looks like a valid, 8-byte aligned canonical
/// kernel address (higher half `0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFF0`).
#[inline]
fn is_valid_kernel_rbp(rbp: u64) -> bool {
    rbp >= 0xFFFF_8000_0000_0000
        && rbp <= 0xFFFF_FFFF_FFFF_FFE0
        && (rbp & 0x7) == 0
}

/// Capture the current RBP register.
#[inline(always)]
pub fn current_rbp() -> u64 {
    let rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags));
    }
    rbp
}

/// Unwind the stack starting from `initial_rbp` and print each frame using the
/// lock-free emergency serial writer.
pub fn print_stack_trace_from(initial_rbp: u64) {
    let mut w = EmergencySerial;
    let _ = writeln!(w, "  Stack Backtrace (max {} frames):", MAX_UNWIND_FRAMES);

    let mut rbp = initial_rbp;
    let mut depth = 0usize;

    while depth < MAX_UNWIND_FRAMES && is_valid_kernel_rbp(rbp) {
        let next_rbp = unsafe { *(rbp as *const u64) };
        let ret_rip = unsafe { *((rbp + 8) as *const u64) };

        if ret_rip == 0 {
            break;
        }

        let section = classify_rip(ret_rip);
        let text_start = unsafe { &__text_start as *const u8 as u64 };
        if ret_rip >= text_start {
            let offset = ret_rip - text_start;
            let _ = writeln!(
                w,
                "    #{:02}: {:#018x} <{}+{:#x}> (rbp={:#018x})",
                depth, ret_rip, section, offset, rbp
            );
        } else {
            let _ = writeln!(
                w,
                "    #{:02}: {:#018x} <{}> (rbp={:#018x})",
                depth, ret_rip, section, rbp
            );
        }

        // Guard against cycles or downward-pointing frame pointers.
        if next_rbp <= rbp || (next_rbp - rbp) > 1024 * 1024 {
            break;
        }
        rbp = next_rbp;
        depth += 1;
    }

    if depth == 0 {
        let _ = writeln!(w, "    <no valid kernel frames>");
    }
}

/// Unwind and print the current kernel stack trace.
pub fn print_current_stack_trace() {
    print_stack_trace_from(current_rbp());
}
