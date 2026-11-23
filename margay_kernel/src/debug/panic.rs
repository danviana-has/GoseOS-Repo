//! Kernel Panic Handler with Nested-Panic Guard & SMP Halt
//!
//! Captures CPU state (CR2, CR3, RSP, RBP, RFLAGS), unwinds the kernel stack
//! via lock-free emergency UART output, broadcasts a Halt IPI to all other
//! online CPUs, and halts the current processor cleanly.

use core::fmt::Write;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::debug::serial::EmergencySerial;
use crate::debug::unwind;

static PANIC_DEPTH: AtomicU32 = AtomicU32::new(0);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // Immediately mask local interrupts to prevent re-entrant timer/IRQ noise.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    let depth = PANIC_DEPTH.fetch_add(1, Ordering::SeqCst);
    let mut w = EmergencySerial;

    if depth >= 1 {
        let _ = writeln!(w, "\n!!! NESTED KERNEL PANIC (depth={}) - HALTING IMMEDIATELY !!!", depth + 1);
        halt_forever();
    }

    let cr2: u64;
    let cr3: u64;
    let rsp: u64;
    let rbp: u64;
    let rflags: u64;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack));
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nomem));
    }

    let _ = writeln!(w, "\n====================================================================");
    let _ = writeln!(w, "                    MARGAY MICROKERNEL PANIC");
    let _ = writeln!(w, "====================================================================");

    if let Some(loc) = info.location() {
        let _ = writeln!(w, "  Location : {}:{}:{}", loc.file(), loc.line(), loc.column());
    } else {
        let _ = writeln!(w, "  Location : <unknown>");
    }

    let _ = writeln!(w, "  Message  : {}", info.message());
    let _ = writeln!(
        w,
        "  State    : CR2={:#018x} CR3={:#018x}",
        cr2, cr3
    );
    let _ = writeln!(
        w,
        "             RSP={:#018x} RBP={:#018x} RFLAGS={:#018x}",
        rsp, rbp, rflags
    );

    unwind::print_stack_trace_from(rbp);

    let _ = writeln!(w, "====================================================================");
    let _ = writeln!(w, "  Halting all CPUs...");

    // Broadcast halt IPI to peer CPUs if APIC is already online.
    crate::arch::x86_64::apic::broadcast_halt_ipi();

    halt_forever()
}

/// Enter an unrecoverable CLI + HLT loop.
#[inline(never)]
pub fn halt_forever() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
