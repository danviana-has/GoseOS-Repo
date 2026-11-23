//! Local APIC (xAPIC MMIO & x2APIC MSR), APIC Timer Calibration, IPIs,
//! and I/O APIC Redirection Controller.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::acpi::{AcpiInfo, MAX_MADT_IOAPICS};
use crate::arch::x86_64::cpuid::CpuFeatures;
use crate::arch::x86_64::msr::{
    self, APIC_BASE_ADDR_MASK, APIC_BASE_GLOBAL_ENABLE, APIC_BASE_X2APIC_ENABLE,
    IA32_APIC_BASE, IA32_X2APIC_APICID, IA32_X2APIC_CUR_COUNT, IA32_X2APIC_DIV_CONF,
    IA32_X2APIC_EOI, IA32_X2APIC_ESR, IA32_X2APIC_ICR, IA32_X2APIC_INIT_COUNT,
    IA32_X2APIC_LVT_ERROR, IA32_X2APIC_LVT_LINT0, IA32_X2APIC_LVT_LINT1,
    IA32_X2APIC_LVT_TIMER, IA32_X2APIC_SIVR, IA32_X2APIC_TPR,
};
use crate::arch::x86_64::port::{inb, outb};

// ---------------------------------------------------------------------------
// Interrupt Vector Assignments
// ---------------------------------------------------------------------------

/// Base vector for hardware IRQs routed through the I/O APIC (0x20..0xDF).
pub const IRQ_VECTOR_BASE: u8 = 0x20;
/// Local APIC periodic preemption timer vector.
pub const VECTOR_APIC_TIMER: u8 = 0xE0;
/// Inter-Processor Interrupt: trigger scheduler reschedule on target CPU.
pub const VECTOR_IPI_RESCHED: u8 = 0xE1;
/// Inter-Processor Interrupt: shoot down TLB entries on target CPU.
pub const VECTOR_IPI_TLB_SHOOTDOWN: u8 = 0xE2;
/// Inter-Processor Interrupt: halt target CPU immediately (kernel panic).
pub const VECTOR_IPI_HALT: u8 = 0xE3;
/// Local APIC internal error vector.
pub const VECTOR_APIC_ERROR: u8 = 0xFE;
/// Local APIC spurious interrupt vector (low 4 bits must be 0xF on older CPUs).
pub const VECTOR_APIC_SPURIOUS: u8 = 0xFF;

// xAPIC MMIO Register Offsets
const XAPIC_ID: usize = 0x020;
const XAPIC_TPR: usize = 0x080;
const XAPIC_EOI: usize = 0x0B0;
const XAPIC_SIVR: usize = 0x0F0;
const XAPIC_ESR: usize = 0x280;
const XAPIC_ICR_LOW: usize = 0x300;
const XAPIC_ICR_HIGH: usize = 0x310;
const XAPIC_LVT_TIMER: usize = 0x320;
const XAPIC_LVT_LINT0: usize = 0x350;
const XAPIC_LVT_LINT1: usize = 0x360;
const XAPIC_LVT_ERROR: usize = 0x370;
const XAPIC_INIT_COUNT: usize = 0x380;
const XAPIC_CUR_COUNT: usize = 0x390;
const XAPIC_DIV_CONF: usize = 0x3E0;

// LVT / SIVR flags
const SIVR_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

// Global APIC state
static LAPIC_VIRT_BASE: AtomicU64 = AtomicU64::new(0);
static USE_X2APIC: AtomicBool = AtomicBool::new(false);
static APIC_READY: AtomicBool = AtomicBool::new(false);
static TIMER_TICKS_PER_MS: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Local APIC Register Access
// ---------------------------------------------------------------------------

#[inline]
unsafe fn xapic_read(offset: usize) -> u32 {
    let base = LAPIC_VIRT_BASE.load(Ordering::Relaxed);
    read_volatile((base as usize + offset) as *const u32)
}

#[inline]
unsafe fn xapic_write(offset: usize, val: u32) {
    let base = LAPIC_VIRT_BASE.load(Ordering::Relaxed);
    write_volatile((base as usize + offset) as *mut u32, val);
}

#[inline]
pub fn is_x2apic() -> bool {
    USE_X2APIC.load(Ordering::Relaxed)
}

#[inline]
pub fn is_ready() -> bool {
    APIC_READY.load(Ordering::Acquire)
}

/// Read the current CPU's Local APIC ID.
#[inline]
pub fn lapic_id() -> u32 {
    if !is_ready() {
        return 0;
    }
    unsafe {
        if is_x2apic() {
            msr::rdmsr(IA32_X2APIC_APICID) as u32
        } else {
            xapic_read(XAPIC_ID) >> 24
        }
    }
}

/// Send End-Of-Interrupt (EOI) to the current CPU's Local APIC.
#[inline]
pub fn eoi() {
    if !is_ready() {
        return;
    }
    unsafe {
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_EOI, 0);
        } else {
            xapic_write(XAPIC_EOI, 0);
        }
    }
}

/// Initialize the Local APIC on the BSP (discovers base, enables x2APIC if
/// supported, calibrates timer via PIT channel 2, and initializes I/O APICs).
pub fn init_bsp(features: &CpuFeatures, acpi: &AcpiInfo, hhdm: u64) {
    assert!(features.has_apic, "CPU does not support Local APIC");

    let apic_base_msr = unsafe { msr::rdmsr(IA32_APIC_BASE) };
    let phys_base = if acpi.lapic_phys_base != 0 {
        acpi.lapic_phys_base
    } else {
        apic_base_msr & APIC_BASE_ADDR_MASK
    };

    LAPIC_VIRT_BASE.store(phys_base + hhdm, Ordering::Release);

    // Prefer x2APIC when supported by the CPU.
    let enable_x2apic = features.has_x2apic;
    USE_X2APIC.store(enable_x2apic, Ordering::Release);

    init_lapic_local();

    // Calibrate the Local APIC timer against the 8254 PIT (10 ms window).
    let ticks_per_ms = calibrate_timer_via_pit();
    TIMER_TICKS_PER_MS.store(ticks_per_ms, Ordering::Release);

    // Initialize all I/O APICs discovered in ACPI MADT.
    init_ioapics(acpi, hhdm);

    APIC_READY.store(true, Ordering::Release);

    crate::kinfo!(
        "APIC",
        "Mode={} PhysBase={:#x} BSP_ID={} TimerCal={} ticks/ms IOAPICs={}",
        if enable_x2apic { "x2APIC" } else { "xAPIC" },
        phys_base,
        lapic_id(),
        ticks_per_ms,
        ioapic_count()
    );
}

/// Initialize the Local APIC on an Application Processor (AP).
pub fn init_ap() {
    init_lapic_local();
}

/// Common per-CPU Local APIC enable sequence (BSP and APs).
fn init_lapic_local() {
    unsafe {
        let mut base = msr::rdmsr(IA32_APIC_BASE) | APIC_BASE_GLOBAL_ENABLE;
        if is_x2apic() {
            base |= APIC_BASE_X2APIC_ENABLE;
        }
        msr::wrmsr(IA32_APIC_BASE, base);

        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_TPR, 0);
            msr::wrmsr(IA32_X2APIC_SIVR, (SIVR_ENABLE | VECTOR_APIC_SPURIOUS as u32) as u64);
            msr::wrmsr(IA32_X2APIC_ESR, 0);
            msr::wrmsr(IA32_X2APIC_LVT_ERROR, VECTOR_APIC_ERROR as u64);
            msr::wrmsr(IA32_X2APIC_LVT_LINT0, LVT_MASKED as u64);
            msr::wrmsr(IA32_X2APIC_LVT_LINT1, LVT_MASKED as u64);
            msr::wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);
        } else {
            xapic_write(XAPIC_TPR, 0);
            xapic_write(XAPIC_SIVR, SIVR_ENABLE | VECTOR_APIC_SPURIOUS as u32);
            xapic_write(XAPIC_ESR, 0);
            xapic_write(XAPIC_LVT_ERROR, VECTOR_APIC_ERROR as u32);
            xapic_write(XAPIC_LVT_LINT0, LVT_MASKED);
            xapic_write(XAPIC_LVT_LINT1, LVT_MASKED);
            xapic_write(XAPIC_LVT_TIMER, LVT_MASKED);
        }
    }
}

/// Calibrate the Local APIC timer frequency using legacy PIT Channel 2
/// over a 10 ms measurement gate (1193182 Hz / 100 = 11932 ticks).
fn calibrate_timer_via_pit() -> u32 {
    const PIT_CH2_DATA: u16 = 0x42;
    const PIT_CMD: u16 = 0x43;
    const PIT_GATE: u16 = 0x61;
    const PIT_10MS_COUNT: u16 = 11_932;

    unsafe {
        // Set APIC timer divide-by-16
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_DIV_CONF, 0x03);
            msr::wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);
        } else {
            xapic_write(XAPIC_DIV_CONF, 0x03);
            xapic_write(XAPIC_LVT_TIMER, LVT_MASKED);
        }

        // Gate PIT channel 2 off, disable speaker output
        let gate = (inb(PIT_GATE) & 0xFD) | 0x01;
        outb(PIT_GATE, gate & !0x01);

        // Channel 2, lobyte/hibyte, mode 0 (interrupt on terminal count)
        outb(PIT_CMD, 0xB0);
        outb(PIT_CH2_DATA, (PIT_10MS_COUNT & 0xFF) as u8);
        outb(PIT_CH2_DATA, (PIT_10MS_COUNT >> 8) as u8);

        // Start APIC countdown from 0xFFFF_FFFF
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_INIT_COUNT, 0xFFFF_FFFF);
        } else {
            xapic_write(XAPIC_INIT_COUNT, 0xFFFF_FFFF);
        }

        // Enable PIT channel 2 gate
        outb(PIT_GATE, gate | 0x01);

        // Poll PIT channel 2 output (bit 5 of port 0x61) with bounded timeout
        let mut guard = 0u32;
        while (inb(PIT_GATE) & 0x20) == 0 && guard < 10_000_000 {
            core::hint::spin_loop();
            guard += 1;
        }

        let remaining = if is_x2apic() {
            msr::rdmsr(IA32_X2APIC_CUR_COUNT) as u32
        } else {
            xapic_read(XAPIC_CUR_COUNT)
        };

        // Stop APIC timer
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_INIT_COUNT, 0);
        } else {
            xapic_write(XAPIC_INIT_COUNT, 0);
        }

        let elapsed = 0xFFFF_FFFFu32.saturating_sub(remaining);
        let per_ms = elapsed / 10;
        if per_ms < 1000 { 10_000 } else { per_ms }
    }
}

/// Start the Local APIC periodic timer on the current CPU at `hz` ticks/sec.
pub fn start_periodic_timer(hz: u32) {
    let ticks_per_ms = TIMER_TICKS_PER_MS.load(Ordering::Relaxed).max(10_000);
    let interval_ms = (1000 / hz.max(1)).max(1);
    let init_count = ticks_per_ms.saturating_mul(interval_ms);

    unsafe {
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_DIV_CONF, 0x03);
            msr::wrmsr(
                IA32_X2APIC_LVT_TIMER,
                (LVT_TIMER_PERIODIC | VECTOR_APIC_TIMER as u32) as u64,
            );
            msr::wrmsr(IA32_X2APIC_INIT_COUNT, init_count as u64);
        } else {
            xapic_write(XAPIC_DIV_CONF, 0x03);
            xapic_write(XAPIC_LVT_TIMER, LVT_TIMER_PERIODIC | VECTOR_APIC_TIMER as u32);
            xapic_write(XAPIC_INIT_COUNT, init_count);
        }
    }
}

/// Stop the Local APIC timer on the current CPU.
pub fn stop_timer() {
    unsafe {
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);
            msr::wrmsr(IA32_X2APIC_INIT_COUNT, 0);
        } else {
            xapic_write(XAPIC_LVT_TIMER, LVT_MASKED);
            xapic_write(XAPIC_INIT_COUNT, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Inter-Processor Interrupts (IPIs)
// ---------------------------------------------------------------------------

/// Send a fixed-vector IPI to a specific target Local APIC ID.
pub fn send_ipi(target_lapic_id: u32, vector: u8) {
    if !is_ready() {
        return;
    }
    crate::debug::telemetry::TELEMETRY
        .ipis_sent
        .fetch_add(1, Ordering::Relaxed);

    unsafe {
        if is_x2apic() {
            let icr = ((target_lapic_id as u64) << 32) | (1 << 14) | (vector as u64);
            msr::wrmsr(IA32_X2APIC_ICR, icr);
        } else {
            // Wait for any previous delivery to complete
            while (xapic_read(XAPIC_ICR_LOW) & (1 << 12)) != 0 {
                core::hint::spin_loop();
            }
            xapic_write(XAPIC_ICR_HIGH, target_lapic_id << 24);
            xapic_write(XAPIC_ICR_LOW, (1 << 14) | (vector as u32));
        }
    }
}

/// Broadcast a fixed-vector IPI to all CPUs excluding self.
pub fn broadcast_ipi_excluding_self(vector: u8) {
    if !is_ready() {
        return;
    }
    crate::debug::telemetry::TELEMETRY
        .ipis_sent
        .fetch_add(1, Ordering::Relaxed);

    // Destination Shorthand = 0b11 (All Excluding Self) at bits 19:18
    let low = (0b11u32 << 18) | (1 << 14) | (vector as u32);
    unsafe {
        if is_x2apic() {
            msr::wrmsr(IA32_X2APIC_ICR, low as u64);
        } else {
            while (xapic_read(XAPIC_ICR_LOW) & (1 << 12)) != 0 {
                core::hint::spin_loop();
            }
            xapic_write(XAPIC_ICR_HIGH, 0);
            xapic_write(XAPIC_ICR_LOW, low);
        }
    }
}

/// Broadcast a Halt IPI to all peer CPUs (used during panic).
pub fn broadcast_halt_ipi() {
    broadcast_ipi_excluding_self(VECTOR_IPI_HALT);
}

// ---------------------------------------------------------------------------
// I/O APIC Driver
// ---------------------------------------------------------------------------

const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;
const IOAPIC_REDTBL_BASE: u32 = 0x10;

#[derive(Clone, Copy)]
struct IoApicDevice {
    virt_base: u64,
    gsi_base: u32,
    max_redir: u32,
    present: bool,
}

impl IoApicDevice {
    const fn empty() -> Self {
        Self {
            virt_base: 0,
            gsi_base: 0,
            max_redir: 0,
            present: false,
        }
    }

    unsafe fn read_reg(&self, reg: u32) -> u32 {
        let ioregsel = self.virt_base as *mut u32;
        let iowin = (self.virt_base + 0x10) as *const u32;
        write_volatile(ioregsel, reg);
        read_volatile(iowin)
    }

    unsafe fn write_reg(&self, reg: u32, val: u32) {
        let ioregsel = self.virt_base as *mut u32;
        let iowin = (self.virt_base + 0x10) as *mut u32;
        write_volatile(ioregsel, reg);
        write_volatile(iowin, val);
    }

    unsafe fn write_redir(&self, index: u32, entry: u64) {
        let reg = IOAPIC_REDTBL_BASE + index * 2;
        self.write_reg(reg, entry as u32);
        self.write_reg(reg + 1, (entry >> 32) as u32);
    }

    unsafe fn read_redir(&self, index: u32) -> u64 {
        let reg = IOAPIC_REDTBL_BASE + index * 2;
        let lo = self.read_reg(reg) as u64;
        let hi = self.read_reg(reg + 1) as u64;
        (hi << 32) | lo
    }
}

static mut IOAPICS: [IoApicDevice; MAX_MADT_IOAPICS] = [IoApicDevice::empty(); MAX_MADT_IOAPICS];
static IOAPIC_COUNT: AtomicU32 = AtomicU32::new(0);

fn init_ioapics(acpi: &AcpiInfo, hhdm: u64) {
    let mut count = 0usize;
    for i in 0..acpi.ioapic_count {
        let desc = acpi.ioapics[i];
        if desc.address == 0 {
            continue;
        }
        let dev = IoApicDevice {
            virt_base: desc.address + hhdm,
            gsi_base: desc.gsi_base,
            max_redir: 0,
            present: true,
        };
        let ver = unsafe { dev.read_reg(IOAPIC_REG_VER) };
        let _id = unsafe { dev.read_reg(IOAPIC_REG_ID) };
        let max_redir = ((ver >> 16) & 0xFF) + 1;

        let mut dev = dev;
        dev.max_redir = max_redir;

        // Mask all redirection entries initially until Ring 3 drivers bind IRQs.
        for pin in 0..max_redir {
            unsafe {
                dev.write_redir(pin, 1u64 << 16);
            }
        }

        unsafe {
            IOAPICS[count] = dev;
        }
        count += 1;
    }
    IOAPIC_COUNT.store(count as u32, Ordering::Release);
}

pub fn ioapic_count() -> u32 {
    IOAPIC_COUNT.load(Ordering::Acquire)
}

/// Program an I/O APIC redirection entry for a given GSI.
pub fn ioapic_route_gsi(
    gsi: u32,
    vector: u8,
    dest_lapic_id: u8,
    active_low: bool,
    level_triggered: bool,
    masked: bool,
) -> bool {
    let count = ioapic_count() as usize;
    for i in 0..count {
        let dev = unsafe { IOAPICS[i] };
        if dev.present && gsi >= dev.gsi_base && gsi < dev.gsi_base + dev.max_redir {
            let pin = gsi - dev.gsi_base;
            let mut entry = vector as u64;
            if active_low {
                entry |= 1 << 13;
            }
            if level_triggered {
                entry |= 1 << 15;
            }
            if masked {
                entry |= 1 << 16;
            }
            entry |= (dest_lapic_id as u64) << 56;
            unsafe {
                dev.write_redir(pin, entry);
            }
            return true;
        }
    }
    false
}

/// Mask or unmask a specific GSI in the owning I/O APIC.
pub fn ioapic_set_mask(gsi: u32, masked: bool) -> bool {
    let count = ioapic_count() as usize;
    for i in 0..count {
        let dev = unsafe { IOAPICS[i] };
        if dev.present && gsi >= dev.gsi_base && gsi < dev.gsi_base + dev.max_redir {
            let pin = gsi - dev.gsi_base;
            unsafe {
                let mut entry = dev.read_redir(pin);
                if masked {
                    entry |= 1 << 16;
                } else {
                    entry &= !(1 << 16);
                }
                dev.write_redir(pin, entry);
            }
            return true;
        }
    }
    false
}
