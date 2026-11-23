//! Hardware Interrupt (IRQ), I/O Port & MMIO Delegation for Ring 3 Drivers
//!
//! Because Margay is a pure microkernel with zero in-kernel device drivers,
//! hardware interrupts, I/O ports, and MMIO ranges are safely delegated to
//! isolated Ring 3 servers via Capabilities:
//! - Hardware IRQs bind to IPC `Notification` objects (masked on level trigger
//!   until the Ring 3 driver explicitly acknowledges via `irq_ack`).
//! - I/O port ranges are granted by clearing bits in the process's 8 KiB TSS IOPB.
//! - MMIO frames are mapped uncacheable (`PCD | PWT | NX | USER`).

use core::sync::atomic::Ordering;

use crate::arch::x86_64::acpi::{AcpiInfo, MadtIso, MAX_MADT_ISOS};
use crate::arch::x86_64::apic::{self, IRQ_VECTOR_BASE};
use crate::arch::x86_64::smp;
use crate::arch::x86_64::tss;
use crate::cap::object::NotificationId;
use crate::debug::telemetry::TELEMETRY;
use crate::ipc::notification;
use crate::mm::frame::PAGE_SIZE;
use crate::mm::paging::PageFlags;
use crate::mm::vspace::{VmaKind, VmaRegion};
use crate::mm::{PhysAddr, VirtAddr};
use crate::sched::process::ProcessId;
use crate::sched::sync::IrqSpinlock;

pub const MAX_DELEGATED_IRQS: usize = 32;

#[derive(Clone, Copy)]
struct IrqBinding {
    bound: bool,
    notif_id: NotificationId,
    badge: u64,
    gsi: u32,
    level_triggered: bool,
    masked_pending_ack: bool,
}

impl IrqBinding {
    const fn empty() -> Self {
        Self {
            bound: false,
            notif_id: 0,
            badge: 0,
            gsi: 0,
            level_triggered: false,
            masked_pending_ack: false,
        }
    }
}

struct IsoTable {
    isos: [MadtIso; MAX_MADT_ISOS],
    count: usize,
}

impl IsoTable {
    const fn empty() -> Self {
        Self {
            isos: [MadtIso {
                bus_source: 0,
                irq_source: 0,
                gsi: 0,
                flags: 0,
            }; MAX_MADT_ISOS],
            count: 0,
        }
    }

    fn resolve_isa(&self, isa_irq: u8) -> (u32, bool, bool) {
        for i in 0..self.count {
            if self.isos[i].bus_source == 0 && self.isos[i].irq_source == isa_irq {
                return (
                    self.isos[i].gsi,
                    self.isos[i].active_low(),
                    self.isos[i].level_triggered(),
                );
            }
        }
        (isa_irq as u32, false, false)
    }
}

static IRQ_TABLE: IrqSpinlock<[IrqBinding; MAX_DELEGATED_IRQS]> =
    IrqSpinlock::new([IrqBinding::empty(); MAX_DELEGATED_IRQS]);
static ISO_TABLE: IrqSpinlock<IsoTable> = IrqSpinlock::new(IsoTable::empty());

pub fn init(acpi: &AcpiInfo) {
    {
        let mut t = ISO_TABLE.lock();
        t.isos = acpi.isos;
        t.count = acpi.iso_count;
    }
    crate::kinfo!(
        "IRQ",
        "Ring 3 Hardware Delegation ready ({} GSI slots, {} ACPI ISOs, TSS IOPB, MMIO mapper)",
        MAX_DELEGATED_IRQS,
        acpi.iso_count
    );
}

/// Bind hardware IRQ line `irq_num` (0..31) to an async IPC `Notification`.
/// Automatically resolves legacy ISA IRQs (0..15) through ACPI MADT ISOs
/// (e.g. ISA IRQ 0 PIT -> GSI 2 on QEMU/PC).
pub fn bind_irq_to_notification(
    irq_num: u8,
    notif_id: NotificationId,
    badge: u64,
    active_low: bool,
    level_triggered: bool,
) -> bool {
    let idx = irq_num as usize;
    if idx >= MAX_DELEGATED_IRQS {
        return false;
    }

    let (gsi, iso_low, iso_level) = if irq_num < 16 {
        ISO_TABLE.lock().resolve_isa(irq_num)
    } else {
        (irq_num as u32, active_low, level_triggered)
    };
    let eff_low = active_low || iso_low;
    let eff_level = level_triggered || iso_level;

    let vector = IRQ_VECTOR_BASE + irq_num;
    let dest_lapic = apic::lapic_id() as u8;

    {
        let mut table = IRQ_TABLE.lock();
        table[idx] = IrqBinding {
            bound: true,
            notif_id,
            badge: if badge == 0 { 1u64 << (irq_num & 63) } else { badge },
            gsi,
            level_triggered: eff_level,
            masked_pending_ack: false,
        };
    }

    // Program I/O APIC redirection entry and unmask the GSI
    apic::ioapic_route_gsi(gsi, vector, dest_lapic, eff_low, eff_level, false)
}

/// Acknowledge a handled hardware IRQ from a Ring 3 driver, unmasking its GSI.
pub fn ack_irq(irq_num: u8) -> bool {
    let idx = irq_num as usize;
    if idx >= MAX_DELEGATED_IRQS {
        return false;
    }
    let gsi = {
        let mut table = IRQ_TABLE.lock();
        if !table[idx].bound {
            return false;
        }
        table[idx].masked_pending_ack = false;
        table[idx].gsi
    };
    apic::ioapic_set_mask(gsi, false)
}

/// Fast-path hardware IRQ dispatcher invoked from `idt.rs`.
/// Signals the bound Ring 3 `Notification` without blocking.
pub fn dispatch_hardware_irq(irq_num: u8) {
    let idx = irq_num as usize;
    if idx >= MAX_DELEGATED_IRQS {
        return;
    }

    let action = {
        let mut table = IRQ_TABLE.lock();
        let entry = &mut table[idx];
        if !entry.bound {
            None
        } else {
            if entry.level_triggered {
                entry.masked_pending_ack = true;
            }
            Some((entry.notif_id, entry.badge, entry.gsi, entry.level_triggered))
        }
    };

    if let Some((notif_id, badge, gsi, level_triggered)) = action {
        if level_triggered {
            apic::ioapic_set_mask(gsi, true);
        }
        let _ = notification::signal(notif_id, badge);
        TELEMETRY.irqs_routed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Grant Ring 3 hardware access to I/O port range `[start..=end]` for `pid`.
pub fn grant_ioport_range(pid: ProcessId, start: u16, end: u16) -> bool {
    let ok = crate::sched::with_process_mut(pid, |proc| {
        proc.allow_io_range(start, end);
    })
    .is_some();

    if ok && crate::sched::current_pid() == pid {
        let cpu_id = smp::current_cpu_id();
        unsafe {
            tss::tss_mut(cpu_id).allow_io_range(start, end);
        }
    }
    ok
}

/// Map a physical MMIO device range into a Ring 3 driver's VSpace with strict
/// uncacheable + no-execute permissions (`PageFlags::user_mmio()`).
pub fn map_mmio_for_process(
    pid: ProcessId,
    phys_base: u64,
    virt_base: u64,
    num_pages: usize,
) -> bool {
    if num_pages == 0 || num_pages > 8192 {
        return false;
    }
    if (phys_base & (PAGE_SIZE as u64 - 1)) != 0 || (virt_base & (PAGE_SIZE as u64 - 1)) != 0 {
        return false;
    }

    crate::sched::with_process_mut(pid, |proc| {
        let flags = PageFlags::user_mmio();
        let length = (num_pages * PAGE_SIZE) as u64;
        if proc
            .vspace
            .register_vma(VmaRegion {
                start: virt_base,
                length,
                flags,
                kind: VmaKind::MmioDevice,
            })
            .is_err()
        {
            return false;
        }
        for i in 0..num_pages {
            let va = VirtAddr::new(virt_base + (i * PAGE_SIZE) as u64);
            let pa = PhysAddr::new(phys_base + (i * PAGE_SIZE) as u64);
            if proc.vspace.map_page(va, pa, flags).is_err() {
                return false;
            }
        }
        true
    })
    .unwrap_or(false)
}
