//! Kernel Telemetry & Performance Counters
//!
//! Lock-free atomic counters tracking microkernel activity across all CPUs:
//! syscalls, IPC fastpath vs slowpath transfers, capability invocations,
//! page faults, CoW resolutions, TLB shootdowns, context switches, and IRQs.

use core::sync::atomic::{AtomicU64, Ordering};

/// Global atomic telemetry counters for the Margay Microkernel.
pub struct KernelTelemetry {
    pub timer_ticks: AtomicU64,
    pub context_switches: AtomicU64,
    pub syscalls_total: AtomicU64,
    pub ipc_fastpath: AtomicU64,
    pub ipc_slowpath: AtomicU64,
    pub ipc_notifications: AtomicU64,
    pub cap_invocations: AtomicU64,
    pub cap_revocations: AtomicU64,
    pub page_faults: AtomicU64,
    pub cow_faults: AtomicU64,
    pub tlb_shootdowns: AtomicU64,
    pub irqs_routed: AtomicU64,
    pub ipis_sent: AtomicU64,
    pub frames_allocated: AtomicU64,
    pub frames_freed: AtomicU64,
    pub slab_allocs: AtomicU64,
    pub slab_frees: AtomicU64,
}

impl KernelTelemetry {
    pub const fn new() -> Self {
        Self {
            timer_ticks: AtomicU64::new(0),
            context_switches: AtomicU64::new(0),
            syscalls_total: AtomicU64::new(0),
            ipc_fastpath: AtomicU64::new(0),
            ipc_slowpath: AtomicU64::new(0),
            ipc_notifications: AtomicU64::new(0),
            cap_invocations: AtomicU64::new(0),
            cap_revocations: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            cow_faults: AtomicU64::new(0),
            tlb_shootdowns: AtomicU64::new(0),
            irqs_routed: AtomicU64::new(0),
            ipis_sent: AtomicU64::new(0),
            frames_allocated: AtomicU64::new(0),
            frames_freed: AtomicU64::new(0),
            slab_allocs: AtomicU64::new(0),
            slab_frees: AtomicU64::new(0),
        }
    }

    /// Snapshot of all counters for structured telemetry reporting.
    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            timer_ticks: self.timer_ticks.load(Ordering::Relaxed),
            context_switches: self.context_switches.load(Ordering::Relaxed),
            syscalls_total: self.syscalls_total.load(Ordering::Relaxed),
            ipc_fastpath: self.ipc_fastpath.load(Ordering::Relaxed),
            ipc_slowpath: self.ipc_slowpath.load(Ordering::Relaxed),
            ipc_notifications: self.ipc_notifications.load(Ordering::Relaxed),
            cap_invocations: self.cap_invocations.load(Ordering::Relaxed),
            cap_revocations: self.cap_revocations.load(Ordering::Relaxed),
            page_faults: self.page_faults.load(Ordering::Relaxed),
            cow_faults: self.cow_faults.load(Ordering::Relaxed),
            tlb_shootdowns: self.tlb_shootdowns.load(Ordering::Relaxed),
            irqs_routed: self.irqs_routed.load(Ordering::Relaxed),
            ipis_sent: self.ipis_sent.load(Ordering::Relaxed),
            frames_allocated: self.frames_allocated.load(Ordering::Relaxed),
            frames_freed: self.frames_freed.load(Ordering::Relaxed),
            slab_allocs: self.slab_allocs.load(Ordering::Relaxed),
            slab_frees: self.slab_frees.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TelemetrySnapshot {
    pub timer_ticks: u64,
    pub context_switches: u64,
    pub syscalls_total: u64,
    pub ipc_fastpath: u64,
    pub ipc_slowpath: u64,
    pub ipc_notifications: u64,
    pub cap_invocations: u64,
    pub cap_revocations: u64,
    pub page_faults: u64,
    pub cow_faults: u64,
    pub tlb_shootdowns: u64,
    pub irqs_routed: u64,
    pub ipis_sent: u64,
    pub frames_allocated: u64,
    pub frames_freed: u64,
    pub slab_allocs: u64,
    pub slab_frees: u64,
}

/// Global telemetry instance.
pub static TELEMETRY: KernelTelemetry = KernelTelemetry::new();

/// Print a formatted telemetry report to COM1.
pub fn dump_report() {
    let s = TELEMETRY.snapshot();
    crate::serial_println!("================ MARGAY MICROKERNEL TELEMETRY ================");
    crate::serial_println!(
        "  Ticks: {:<10} | Context Switches: {:<10} | Syscalls: {}",
        s.timer_ticks,
        s.context_switches,
        s.syscalls_total
    );
    crate::serial_println!(
        "  IPC Fastpath: {:<6} | IPC Slowpath: {:<8} | Notifications: {}",
        s.ipc_fastpath,
        s.ipc_slowpath,
        s.ipc_notifications
    );
    crate::serial_println!(
        "  Cap Invokes: {:<7} | Cap Revokes: {:<9} | IRQs Routed: {}",
        s.cap_invocations,
        s.cap_revocations,
        s.irqs_routed
    );
    crate::serial_println!(
        "  Page Faults: {:<7} | CoW Faults: {:<10} | TLB Shootdowns: {}",
        s.page_faults,
        s.cow_faults,
        s.tlb_shootdowns
    );
    crate::serial_println!(
        "  Frames Alloc/Free: {}/{} | Slab Alloc/Free: {}/{} | IPIs: {}",
        s.frames_allocated,
        s.frames_freed,
        s.slab_allocs,
        s.slab_frees,
        s.ipis_sent
    );
    crate::serial_println!("==============================================================");
}
