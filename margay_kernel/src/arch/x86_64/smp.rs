//! SMP (Symmetric Multiprocessing) & Per-CPU Control Block (`PerCpu`)
//!
//! Each CPU core owns a dedicated `PerCpu` structure anchored to `IA32_GS_BASE`
//! in Ring 0 (and exchanged with user GS via `swapgs` on Ring 3 transitions).
//! Application Processors (APs) are brought online via Limine SMP, initialize
//! their own GDT, TSS, IDT, FPU, Local APIC, SYSCALL MSRs, and enter the
//! per-CPU SMP scheduler idle loop.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::apic;
use crate::arch::x86_64::cpuid::CpuFeatures;
use crate::arch::x86_64::fpu;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::idt;
use crate::arch::x86_64::limine::{self, LimineSmpInfo};
use crate::arch::x86_64::msr::{self, IA32_GS_BASE, IA32_KERNEL_GS_BASE};
use crate::arch::x86_64::tss::{self, MAX_CPUS};

pub const KERNEL_STACK_SIZE: usize = 32 * 1024;

/// Per-CPU state anchored at `IA32_GS_BASE` while executing in Ring 0.
///
/// IMPORTANT: Offsets 0, 8, and 16 are accessed directly by `margay_syscall_entry`
/// in assembly (`gs:[8]` = `kernel_rsp`, `gs:[16]` = `user_rsp_scratch`).
#[repr(C, align(64))]
pub struct PerCpu {
    /// Offset 0: Self-pointer for fast `mov rax, gs:[0]`.
    pub self_ptr: u64,
    /// Offset 8: Current thread's Ring 0 kernel stack top (loaded on `syscall`).
    pub kernel_rsp: u64,
    /// Offset 16: Scratch slot holding user RSP during `syscall` entry.
    pub user_rsp_scratch: u64,
    /// Offset 24: Logical CPU index (0 = BSP, 1..N = APs).
    pub cpu_id: u32,
    /// Offset 28: Hardware Local APIC ID.
    pub lapic_id: u32,
    /// Offset 32: Currently executing ThreadId (0 = idle).
    pub current_tid: AtomicU64,
    /// Offset 40: Currently active ProcessId.
    pub current_pid: AtomicU64,
    /// Offset 48: True once this CPU has completed early init.
    pub online: AtomicBool,
    /// Offset 56: Local timer tick counter for this CPU.
    pub local_ticks: AtomicU64,
}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            self_ptr: 0,
            kernel_rsp: 0,
            user_rsp_scratch: 0,
            cpu_id: 0,
            lapic_id: 0,
            current_tid: AtomicU64::new(0),
            current_pid: AtomicU64::new(0),
            online: AtomicBool::new(false),
            local_ticks: AtomicU64::new(0),
        }
    }
}

#[repr(C, align(16))]
struct CpuKernelStack([u8; KERNEL_STACK_SIZE]);

impl CpuKernelStack {
    const fn new() -> Self {
        Self([0; KERNEL_STACK_SIZE])
    }

    fn top(&self) -> u64 {
        (self.0.as_ptr() as u64 + KERNEL_STACK_SIZE as u64) & !0xF
    }
}

static mut PER_CPU: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];
static mut BOOT_STACKS: [CpuKernelStack; MAX_CPUS] = [const { CpuKernelStack::new() }; MAX_CPUS];
static ONLINE_CPU_COUNT: AtomicU32 = AtomicU32::new(1);
static TOTAL_CPU_COUNT: AtomicU32 = AtomicU32::new(1);
static AP_SCHED_GO: AtomicBool = AtomicBool::new(false);
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

/// Return the top of the BSP boot kernel stack.
pub unsafe fn bsp_boot_stack_top() -> u64 {
    BOOT_STACKS[0].top()
}

/// Initialize `PerCpu[0]` and anchor `IA32_GS_BASE` on the BSP.
/// MUST be called AFTER `gdt::init_for_cpu` because `mov gs, ax` zeroes `IA32_GS_BASE`.
pub unsafe fn init_bsp_percpu(bsp_lapic_id: u32) -> u64 {
    let stack_top = BOOT_STACKS[0].top();
    let p = &mut PER_CPU[0];
    p.self_ptr = p as *const PerCpu as u64;
    p.kernel_rsp = stack_top;
    p.user_rsp_scratch = 0;
    p.cpu_id = 0;
    p.lapic_id = bsp_lapic_id;
    p.online.store(true, Ordering::Release);

    msr::wrmsr(IA32_GS_BASE, p.self_ptr);
    msr::wrmsr(IA32_KERNEL_GS_BASE, 0);
    stack_top
}

/// Access the current CPU's `PerCpu` structure via `gs:[0]`.
#[inline]
pub fn current_cpu() -> &'static mut PerCpu {
    let ptr: u64;
    unsafe {
        asm!("mov {}, gs:[0]", out(reg) ptr, options(nomem, nostack, preserves_flags));
        &mut *(ptr as *mut PerCpu)
    }
}

/// Logical ID of the current CPU (0..MAX_CPUS).
#[inline]
pub fn current_cpu_id() -> usize {
    current_cpu().cpu_id as usize
}

/// Update both `PerCpu.kernel_rsp` (for `syscall`) and `TSS.rsp0` (for interrupts)
/// when switching to a thread with kernel stack top `rsp0`.
#[inline]
pub fn set_kernel_stack(rsp0: u64) {
    let cpu = current_cpu();
    cpu.kernel_rsp = rsp0;
    unsafe {
        tss::tss_mut(cpu.cpu_id as usize).set_rsp0(rsp0);
    }
}

/// Access `PerCpu` by logical CPU ID.
pub fn cpu_by_id(cpu_id: usize) -> Option<&'static PerCpu> {
    if cpu_id < total_cpus() as usize && cpu_id < MAX_CPUS {
        Some(unsafe { &PER_CPU[cpu_id] })
    } else {
        None
    }
}

#[inline]
pub fn online_cpus() -> u32 {
    ONLINE_CPU_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn total_cpus() -> u32 {
    TOTAL_CPU_COUNT.load(Ordering::Acquire)
}

/// Boot all Application Processors (APs) listed by Limine's SMP response.
pub fn bring_up_aps(kernel_cr3: u64) {
    KERNEL_CR3.store(kernel_cr3, Ordering::Release);

    let Some(smp) = limine::smp_response() else {
        crate::kinfo!("SMP", "No Limine SMP response; running uniprocessor (1 CPU)");
        return;
    };

    let bsp_lapic = smp.bsp_lapic_id;
    let count = (smp.cpu_count as usize).min(MAX_CPUS);
    TOTAL_CPU_COUNT.store(count as u32, Ordering::Release);

    if count <= 1 {
        crate::kinfo!("SMP", "Single-core system detected (BSP LAPIC={})", bsp_lapic);
        return;
    }

    let cpus = unsafe { core::slice::from_raw_parts(smp.cpus, count) };
    let mut logical_id = 1usize;

    for &info_ptr in cpus {
        if info_ptr.is_null() {
            continue;
        }
        let info = unsafe { &mut *info_ptr };
        if info.lapic_id == bsp_lapic {
            continue;
        }
        if logical_id >= MAX_CPUS {
            break;
        }

        info.extra_argument.store(logical_id as u64, Ordering::Release);
        info.goto_address
            .store(ap_entry as *const () as u64, Ordering::Release);
        logical_id += 1;
    }

    // Wait up to a bounded spin for all APs to report online
    let expected = logical_id as u32;
    let mut spins = 0u64;
    while ONLINE_CPU_COUNT.load(Ordering::Acquire) < expected && spins < 50_000_000 {
        core::hint::spin_loop();
        spins += 1;
    }

    crate::kinfo!(
        "SMP",
        "Brought online {}/{} CPUs (BSP LAPIC={})",
        ONLINE_CPU_COUNT.load(Ordering::Acquire),
        expected,
        bsp_lapic
    );
}

/// Signal all online APs to start their Local APIC timer and enter the SMP scheduler.
pub fn release_aps_to_scheduler() {
    AP_SCHED_GO.store(true, Ordering::Release);
}

/// Entry point executed by each Application Processor (AP) woken by Limine.
unsafe extern "C" fn ap_entry(info: *const LimineSmpInfo) -> ! {
    asm!("cli", options(nomem, nostack));

    let cpu_id = (*info).extra_argument.load(Ordering::Acquire) as usize;
    let lapic_id = (*info).lapic_id;

    // Load the kernel's unified higher-half CR3
    let cr3 = KERNEL_CR3.load(Ordering::Acquire);
    if cr3 != 0 {
        crate::arch::x86_64::write_cr3(cr3);
    }

    // Initialize per-CPU TSS, GDT, shared IDT FIRST (because `mov gs, ax` zeroes IA32_GS_BASE)
    let stack_top = BOOT_STACKS[cpu_id].top();
    let tss_ptr = tss::init_tss_for_cpu(cpu_id, stack_top);
    gdt::init_for_cpu(cpu_id, tss_ptr);
    idt::load_for_current_cpu();

    // Now initialize PerCpu and anchor IA32_GS_BASE
    let p = &mut PER_CPU[cpu_id];
    p.self_ptr = p as *const PerCpu as u64;
    p.kernel_rsp = stack_top;
    p.user_rsp_scratch = 0;
    p.cpu_id = cpu_id as u32;
    p.lapic_id = lapic_id;

    msr::wrmsr(IA32_GS_BASE, p.self_ptr);
    msr::wrmsr(IA32_KERNEL_GS_BASE, 0);

    let features = CpuFeatures::detect();
    crate::arch::x86_64::enable_cpu_security_features(&features);
    fpu::init_for_current_cpu(&features, false);
    crate::syscall::init_for_current_cpu();
    apic::init_ap();

    p.online.store(true, Ordering::Release);
    ONLINE_CPU_COUNT.fetch_add(1, Ordering::AcqRel);

    // Wait until BSP finishes initializing global subsystems & scheduler
    while !AP_SCHED_GO.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Start local preemption timer (100 Hz) and enter AP idle/scheduler loop
    apic::start_periodic_timer(100);
    asm!("sti", options(nomem, nostack));

    crate::sched::ap_idle_loop()
}
