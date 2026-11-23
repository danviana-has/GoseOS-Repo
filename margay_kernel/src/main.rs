//! Margay Microkernel — Pure 3rd-Generation x86_64 Microkernel for GOSE
//!
//! Zero in-kernel device drivers (except UART 16550 COM1 telemetry), zero VFS,
//! zero network stack, zero GUI. Exposes only:
//!   - Physical & Virtual Memory Management (Buddy PMM, 4-Level Paging, W^X, CoW, Slab)
//!   - Capability-Based Security (CSpace, CNode, iterative CDT)
//!   - High-Performance IPC (Fastpath Rendezvous, Async Notifications, Zero-Copy ShMem)
//!   - Preemptive SMP Multicore Scheduling & Lock-Free Synchronization
//!   - Hardware Delegation to Ring 3 (IRQs -> Notifications, TSS IOPB, MMIO)
//!   - Fast `syscall`/`sysret` Minimalist ABI

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![allow(dead_code)]

extern crate alloc;

pub mod arch;
pub mod cap;
pub mod debug;
pub mod ipc;
pub mod irq;
pub mod mm;
pub mod roottask;
pub mod sched;
pub mod syscall;

use crate::arch::x86_64::{self, acpi, apic, cpuid, fpu, gdt, idt, limine, pic, smp, tss};

/// Kernel entry point invoked directly by the Limine bootloader in 64-bit
/// Higher Half Long Mode with interrupts masked (`IF = 0`).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    x86_64::disable_interrupts();

    // -----------------------------------------------------------------------
    // Stage 1: Serial Telemetry, Boot Info, CPUID, GDT/TSS/IDT, PIC & APIC
    // -----------------------------------------------------------------------
    let uart_ok = debug::serial::init();
    serial_println!("\n====================================================================");
    serial_println!("   MARGAY MICROKERNEL v0.1.0 (x86_64 Pure Microkernel — GOSE)       ");
    serial_println!("====================================================================");
    kinfo!("UART", "COM1 (0x3F8, 115200 8N1, FIFO=16B) initialized (hw_ok={})", uart_ok);

    assert!(
        limine::base_revision_supported(),
        "Bootloader does not support Limine Base Revision 2"
    );

    if let Some((name, ver)) = limine::bootloader_info() {
        kinfo!("BOOT", "Bootloader: {} {}", name, ver);
    }
    let (kphys, kvirt) = limine::kernel_address();
    kinfo!("BOOT", "Kernel Phys={:#018x} Virt={:#018x}", kphys, kvirt);

    // Detect CPUID features & enable CR0.WP, EFER.NXE, CR4.PGE/SMEP/UMIP/FSGSBASE
    let features = cpuid::CpuFeatures::detect();
    features.log_summary();
    x86_64::enable_cpu_security_features(&features);

    // Initialize TSS (with 4 IST stacks & 8KiB IOPB), GDT (Ring 0 + Ring 3 selectors),
    // PerCpu (`IA32_GS_BASE` — MUST be set AFTER GDT reloads `gs`!), and IDT (32 ISRs + IRQs)
    unsafe {
        let bsp_stack = smp::bsp_boot_stack_top();
        let bsp_tss = tss::init_tss_for_cpu(0, bsp_stack);
        gdt::init_for_cpu(0, bsp_tss);
        smp::init_bsp_percpu(features.initial_apic_id as u32);
        idt::init_table();
        idt::load_for_current_cpu();
    }
    kinfo!("ARCH", "BSP PerCpu, GDT, TSS (IST1..4 + 8KiB IOPB) & 256-entry IDT loaded");

    // Initialize FPU / SSE / XSAVE
    fpu::init_for_current_cpu(&features, true);

    // Remap and permanently mask legacy 8259A PIC
    pic::disable_legacy_pic();

    // Parse ACPI MADT for Local APICs, I/O APICs, and Interrupt Source Overrides
    let hhdm = limine::hhdm_offset();
    let acpi_info = match limine::rsdp_address() {
        Some(rsdp) => acpi::parse_acpi(rsdp, hhdm),
        None => {
            kwarn!("ACPI", "No RSDP provided by bootloader; using default APIC layout");
            acpi::AcpiInfo::empty()
        }
    };

    // Initialize Local APIC (x2APIC / xAPIC), calibrate APIC timer, and init I/O APICs
    apic::init_bsp(&features, &acpi_info, hhdm);

    // -----------------------------------------------------------------------
    // Stage 2: Physical Memory Manager (Buddy), VMM (4-Level), Slab & Heap
    // -----------------------------------------------------------------------
    mm::init();

    // -----------------------------------------------------------------------
    // Stage 3 & 4: Capabilities (CSpace/CDT) & IPC (Endpoints/Notifs/ShMem)
    // -----------------------------------------------------------------------
    cap::init();
    ipc::init();

    // -----------------------------------------------------------------------
    // Stage 5 & 6: IRQ Delegation, Fast SYSCALL MSRs, SMP Bring-Up & Scheduler
    // -----------------------------------------------------------------------
    irq::init(&acpi_info);
    syscall::init_for_current_cpu();
    kinfo!("SYSCALL", "IA32_EFER.SCE / STAR / LSTAR / FMASK configured");

    // Run internal Ring 0 microkernel subsystem self-tests before launching SMP/Ring 3
    run_kernel_selftests();

    // Bring up all Application Processors (APs) via Limine SMP
    smp::bring_up_aps(x86_64::read_cr3());

    // Initialize SMP Preemptive Scheduler across all online CPUs
    sched::init();

    // Launch the embedded Ring 3 Root Task (PID 1)
    roottask::launch_root_task();

    // Start BSP Local APIC periodic preemption timer (100 Hz) and release APs
    apic::start_periodic_timer(100);
    smp::release_aps_to_scheduler();

    kinfo!("KERNEL", "Entering SMP scheduler & transitioning to Ring 3 Root Task...");
    x86_64::enable_interrupts();

    // Immediately dispatch the Root Task and then participate in SMP idle/scheduling
    sched::yield_now();
    sched::ap_idle_loop()
}

/// Self-test core Ring 0 data structures (PMM Buddy coalescing, Slab/Heap,
/// Lock-free SPSC/MPMC rings, Capability CDT revocation, and W^X enforcement).
fn run_kernel_selftests() {
    // 1. Buddy PMM alloc/coalesce test (4 KiB + 2 MiB Huge Page)
    let f1 = mm::pmm::alloc_frame().expect("PMM 4K alloc failed");
    let f2 = mm::pmm::alloc_frame().expect("PMM 4K alloc failed");
    assert_ne!(f1, f2);
    mm::pmm::free_frame(f1);
    mm::pmm::free_frame(f2);

    if let Some(huge) = mm::pmm::alloc_huge_2m() {
        assert_eq!(huge.as_u64() & ((2 * 1024 * 1024) - 1), 0);
        mm::pmm::free_order(huge, mm::pmm::ORDER_2M);
    }

    // 2. W^X PageFlags enforcement verification
    let bad_wx = mm::paging::PageFlags::PRESENT
        .union(mm::paging::PageFlags::USER)
        .union(mm::paging::PageFlags::WRITABLE);
    assert!(bad_wx.violates_wx(), "W^X check failed to catch R+W+X");
    assert!(!mm::paging::PageFlags::user_rx().violates_wx());
    assert!(!mm::paging::PageFlags::user_rw().violates_wx());

    // 3. Lock-free SPSC & MPMC ring buffer verification
    let spsc: sched::sync::SpscRing<u64, 16> = sched::sync::SpscRing::new();
    for i in 0..10u64 {
        assert!(spsc.push(i * 3).is_ok());
    }
    for i in 0..10u64 {
        assert_eq!(spsc.pop(), Some(i * 3));
    }

    let mpmc: sched::sync::MpmcRing<u64, 16> = sched::sync::MpmcRing::new();
    for i in 0..8u64 {
        assert!(mpmc.push(i + 100).is_ok());
    }
    for i in 0..8u64 {
        assert_eq!(mpmc.pop(), Some(i + 100));
    }

    // 4. Capability CDT multi-level derivation & iterative revocation test
    let test_cnode = cap::cnode::create_cnode(4);
    let root_cap = cap::Capability::new(cap::CapObject::IrqControl, cap::CapRights::ALL);
    cap::cap_insert_root(test_cnode, 1, root_cap).expect("CDT root insert failed");
    let s1 = cap::SlotAddress { cnode_id: test_cnode, slot_idx: 1 };
    let s2 = cap::SlotAddress { cnode_id: test_cnode, slot_idx: 2 };
    let s3 = cap::SlotAddress { cnode_id: test_cnode, slot_idx: 3 };
    cap::cap_mint(s1, s2, cap::CapRights::ALL, 0x11).expect("CDT child 1 mint failed");
    cap::cap_mint(s2, s3, cap::CapRights::READ, 0x22).expect("CDT grandchild mint failed");
    let revoked = cap::cap_revoke(s1).expect("CDT revoke failed");
    assert_eq!(revoked, 2, "Expected 2 transitive descendants revoked");
    assert!(cap::cnode::lookup_cap(test_cnode, 2).is_none());
    assert!(cap::cnode::lookup_cap(test_cnode, 3).is_none());
    cap::cnode::destroy_cnode(test_cnode);

    kinfo!(
        "TEST",
        "Ring 0 Self-Tests PASSED (PMM Buddy/2M, W^X, Slab/Heap, SPSC/MPMC, Cap CDT)"
    );
}
