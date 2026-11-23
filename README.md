# Margay Microkernel (GOSE)

**Margay** is a pure, third-generation **x86_64 microkernel** written 100% from scratch in `#![no_std]` Rust (`nightly`, target `x86_64-unknown-none`) with zero external crate dependencies. It forms the isolated core of **GOSE (Guilherme's Operating System Ecosystem)**.

## Pure Microkernel Architecture

Margay contains **no** in-kernel filesystem, network stack, USB stack, graphical framebuffer, or input drivers. Only UART 16550 (`COM1`, `0x3F8`) is compiled in for kernel telemetry and diagnostics. All device drivers and OS services run in isolated Ring 3 user-space servers controlled by unforgeable **Capabilities**.

```text
/
├── margay_kernel/
│   ├── .cargo/config.toml       # x86_64-unknown-none, build-std, kernel code-model
│   ├── Cargo.toml               # Zero external dependencies
│   ├── linker.ld                # Higher-Half (0xffffffff80000000) W^X PHDRs
│   └── src/
│       ├── arch/x86_64/         # Limine, ACPI/MADT, GDT, TSS+IST+IOPB, IDT, APIC/x2APIC, IOAPIC, SMP, FPU/XSAVE, Context Switch
│       ├── mm/                  # Buddy PMM + PageFrame refcounting, 4-Level VMM (W^X, CoW, TLB Shootdown), Slab & Heap
│       ├── cap/                 # CSpace, CNode, CapRights, iterative CDT Derivation/Revocation
│       ├── ipc/                 # Fastpath Rendezvous Endpoints, Async Notifications, Zero-Copy Shared Memory
│       ├── sched/               # Process/Thread TCB, SMP 32-level Priority Scheduler, IrqSpinlock/Ticket/Rw/SeqLock, SPSC/MPMC
│       ├── irq/                 # Hardware IRQ -> Notification routing, TSS IOPB, MMIO mapping
│       ├── syscall/             # Fast syscall/sysret MSRs & typed ABI dispatcher
│       ├── debug/               # UART 16550 (COM1), Stack Unwinder, Telemetry, Nested-Panic Guard
│       ├── roottask.rs          # Embedded Ring 3 Root Task boot self-test
│       └── main.rs              # Kernel entry point & subsystem bootstrap
└── build/
    ├── limine.conf
    ├── build.sh / build.ps1
    └── Makefile
```

## Building & Running in QEMU

### Windows (PowerShell)
```powershell
.\build\build.ps1
& "C:\Program Files\qemu\qemu-system-x86_64.exe" -cdrom build\margay_microkernel.iso -m 256M -smp 4 -cpu qemu64,+x2apic -nographic -serial mon:stdio -no-reboot
```

### Linux / macOS
```bash
./build/build.sh
qemu-system-x86_64 -cdrom build/margay_microkernel.iso -m 256M -smp 4 -cpu qemu64,+x2apic -nographic -serial mon:stdio -no-reboot
```
