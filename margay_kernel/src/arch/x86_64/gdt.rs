//! Per-CPU Global Descriptor Table (GDT) for Ring 0 and Ring 3
//!
//! Segment selector layout is strictly aligned with `IA32_STAR` for `syscall`/`sysret`:
//!   - `0x00`: Null Descriptor
//!   - `0x08`: Kernel Code (Ring 0, 64-bit, Execute/Read)
//!   - `0x10`: Kernel Data (Ring 0, Read/Write)
//!   - `0x18`: User Data   (Ring 3, Read/Write)  -> selector `0x1B` (STAR[63:48] + 8)
//!   - `0x20`: User Code   (Ring 3, 64-bit, RX)  -> selector `0x23` (STAR[63:48] + 16)
//!   - `0x28`: 64-bit TSS Descriptor (16 bytes, occupies slots 5 and 6)

use core::arch::asm;
use core::mem::size_of;

use crate::arch::x86_64::tss::{TaskStateSegment, MAX_CPUS};

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18 | 3; // 0x1B
pub const USER_CS: u16 = 0x20 | 3; // 0x23
pub const TSS_SEL: u16 = 0x28;

/// Value programmed into `IA32_STAR`:
/// - bits 47:32 = Kernel CS (`0x08`) -> `syscall` loads CS=0x08, SS=0x10
/// - bits 63:48 = `0x13` (`0x10 | 3`) -> `sysretq` loads SS=0x1B, CS=0x23
pub const IA32_STAR_VALUE: u64 = ((0x13u64) << 48) | ((KERNEL_CS as u64) << 32);

#[repr(C, align(16))]
struct GdtTable {
    entries: [u64; 7],
}

impl GdtTable {
    const fn new() -> Self {
        Self {
            entries: [
                0x0000_0000_0000_0000, // 0x00: Null
                0x00AF_9A00_0000_FFFF, // 0x08: Kernel Code 64-bit (P=1, DPL=0, S=1, Type=0xA, L=1)
                0x00CF_9200_0000_FFFF, // 0x10: Kernel Data        (P=1, DPL=0, S=1, Type=0x2)
                0x00CF_F200_0000_FFFF, // 0x18: User Data          (P=1, DPL=3, S=1, Type=0x2)
                0x00AF_FA00_0000_FFFF, // 0x20: User Code 64-bit   (P=1, DPL=3, S=1, Type=0xA, L=1)
                0x0000_0000_0000_0000, // 0x28: TSS low
                0x0000_0000_0000_0000, // 0x30: TSS high
            ],
        }
    }

    fn set_tss(&mut self, tss_ptr: *const TaskStateSegment) {
        let base = tss_ptr as u64;
        let limit = (size_of::<TaskStateSegment>() - 1) as u64;

        let low = (limit & 0xFFFF)
            | ((base & 0x00FF_FFFF) << 16)
            | (0x89u64 << 40) // Present=1, DPL=0, Type=0x9 (64-bit Available TSS)
            | (((limit >> 16) & 0x0F) << 48)
            | (((base >> 24) & 0xFF) << 56);

        let high = base >> 32;

        self.entries[5] = low;
        self.entries[6] = high;
    }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static mut CPU_GDTS: [GdtTable; MAX_CPUS] = [const { GdtTable::new() }; MAX_CPUS];

/// Initialize and load the GDT and TSS for `cpu_id`.
pub unsafe fn init_for_cpu(cpu_id: usize, tss_ptr: *const TaskStateSegment) {
    assert!(cpu_id < MAX_CPUS);
    let gdt = &mut CPU_GDTS[cpu_id];
    gdt.set_tss(tss_ptr);

    let gdtr = DescriptorTablePointer {
        limit: (size_of::<GdtTable>() - 1) as u16,
        base: gdt as *const GdtTable as u64,
    };

    // Load GDTR, reload CS via far return (`retfq`), reload data segments, and load TR.
    asm!(
        "lgdt [{gdtr}]",
        "push {kcs}",
        "lea rax, [rip + 2f]",
        "push rax",
        "retfq",
        "2:",
        "mov ds, {kds:x}",
        "mov es, {kds:x}",
        "mov fs, {kds:x}",
        "mov gs, {kds:x}",
        "mov ss, {kds:x}",
        "ltr {tss:x}",
        gdtr = in(reg) &gdtr,
        kcs = const KERNEL_CS as u64,
        kds = in(reg) KERNEL_DS as u64,
        tss = in(reg) TSS_SEL as u64,
        out("rax") _,
        options(preserves_flags)
    );
}
