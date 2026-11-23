//! Legacy 8259A Programmable Interrupt Controller (PIC) Disabler
//!
//! Remaps the dual 8259A PICs away from CPU exception vectors (0x00..0x1F)
//! to vectors 0x20..0x2F and permanently masks all 16 legacy IRQ lines so
//! the Local APIC and I/O APIC own all interrupt routing cleanly.

use crate::arch::x86_64::port::{io_wait, outb};

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

/// Remap both 8259A PICs to vectors 0x20..0x2F and mask every line.
pub fn disable_legacy_pic() {
    unsafe {
        // Start initialization sequence in cascade mode
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: Vector offsets (Master = 0x20, Slave = 0x28)
        outb(PIC1_DATA, 0x20);
        io_wait();
        outb(PIC2_DATA, 0x28);
        io_wait();

        // ICW3: Master has slave at IRQ2 (bit 2); Slave cascade identity = 2
        outb(PIC1_DATA, 0x04);
        io_wait();
        outb(PIC2_DATA, 0x02);
        io_wait();

        // ICW4: 8086/88 mode
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask all interrupts on both PICs (0xFF = all masked)
        outb(PIC1_DATA, 0xFF);
        io_wait();
        outb(PIC2_DATA, 0xFF);
        io_wait();
    }
    crate::kinfo!("PIC", "Legacy 8259A PIC remapped (0x20..0x2F) and fully masked");
}
