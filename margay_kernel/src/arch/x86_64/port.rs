//! x86_64 I/O Port Access Primitives
//!
//! Provides low-level, zero-overhead wrappers around the `in` and `out`
//! instructions for 8-bit, 16-bit, and 32-bit I/O port transfers, as well
//! as typed `Port<T>` handles used by early kernel hardware controllers
//! (UART 16550, legacy PIC 8259A, PIT 8254 calibration, CMOS/POST delay).

use core::arch::asm;
use core::marker::PhantomData;

/// Read a single byte from an x86 I/O port.
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write a single byte to an x86 I/O port.
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read a 16-bit word from an x86 I/O port.
#[inline(always)]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    asm!(
        "in ax, dx",
        out("ax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write a 16-bit word to an x86 I/O port.
#[inline(always)]
pub unsafe fn outw(port: u16, value: u16) {
    asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read a 32-bit doubleword from an x86 I/O port.
#[inline(always)]
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write a 32-bit doubleword to an x86 I/O port.
#[inline(always)]
pub unsafe fn outl(port: u16, value: u32) {
    asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Short I/O delay (~1-4 microseconds) by writing to the unused POST
/// diagnostic port `0x80`. Required by legacy controllers such as the 8259A PIC.
#[inline(always)]
pub unsafe fn io_wait() {
    outb(0x80, 0x00);
}

/// Trait implemented by primitive widths supported by x86 I/O instructions.
pub trait PortIo: Copy {
    unsafe fn read_port(port: u16) -> Self;
    unsafe fn write_port(port: u16, value: Self);
}

impl PortIo for u8 {
    #[inline(always)]
    unsafe fn read_port(port: u16) -> Self {
        inb(port)
    }

    #[inline(always)]
    unsafe fn write_port(port: u16, value: Self) {
        outb(port, value);
    }
}

impl PortIo for u16 {
    #[inline(always)]
    unsafe fn read_port(port: u16) -> Self {
        inw(port)
    }

    #[inline(always)]
    unsafe fn write_port(port: u16, value: Self) {
        outw(port, value);
    }
}

impl PortIo for u32 {
    #[inline(always)]
    unsafe fn read_port(port: u16) -> Self {
        inl(port)
    }

    #[inline(always)]
    unsafe fn write_port(port: u16, value: Self) {
        outl(port, value);
    }
}

/// Strongly-typed handle to a single x86 I/O port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port<T: PortIo> {
    addr: u16,
    _marker: PhantomData<T>,
}

impl<T: PortIo> Port<T> {
    /// Construct a new port handle at the given 16-bit I/O address.
    #[inline(always)]
    pub const fn new(addr: u16) -> Self {
        Self {
            addr,
            _marker: PhantomData,
        }
    }

    /// Return the underlying 16-bit I/O address.
    #[inline(always)]
    pub const fn addr(&self) -> u16 {
        self.addr
    }

    /// Read a value from this port.
    #[inline(always)]
    pub unsafe fn read(&self) -> T {
        T::read_port(self.addr)
    }

    /// Write a value to this port.
    #[inline(always)]
    pub unsafe fn write(&self, value: T) {
        T::write_port(self.addr, value);
    }
}
