//! UART 16550 Serial Telemetry Driver (COM1 / COM2)
//!
//! The Margay Microkernel contains no graphical framebuffer or console
//! subsystem. All kernel diagnostics, boot telemetry, exception dumps,
//! and Ring 3 debug output (`sys_debug_print`) flow through the 16550 UART.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::port::{inb, outb};

/// Standard PC COM1 base I/O port.
pub const COM1_PORT: u16 = 0x3F8;
/// Standard PC COM2 base I/O port.
pub const COM2_PORT: u16 = 0x2F8;

// 16550 Register Offsets
const REG_DATA: u16 = 0;       // RBR (read) / THR (write) when DLAB=0
const REG_DIV_LO: u16 = 0;     // Divisor Latch Low when DLAB=1
const REG_IER: u16 = 1;        // Interrupt Enable Register when DLAB=0
const REG_DIV_HI: u16 = 1;     // Divisor Latch High when DLAB=1
const REG_IIR_FCR: u16 = 2;    // Interrupt ID (read) / FIFO Control (write)
const REG_LCR: u16 = 3;        // Line Control Register
const REG_MCR: u16 = 4;        // Modem Control Register
const REG_LSR: u16 = 5;        // Line Status Register
const REG_MSR: u16 = 6;        // Modem Status Register
const REG_SCRATCH: u16 = 7;    // Scratch Register

// LCR flags
const LCR_8N1: u8 = 0x03;      // 8 data bits, no parity, 1 stop bit
const LCR_DLAB: u8 = 0x80;     // Divisor Latch Access Bit

// FCR flags
const FCR_ENABLE_FIFO: u8 = 0x01;
const FCR_CLEAR_RX: u8 = 0x02;
const FCR_CLEAR_TX: u8 = 0x04;
const FCR_TRIGGER_14: u8 = 0xC0;

// MCR flags
const MCR_DTR: u8 = 0x01;
const MCR_RTS: u8 = 0x02;
const MCR_OUT1: u8 = 0x04;
const MCR_OUT2: u8 = 0x08;     // Enables IRQ line routing on PC UARTs
const MCR_LOOPBACK: u8 = 0x10;

// LSR flags
const LSR_DATA_READY: u8 = 0x01;
const LSR_TX_HOLDING_EMPTY: u8 = 0x20;
const LSR_TX_EMPTY: u8 = 0x40;

/// Baud rate divisors for the standard 115200 Hz UART base clock.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    B115200 = 1,
    B57600 = 2,
    B38400 = 3,
    B19200 = 6,
    B9600 = 12,
}

/// Low-level 16550 UART controller handle.
pub struct Uart16550 {
    base: u16,
    initialized: bool,
    bytes_tx: u64,
}

impl Uart16550 {
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            initialized: false,
            bytes_tx: 0,
        }
    }

    /// Initialize the 16550 UART with the given baud rate, 8N1 framing,
    /// 16-byte FIFO enabled, and loopback self-test verification.
    pub fn init(&mut self, baud: BaudRate) -> bool {
        unsafe {
            // 1. Disable all UART interrupts
            outb(self.base + REG_IER, 0x00);

            // 2. Enable DLAB to set baud rate divisor
            outb(self.base + REG_LCR, LCR_DLAB);
            let divisor = baud as u16;
            outb(self.base + REG_DIV_LO, (divisor & 0xFF) as u8);
            outb(self.base + REG_DIV_HI, ((divisor >> 8) & 0xFF) as u8);

            // 3. Configure 8N1 and clear DLAB
            outb(self.base + REG_LCR, LCR_8N1);

            // 4. Enable FIFO, clear RX/TX queues, 14-byte trigger threshold
            outb(
                self.base + REG_IIR_FCR,
                FCR_ENABLE_FIFO | FCR_CLEAR_RX | FCR_CLEAR_TX | FCR_TRIGGER_14,
            );

            // 5. Perform loopback self-test to verify hardware presence
            outb(
                self.base + REG_MCR,
                MCR_RTS | MCR_OUT1 | MCR_OUT2 | MCR_LOOPBACK,
            );
            outb(self.base + REG_DATA, 0xAE);

            // Wait briefly for loopback byte
            let mut spins = 0u32;
            while (inb(self.base + REG_LSR) & LSR_DATA_READY) == 0 && spins < 10_000 {
                core::hint::spin_loop();
                spins += 1;
            }

            let loopback_ok = inb(self.base + REG_DATA) == 0xAE;

            // 6. Switch to normal operation mode (DTR + RTS + OUT1 + OUT2)
            outb(self.base + REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT1 | MCR_OUT2);

            // Scratch register probe as fallback on virtualized UARTs
            outb(self.base + REG_SCRATCH, 0x5A);
            let scratch_ok = inb(self.base + REG_SCRATCH) == 0x5A;

            self.initialized = loopback_ok || scratch_ok;
            self.initialized
        }
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    #[inline]
    pub fn bytes_transmitted(&self) -> u64 {
        self.bytes_tx
    }

    /// Wait until the Transmit Holding Register is empty (with bounded timeout
    /// so missing hardware can never deadlock the kernel).
    #[inline]
    fn wait_tx_ready(&self) {
        let mut timeout = 100_000u32;
        unsafe {
            while (inb(self.base + REG_LSR) & LSR_TX_HOLDING_EMPTY) == 0 && timeout > 0 {
                core::hint::spin_loop();
                timeout -= 1;
            }
        }
    }

    /// Transmit a single raw byte over UART.
    #[inline]
    pub fn write_byte(&mut self, byte: u8) {
        if byte == b'\n' {
            self.wait_tx_ready();
            unsafe {
                outb(self.base + REG_DATA, b'\r');
            }
            self.bytes_tx = self.bytes_tx.wrapping_add(1);
        }
        self.wait_tx_ready();
        unsafe {
            outb(self.base + REG_DATA, byte);
        }
        self.bytes_tx = self.bytes_tx.wrapping_add(1);
    }

    /// Transmit a byte slice.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }

    /// Non-blocking read of one byte if available.
    pub fn try_read_byte(&self) -> Option<u8> {
        unsafe {
            if (inb(self.base + REG_LSR) & LSR_DATA_READY) != 0 {
                Some(inb(self.base + REG_DATA))
            } else {
                None
            }
        }
    }

    /// Flush transmitter shift register.
    pub fn flush(&self) {
        let mut timeout = 100_000u32;
        unsafe {
            while (inb(self.base + REG_LSR) & LSR_TX_EMPTY) == 0 && timeout > 0 {
                core::hint::spin_loop();
                timeout -= 1;
            }
        }
    }

    /// Read raw Modem Status Register (diagnostics).
    pub fn modem_status(&self) -> u8 {
        unsafe { inb(self.base + REG_MSR) }
    }
}

impl Write for Uart16550 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Global IRQ-Safe Serial Console Lock
// ---------------------------------------------------------------------------

struct SerialLock {
    locked: AtomicBool,
    uart: core::cell::UnsafeCell<Uart16550>,
}

unsafe impl Sync for SerialLock {}

static COM1: SerialLock = SerialLock {
    locked: AtomicBool::new(false),
    uart: core::cell::UnsafeCell::new(Uart16550::new(COM1_PORT)),
};

static SERIAL_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Save RFLAGS and disable local interrupts while holding the serial spinlock.
#[inline]
fn save_and_disable_irq() -> u64 {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) rflags,
            options(nomem)
        );
    }
    rflags
}

#[inline]
fn restore_irq(rflags: u64) {
    if (rflags & (1 << 9)) != 0 {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}

/// Initialize the global COM1 serial port at 115200 8N1.
pub fn init() -> bool {
    let flags = save_and_disable_irq();
    while COM1
        .locked
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let ok = unsafe { (*COM1.uart.get()).init(BaudRate::B115200) };
    COM1.locked.store(false, Ordering::Release);
    restore_irq(flags);
    ok
}

/// Execute a closure with exclusive, IRQ-safe access to COM1.
pub fn with_serial<F, R>(f: F) -> R
where
    F: FnOnce(&mut Uart16550) -> R,
{
    let flags = save_and_disable_irq();
    while COM1
        .locked
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let uart = unsafe { &mut *COM1.uart.get() };
    let before = uart.bytes_transmitted();
    let res = f(uart);
    let delta = uart.bytes_transmitted().wrapping_sub(before);
    SERIAL_BYTES_TOTAL.fetch_add(delta, Ordering::Relaxed);
    COM1.locked.store(false, Ordering::Release);
    restore_irq(flags);
    res
}

/// Write formatted arguments to COM1 under the IRQ-safe lock.
pub fn _print(args: fmt::Arguments<'_>) {
    with_serial(|uart| {
        let _ = uart.write_fmt(args);
    });
}

/// Write raw string bytes to COM1 under the IRQ-safe lock.
pub fn write_str(s: &str) {
    with_serial(|uart| {
        uart.write_bytes(s.as_bytes());
    });
}

/// Lock-free emergency serial writer for panic / Double Fault / NMI contexts
/// where another CPU or interrupted frame might already hold the serial lock.
pub struct EmergencySerial;

impl Write for EmergencySerial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                emergency_put_byte(b'\r');
            }
            emergency_put_byte(b);
        }
        Ok(())
    }
}

#[inline]
fn emergency_put_byte(b: u8) {
    let mut spins = 100_000u32;
    unsafe {
        while (inb(COM1_PORT + REG_LSR) & LSR_TX_HOLDING_EMPTY) == 0 && spins > 0 {
            core::hint::spin_loop();
            spins -= 1;
        }
        outb(COM1_PORT + REG_DATA, b);
    }
}

/// Print directly to COM1 bypassing all locks (panic / NMI / Double Fault only).
pub fn _emergency_print(args: fmt::Arguments<'_>) {
    let mut w = EmergencySerial;
    let _ = w.write_fmt(args);
}

/// Total bytes transmitted through the serial driver since boot.
pub fn total_bytes_tx() -> u64 {
    SERIAL_BYTES_TOTAL.load(Ordering::Relaxed)
}
