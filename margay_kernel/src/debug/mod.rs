//! Kernel Debug, Serial Telemetry, Stack Unwinding & Panic Subsystem

pub mod panic;
pub mod serial;
pub mod telemetry;
pub mod unwind;

use core::sync::atomic::{AtomicU8, Ordering};

/// Kernel log verbosity levels.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

static MAX_LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

/// Set the maximum active log verbosity level.
pub fn set_log_level(level: LogLevel) {
    MAX_LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Check if a log message at `level` should be emitted.
#[inline]
pub fn log_enabled(level: LogLevel) -> bool {
    (level as u8) <= MAX_LOG_LEVEL.load(Ordering::Relaxed)
}

/// Print formatted text to COM1 serial port.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::debug::serial::_print(core::format_args!($($arg)*))
    };
}

/// Print formatted line to COM1 serial port.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", core::format_args!($($arg)*)));
}

/// Structured kernel info log.
#[macro_export]
macro_rules! kinfo {
    ($subsys:expr, $($arg:tt)*) => {
        if $crate::debug::log_enabled($crate::debug::LogLevel::Info) {
            $crate::serial_println!("[INFO ] [{:<8}] {}", $subsys, core::format_args!($($arg)*));
        }
    };
}

/// Structured kernel warning log.
#[macro_export]
macro_rules! kwarn {
    ($subsys:expr, $($arg:tt)*) => {
        if $crate::debug::log_enabled($crate::debug::LogLevel::Warn) {
            $crate::serial_println!("[WARN ] [{:<8}] {}", $subsys, core::format_args!($($arg)*));
        }
    };
}

/// Structured kernel error log.
#[macro_export]
macro_rules! kerror {
    ($subsys:expr, $($arg:tt)*) => {
        if $crate::debug::log_enabled($crate::debug::LogLevel::Error) {
            $crate::serial_println!("[ERROR] [{:<8}] {}", $subsys, core::format_args!($($arg)*));
        }
    };
}

/// Structured kernel debug log.
#[macro_export]
macro_rules! kdebug {
    ($subsys:expr, $($arg:tt)*) => {
        if $crate::debug::log_enabled($crate::debug::LogLevel::Debug) {
            $crate::serial_println!("[DEBUG] [{:<8}] {}", $subsys, core::format_args!($($arg)*));
        }
    };
}

/// Emit a formatted hexadecimal + ASCII dump of a memory slice to COM1.
pub fn hex_dump(label: &str, base_addr: u64, data: &[u8]) {
    crate::serial_println!("--- Hex Dump: {} ({} bytes @ {:#018x}) ---", label, data.len(), base_addr);
    for (row, chunk) in data.chunks(16).enumerate() {
        let addr = base_addr + (row * 16) as u64;
        crate::serial_print!("  {:#018x}: ", addr);
        for i in 0..16 {
            if i < chunk.len() {
                crate::serial_print!("{:02x} ", chunk[i]);
            } else {
                crate::serial_print!("   ");
            }
            if i == 7 {
                crate::serial_print!(" ");
            }
        }
        crate::serial_print!(" |");
        for &b in chunk {
            let c = if (0x20..=0x7E).contains(&b) { b as char } else { '.' };
            crate::serial_print!("{}", c);
        }
        crate::serial_println!("|");
    }
}
