//! `gose_sdk` — Shared Ring 3 SDK, IPC Protocols & ELF64 Process Loader
//! for GOSE Modular User-Space Servers on Margay Microkernel.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod elf_loader;
pub mod ipc_proto;
pub mod libmargay;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    libmargay::debug_print("[GOSE ELF PANIC] ");
    if let Some(msg) = info.message().as_str() {
        libmargay::debug_print(msg);
    }
    libmargay::debug_print("\n");
    libmargay::thread_exit();
}
