//! `HELLO.ELF` — Standalone Ring 3 ELF User Program for `execbin HELLO.ELF`
//!
//! Runs in its own isolated Process (CR3 + CSpace) spawned dynamically from
//! FAT32 by `gosebi.elf` via `execbin HELLO.ELF`. Communicates with `drivergop.elf`
//! over Margay IPC and signals `exit_notif_slot` before terminating.

#![no_std]
#![no_main]

extern crate alloc;
extern crate gose_sdk;

use gose_sdk::gop_println;
use gose_sdk::ipc_proto::{self, COLOR_LIGHT_CYAN, COLOR_LIGHT_GRAY};
use gose_sdk::libmargay::{self, GoseBootInfo};

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    let bi = unsafe { &*(boot_info_ptr as *const GoseBootInfo) };
    ipc_proto::init_client_ipc(bi);

    ipc_proto::gop_set_color(COLOR_LIGHT_CYAN, 0);
    gop_println!("");
    gop_println!("============================================================");
    gop_println!("  [HELLO.ELF] Executed via `execbin` in isolated Ring 3 PID!");
    gop_println!("  Kernel: {} | CPUs: {}", bi.kernel_ver_str(), libmargay::sysinfo(0));
    gop_println!("============================================================");
    ipc_proto::gop_set_color(COLOR_LIGHT_GRAY, 0);

    libmargay::exit_process(bi);
}
