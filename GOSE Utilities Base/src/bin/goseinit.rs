//! `goseinit.elf` — Ring 3 Root Init Server (PID 1)
//!
//! Bootstraps the modular GOSE multi-server OS on top of the Margay Microkernel:
//! - Retypes IPC Endpoints (`ep_gop`, `ep_ps2`, `ep_fs`) from `UntypedMemory`
//! - Allocates SharedMemory IPC buffers (`shm_gop`, `shm_fs`)
//! - Spawns each driver and shell as its own isolated Ring 3 Process with
//!   strict least-privilege capability delegation:
//!     - `drivergop.elf` -> GOP Framebuffer MMIO only
//!     - `driverps2.elf` -> PS/2 (`0x60..0x64`) + COM1 only
//!     - `driverfs.elf`  -> ATA IDE (`0x1F0..0x1F7`, `0x3F6`) only
//!     - `gosebi.elf`    -> IPC Endpoints + ShMem + Untyped2 (for `execbin`)

#![no_std]
#![no_main]

extern crate alloc;
extern crate gose_sdk;

use gose_sdk::elf_loader::{spawn_elf_process, CapGrant};
use gose_sdk::libmargay::{self, GoseBootInfo, RETYPE_ENDPOINT};

const SLOT_EP_GOP: u64 = 20;
const SLOT_EP_PS2: u64 = 21;
const SLOT_EP_FS: u64 = 22;

fn find_module(bi: &GoseBootInfo, needle: &str) -> Option<&'static [u8]> {
    for i in 0..(bi.module_count as usize).min(8) {
        let m = &bi.modules[i];
        if m.vaddr != 0 && m.size > 0 && m.name_str().contains(needle) {
            return Some(unsafe {
                core::slice::from_raw_parts(m.vaddr as *const u8, m.size as usize)
            });
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    libmargay::debug_print("[goseinit.elf] Ring 3 Modular Init online (PID 1)!\n");

    let bi = unsafe { &*(boot_info_ptr as *const GoseBootInfo) };
    if bi.magic != 0x474F_5345_424F_4F54 {
        libmargay::debug_print("[goseinit.elf] Invalid BootInfo magic!\n");
        libmargay::thread_exit();
    }

    // 1. Retype IPC Endpoints from UntypedMemory
    assert!(libmargay::cap_retype(bi.untyped_slot, SLOT_EP_GOP, RETYPE_ENDPOINT, 0));
    assert!(libmargay::cap_retype(bi.untyped_slot, SLOT_EP_PS2, RETYPE_ENDPOINT, 0));
    assert!(libmargay::cap_retype(bi.untyped_slot, SLOT_EP_FS, RETYPE_ENDPOINT, 0));

    // 2. Create 256 KiB SharedMemory buffers for GOP & FS zero-copy IPC
    let shm_gop_slot = libmargay::shmem_create(64) as u64;
    let shm_fs_slot = libmargay::shmem_create(64) as u64;
    assert!(shm_gop_slot > 0 && shm_fs_slot > 0);

    // 3. Spawn `drivergop.elf` (GOP MMIO only)
    if let Some(elf) = find_module(bi, "drivergop") {
        let mut child_bi = *bi;
        child_bi.ep_gop_slot = 20;
        child_bi.shm_gop_slot = 23;
        child_bi.fb_cap_slot = 8;
        let grants = [
            CapGrant { src_slot: bi.fb_cap_slot, dst_slot: 8 },
            CapGrant { src_slot: SLOT_EP_GOP, dst_slot: 20 },
            CapGrant { src_slot: shm_gop_slot, dst_slot: 23 },
        ];
        let (pid, _) = spawn_elf_process(elf, bi.untyped_slot, &child_bi, &grants)
            .expect("Failed to spawn drivergop.elf");
        libmargay::debug_print("[goseinit.elf] Spawned isolated drivergop.elf\n");
        let _ = pid;
    }

    // 4. Spawn `driverps2.elf` (PS/2 + COM1 I/O ports only)
    if let Some(elf) = find_module(bi, "driverps2") {
        let mut child_bi = *bi;
        child_bi.ep_ps2_slot = 21;
        child_bi.ps2_ioport_slot = 9;
        child_bi.com1_ioport_slot = 6;
        let grants = [
            CapGrant { src_slot: bi.ps2_ioport_slot, dst_slot: 9 },
            CapGrant { src_slot: bi.com1_ioport_slot, dst_slot: 6 },
            CapGrant { src_slot: SLOT_EP_PS2, dst_slot: 21 },
        ];
        let _ = spawn_elf_process(elf, bi.untyped_slot, &child_bi, &grants)
            .expect("Failed to spawn driverps2.elf");
        libmargay::debug_print("[goseinit.elf] Spawned isolated driverps2.elf\n");
    }

    // 5. Spawn `driverfs.elf` (ATA PIO IDE I/O ports only)
    if let Some(elf) = find_module(bi, "driverfs") {
        let mut child_bi = *bi;
        child_bi.ep_fs_slot = 22;
        child_bi.shm_fs_slot = 24;
        child_bi.ata_pri_ioport_slot = 10;
        child_bi.ata_ctl_ioport_slot = 11;
        let grants = [
            CapGrant { src_slot: bi.ata_pri_ioport_slot, dst_slot: 10 },
            CapGrant { src_slot: bi.ata_ctl_ioport_slot, dst_slot: 11 },
            CapGrant { src_slot: SLOT_EP_FS, dst_slot: 22 },
            CapGrant { src_slot: shm_fs_slot, dst_slot: 24 },
        ];
        let _ = spawn_elf_process(elf, bi.untyped_slot, &child_bi, &grants)
            .expect("Failed to spawn driverfs.elf");
        libmargay::debug_print("[goseinit.elf] Spawned isolated driverfs.elf\n");
    }

    // Give drivers a brief yield to finish mounting hardware before shell starts
    for _ in 0..8 {
        libmargay::yield_now();
    }

    // 6. Spawn `gosebi.elf` (Zero direct hardware caps — pure IPC + Untyped2 for `execbin`)
    if let Some(elf) = find_module(bi, "gosebi") {
        let mut child_bi = *bi;
        child_bi.fb_cap_slot = 0;
        child_bi.ps2_ioport_slot = 0;
        child_bi.ata_pri_ioport_slot = 0;
        child_bi.ata_ctl_ioport_slot = 0;
        child_bi.ep_gop_slot = 20;
        child_bi.ep_ps2_slot = 21;
        child_bi.ep_fs_slot = 22;
        child_bi.shm_gop_slot = 23;
        child_bi.shm_fs_slot = 24;
        child_bi.untyped_slot = 12;
        let grants = [
            CapGrant { src_slot: SLOT_EP_GOP, dst_slot: 20 },
            CapGrant { src_slot: SLOT_EP_PS2, dst_slot: 21 },
            CapGrant { src_slot: SLOT_EP_FS, dst_slot: 22 },
            CapGrant { src_slot: shm_gop_slot, dst_slot: 23 },
            CapGrant { src_slot: shm_fs_slot, dst_slot: 24 },
            CapGrant { src_slot: bi.untyped2_slot, dst_slot: 12 },
        ];
        let _ = spawn_elf_process(elf, bi.untyped_slot, &child_bi, &grants)
            .expect("Failed to spawn gosebi.elf");
        libmargay::debug_print("[goseinit.elf] Spawned isolated gosebi.elf (GOSE Shell)\n");
    }

    // `goseinit.elf` remains idle cleanly
    loop {
        libmargay::yield_now();
    }
}
