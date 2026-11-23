//! GOSE Microkernel Inter-Process Communication (IPC) Protocols
//!
//! Defines the wire protocol between Ring 3 clients (`gosebi.elf`, `hello.elf`,
//! and `execbin` programs) and the isolated Ring 3 hardware/FS servers
//! (`drivergop.elf`, `driverps2.elf`, `driverfs.elf`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::libmargay::{self, GoseBootInfo};

pub const SHM_GOP_VA: u64 = 0x0000_0000_4000_0000;
pub const SHM_FS_VA: u64 = 0x0000_0000_4100_0000;
pub const SHM_SIZE_BYTES: usize = 256 * 1024; // 64 pages = 256 KiB

// GOP Server IPC Tags
pub const GOP_OP_PRINT: u64 = 1;
pub const GOP_OP_CLEAR: u64 = 2;
pub const GOP_OP_SET_COLOR: u64 = 3;
pub const GOP_OP_DRAW_CELL: u64 = 4;
pub const GOP_OP_GET_DIMS: u64 = 5;
pub const GOP_OP_SET_MIRROR: u64 = 6;
pub const GOP_OP_DRAW_BAR: u64 = 7;

// PS/2 Server IPC Tags
pub const PS2_OP_READ_KEY: u64 = 1;
pub const PS2_OP_POLL_KEY: u64 = 2;

// FS Server IPC Tags
pub const FS_OP_IS_MOUNTED: u64 = 1;
pub const FS_OP_CWD: u64 = 2;
pub const FS_OP_LS: u64 = 3;
pub const FS_OP_CD: u64 = 4;
pub const FS_OP_READ: u64 = 5;
pub const FS_OP_WRITE: u64 = 6;
pub const FS_OP_MKDIR: u64 = 7;
pub const FS_OP_RM: u64 = 8;

// Colors
pub const COLOR_BLACK: u32 = 0x0000_0000;
pub const COLOR_BLUE: u32 = 0x0000_00AA;
pub const COLOR_CYAN: u32 = 0x0000_AAAA;
pub const COLOR_LIGHT_GRAY: u32 = 0x00AA_AAAA;
pub const COLOR_LIGHT_GREEN: u32 = 0x0055_FF55;
pub const COLOR_LIGHT_CYAN: u32 = 0x0055_FFFF;
pub const COLOR_YELLOW: u32 = 0x00FF_FF55;
pub const COLOR_WHITE: u32 = 0x00FF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    Char(u8),
    Enter,
    Backspace,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Tab,
}

impl KeyEvent {
    pub fn encode(self) -> (u64, u64) {
        match self {
            KeyEvent::Char(c) => (1, c as u64),
            KeyEvent::Enter => (2, 0),
            KeyEvent::Backspace => (3, 0),
            KeyEvent::Escape => (4, 0),
            KeyEvent::Up => (5, 0),
            KeyEvent::Down => (6, 0),
            KeyEvent::Left => (7, 0),
            KeyEvent::Right => (8, 0),
            KeyEvent::Tab => (9, 0),
        }
    }

    pub fn decode(kind: u64, ch: u64) -> Option<Self> {
        match kind {
            1 => Some(KeyEvent::Char(ch as u8)),
            2 => Some(KeyEvent::Enter),
            3 => Some(KeyEvent::Backspace),
            4 => Some(KeyEvent::Escape),
            5 => Some(KeyEvent::Up),
            6 => Some(KeyEvent::Down),
            7 => Some(KeyEvent::Left),
            8 => Some(KeyEvent::Right),
            9 => Some(KeyEvent::Tab),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Client-Side IPC Helpers (used by `gosebi.elf`, `hello.elf`, etc.)
// ---------------------------------------------------------------------------

static mut CLIENT_EP_GOP: u64 = 0;
static mut CLIENT_EP_PS2: u64 = 0;
static mut CLIENT_EP_FS: u64 = 0;

pub fn init_client_ipc(bi: &GoseBootInfo) {
    unsafe {
        CLIENT_EP_GOP = bi.ep_gop_slot;
        CLIENT_EP_PS2 = bi.ep_ps2_slot;
        CLIENT_EP_FS = bi.ep_fs_slot;
    }
    if bi.shm_gop_slot != 0 {
        let _ = libmargay::shmem_map(bi.shm_gop_slot, SHM_GOP_VA);
    }
    if bi.shm_fs_slot != 0 {
        let _ = libmargay::shmem_map(bi.shm_fs_slot, SHM_FS_VA);
    }
}

pub fn gop_print_str(s: &str) {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep == 0 || s.is_empty() {
        libmargay::debug_print(s);
        return;
    }
    let bytes = s.as_bytes();
    let mut off = 0usize;
    while off < bytes.len() {
        let chunk = (bytes.len() - off).min(4096);
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), SHM_GOP_VA as *mut u8, chunk);
        }
        let _ = libmargay::ipc_call(ep, GOP_OP_PRINT, chunk as u64, 0, 0, 0);
        off += chunk;
    }
}

pub fn gop_clear() {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep != 0 {
        let _ = libmargay::ipc_call(ep, GOP_OP_CLEAR, 0, 0, 0, 0);
    }
}

pub fn gop_set_color(fg: u32, bg: u32) {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep != 0 {
        let _ = libmargay::ipc_call(ep, GOP_OP_SET_COLOR, fg as u64, bg as u64, 0, 0);
    }
}

pub fn gop_set_mirror(enabled: bool) {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep != 0 {
        let _ = libmargay::ipc_call(ep, GOP_OP_SET_MIRROR, enabled as u64, 0, 0, 0);
    }
}

pub fn gop_get_dims() -> (usize, usize) {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep == 0 {
        return (80, 25);
    }
    let rep = libmargay::ipc_call(ep, GOP_OP_GET_DIMS, 0, 0, 0, 0);
    ((rep.r0 as usize).max(40), (rep.r1 as usize).max(10))
}

pub fn gop_draw_cell(col: usize, row: usize, ch: u8, fg: u32, bg: u32) {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep != 0 {
        let pos = ((row as u64) << 16) | (col as u64);
        let _ = libmargay::ipc_call(ep, GOP_OP_DRAW_CELL, pos, ch as u64, fg as u64, bg as u64);
    }
}

pub fn gop_draw_bar(row: usize, text: &str, fg: u32, bg: u32) {
    let ep = unsafe { CLIENT_EP_GOP };
    if ep == 0 {
        return;
    }
    let bytes = text.as_bytes();
    let len = bytes.len().min(256);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), SHM_GOP_VA as *mut u8, len);
    }
    let _ = libmargay::ipc_call(ep, GOP_OP_DRAW_BAR, row as u64, len as u64, fg as u64, bg as u64);
}

pub fn ps2_read_key() -> KeyEvent {
    let ep = unsafe { CLIENT_EP_PS2 };
    loop {
        let rep = libmargay::ipc_call(ep, PS2_OP_READ_KEY, 0, 0, 0, 0);
        if let Some(ev) = KeyEvent::decode(rep.r0, rep.r1) {
            return ev;
        }
        libmargay::yield_now();
    }
}

pub fn fs_is_mounted() -> bool {
    let ep = unsafe { CLIENT_EP_FS };
    if ep == 0 {
        return false;
    }
    libmargay::ipc_call(ep, FS_OP_IS_MOUNTED, 0, 0, 0, 0).r0 != 0
}

pub fn fs_cwd() -> String {
    let ep = unsafe { CLIENT_EP_FS };
    if ep == 0 {
        return String::from("/");
    }
    let rep = libmargay::ipc_call(ep, FS_OP_CWD, 0, 0, 0, 0);
    let len = (rep.r0 as usize).min(256);
    let slice = unsafe { core::slice::from_raw_parts(SHM_FS_VA as *const u8, len) };
    String::from(core::str::from_utf8(slice).unwrap_or("/"))
}

pub fn fs_ls(path: &str) -> String {
    let ep = unsafe { CLIENT_EP_FS };
    let bytes = path.as_bytes();
    let plen = bytes.len().min(512);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), SHM_FS_VA as *mut u8, plen);
    }
    let rep = libmargay::ipc_call(ep, FS_OP_LS, plen as u64, 0, 0, 0);
    let out_len = (rep.r0 as usize).min(SHM_SIZE_BYTES);
    let slice = unsafe { core::slice::from_raw_parts(SHM_FS_VA as *const u8, out_len) };
    String::from(core::str::from_utf8(slice).unwrap_or(""))
}

pub fn fs_cd(path: &str) -> bool {
    let ep = unsafe { CLIENT_EP_FS };
    let bytes = path.as_bytes();
    let plen = bytes.len().min(512);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), SHM_FS_VA as *mut u8, plen);
    }
    libmargay::ipc_call(ep, FS_OP_CD, plen as u64, 0, 0, 0).r0 != 0
}

pub fn fs_read_file(path: &str) -> Option<Vec<u8>> {
    let ep = unsafe { CLIENT_EP_FS };
    let bytes = path.as_bytes();
    let plen = bytes.len().min(512);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), SHM_FS_VA as *mut u8, plen);
    }
    let rep = libmargay::ipc_call(ep, FS_OP_READ, plen as u64, 0, 0, 0);
    if rep.r1 == 0 {
        return None;
    }
    let len = (rep.r0 as usize).min(SHM_SIZE_BYTES);
    let slice = unsafe { core::slice::from_raw_parts(SHM_FS_VA as *const u8, len) };
    Some(slice.to_vec())
}

pub fn fs_write_file(path: &str, data: &[u8]) -> bool {
    let ep = unsafe { CLIENT_EP_FS };
    let pbytes = path.as_bytes();
    let plen = pbytes.len().min(512);
    let dlen = data.len().min(SHM_SIZE_BYTES - 4096);
    unsafe {
        core::ptr::copy_nonoverlapping(pbytes.as_ptr(), SHM_FS_VA as *mut u8, plen);
        core::ptr::copy_nonoverlapping(data.as_ptr(), (SHM_FS_VA + 4096) as *mut u8, dlen);
    }
    libmargay::ipc_call(ep, FS_OP_WRITE, plen as u64, dlen as u64, 0, 0).r0 != 0
}

pub fn fs_mkdir(path: &str) -> bool {
    let ep = unsafe { CLIENT_EP_FS };
    let bytes = path.as_bytes();
    let plen = bytes.len().min(512);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), SHM_FS_VA as *mut u8, plen);
    }
    libmargay::ipc_call(ep, FS_OP_MKDIR, plen as u64, 0, 0, 0).r0 != 0
}

pub fn fs_rm(path: &str, expect_dir: bool) -> (bool, String) {
    let ep = unsafe { CLIENT_EP_FS };
    let bytes = path.as_bytes();
    let plen = bytes.len().min(512);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), SHM_FS_VA as *mut u8, plen);
    }
    let rep = libmargay::ipc_call(ep, FS_OP_RM, plen as u64, expect_dir as u64, 0, 0);
    let ok = rep.r0 != 0;
    let msg_len = (rep.r1 as usize).min(256);
    let slice = unsafe { core::slice::from_raw_parts(SHM_FS_VA as *const u8, msg_len) };
    let msg = String::from(core::str::from_utf8(slice).unwrap_or(""));
    (ok, msg)
}

pub struct IpcGopWriter;

impl Write for IpcGopWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        gop_print_str(s);
        Ok(())
    }
}

pub fn _ipc_print(args: fmt::Arguments<'_>) {
    let mut w = IpcGopWriter;
    let _ = w.write_fmt(args);
}

#[macro_export]
macro_rules! gop_print {
    ($($arg:tt)*) => {
        $crate::ipc_proto::_ipc_print(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! gop_println {
    () => ($crate::gop_print!("\n"));
    ($($arg:tt)*) => ($crate::gop_print!("{}\n", core::format_args!($($arg)*)));
}
