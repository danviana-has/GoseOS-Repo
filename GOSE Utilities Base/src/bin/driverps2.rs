//! `driverps2.elf` — Isolated Ring 3 PS/2 Keyboard Server
//!
//! Owns ONLY the PS/2 I/O ports (`0x60..0x64`) + COM1 RX fallback (`0x3F8..0x3FF`).
//! Serves key events over Margay IPC (`ep_ps2_slot`).

#![no_std]
#![no_main]

extern crate alloc;
extern crate gose_sdk;

use gose_sdk::ipc_proto::{KeyEvent, PS2_OP_POLL_KEY, PS2_OP_READ_KEY};
use gose_sdk::libmargay::{self, inb, outb, GoseBootInfo};

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const COM1_DATA: u16 = 0x3F8;
const COM1_LSR: u16 = 0x3FD;

struct Ps2State {
    shift: bool,
    caps: bool,
    ext: bool,
    serial_ok: bool,
}

impl Ps2State {
    const fn new() -> Self {
        Self {
            shift: false,
            caps: false,
            ext: false,
            serial_ok: false,
        }
    }

    fn init(&mut self, bi: &GoseBootInfo) {
        let _ = libmargay::grant_ioport(bi.ps2_ioport_slot);
        if libmargay::grant_ioport(bi.com1_ioport_slot) {
            self.serial_ok = true;
        }
        unsafe {
            for _ in 0..32 {
                if (inb(PS2_STATUS) & 0x01) == 0 {
                    break;
                }
                let _ = inb(PS2_DATA);
            }
            let mut spins = 0u32;
            while (inb(PS2_STATUS) & 0x02) != 0 && spins < 10_000 {
                spins += 1;
            }
            outb(PS2_DATA, 0xF4);
        }
        libmargay::debug_print("[driverps2.elf] Isolated PS/2 server online\n");
    }

    fn poll(&mut self) -> Option<KeyEvent> {
        unsafe {
            let st = inb(PS2_STATUS);
            if (st & 0x01) != 0 && (st & 0x20) == 0 {
                let sc = inb(PS2_DATA);
                if let Some(ev) = self.decode_scancode(sc) {
                    return Some(ev);
                }
            }
            if self.serial_ok && (inb(COM1_LSR) & 0x01) != 0 {
                let ch = inb(COM1_DATA);
                return Some(match ch {
                    b'\r' | b'\n' => KeyEvent::Enter,
                    0x7F | 0x08 => KeyEvent::Backspace,
                    0x1B => KeyEvent::Escape,
                    b'\t' => KeyEvent::Tab,
                    c => KeyEvent::Char(c),
                });
            }
        }
        None
    }

    fn decode_scancode(&mut self, sc: u8) -> Option<KeyEvent> {
        if sc == 0xE0 {
            self.ext = true;
            return None;
        }
        if self.ext {
            self.ext = false;
            if (sc & 0x80) != 0 {
                return None;
            }
            return match sc {
                0x48 => Some(KeyEvent::Up),
                0x50 => Some(KeyEvent::Down),
                0x4B => Some(KeyEvent::Left),
                0x4D => Some(KeyEvent::Right),
                _ => None,
            };
        }
        if (sc & 0x80) != 0 {
            let code = sc & 0x7F;
            if code == 0x2A || code == 0x36 {
                self.shift = false;
            }
            return None;
        }
        match sc {
            0x2A | 0x36 => {
                self.shift = true;
                None
            }
            0x3A => {
                self.caps = !self.caps;
                None
            }
            0x01 => Some(KeyEvent::Escape),
            0x0E => Some(KeyEvent::Backspace),
            0x0F => Some(KeyEvent::Tab),
            0x1C => Some(KeyEvent::Enter),
            _ => {
                let base = SCANCODE_SET1.get(sc as usize).copied().unwrap_or(0);
                if base == 0 {
                    return None;
                }
                let ch = if base.is_ascii_alphabetic() {
                    if self.shift ^ self.caps {
                        base.to_ascii_uppercase()
                    } else {
                        base
                    }
                } else if self.shift {
                    SCANCODE_SET1_SHIFT.get(sc as usize).copied().unwrap_or(base)
                } else {
                    base
                };
                Some(KeyEvent::Char(ch))
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    let bi = unsafe { &*(boot_info_ptr as *const GoseBootInfo) };
    let mut ps2 = Ps2State::new();
    ps2.init(bi);

    let ep = bi.ep_ps2_slot;
    loop {
        let req = libmargay::ipc_recv(ep);
        match req.tag {
            PS2_OP_READ_KEY => {
                let ev = loop {
                    if let Some(k) = ps2.poll() {
                        break k;
                    }
                    libmargay::yield_now();
                };
                let (kind, ch) = ev.encode();
                libmargay::ipc_reply(0, kind, ch, 0, 0);
            }
            PS2_OP_POLL_KEY => {
                if let Some(ev) = ps2.poll() {
                    let (kind, ch) = ev.encode();
                    libmargay::ipc_reply(0, kind, ch, 0, 0);
                } else {
                    libmargay::ipc_reply(0, 0, 0, 0, 0);
                }
            }
            _ => {
                libmargay::ipc_reply(0, 0, 0, 0, 0);
            }
        }
    }
}

#[rustfmt::skip]
static SCANCODE_SET1: [u8; 58] = [
    0,    0,    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 0,    0,
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', 0,    0,    b'a', b's',
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'',b'`', 0,    b'\\',b'z', b'x', b'c', b'v',
    b'b', b'n', b'm', b',', b'.', b'/', 0,    b'*', 0,    b' ',
];

#[rustfmt::skip]
static SCANCODE_SET1_SHIFT: [u8; 58] = [
    0,    0,    b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 0,    0,
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', 0,    0,    b'A', b'S',
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0,    b'|', b'Z', b'X', b'C', b'V',
    b'B', b'N', b'M', b'<', b'>', b'?', 0,    b'*', 0,    b' ',
];
