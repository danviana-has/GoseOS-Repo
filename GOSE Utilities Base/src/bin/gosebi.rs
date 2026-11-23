//! `gosebi.elf` — Isolated Ring 3 GOSE Bash Interpreter (GOSE BI),
//! GOSE Editor, GOSE BSI, and `execbin` ELF64 Loader.
//!
//! Holds ZERO direct hardware I/O ports or framebuffer MMIO. All screen,
//! keyboard, and FAT32 filesystem operations go over Margay IPC to
//! `drivergop.elf`, `driverps2.elf`, and `driverfs.elf`.

#![no_std]
#![no_main]

extern crate alloc;
extern crate gose_sdk;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use gose_sdk::elf_loader::{spawn_elf_process, CapGrant};
use gose_sdk::ipc_proto::{
    self, KeyEvent, COLOR_BLACK, COLOR_BLUE, COLOR_CYAN, COLOR_LIGHT_CYAN, COLOR_LIGHT_GRAY,
    COLOR_LIGHT_GREEN, COLOR_WHITE, COLOR_YELLOW,
};
use gose_sdk::libmargay::{self, GoseBootInfo, RETYPE_NOTIFICATION};
use gose_sdk::{gop_print, gop_println};

struct UserAccount {
    name: String,
    password: String,
}

struct ShellState {
    current_user: String,
    hostname: String,
    users: Vec<UserAccount>,
}

static mut SHELL: Option<ShellState> = None;
static NEXT_NOTIF_SLOT: AtomicU64 = AtomicU64::new(40);

fn shell() -> &'static mut ShellState {
    unsafe {
        if SHELL.is_none() {
            let mut users = Vec::new();
            users.push(UserAccount {
                name: String::from("root"),
                password: String::from("gose"),
            });
            if let Some(bytes) = ipc_proto::fs_read_file("/USERS.TXT") {
                if let Ok(txt) = core::str::from_utf8(&bytes) {
                    for line in txt.split('\n') {
                        let l = line.trim();
                        if let Some((u, p)) = l.split_once(':') {
                            if u != "root" && !u.is_empty() {
                                users.push(UserAccount {
                                    name: String::from(u),
                                    password: String::from(p),
                                });
                            }
                        }
                    }
                }
            }
            SHELL = Some(ShellState {
                current_user: String::from("root"),
                hostname: String::from("gose-pc"),
                users,
            });
        }
        SHELL.as_mut().unwrap()
    }
}

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    let bi = unsafe { &*(boot_info_ptr as *const GoseBootInfo) };
    ipc_proto::init_client_ipc(bi);

    print_banner(bi);

    if let Some(bytes) = ipc_proto::fs_read_file("/AUTOSTART.CFG") {
        if let Ok(cfg) = core::str::from_utf8(&bytes) {
            for line in cfg.split('\n') {
                let target = line.trim();
                if !target.is_empty() {
                    gop_println!("[AUTOSTART] Launching '{}'...", target);
                    run_bsi_script(target, bi);
                }
            }
        }
    }

    if ipc_proto::fs_read_file("/AUTOEXEC.BSI").is_some() {
        run_bsi_script("/AUTOEXEC.BSI", bi);
    }

    loop {
        print_prompt();
        let line = read_line();
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            execute_line(trimmed, bi);
        }
    }
}

fn print_banner(bi: &GoseBootInfo) {
    let mounted = ipc_proto::fs_is_mounted();
    ipc_proto::gop_set_color(COLOR_LIGHT_CYAN, COLOR_BLACK);
    gop_println!("========================================================================");
    gop_println!("  GOSE OS (Modular Multi-Server Microkernel Architecture)");
    gop_println!(
        "  Kernel: {} | Servers: GOP + PS2 + FAT32 + BI | FAT32: {}",
        bi.kernel_ver_str(),
        if mounted { "Mounted (/)" } else { "Not detected" }
    );
    gop_println!("========================================================================");
    ipc_proto::gop_set_color(COLOR_LIGHT_GRAY, COLOR_BLACK);
    gop_println!("Type 'help' for commands, 'execbin HELLO.ELF' to run ELF binaries.\n");
}

fn print_prompt() {
    let sh = shell();
    let cwd = ipc_proto::fs_cwd();
    ipc_proto::gop_set_color(COLOR_LIGHT_GREEN, COLOR_BLACK);
    gop_print!("{}@{}", sh.current_user, sh.hostname);
    ipc_proto::gop_set_color(COLOR_LIGHT_GRAY, COLOR_BLACK);
    gop_print!(":");
    ipc_proto::gop_set_color(COLOR_LIGHT_CYAN, COLOR_BLACK);
    gop_print!("{}", cwd);
    ipc_proto::gop_set_color(COLOR_LIGHT_GRAY, COLOR_BLACK);
    gop_print!("$ ");
}

fn read_line() -> String {
    let mut buf = String::new();
    loop {
        match ipc_proto::ps2_read_key() {
            KeyEvent::Enter => {
                gop_println!();
                return buf;
            }
            KeyEvent::Backspace => {
                if !buf.is_empty() {
                    buf.pop();
                    ipc_proto::gop_print_str("\x08");
                }
            }
            KeyEvent::Char(ch) => {
                if (0x20..=0x7E).contains(&ch) {
                    buf.push(ch as char);
                    let tmp = [ch];
                    if let Ok(s) = core::str::from_utf8(&tmp) {
                        ipc_proto::gop_print_str(s);
                    }
                }
            }
            _ => {}
        }
    }
}

fn execute_line(line: &str, bi: &GoseBootInfo) {
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("").trim();
    let arg = parts.next().unwrap_or("").trim();

    match cmd {
        "ls" => {
            let listing = ipc_proto::fs_ls(arg);
            gop_print!("{}", listing);
        }
        "cd" => {
            let target = if arg.is_empty() { "/" } else { arg };
            if !ipc_proto::fs_cd(target) {
                gop_println!("cd: '{}': No such directory", target);
            }
        }
        "mkdir" => {
            if arg.is_empty() {
                gop_println!("Usage: mkdir <folder>");
            } else if ipc_proto::fs_mkdir(arg) {
                gop_println!("Directory '{}' created.", arg);
            } else {
                gop_println!("mkdir: failed to create '{}'.", arg);
            }
        }
        "rm" => cmd_rm(arg),
        "cat" => cmd_cat(arg),
        "echo" => gop_println!("{}", arg),
        "memoryinfo" => cmd_memoryinfo(bi),
        "cpuinfo" => cmd_cpuinfo(bi),
        "hostname" => cmd_hostname(bi),
        "adduser" => cmd_adduser(arg),
        "gouser" => cmd_gouser(arg),
        "goseeditor" => {
            if arg.is_empty() {
                gop_println!("Usage: goseeditor <filename>");
            } else {
                run_editor(arg);
            }
        }
        "bsi" => cmd_bsi(arg, bi),
        "execbin" => cmd_execbin(arg, bi),
        "clear" => ipc_proto::gop_clear(),
        "help" => cmd_help(),
        _ => {
            if cmd.to_ascii_lowercase().ends_with(".bsi") {
                run_bsi_script(cmd, bi);
            } else {
                gop_println!("gose-bi: command not found: '{}'. Type 'help'.", cmd);
            }
        }
    }
}

fn cmd_rm(arg: &str) {
    let mut parts = arg.splitn(2, ' ');
    let flag = parts.next().unwrap_or("").trim();
    let target = parts.next().unwrap_or("").trim();
    if target.is_empty() || (flag != "-dir" && flag != "-file") {
        gop_println!("Usage: rm -dir <folder> | rm -file <file>");
        return;
    }
    let (ok, msg) = ipc_proto::fs_rm(target, flag == "-dir");
    if ok {
        gop_println!("Removed '{}'.", target);
    } else {
        gop_println!("rm: cannot remove '{}': {}", target, msg);
    }
}

fn cmd_cat(path: &str) {
    if path.is_empty() {
        gop_println!("Usage: cat <file>");
        return;
    }
    match ipc_proto::fs_read_file(path) {
        Some(bytes) => {
            if let Ok(s) = core::str::from_utf8(&bytes) {
                gop_println!("{}", s);
            } else {
                gop_println!("<binary file: {} bytes>", bytes.len());
            }
        }
        None => gop_println!("cat: '{}': No such file", path),
    }
}

fn cmd_memoryinfo(bi: &GoseBootInfo) {
    let free_pages = libmargay::sysinfo(1);
    let total_pages = libmargay::sysinfo(3).max(bi.total_mem_pages);
    let used_pages = total_pages.saturating_sub(free_pages);
    gop_println!("=== GOSE Memory Info (Margay PMM) ===");
    gop_println!("  Total Managed : {} MiB ({} pages)", (total_pages * 4) / 1024, total_pages);
    gop_println!("  Used          : {} MiB ({} pages)", (used_pages * 4) / 1024, used_pages);
    gop_println!("  Free          : {} MiB ({} pages)", (free_pages * 4) / 1024, free_pages);
}

fn cmd_cpuinfo(bi: &GoseBootInfo) {
    let cpus = libmargay::sysinfo(0).max(bi.cpu_count as u64);
    gop_println!("=== GOSE CPU Info ===");
    gop_println!("  Architecture  : x86_64");
    gop_println!("  Vendor        : {}", bi.cpu_vendor_str());
    gop_println!("  Brand         : {}", bi.cpu_brand_str());
    gop_println!("  Online Cores  : {} SMP CPUs (x2APIC)", cpus);
}

fn cmd_hostname(bi: &GoseBootInfo) {
    let sh = shell();
    gop_println!("Hostname       : {}", sh.hostname);
    gop_println!("Kernel Version : {}", bi.kernel_ver_str());
}

fn cmd_adduser(arg: &str) {
    let username = if arg.is_empty() {
        gop_print!("New username: ");
        read_line()
    } else {
        String::from(arg)
    };
    let username = username.trim();
    if username.is_empty() {
        gop_println!("adduser: username cannot be empty.");
        return;
    }
    let sh = shell();
    if sh.users.iter().any(|u| u.name == username) {
        gop_println!("adduser: user '{}' already exists.", username);
        return;
    }
    gop_print!("Password for {}: ", username);
    let pass = read_line();
    sh.users.push(UserAccount {
        name: String::from(username),
        password: String::from(pass.trim()),
    });
    let mut data = String::new();
    for u in &sh.users {
        data.push_str(&format!("{}:{}\n", u.name, u.password));
    }
    let _ = ipc_proto::fs_write_file("/USERS.TXT", data.as_bytes());
    gop_println!("User '{}' created successfully.", username);
}

fn cmd_gouser(arg: &str) {
    let username = if arg.is_empty() {
        gop_print!("Login user: ");
        read_line()
    } else {
        String::from(arg)
    };
    let username = username.trim();
    let sh = shell();
    let Some(idx) = sh.users.iter().position(|u| u.name == username) else {
        gop_println!("gouser: user '{}' not found.", username);
        return;
    };
    gop_print!("Password: ");
    let pass = read_line();
    if sh.users[idx].password == pass.trim() {
        sh.current_user = sh.users[idx].name.clone();
        gop_println!("Switched to user '{}'.", sh.current_user);
    } else {
        gop_println!("gouser: incorrect password.");
    }
}

fn cmd_bsi(arg: &str, bi: &GoseBootInfo) {
    if arg.is_empty() {
        gop_println!("Usage: bsi <script.bsi> | bsi -autostart <script.bsi>");
        return;
    }
    if let Some(rest) = arg.strip_prefix("-autostart") {
        let target = rest.trim();
        if target.is_empty() {
            gop_println!("Usage: bsi -autostart <script.bsi>");
            return;
        }
        if target == "off" || target == "clear" {
            let _ = ipc_proto::fs_rm("/AUTOSTART.CFG", false);
            gop_println!("[GOSE BSI] Autostart cleared.");
            return;
        }
        if ipc_proto::fs_read_file(target).is_none() {
            gop_println!("bsi -autostart: file '{}' not found on FAT32.", target);
            return;
        }
        let abs_path = if target.starts_with('/') {
            String::from(target)
        } else {
            let cwd = ipc_proto::fs_cwd();
            if cwd == "/" || cwd.is_empty() {
                format!("/{}", target)
            } else {
                format!("{}/{}", cwd, target)
            }
        };
        if ipc_proto::fs_write_file("/AUTOSTART.CFG", abs_path.as_bytes()) {
            gop_println!("[GOSE BSI] Autostart enabled for '{}'.", abs_path);
        } else {
            gop_println!("[GOSE BSI] Failed to write /AUTOSTART.CFG.");
        }
        return;
    }
    run_bsi_script(arg, bi);
}

/// `execbin <NOMEAQUI.elf>`: Load an ELF64 executable from FAT32 into a new
/// isolated Ring 3 Process (CR3 + CSpace), delegate IPC caps, and wait for exit.
fn cmd_execbin(filename: &str, bi: &GoseBootInfo) {
    if filename.is_empty() {
        gop_println!("Usage: execbin <FILE.ELF>");
        return;
    }
    let Some(elf_bytes) = ipc_proto::fs_read_file(filename) else {
        gop_println!("execbin: '{}' not found on FAT32.", filename);
        return;
    };
    if !elf_bytes.starts_with(b"\x7FELF") {
        gop_println!("execbin: '{}' is not a valid ELF64 binary.", filename);
        return;
    }

    let notif_slot = NEXT_NOTIF_SLOT.fetch_add(1, Ordering::Relaxed);
    if notif_slot >= 95 {
        NEXT_NOTIF_SLOT.store(40, Ordering::Relaxed);
    }
    if !libmargay::cap_retype(bi.untyped_slot, notif_slot, RETYPE_NOTIFICATION, 0) {
        gop_println!("execbin: out of UntypedMemory for exit notification.");
        return;
    }

    let mut child_bi = *bi;
    child_bi.untyped_slot = 0;
    child_bi.untyped2_slot = 0;
    child_bi.exit_notif_slot = 25;

    let grants = [
        CapGrant { src_slot: bi.ep_gop_slot, dst_slot: 20 },
        CapGrant { src_slot: bi.ep_ps2_slot, dst_slot: 21 },
        CapGrant { src_slot: bi.ep_fs_slot, dst_slot: 22 },
        CapGrant { src_slot: bi.shm_gop_slot, dst_slot: 23 },
        CapGrant { src_slot: bi.shm_fs_slot, dst_slot: 24 },
        CapGrant { src_slot: notif_slot, dst_slot: 25 },
    ];

    match spawn_elf_process(&elf_bytes, bi.untyped_slot, &child_bi, &grants) {
        Some((pid, tid)) => {
            gop_println!("[execbin] Spawned '{}' (pid={}, tid={})...", filename, pid, tid);
            let _ = libmargay::notify_wait(notif_slot);
            gop_println!("[execbin] '{}' (pid={}) exited cleanly.", filename, pid);
        }
        None => {
            gop_println!("execbin: failed to load ELF64 binary '{}'.", filename);
        }
    }
}

// ---------------------------------------------------------------------------
// GOSE Editor (MS-DOS Edit Style over GOP IPC)
// ---------------------------------------------------------------------------

fn run_editor(filename: &str) {
    let mut lines: Vec<String> = Vec::new();
    if let Some(bytes) = ipc_proto::fs_read_file(filename) {
        if let Ok(text) = core::str::from_utf8(&bytes) {
            for line in text.split('\n') {
                lines.push(String::from(line.trim_end_matches('\r')));
            }
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }

    let mut cur_line: usize = 0;
    let mut cur_col: usize = 0;
    let mut scroll_y: usize = 0;
    let (cols, rows) = ipc_proto::gop_get_dims();
    let view_rows = rows - 2;

    ipc_proto::gop_set_mirror(false);

    loop {
        if cur_line < scroll_y {
            scroll_y = cur_line;
        } else if cur_line >= scroll_y + view_rows {
            scroll_y = cur_line - view_rows + 1;
        }

        let title = format!("  GOSE Editor v1.0   |   Editing: {}", filename);
        ipc_proto::gop_draw_bar(0, &title, COLOR_BLACK, COLOR_LIGHT_GRAY);

        for r in 0..view_rows {
            let line_idx = scroll_y + r;
            let screen_row = r + 1;
            let line_bytes = lines.get(line_idx).map(|s| s.as_bytes()).unwrap_or(&[]);
            for col in 0..cols.min(90) {
                let ch = line_bytes.get(col).copied().unwrap_or(b' ');
                if line_idx == cur_line && col == cur_col {
                    ipc_proto::gop_draw_cell(col, screen_row, ch, COLOR_BLACK, COLOR_YELLOW);
                } else {
                    ipc_proto::gop_draw_cell(col, screen_row, ch, COLOR_WHITE, COLOR_BLUE);
                }
            }
        }

        let status = format!(
            "  ESC: Save & Exit   |   Arrows: Navigate   |   Ln {}, Col {}",
            cur_line + 1,
            cur_col + 1
        );
        ipc_proto::gop_draw_bar(rows - 1, &status, COLOR_BLACK, COLOR_CYAN);

        match ipc_proto::ps2_read_key() {
            KeyEvent::Escape => {
                let mut content = String::new();
                for (i, l) in lines.iter().enumerate() {
                    content.push_str(l);
                    if i + 1 < lines.len() {
                        content.push('\n');
                    }
                }
                let saved = ipc_proto::fs_write_file(filename, content.as_bytes());
                ipc_proto::gop_set_mirror(true);
                ipc_proto::gop_set_color(COLOR_LIGHT_GRAY, COLOR_BLACK);
                ipc_proto::gop_clear();
                if saved {
                    gop_println!("[GOSE Editor] Saved '{}' ({} bytes).", filename, content.len());
                } else {
                    gop_println!("[GOSE Editor] Warning: failed to save '{}'.", filename);
                }
                return;
            }
            KeyEvent::Up => {
                if cur_line > 0 {
                    cur_line -= 1;
                    cur_col = cur_col.min(lines[cur_line].len());
                }
            }
            KeyEvent::Down => {
                if cur_line + 1 < lines.len() {
                    cur_line += 1;
                    cur_col = cur_col.min(lines[cur_line].len());
                }
            }
            KeyEvent::Left => {
                if cur_col > 0 {
                    cur_col -= 1;
                } else if cur_line > 0 {
                    cur_line -= 1;
                    cur_col = lines[cur_line].len();
                }
            }
            KeyEvent::Right => {
                if cur_col < lines[cur_line].len() {
                    cur_col += 1;
                } else if cur_line + 1 < lines.len() {
                    cur_line += 1;
                    cur_col = 0;
                }
            }
            KeyEvent::Enter => {
                let tail = lines[cur_line].split_off(cur_col);
                cur_line += 1;
                lines.insert(cur_line, tail);
                cur_col = 0;
            }
            KeyEvent::Backspace => {
                if cur_col > 0 {
                    lines[cur_line].remove(cur_col - 1);
                    cur_col -= 1;
                } else if cur_line > 0 {
                    let removed = lines.remove(cur_line);
                    cur_line -= 1;
                    cur_col = lines[cur_line].len();
                    lines[cur_line].push_str(&removed);
                }
            }
            KeyEvent::Tab => {
                for _ in 0..4 {
                    lines[cur_line].insert(cur_col, ' ');
                    cur_col += 1;
                }
            }
            KeyEvent::Char(ch) => {
                if (0x20..=0x7E).contains(&ch) {
                    lines[cur_line].insert(cur_col, ch as char);
                    cur_col += 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GOSE BSI (Order-Tagged + Loop Script Interpreter)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum LoopCount {
    Finite(u32),
    Infinite,
}

enum BsiNode {
    Single { order: u32, cmd: String },
    Loop { order: u32, count: LoopCount, body: Vec<(u32, String)> },
}

impl BsiNode {
    fn order(&self) -> u32 {
        match self {
            BsiNode::Single { order, .. } => *order,
            BsiNode::Loop { order, .. } => *order,
        }
    }
}

fn run_bsi_script(filename: &str, bi: &GoseBootInfo) {
    let Some(bytes) = ipc_proto::fs_read_file(filename) else {
        gop_println!("[GOSE BSI] File not found: {}", filename);
        return;
    };
    let Ok(text) = core::str::from_utf8(&bytes) else {
        gop_println!("[GOSE BSI] Invalid UTF-8 in '{}'", filename);
        return;
    };

    let mut nodes: Vec<BsiNode> = Vec::new();
    let mut pending_order: Option<u32> = None;
    let mut auto_order: u32 = 1000;
    let mut in_loop = false;
    let mut loop_count = LoopCount::Finite(1);
    let mut loop_body: Vec<(u32, String)> = Vec::new();
    let mut loop_pending: Option<u32> = None;

    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_loop {
            if line == "}" {
                let ord = pending_order.take().unwrap_or_else(|| {
                    auto_order += 1;
                    auto_order
                });
                nodes.push(BsiNode::Loop {
                    order: ord,
                    count: loop_count,
                    body: core::mem::take(&mut loop_body),
                });
                in_loop = false;
                loop_pending = None;
                continue;
            }
            if let Some(ord) = parse_order_header(line) {
                loop_pending = Some(ord);
            } else {
                loop_body.push((loop_pending.take().unwrap_or(1), String::from(line)));
            }
            continue;
        }
        if let Some(cnt) = parse_loop_header(line) {
            in_loop = true;
            loop_count = cnt;
            loop_body.clear();
            loop_pending = None;
            continue;
        }
        if let Some(ord) = parse_order_header(line) {
            pending_order = Some(ord);
        } else if let Some(ord) = pending_order.take() {
            nodes.push(BsiNode::Single {
                order: ord,
                cmd: String::from(line),
            });
        }
    }

    nodes.sort_by_key(|n| n.order());
    gop_println!("[GOSE BSI] Executing '{}' ({} blocks)...", filename, nodes.len());

    for node in &nodes {
        match node {
            BsiNode::Single { order, cmd } => {
                gop_println!("  [step {}] > {}", order, cmd);
                execute_line(cmd, bi);
            }
            BsiNode::Loop { count, body, .. } => {
                let mut sorted = body.clone();
                sorted.sort_by_key(|(o, _)| *o);
                match count {
                    LoopCount::Finite(n) => {
                        for iter in 1..=*n {
                            gop_println!("  [loop {}/{}]", iter, n);
                            for (_, cmd) in &sorted {
                                execute_line(cmd, bi);
                            }
                        }
                    }
                    LoopCount::Infinite => {
                        let mut iter = 1u64;
                        loop {
                            gop_println!("  [loop infinite #{}]", iter);
                            for (_, cmd) in &sorted {
                                execute_line(cmd, bi);
                            }
                            iter = iter.wrapping_add(1);
                            libmargay::yield_now();
                        }
                    }
                }
            }
        }
    }
}

fn parse_order_header(line: &str) -> Option<u32> {
    let lower = line.to_ascii_lowercase();
    let trimmed = lower.trim();
    if let Some(n) = trimmed.strip_suffix("command:") {
        return n.trim().parse::<u32>().ok();
    }
    if let Some(rest) = trimmed.strip_prefix("command") {
        if let Some(n) = rest.trim().strip_suffix(':') {
            return n.trim().parse::<u32>().ok();
        }
    }
    None
}

fn parse_loop_header(line: &str) -> Option<LoopCount> {
    let lower = line.to_ascii_lowercase();
    let trimmed = lower.trim();
    if !trimmed.starts_with("loop") || !trimmed.ends_with('{') {
        return None;
    }
    let inner = trimmed.strip_prefix("loop")?.strip_suffix('{')?.trim();
    let arg = inner.strip_prefix('(')?.strip_suffix(')')?.trim();
    if arg == "infinite" {
        Some(LoopCount::Infinite)
    } else {
        arg.parse::<u32>().ok().map(LoopCount::Finite)
    }
}

fn cmd_help() {
    gop_println!("GOSE Bash Interpreter (GOSE BI) Commands:");
    gop_println!("  ls [dir]                 List files/folders in FAT32");
    gop_println!("  cd <dir>                 Change current FAT32 directory");
    gop_println!("  mkdir <dir>              Create a new folder in FAT32");
    gop_println!("  rm -dir <dir>            Remove a folder from FAT32");
    gop_println!("  rm -file <file>          Remove a file from FAT32");
    gop_println!("  cat <file>               Display file contents");
    gop_println!("  echo <text>              Print text to console");
    gop_println!("  memoryinfo               Show Margay managed RAM statistics");
    gop_println!("  cpuinfo                  Show CPU vendor, brand and SMP cores");
    gop_println!("  hostname                 Show system hostname and kernel version");
    gop_println!("  adduser [name]           Create a new OS user");
    gop_println!("  gouser [name]            Switch to an existing OS user");
    gop_println!("  goseeditor <file>        Open MS-DOS style editor (ESC saves & exits)");
    gop_println!("  bsi <script.bsi>         Run a GOSE BSI ordered/loop script");
    gop_println!("  bsi -autostart <file>    Run <file> automatically on every boot");
    gop_println!("  execbin <FILE.ELF>       Execute a standalone ELF64 binary from FAT32");
    gop_println!("  clear                    Clear GOP text console");
}
