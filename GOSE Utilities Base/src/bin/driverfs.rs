//! `driverfs.elf` — Isolated Ring 3 Real FAT32 Filesystem Server (ATA PIO)
//!
//! Owns ONLY the Primary ATA IDE I/O ports (`0x1F0..0x1F7` and `0x3F6..0x3F7`).
//! Serves all FAT32 directory, file read/write, mkdir, and rm operations over
//! Margay IPC (`ep_fs_slot`) + zero-copy SharedMemory (`shm_fs_slot`).

#![no_std]
#![no_main]

extern crate alloc;
extern crate gose_sdk;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gose_sdk::ipc_proto::{
    FS_OP_CD, FS_OP_CWD, FS_OP_IS_MOUNTED, FS_OP_LS, FS_OP_MKDIR, FS_OP_READ, FS_OP_RM,
    FS_OP_WRITE, SHM_FS_VA, SHM_SIZE_BYTES,
};
use gose_sdk::libmargay::{self, inb, inw, outb, outw, GoseBootInfo};

const ATA_DATA: u16 = 0x1F0;
const ATA_SEC_CNT: u16 = 0x1F2;
const ATA_LBA_LO: u16 = 0x1F3;
const ATA_LBA_MID: u16 = 0x1F4;
const ATA_LBA_HI: u16 = 0x1F5;
const ATA_DRIVE: u16 = 0x1F6;
const ATA_STATUS: u16 = 0x1F7;
const ATA_CMD: u16 = 0x1F7;
const ATA_ALT_STATUS: u16 = 0x3F6;

const ATA_CMD_READ_PIO: u8 = 0x20;
const ATA_CMD_WRITE_PIO: u8 = 0x30;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;

const SR_BSY: u8 = 0x80;
const SR_DRQ: u8 = 0x08;
const SR_ERR: u8 = 0x01;

const FAT32_EOC: u32 = 0x0FFF_FFF8;
const FAT32_MASK: u32 = 0x0FFF_FFFF;

#[derive(Clone)]
struct DirEntryInfo {
    name: String,
    is_dir: bool,
    size: u32,
    first_cluster: u32,
}

struct Fat32Volume {
    mounted: bool,
    part_lba: u32,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size_sectors: u32,
    root_cluster: u32,
    first_data_sector: u32,
    total_clusters: u32,
    cwd_cluster: u32,
    cwd_path: String,
}

fn ata_wait_not_busy() -> bool {
    unsafe {
        for _ in 0..1_000_000 {
            if (inb(ATA_STATUS) & SR_BSY) == 0 {
                return true;
            }
        }
    }
    false
}

fn ata_wait_drq() -> bool {
    unsafe {
        for _ in 0..1_000_000 {
            let st = inb(ATA_STATUS);
            if (st & SR_ERR) != 0 {
                return false;
            }
            if (st & SR_BSY) == 0 && (st & SR_DRQ) != 0 {
                return true;
            }
        }
    }
    false
}

fn ata_read_sector(lba: u32, buf: &mut [u8; 512]) -> bool {
    if !ata_wait_not_busy() {
        return false;
    }
    unsafe {
        outb(ATA_DRIVE, 0xE0 | (((lba >> 24) & 0x0F) as u8));
        outb(ATA_SEC_CNT, 1);
        outb(ATA_LBA_LO, (lba & 0xFF) as u8);
        outb(ATA_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        outb(ATA_LBA_HI, ((lba >> 16) & 0xFF) as u8);
        outb(ATA_CMD, ATA_CMD_READ_PIO);
        let _ = inb(ATA_ALT_STATUS);
        if !ata_wait_drq() {
            return false;
        }
        for i in 0..256 {
            let w = inw(ATA_DATA);
            buf[i * 2] = (w & 0xFF) as u8;
            buf[i * 2 + 1] = (w >> 8) as u8;
        }
    }
    true
}

fn ata_write_sector(lba: u32, buf: &[u8; 512]) -> bool {
    if !ata_wait_not_busy() {
        return false;
    }
    unsafe {
        outb(ATA_DRIVE, 0xE0 | (((lba >> 24) & 0x0F) as u8));
        outb(ATA_SEC_CNT, 1);
        outb(ATA_LBA_LO, (lba & 0xFF) as u8);
        outb(ATA_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        outb(ATA_LBA_HI, ((lba >> 16) & 0xFF) as u8);
        outb(ATA_CMD, ATA_CMD_WRITE_PIO);
        let _ = inb(ATA_ALT_STATUS);
        if !ata_wait_drq() {
            return false;
        }
        for i in 0..256 {
            let w = (buf[i * 2] as u16) | ((buf[i * 2 + 1] as u16) << 8);
            outw(ATA_DATA, w);
        }
        outb(ATA_CMD, ATA_CMD_CACHE_FLUSH);
        ata_wait_not_busy();
    }
    true
}

#[inline]
fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline]
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl Fat32Volume {
    fn mount(bi: &GoseBootInfo) -> Self {
        let mut vol = Self {
            mounted: false,
            part_lba: 0,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            num_fats: 2,
            fat_size_sectors: 0,
            root_cluster: 2,
            first_data_sector: 0,
            total_clusters: 0,
            cwd_cluster: 2,
            cwd_path: String::from("/"),
        };

        if !libmargay::grant_ioport(bi.ata_pri_ioport_slot)
            || !libmargay::grant_ioport(bi.ata_ctl_ioport_slot)
        {
            return vol;
        }

        let mut sec0 = [0u8; 512];
        if !ata_read_sector(0, &mut sec0) || sec0[510] != 0x55 || sec0[511] != 0xAA {
            return vol;
        }

        let mut part_lba = 0u32;
        if &sec0[82..90] != b"FAT32   " {
            for i in 0..4 {
                let off = 446 + i * 16;
                if sec0[off + 4] == 0x0B || sec0[off + 4] == 0x0C {
                    part_lba = le_u32(&sec0, off + 8);
                    break;
                }
            }
            if part_lba == 0 || !ata_read_sector(part_lba, &mut sec0) {
                return vol;
            }
        }

        let bps = le_u16(&sec0, 11);
        let spc = sec0[13];
        let rsvd = le_u16(&sec0, 14);
        let nfats = sec0[16];
        let tot = {
            let s16 = le_u16(&sec0, 19) as u32;
            if s16 != 0 { s16 } else { le_u32(&sec0, 32) }
        };
        let fsz = le_u32(&sec0, 36);
        let root_c = le_u32(&sec0, 44);
        if bps != 512 || spc == 0 || fsz == 0 {
            return vol;
        }

        let first_data = (rsvd as u32) + (nfats as u32) * fsz;
        vol.mounted = true;
        vol.part_lba = part_lba;
        vol.sectors_per_cluster = spc;
        vol.reserved_sectors = rsvd;
        vol.num_fats = nfats;
        vol.fat_size_sectors = fsz;
        vol.root_cluster = root_c;
        vol.first_data_sector = first_data;
        vol.total_clusters = tot.saturating_sub(first_data) / (spc as u32);
        vol.cwd_cluster = root_c;
        libmargay::debug_print("[driverfs.elf] Real FAT32 mounted over ATA PIO\n");
        vol
    }

    #[inline]
    fn cluster_to_lba(&self, cluster: u32) -> u32 {
        self.part_lba
            + self.first_data_sector
            + (cluster.saturating_sub(2)) * (self.sectors_per_cluster as u32)
    }

    fn read_fat_entry(&self, cluster: u32) -> Option<u32> {
        let fat_off = cluster * 4;
        let sec = self.part_lba + (self.reserved_sectors as u32) + (fat_off / 512);
        let ent = (fat_off % 512) as usize;
        let mut buf = [0u8; 512];
        if !ata_read_sector(sec, &mut buf) {
            return None;
        }
        Some(le_u32(&buf, ent) & FAT32_MASK)
    }

    fn write_fat_entry(&self, cluster: u32, value: u32) -> bool {
        let fat_off = cluster * 4;
        let rel = fat_off / 512;
        let ent = (fat_off % 512) as usize;
        for f in 0..(self.num_fats as u32) {
            let sec = self.part_lba + (self.reserved_sectors as u32) + f * self.fat_size_sectors + rel;
            let mut buf = [0u8; 512];
            if !ata_read_sector(sec, &mut buf) {
                return false;
            }
            let updated = (le_u32(&buf, ent) & !FAT32_MASK) | (value & FAT32_MASK);
            buf[ent..ent + 4].copy_from_slice(&updated.to_le_bytes());
            if !ata_write_sector(sec, &buf) {
                return false;
            }
        }
        true
    }

    fn alloc_free_cluster(&self) -> Option<u32> {
        let max_c = (self.total_clusters + 2).min(65536);
        let mut buf = [0u8; 512];
        let mut cached = u32::MAX;
        for c in 2..max_c {
            let fat_off = c * 4;
            let sec = self.part_lba + (self.reserved_sectors as u32) + (fat_off / 512);
            let ent = (fat_off % 512) as usize;
            if sec != cached {
                if !ata_read_sector(sec, &mut buf) {
                    return None;
                }
                cached = sec;
            }
            if (le_u32(&buf, ent) & FAT32_MASK) == 0 && self.write_fat_entry(c, 0x0FFF_FFFF) {
                let zero = [0u8; 512];
                let base = self.cluster_to_lba(c);
                for s in 0..(self.sectors_per_cluster as u32) {
                    let _ = ata_write_sector(base + s, &zero);
                }
                return Some(c);
            }
        }
        None
    }

    fn free_chain(&self, start: u32) {
        let mut cur = start;
        for _ in 0..4096 {
            if cur < 2 || cur >= FAT32_EOC {
                break;
            }
            let next = self.read_fat_entry(cur).unwrap_or(FAT32_EOC);
            let _ = self.write_fat_entry(cur, 0);
            cur = next;
        }
    }

    fn list_dir(&self, dir_cluster: u32) -> Vec<DirEntryInfo> {
        let mut out = Vec::new();
        if !self.mounted || dir_cluster < 2 {
            return out;
        }
        let mut cur = dir_cluster;
        let mut buf = [0u8; 512];
        for _ in 0..256 {
            if cur < 2 || cur >= FAT32_EOC {
                break;
            }
            let base = self.cluster_to_lba(cur);
            for s in 0..(self.sectors_per_cluster as u32) {
                if !ata_read_sector(base + s, &mut buf) {
                    return out;
                }
                for idx in 0..16 {
                    let off = idx * 32;
                    if buf[off] == 0x00 {
                        return out;
                    }
                    if buf[off] == 0xE5 {
                        continue;
                    }
                    let attr = buf[off + 11];
                    if attr == 0x0F || (attr & 0x08) != 0 {
                        continue;
                    }
                    let hi = le_u16(&buf, off + 20) as u32;
                    let lo = le_u16(&buf, off + 26) as u32;
                    out.push(DirEntryInfo {
                        name: decode_8_3_name(&buf[off..off + 11]),
                        is_dir: (attr & 0x10) != 0,
                        size: le_u32(&buf, off + 28),
                        first_cluster: (hi << 16) | lo,
                    });
                }
            }
            cur = self.read_fat_entry(cur).unwrap_or(FAT32_EOC);
        }
        out
    }

    fn resolve_entry(&self, path: &str) -> Option<(u32, DirEntryInfo)> {
        let mut dir_c = if path.starts_with('/') {
            self.root_cluster
        } else {
            self.cwd_cluster
        };
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Some((
                self.root_cluster,
                DirEntryInfo {
                    name: String::from("/"),
                    is_dir: true,
                    size: 0,
                    first_cluster: self.root_cluster,
                },
            ));
        }
        for (i, part) in parts.iter().enumerate() {
            let found = self
                .list_dir(dir_c)
                .into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(part))?;
            let target_c = if found.first_cluster == 0 {
                self.root_cluster
            } else {
                found.first_cluster
            };
            if i + 1 == parts.len() {
                let mut res = found;
                res.first_cluster = target_c;
                return Some((dir_c, res));
            }
            if !found.is_dir {
                return None;
            }
            dir_c = target_c;
        }
        None
    }

    fn change_dir(&mut self, path: &str) -> bool {
        if path == "/" {
            self.cwd_cluster = self.root_cluster;
            self.cwd_path = String::from("/");
            return true;
        }
        if path == "." {
            return true;
        }
        let Some((_, entry)) = self.resolve_entry(path) else {
            return false;
        };
        if !entry.is_dir {
            return false;
        }
        self.cwd_cluster = entry.first_cluster;
        if path.starts_with('/') {
            self.cwd_path = String::from(path);
        } else if path == ".." {
            if let Some(pos) = self.cwd_path.rfind('/') {
                if pos == 0 {
                    self.cwd_path = String::from("/");
                } else {
                    self.cwd_path.truncate(pos);
                }
            }
        } else {
            if self.cwd_path != "/" {
                self.cwd_path.push('/');
            }
            self.cwd_path.push_str(&entry.name);
        }
        true
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let (_, entry) = self.resolve_entry(path)?;
        if entry.is_dir {
            return None;
        }
        let mut data = Vec::with_capacity(entry.size as usize);
        if entry.size == 0 || entry.first_cluster < 2 {
            return Some(data);
        }
        let mut cur = entry.first_cluster;
        let mut rem = entry.size as usize;
        let mut buf = [0u8; 512];
        for _ in 0..4096 {
            if cur < 2 || cur >= FAT32_EOC || rem == 0 {
                break;
            }
            let base = self.cluster_to_lba(cur);
            for s in 0..(self.sectors_per_cluster as u32) {
                if rem == 0 {
                    break;
                }
                if !ata_read_sector(base + s, &mut buf) {
                    return None;
                }
                let take = rem.min(512);
                data.extend_from_slice(&buf[..take]);
                rem -= take;
            }
            cur = self.read_fat_entry(cur).unwrap_or(FAT32_EOC);
        }
        Some(data)
    }

    fn write_file(&mut self, name: &str, data: &[u8]) -> bool {
        if !self.mounted {
            return false;
        }
        let (parent_c, leaf) = self.split_parent(name);
        let Some(parent_c) = parent_c else {
            return false;
        };
        let short_name = encode_8_3_name(leaf);
        if let Some((lba, off, old_c, _)) = self.find_raw_slot(parent_c, &short_name) {
            if old_c >= 2 {
                self.free_chain(old_c);
            }
            let fc = match self.write_data_clusters(data) {
                Some(c) => c,
                None if data.is_empty() => 0,
                None => return false,
            };
            return self.update_raw_slot(lba, off, &short_name, 0x20, fc, data.len() as u32);
        }
        let fc = match self.write_data_clusters(data) {
            Some(c) => c,
            None if data.is_empty() => 0,
            None => return false,
        };
        self.insert_dir_entry(parent_c, &short_name, 0x20, fc, data.len() as u32)
    }

    fn create_dir(&mut self, name: &str) -> bool {
        if !self.mounted || name.is_empty() {
            return false;
        }
        let (parent_c, leaf) = self.split_parent(name);
        let Some(parent_c) = parent_c else {
            return false;
        };
        if leaf.is_empty() || leaf == "." || leaf == ".." {
            return false;
        }
        let short_name = encode_8_3_name(leaf);
        if self.find_raw_slot(parent_c, &short_name).is_some() {
            return false;
        }
        let Some(new_c) = self.alloc_free_cluster() else {
            return false;
        };
        let mut dir_sec = [0u8; 512];
        let dot_parent = if parent_c == self.root_cluster { 0 } else { parent_c };
        write_raw_dir_entry(&mut dir_sec[0..32], b".          ", 0x10, new_c, 0);
        write_raw_dir_entry(&mut dir_sec[32..64], b"..         ", 0x10, dot_parent, 0);
        if !ata_write_sector(self.cluster_to_lba(new_c), &dir_sec) {
            self.free_chain(new_c);
            return false;
        }
        self.insert_dir_entry(parent_c, &short_name, 0x10, new_c, 0)
    }

    fn remove_entry(&mut self, name: &str, expect_dir: bool) -> Result<(), &'static str> {
        if !self.mounted {
            return Err("No FAT32 volume mounted");
        }
        let (parent_c, leaf) = self.split_parent(name);
        let parent_c = parent_c.ok_or("Parent directory not found")?;
        if leaf.is_empty() || leaf == "." || leaf == ".." {
            return Err("Invalid target name");
        }
        let short_name = encode_8_3_name(leaf);
        let (lba, off, fc, attr) = self
            .find_raw_slot(parent_c, &short_name)
            .ok_or("Target not found")?;
        let is_dir = (attr & 0x10) != 0;
        if expect_dir && !is_dir {
            return Err("Target is a file (use rm -file)");
        }
        if !expect_dir && is_dir {
            return Err("Target is a directory (use rm -dir)");
        }
        if is_dir && fc == self.cwd_cluster {
            return Err("Cannot remove current working directory");
        }
        if fc >= 2 {
            self.free_chain(fc);
        }
        let mut buf = [0u8; 512];
        if !ata_read_sector(lba, &mut buf) {
            return Err("Disk read error");
        }
        buf[off] = 0xE5;
        if !ata_write_sector(lba, &buf) {
            return Err("Disk write error");
        }
        Ok(())
    }

    fn split_parent<'a>(&self, path: &'a str) -> (Option<u32>, &'a str) {
        if let Some(pos) = path.rfind('/') {
            let dir_part = if pos == 0 { "/" } else { &path[..pos] };
            let leaf = &path[pos + 1..];
            match self.resolve_entry(dir_part) {
                Some((_, d)) if d.is_dir => (Some(d.first_cluster), leaf),
                _ => (None, leaf),
            }
        } else {
            (Some(self.cwd_cluster), path)
        }
    }

    fn write_data_clusters(&self, data: &[u8]) -> Option<u32> {
        if data.is_empty() {
            return Some(0);
        }
        let clus_bytes = (self.sectors_per_cluster as usize) * 512;
        let needed = (data.len() + clus_bytes - 1) / clus_bytes;
        let mut first = 0u32;
        let mut prev = 0u32;
        let mut off = 0usize;
        for _ in 0..needed {
            let c = self.alloc_free_cluster()?;
            if first == 0 {
                first = c;
            }
            if prev != 0 {
                let _ = self.write_fat_entry(prev, c);
            }
            let base = self.cluster_to_lba(c);
            for s in 0..(self.sectors_per_cluster as u32) {
                let mut sec = [0u8; 512];
                if off < data.len() {
                    let take = (data.len() - off).min(512);
                    sec[..take].copy_from_slice(&data[off..off + take]);
                    off += take;
                }
                if !ata_write_sector(base + s, &sec) {
                    return None;
                }
            }
            prev = c;
        }
        Some(first)
    }

    fn find_raw_slot(&self, dir_c: u32, short_name: &[u8; 11]) -> Option<(u32, usize, u32, u8)> {
        let mut cur = dir_c;
        let mut buf = [0u8; 512];
        for _ in 0..256 {
            if cur < 2 || cur >= FAT32_EOC {
                break;
            }
            let base = self.cluster_to_lba(cur);
            for s in 0..(self.sectors_per_cluster as u32) {
                let lba = base + s;
                if !ata_read_sector(lba, &mut buf) {
                    return None;
                }
                for idx in 0..16 {
                    let off = idx * 32;
                    if buf[off] == 0x00 {
                        return None;
                    }
                    if buf[off] == 0xE5 {
                        continue;
                    }
                    if &buf[off..off + 11] == short_name {
                        let attr = buf[off + 11];
                        let hi = le_u16(&buf, off + 20) as u32;
                        let lo = le_u16(&buf, off + 26) as u32;
                        return Some((lba, off, (hi << 16) | lo, attr));
                    }
                }
            }
            cur = self.read_fat_entry(cur).unwrap_or(FAT32_EOC);
        }
        None
    }

    fn update_raw_slot(
        &self,
        lba: u32,
        off: usize,
        short_name: &[u8; 11],
        attr: u8,
        fc: u32,
        size: u32,
    ) -> bool {
        let mut buf = [0u8; 512];
        if !ata_read_sector(lba, &mut buf) {
            return false;
        }
        write_raw_dir_entry(&mut buf[off..off + 32], short_name, attr, fc, size);
        ata_write_sector(lba, &buf)
    }

    fn insert_dir_entry(
        &self,
        dir_c: u32,
        short_name: &[u8; 11],
        attr: u8,
        fc: u32,
        size: u32,
    ) -> bool {
        let mut cur = dir_c;
        let mut buf = [0u8; 512];
        for _ in 0..256 {
            if cur < 2 || cur >= FAT32_EOC {
                break;
            }
            let base = self.cluster_to_lba(cur);
            for s in 0..(self.sectors_per_cluster as u32) {
                let lba = base + s;
                if !ata_read_sector(lba, &mut buf) {
                    return false;
                }
                for idx in 0..16 {
                    let off = idx * 32;
                    if buf[off] == 0x00 || buf[off] == 0xE5 {
                        return self.update_raw_slot(lba, off, short_name, attr, fc, size);
                    }
                }
            }
            let next = self.read_fat_entry(cur).unwrap_or(FAT32_EOC);
            if next >= FAT32_EOC {
                if let Some(nc) = self.alloc_free_cluster() {
                    let _ = self.write_fat_entry(cur, nc);
                    cur = nc;
                } else {
                    return false;
                }
            } else {
                cur = next;
            }
        }
        false
    }
}

fn write_raw_dir_entry(slot: &mut [u8], short_name: &[u8; 11], attr: u8, fc: u32, size: u32) {
    slot[0..11].copy_from_slice(short_name);
    slot[11] = attr;
    slot[20..22].copy_from_slice(&((fc >> 16) as u16).to_le_bytes());
    slot[26..28].copy_from_slice(&((fc & 0xFFFF) as u16).to_le_bytes());
    slot[28..32].copy_from_slice(&size.to_le_bytes());
}

fn decode_8_3_name(raw: &[u8]) -> String {
    let base = core::str::from_utf8(&raw[0..8]).unwrap_or("").trim_end();
    let ext = core::str::from_utf8(&raw[8..11]).unwrap_or("").trim_end();
    let mut out = String::from(base);
    if !ext.is_empty() {
        out.push('.');
        out.push_str(ext);
    }
    out
}

fn encode_8_3_name(name: &str) -> [u8; 11] {
    let mut out = [b' '; 11];
    let (base, ext) = match name.rfind('.') {
        Some(pos) => (&name[..pos], &name[pos + 1..]),
        None => (name, ""),
    };
    for (i, &b) in base.as_bytes().iter().take(8).enumerate() {
        out[i] = b.to_ascii_uppercase();
    }
    for (i, &b) in ext.as_bytes().iter().take(3).enumerate() {
        out[8 + i] = b.to_ascii_uppercase();
    }
    out
}

fn shm_read_str(len: u64) -> String {
    let l = (len as usize).min(512);
    let slice = unsafe { core::slice::from_raw_parts(SHM_FS_VA as *const u8, l) };
    String::from(core::str::from_utf8(slice).unwrap_or(""))
}

fn shm_write_bytes(data: &[u8]) -> usize {
    let len = data.len().min(SHM_SIZE_BYTES);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), SHM_FS_VA as *mut u8, len);
    }
    len
}

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    let bi = unsafe { &*(boot_info_ptr as *const GoseBootInfo) };
    if bi.shm_fs_slot != 0 {
        let _ = libmargay::shmem_map(bi.shm_fs_slot, SHM_FS_VA);
    }

    let mut vol = Fat32Volume::mount(bi);
    let ep = bi.ep_fs_slot;

    loop {
        let req = libmargay::ipc_recv(ep);
        match req.tag {
            FS_OP_IS_MOUNTED => {
                libmargay::ipc_reply(0, vol.mounted as u64, 0, 0, 0);
            }
            FS_OP_CWD => {
                let len = shm_write_bytes(vol.cwd_path.as_bytes());
                libmargay::ipc_reply(0, len as u64, 0, 0, 0);
            }
            FS_OP_LS => {
                let path = shm_read_str(req.r0);
                if !vol.mounted {
                    let len = shm_write_bytes(b"GOSE FS: No FAT32 volume mounted.\n");
                    libmargay::ipc_reply(0, len as u64, 0, 0, 0);
                    continue;
                }
                let cluster = if path.is_empty() {
                    Some(vol.cwd_cluster)
                } else {
                    match vol.resolve_entry(&path) {
                        Some((_, e)) if e.is_dir => Some(e.first_cluster),
                        _ => None,
                    }
                };
                match cluster {
                    Some(c) => {
                        let mut out = String::new();
                        for e in vol.list_dir(c) {
                            if e.is_dir {
                                out.push_str(&format!("  <DIR>          {}\n", e.name));
                            } else {
                                out.push_str(&format!("  {:>10} B   {}\n", e.size, e.name));
                            }
                        }
                        let len = shm_write_bytes(out.as_bytes());
                        libmargay::ipc_reply(0, len as u64, 1, 0, 0);
                    }
                    None => {
                        let msg = format!("ls: cannot access '{}': No such directory\n", path);
                        let len = shm_write_bytes(msg.as_bytes());
                        libmargay::ipc_reply(0, len as u64, 0, 0, 0);
                    }
                }
            }
            FS_OP_CD => {
                let path = shm_read_str(req.r0);
                let ok = vol.change_dir(&path);
                libmargay::ipc_reply(0, ok as u64, 0, 0, 0);
            }
            FS_OP_READ => {
                let path = shm_read_str(req.r0);
                match vol.read_file(&path) {
                    Some(bytes) => {
                        let len = shm_write_bytes(&bytes);
                        libmargay::ipc_reply(0, len as u64, 1, 0, 0);
                    }
                    None => {
                        libmargay::ipc_reply(0, 0, 0, 0, 0);
                    }
                }
            }
            FS_OP_WRITE => {
                let path = shm_read_str(req.r0);
                let dlen = (req.r1 as usize).min(SHM_SIZE_BYTES - 4096);
                let data = unsafe {
                    core::slice::from_raw_parts((SHM_FS_VA + 4096) as *const u8, dlen)
                };
                let ok = vol.write_file(&path, data);
                libmargay::ipc_reply(0, ok as u64, 0, 0, 0);
            }
            FS_OP_MKDIR => {
                let path = shm_read_str(req.r0);
                let ok = vol.create_dir(&path);
                libmargay::ipc_reply(0, ok as u64, 0, 0, 0);
            }
            FS_OP_RM => {
                let path = shm_read_str(req.r0);
                let expect_dir = req.r1 != 0;
                match vol.remove_entry(&path, expect_dir) {
                    Ok(()) => {
                        libmargay::ipc_reply(0, 1, 0, 0, 0);
                    }
                    Err(msg) => {
                        let len = shm_write_bytes(msg.as_bytes());
                        libmargay::ipc_reply(0, 0, len as u64, 0, 0);
                    }
                }
            }
            _ => {
                libmargay::ipc_reply(0, 0, 0, 0, 0);
            }
        }
    }
}
