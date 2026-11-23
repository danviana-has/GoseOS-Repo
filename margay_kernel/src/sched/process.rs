//! Process / Task Container (VSpace + CSpace + I/O Permission Bitmap)
//!
//! A Process in Margay is strictly a security and resource isolation boundary:
//! - Isolated 4-level virtual `AddressSpace` (VSpace)
//! - Root `CNode` capability table (CSpace)
//! - Per-process 8 KiB x86 I/O Permission Bitmap (IOPB) for Ring 3 drivers
//! - List of owned execution `Thread`s

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::tss::IOPB_BYTES;
use crate::cap::cnode;
use crate::cap::object::{CNodeId, ThreadId};
use crate::mm::paging::MapError;
use crate::mm::vspace::AddressSpace;

pub type ProcessId = u64;

static NEXT_PID: AtomicU64 = AtomicU64::new(1);

pub struct Process {
    pub pid: ProcessId,
    pub name: [u8; 32],
    pub vspace: AddressSpace,
    pub root_cnode: CNodeId,
    pub iopb: Box<[u8; IOPB_BYTES]>,
    pub has_custom_iopb: bool,
    pub threads: Vec<ThreadId>,
}

impl Process {
    /// Create a new isolated Ring 3 Process with its own VSpace and root CNode.
    pub fn new(name_str: &str, cnode_radix: u8) -> Result<Self, MapError> {
        let vspace = AddressSpace::new_user()?;
        let root_cnode = cnode::create_cnode(cnode_radix);
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);

        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let copy_len = bytes.len().min(31);
        name[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Ok(Self {
            pid,
            name,
            vspace,
            root_cnode,
            iopb: Box::new([0xFFu8; IOPB_BYTES]),
            has_custom_iopb: false,
            threads: Vec::new(),
        })
    }

    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).unwrap_or("unnamed")
    }

    /// Grant this process Ring 3 hardware access to I/O port range `[start..=end]`.
    pub fn allow_io_range(&mut self, start: u16, end: u16) {
        if start > end {
            return;
        }
        for port in start..=end {
            let byte_idx = (port as usize) >> 3;
            let bit = port & 7;
            self.iopb[byte_idx] &= !(1u8 << bit);
        }
        self.has_custom_iopb = true;
    }

    /// Revoke Ring 3 hardware access to I/O port range `[start..=end]`.
    pub fn deny_io_range(&mut self, start: u16, end: u16) {
        if start > end {
            return;
        }
        for port in start..=end {
            let byte_idx = (port as usize) >> 3;
            let bit = port & 7;
            self.iopb[byte_idx] |= 1u8 << bit;
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        cnode::destroy_cnode(self.root_cnode);
    }
}
