//! Capability Security Model (CSpace, CNode, CDT, Rights & Operations)
//!
//! Inspired by seL4 and Zircon: Ring 3 servers hold zero ambient authority.
//! Every memory frame, address space, IPC endpoint, notification, thread,
//! I/O port range, and hardware IRQ requires a valid, unforgeable Capability.

pub mod cdt;
pub mod cnode;
pub mod object;
pub mod ops;
pub mod rights;

pub use cdt::SlotAddress;
pub use cnode::{CPtr, CNode};
pub use object::{CNodeId, CapObject, Capability, FrameSize};
pub use ops::{
    cap_copy, cap_delete, cap_insert_root, cap_mint, cap_move, cap_mutate, cap_retype, cap_revoke,
    CapError, RetypeKind,
};
pub use rights::CapRights;

/// Initialize the Capability subsystem.
pub fn init() {
    crate::kinfo!(
        "CAP",
        "Capability Security Engine online (CSpace radix CNodes + iterative CDT)"
    );
}
