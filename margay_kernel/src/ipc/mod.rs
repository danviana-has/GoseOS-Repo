//! Inter-Process Communication (IPC) Subsystem
//!
//! The heart of the Margay Microkernel:
//! - Synchronous Rendezvous Endpoints (Fastpath register-to-register transfer
//!   with optional Capability delegation)
//! - Asynchronous Lock-Free Bitmask Notifications (Event Flags & IRQ delivery)
//! - Zero-Copy Shared Memory Regions controlled by Capabilities

pub mod endpoint;
pub mod notification;
pub mod shmem;

use crate::cap::SlotAddress;

/// Short IPC message transported directly in CPU registers (zero kernel buffer copy).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcMessage {
    /// Message metadata tag (label, word count, flags).
    pub tag: u64,
    /// Up to 4 payload words passed directly in general-purpose registers (rdi/rsi/rdx/r10/r8/r9).
    pub regs: [u64; 4],
    /// Immutable sender badge stamped on the Endpoint capability.
    pub badge: u64,
    /// Optional capability slot to transfer along with the message (requires GRANT right).
    pub cap_src: Option<SlotAddress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    InvalidEndpoint,
    InvalidNotification,
    InvalidSharedMem,
    NoReplyPending,
    WouldBlock,
    OutOfMemory,
    PermissionDenied,
    InvalidAddress,
}

/// Initialize the IPC subsystem.
pub fn init() {
    crate::kinfo!(
        "IPC",
        "Fastpath Rendezvous Endpoints, Async Notifications & Zero-Copy ShMem online"
    );
}
