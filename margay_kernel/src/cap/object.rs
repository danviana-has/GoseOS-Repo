//! Kernel Object Descriptors Managed by Capabilities
//!
//! Every hardware and kernel resource accessible to Ring 3 servers is
//! represented as a strongly-typed `CapObject`.

use crate::cap::rights::CapRights;

pub type CNodeId = u64;
pub type EndpointId = u64;
pub type NotificationId = u64;
pub type SharedMemId = u64;
pub type ThreadId = u64;
pub type VSpaceId = u64;

/// Physical frame granularity represented by a `CapObject::Frame`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSize {
    Size4K = 0,
    Size2M = 1,
    Size1G = 2,
}

impl FrameSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size4K => 4096,
            Self::Size2M => 2 * 1024 * 1024,
            Self::Size1G => 1024 * 1024 * 1024,
        }
    }
}

/// Typed kernel object referenced by a `Capability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapObject {
    /// Empty / revoked slot.
    Null,
    /// Raw untyped physical memory region that can be retyped into kernel objects.
    UntypedMemory {
        paddr: u64,
        size_bits: u8,
        watermark: u64,
    },
    /// Physical memory frame (RAM or MMIO device page).
    Frame {
        paddr: u64,
        size: FrameSize,
        is_device: bool,
    },
    /// Hardware paging structure (PML4 / PDPT / PD / PT).
    PageTable {
        paddr: u64,
        level: u8,
    },
    /// Virtual Address Space (VSpace).
    VSpace {
        id: VSpaceId,
    },
    /// Capability Node (hierarchical CSpace table).
    CNode {
        id: CNodeId,
        radix_bits: u8,
    },
    /// Synchronous Rendezvous IPC Endpoint.
    Endpoint {
        id: EndpointId,
    },
    /// Asynchronous Atomic Bitmask Notification.
    Notification {
        id: NotificationId,
    },
    /// Execution Thread (TCB).
    Thread {
        tid: ThreadId,
    },
    /// Delegated x86 I/O Port range `[start_port..=end_port]`.
    IoPort {
        start_port: u16,
        end_port: u16,
    },
    /// Singleton authority to mint `IrqHandler` capabilities for hardware GSIs.
    IrqControl,
    /// Authority to bind, unmask, and acknowledge a specific hardware IRQ line.
    IrqHandler {
        irq_num: u8,
    },
    /// Zero-copy Shared Memory region mappable into multiple VSpaces.
    SharedMem {
        id: SharedMemId,
    },
    /// Single-use Reply capability minted automatically by `ipc_call`.
    Reply {
        caller_tid: ThreadId,
    },
}

/// Complete unforgeable capability descriptor stored inside a `CapSlot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub object: CapObject,
    pub rights: CapRights,
    /// Optional immutable badge stamped via `cap_mint` (delivered to IPC receivers
    /// or ORed into Notification bitmasks).
    pub badge: u64,
    /// Optional CNode guard value for multi-level CSpace path resolution.
    pub guard: u64,
    pub guard_bits: u8,
}

impl Capability {
    pub const fn null() -> Self {
        Self {
            object: CapObject::Null,
            rights: CapRights::NONE,
            badge: 0,
            guard: 0,
            guard_bits: 0,
        }
    }

    pub const fn new(object: CapObject, rights: CapRights) -> Self {
        Self {
            object,
            rights,
            badge: 0,
            guard: 0,
            guard_bits: 0,
        }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self.object, CapObject::Null)
    }

    #[inline]
    pub fn has_rights(&self, req: CapRights) -> bool {
        !self.is_null() && self.rights.contains(req)
    }

    /// Create a minted derivative with attenuated rights and an optional badge.
    /// If this capability already has a non-zero badge, the badge cannot be forged
    /// or overwritten by a downstream holder.
    pub fn mint(&self, new_rights: CapRights, new_badge: u64) -> Self {
        let effective_badge = if self.badge != 0 { self.badge } else { new_badge };
        Self {
            object: self.object,
            rights: self.rights.attenuate(new_rights),
            badge: effective_badge,
            guard: self.guard,
            guard_bits: self.guard_bits,
        }
    }
}
