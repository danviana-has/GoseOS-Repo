//! CSpace & CNode Hierarchical Capability Tables
//!
//! Each Process owns a root `CNode` (Capability Node) of `2^radix_bits` slots.
//! CNodes can contain capabilities to child CNodes, forming a guarded radix
//! tree (CSpace) resolved by `cspace_resolve(root_cnode, cptr, depth)`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::cdt::{CdtNodeId, SlotAddress, CDT_NONE};
use crate::cap::object::{CNodeId, CapObject, Capability};
use crate::sched::sync::IrqSpinlock;

/// Capability Pointer (`CPtr`) passed by Ring 3 servers in syscall registers.
///
/// Encoding:
/// - Bits `63..56`: `depth` (0 = flat lookup in root CNode; 1..=56 = hierarchical
///   multi-level radix traversal starting from root CNode).
/// - Bits `55..0`: CSpace path bits / flat slot index.
pub type CPtr = u64;

/// Construct a hierarchical `CPtr` with explicit bit `depth` (1..=56).
#[inline]
pub const fn make_hierarchical_cptr(path: u64, depth: u8) -> CPtr {
    ((depth as u64) << 56) | (path & 0x00FF_FFFF_FFFF_FFFF)
}

/// Decode a `CPtr` into `(path, depth)`.
#[inline]
pub const fn decode_cptr(cptr: CPtr) -> (u64, u8) {
    let depth = ((cptr >> 56) & 0xFF) as u8;
    let path = cptr & 0x00FF_FFFF_FFFF_FFFF;
    (path, depth)
}

/// A single slot inside a `CNode`, pairing a `Capability` with its CDT link.
#[derive(Debug, Clone, Copy)]
pub struct CapSlot {
    pub cap: Capability,
    pub cdt_node: CdtNodeId,
}

impl CapSlot {
    pub const fn empty() -> Self {
        Self {
            cap: Capability::null(),
            cdt_node: CDT_NONE,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cap.is_null()
    }

    pub fn clear(&mut self) {
        self.cap = Capability::null();
        self.cdt_node = CDT_NONE;
    }
}

/// Fixed-radix table of capability slots.
pub struct CNode {
    pub id: CNodeId,
    pub radix_bits: u8,
    pub slots: Vec<CapSlot>,
}

impl CNode {
    pub fn new(id: CNodeId, radix_bits: u8) -> Self {
        let clamped = radix_bits.clamp(2, 12); // 4 .. 4096 slots
        let count = 1usize << clamped;
        let mut slots = Vec::with_capacity(count);
        slots.resize(count, CapSlot::empty());
        Self {
            id,
            radix_bits: clamped,
            slots,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    #[inline]
    pub fn get(&self, idx: usize) -> Option<&CapSlot> {
        self.slots.get(idx)
    }

    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut CapSlot> {
        self.slots.get_mut(idx)
    }

    /// Find the first unoccupied slot index (skipping slot 0, which is reserved as Null).
    pub fn find_free_slot(&self) -> Option<usize> {
        for i in 1..self.slots.len() {
            if self.slots[i].is_empty() {
                return Some(i);
            }
        }
        None
    }
}

/// Global CNode Registry mapping `CNodeId -> CNode`.
struct CNodeRegistry {
    cnodes: BTreeMap<CNodeId, CNode>,
}

impl CNodeRegistry {
    const fn new() -> Self {
        Self {
            cnodes: BTreeMap::new(),
        }
    }
}

static NEXT_CNODE_ID: AtomicU64 = AtomicU64::new(1);
static CNODE_REGISTRY: IrqSpinlock<CNodeRegistry> = IrqSpinlock::new(CNodeRegistry::new());

/// Create a new `CNode` with `2^radix_bits` slots and register it globally.
pub fn create_cnode(radix_bits: u8) -> CNodeId {
    let id = NEXT_CNODE_ID.fetch_add(1, Ordering::Relaxed);
    let node = CNode::new(id, radix_bits);
    CNODE_REGISTRY.lock().cnodes.insert(id, node);
    id
}

/// Destroy a `CNode` and remove it from the global registry.
pub fn destroy_cnode(id: CNodeId) {
    CNODE_REGISTRY.lock().cnodes.remove(&id);
}

/// Resolve a `CPtr` in a process's CSpace starting at `root_cnode`.
///
/// For single-level CSpaces (depth = 0 or flat index < radix capacity), `cptr`
/// directly indexes `root_cnode`. For multi-level guarded CSpaces (`depth > 0`),
/// traverses child `CapObject::CNode` entries checking guard bits at each hop.
pub fn resolve_slot(root_cnode: CNodeId, cptr: CPtr, depth: u8) -> Option<SlotAddress> {
    let reg = CNODE_REGISTRY.lock();
    let mut cur_id = root_cnode;

    // Fast path: flat lookup in root CNode (depth == 0)
    if depth == 0 {
        let node = reg.cnodes.get(&cur_id)?;
        let idx = cptr as usize;
        if idx < node.capacity() {
            return Some(SlotAddress {
                cnode_id: cur_id,
                slot_idx: idx,
            });
        }
        return None;
    }

    // Multi-level guarded radix traversal
    let mut bits_remaining = depth.min(64) as usize;
    let mut cursor = cptr;

    for _hop in 0..8 {
        let node = reg.cnodes.get(&cur_id)?;
        let radix = node.radix_bits as usize;
        if bits_remaining < radix {
            return None;
        }
        let shift = bits_remaining - radix;
        let idx = ((cursor >> shift) & ((1u64 << radix) - 1)) as usize;
        bits_remaining -= radix;

        if bits_remaining == 0 {
            return Some(SlotAddress {
                cnode_id: cur_id,
                slot_idx: idx,
            });
        }

        let slot = node.get(idx)?;
        match slot.cap.object {
            CapObject::CNode { id: next_id, .. } => {
                // Verify CNode guard bits if configured
                let gbits = slot.cap.guard_bits as usize;
                if gbits > 0 {
                    if bits_remaining < gbits {
                        return None;
                    }
                    let gshift = bits_remaining - gbits;
                    let observed = (cursor >> gshift) & ((1u64 << gbits) - 1);
                    if observed != slot.cap.guard {
                        return None;
                    }
                    bits_remaining -= gbits;
                }
                cursor &= (1u64 << bits_remaining).wrapping_sub(1);
                cur_id = next_id;
            }
            _ => return None,
        }
    }
    None
}

/// Read a copy of the `CapSlot` at `addr`.
pub fn read_slot(addr: SlotAddress) -> Option<CapSlot> {
    let reg = CNODE_REGISTRY.lock();
    reg.cnodes.get(&addr.cnode_id)?.get(addr.slot_idx).copied()
}

/// Resolve a `CPtr` using its embedded depth byte (bits 63..56):
/// `depth == 0` performs a flat lookup in `root_cnode`; `depth > 0` performs
/// multi-level guarded radix traversal across child `CNode`s.
pub fn resolve_cptr(root_cnode: CNodeId, cptr: CPtr) -> Option<SlotAddress> {
    let (path, depth) = decode_cptr(cptr);
    resolve_slot(root_cnode, path, depth)
}

/// Read just the `Capability` at `(root_cnode, cptr)` (supports both flat and hierarchical CPtrs).
pub fn lookup_cap(root_cnode: CNodeId, cptr: CPtr) -> Option<Capability> {
    let addr = resolve_cptr(root_cnode, cptr)?;
    let slot = read_slot(addr)?;
    if slot.is_empty() {
        None
    } else {
        Some(slot.cap)
    }
}

/// Write a `CapSlot` directly (internal to `cap::ops`).
pub(crate) fn write_slot(addr: SlotAddress, slot: CapSlot) -> bool {
    let mut reg = CNODE_REGISTRY.lock();
    if let Some(node) = reg.cnodes.get_mut(&addr.cnode_id) {
        if let Some(s) = node.get_mut(addr.slot_idx) {
            *s = slot;
            return true;
        }
    }
    false
}

/// Clear a slot directly (used during revocation / deletion).
pub(crate) fn clear_slot(addr: SlotAddress) {
    let mut reg = CNODE_REGISTRY.lock();
    if let Some(node) = reg.cnodes.get_mut(&addr.cnode_id) {
        if let Some(s) = node.get_mut(addr.slot_idx) {
            s.clear();
        }
    }
}

/// Find an empty slot inside `cnode_id`.
pub fn find_free_slot(cnode_id: CNodeId) -> Option<usize> {
    let reg = CNODE_REGISTRY.lock();
    reg.cnodes.get(&cnode_id)?.find_free_slot()
}
