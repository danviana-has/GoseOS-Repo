//! Capability Operations: Insert, Copy, Mint, Move, Mutate, Delete, Revoke
//!
//! Enforces strict capability security invariants:
//! - Rights can only be attenuated (`CapRights::attenuate`), never amplified.
//! - Badges are immutable once set.
//! - Every derivation links into the global CDT so `cap_revoke` invalidates
//!   all transitive descendants across all CSpaces.

use core::sync::atomic::Ordering;

use crate::cap::cdt::{self, SlotAddress};
use crate::cap::cnode::{self, CapSlot};
use crate::cap::object::{CNodeId, CapObject, Capability, FrameSize};
use crate::cap::rights::CapRights;
use crate::debug::telemetry::TELEMETRY;
use crate::ipc::{endpoint, notification};
use crate::mm::frame::{frame_flags, frame_meta, PAGE_SIZE};
use crate::mm::phys_to_virt;
use crate::sched::process::Process;

/// Target kernel object types that can be carved from `CapObject::UntypedMemory`.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetypeKind {
    Frame4K = 1,
    Endpoint = 2,
    Notification = 3,
    CNode = 4,
    VSpace = 5,
}

impl RetypeKind {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(Self::Frame4K),
            2 => Some(Self::Endpoint),
            3 => Some(Self::Notification),
            4 => Some(Self::CNode),
            5 => Some(Self::VSpace),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    InvalidSlot,
    SlotEmpty,
    SlotOccupied,
    InsufficientRights,
    NotOriginal,
    CannotDerive,
    OutOfMemory,
    InvalidObjectType,
}

/// Insert a fresh root capability into `(cnode_id, slot_idx)` with a new CDT root node.
pub fn cap_insert_root(
    cnode_id: CNodeId,
    slot_idx: usize,
    cap: Capability,
) -> Result<(), CapError> {
    let addr = SlotAddress { cnode_id, slot_idx };
    let existing = cnode::read_slot(addr).ok_or(CapError::InvalidSlot)?;
    if !existing.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    let cdt_id = cdt::cdt_insert_root(addr);
    let ok = cnode::write_slot(
        addr,
        CapSlot {
            cap,
            cdt_node: cdt_id,
        },
    );
    if ok {
        Ok(())
    } else {
        cdt::cdt_remove_node(cdt_id);
        Err(CapError::InvalidSlot)
    }
}

/// Copy a capability from `src` to `dst`, attenuating rights to `rights_mask`,
/// and linking `dst` as a child of `src` in the CDT.
pub fn cap_copy(
    src: SlotAddress,
    dst: SlotAddress,
    rights_mask: CapRights,
) -> Result<(), CapError> {
    cap_mint(src, dst, rights_mask, 0)
}

/// Mint a derived capability from `src` to `dst` with attenuated `rights_mask`
/// and an optional immutable `badge`. Requires `CapRights::DERIVE` on `src`.
pub fn cap_mint(
    src: SlotAddress,
    dst: SlotAddress,
    rights_mask: CapRights,
    badge: u64,
) -> Result<(), CapError> {
    TELEMETRY.cap_invocations.fetch_add(1, Ordering::Relaxed);

    let src_slot = cnode::read_slot(src).ok_or(CapError::InvalidSlot)?;
    if src_slot.is_empty() {
        return Err(CapError::SlotEmpty);
    }
    if !src_slot.cap.has_rights(CapRights::DERIVE) {
        return Err(CapError::InsufficientRights);
    }
    // Single-use Reply capabilities cannot be copied/minted.
    if matches!(src_slot.cap.object, CapObject::Reply { .. }) {
        return Err(CapError::CannotDerive);
    }

    let dst_slot = cnode::read_slot(dst).ok_or(CapError::InvalidSlot)?;
    if !dst_slot.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    let derived_cap = src_slot.cap.mint(rights_mask, badge);
    let child_cdt = cdt::cdt_insert_child(src_slot.cdt_node, dst);

    if !cnode::write_slot(
        dst,
        CapSlot {
            cap: derived_cap,
            cdt_node: child_cdt,
        },
    ) {
        cdt::cdt_remove_node(child_cdt);
        return Err(CapError::InvalidSlot);
    }
    Ok(())
}

/// Move a capability from `src` to `dst`, preserving its exact position in the CDT.
pub fn cap_move(src: SlotAddress, dst: SlotAddress) -> Result<(), CapError> {
    TELEMETRY.cap_invocations.fetch_add(1, Ordering::Relaxed);

    let src_slot = cnode::read_slot(src).ok_or(CapError::InvalidSlot)?;
    if src_slot.is_empty() {
        return Err(CapError::SlotEmpty);
    }
    let dst_slot = cnode::read_slot(dst).ok_or(CapError::InvalidSlot)?;
    if !dst_slot.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    cdt::cdt_move_node(src_slot.cdt_node, dst);
    cnode::write_slot(dst, src_slot);
    cnode::clear_slot(src);
    Ok(())
}

/// Atomically move a capability from `src` to `dst` while attenuating its rights
/// and stamping an optional badge (without creating a new CDT child).
pub fn cap_mutate(
    src: SlotAddress,
    dst: SlotAddress,
    rights_mask: CapRights,
    badge: u64,
) -> Result<(), CapError> {
    TELEMETRY.cap_invocations.fetch_add(1, Ordering::Relaxed);

    let src_slot = cnode::read_slot(src).ok_or(CapError::InvalidSlot)?;
    if src_slot.is_empty() {
        return Err(CapError::SlotEmpty);
    }
    let dst_slot = cnode::read_slot(dst).ok_or(CapError::InvalidSlot)?;
    if !dst_slot.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    let mutated = src_slot.cap.mint(rights_mask, badge);
    cdt::cdt_move_node(src_slot.cdt_node, dst);
    cnode::write_slot(
        dst,
        CapSlot {
            cap: mutated,
            cdt_node: src_slot.cdt_node,
        },
    );
    cnode::clear_slot(src);
    Ok(())
}

/// Delete a single capability slot and unlink it from the CDT.
pub fn cap_delete(target: SlotAddress) -> Result<(), CapError> {
    TELEMETRY.cap_invocations.fetch_add(1, Ordering::Relaxed);

    let slot = cnode::read_slot(target).ok_or(CapError::InvalidSlot)?;
    if slot.is_empty() {
        return Err(CapError::SlotEmpty);
    }

    cdt::cdt_remove_node(slot.cdt_node);
    cnode::clear_slot(target);
    Ok(())
}

/// Recursively revoke ALL capabilities derived from `target` across all CSpaces.
/// Requires `CapRights::REVOKE` on `target`. Returns the count of revoked slots.
pub fn cap_revoke(target: SlotAddress) -> Result<usize, CapError> {
    TELEMETRY.cap_invocations.fetch_add(1, Ordering::Relaxed);

    let slot = cnode::read_slot(target).ok_or(CapError::InvalidSlot)?;
    if slot.is_empty() {
        return Err(CapError::SlotEmpty);
    }
    if !slot.cap.has_rights(CapRights::REVOKE) {
        return Err(CapError::InsufficientRights);
    }

    let descendants = cdt::cdt_detach_descendants(slot.cdt_node);
    let count = descendants.len();
    for addr in descendants {
        cnode::clear_slot(addr);
    }

    TELEMETRY
        .cap_revocations
        .fetch_add(count as u64, Ordering::Relaxed);
    Ok(count)
}

/// Retype raw physical memory from a `CapObject::UntypedMemory` capability into
/// a typed kernel object (`Frame4K`, `Endpoint`, `Notification`, `CNode`, or `VSpace`).
///
/// Advances the `UntypedMemory` watermark monotonically and links the new object
/// as a CDT child of `untyped_src` so `cap_revoke(untyped_src)` reclaims authority.
pub fn cap_retype(
    untyped_src: SlotAddress,
    dst: SlotAddress,
    kind: RetypeKind,
    size_param: u64,
) -> Result<CapObject, CapError> {
    TELEMETRY.cap_invocations.fetch_add(1, Ordering::Relaxed);

    let mut src_slot = cnode::read_slot(untyped_src).ok_or(CapError::InvalidSlot)?;
    if src_slot.is_empty() {
        return Err(CapError::SlotEmpty);
    }
    if !src_slot.cap.has_rights(CapRights::WRITE) {
        return Err(CapError::InsufficientRights);
    }

    let (base_paddr, size_bits, watermark) = match src_slot.cap.object {
        CapObject::UntypedMemory {
            paddr,
            size_bits,
            watermark,
        } => (paddr, size_bits, watermark),
        _ => return Err(CapError::InvalidObjectType),
    };

    let dst_slot = cnode::read_slot(dst).ok_or(CapError::InvalidSlot)?;
    if !dst_slot.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    let total_bytes = 1u64.checked_shl(size_bits as u32).ok_or(CapError::OutOfMemory)?;
    let (obj_bytes, obj_align): (u64, u64) = match kind {
        RetypeKind::Frame4K => (PAGE_SIZE as u64, PAGE_SIZE as u64),
        RetypeKind::Endpoint => (256, 64),
        RetypeKind::Notification => (256, 64),
        RetypeKind::CNode => {
            let radix = (size_param as u8).clamp(2, 10);
            (((1u64 << radix) * 32).max(256), 64)
        }
        RetypeKind::VSpace => (PAGE_SIZE as u64, PAGE_SIZE as u64),
    };

    let aligned_off = (watermark + obj_align - 1) & !(obj_align - 1);
    let new_watermark = aligned_off.checked_add(obj_bytes).ok_or(CapError::OutOfMemory)?;
    if new_watermark > total_bytes {
        return Err(CapError::OutOfMemory);
    }

    let carved_paddr = base_paddr + aligned_off;

    let new_obj = match kind {
        RetypeKind::Frame4K => {
            // Zero the freshly carved 4 KiB frame and set its PageFrame refcount to 1
            unsafe {
                core::ptr::write_bytes(phys_to_virt(carved_paddr) as *mut u8, 0, PAGE_SIZE);
            }
            if let Some(meta) = frame_meta(carved_paddr) {
                meta.refcount.store(1, Ordering::Release);
                meta.set_flags(frame_flags::USER);
            }
            CapObject::Frame {
                paddr: carved_paddr,
                size: FrameSize::Size4K,
                is_device: false,
            }
        }
        RetypeKind::Endpoint => {
            let id = endpoint::create_endpoint();
            CapObject::Endpoint { id }
        }
        RetypeKind::Notification => {
            let id = notification::create_notification();
            CapObject::Notification { id }
        }
        RetypeKind::CNode => {
            let radix_bits = (size_param as u8).clamp(2, 10);
            let id = cnode::create_cnode(radix_bits);
            CapObject::CNode { id, radix_bits }
        }
        RetypeKind::VSpace => {
            let proc = Process::new("retyped_vspace", 6).map_err(|_| CapError::OutOfMemory)?;
            let vspace_id = proc.vspace.id;
            crate::sched::register_process(proc);
            CapObject::VSpace { id: vspace_id }
        }
    };

    // Update UntypedMemory watermark in source slot
    src_slot.cap.object = CapObject::UntypedMemory {
        paddr: base_paddr,
        size_bits,
        watermark: new_watermark,
    };
    cnode::write_slot(untyped_src, src_slot);

    // Insert new object capability as a CDT child of `untyped_src`
    let child_cdt = cdt::cdt_insert_child(src_slot.cdt_node, dst);
    let new_cap = Capability::new(new_obj, CapRights::ALL);
    if !cnode::write_slot(
        dst,
        CapSlot {
            cap: new_cap,
            cdt_node: child_cdt,
        },
    ) {
        cdt::cdt_remove_node(child_cdt);
        return Err(CapError::InvalidSlot);
    }

    Ok(new_obj)
}
