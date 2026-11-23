//! Capability Derivation Tree (CDT)
//!
//! Tracks parent -> child derivation relationships across all CSpaces so that
//! `cap_revoke` recursively invalidates every capability derived from a root
//! or intermediate capability — even if it was transferred over IPC to another
//! Ring 3 server. Uses an iterative traversal (zero unbounded stack recursion).

use alloc::vec::Vec;

use crate::cap::object::CNodeId;
use crate::sched::sync::IrqSpinlock;

pub type CdtNodeId = u32;
pub const CDT_NONE: CdtNodeId = u32::MAX;

/// Back-pointer identifying the exact `(CNodeId, slot_idx)` holding a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotAddress {
    pub cnode_id: CNodeId,
    pub slot_idx: usize,
}

#[derive(Debug, Clone, Copy)]
struct CdtNode {
    slot: SlotAddress,
    parent: CdtNodeId,
    first_child: CdtNodeId,
    next_sibling: CdtNodeId,
    prev_sibling: CdtNodeId,
    in_use: bool,
}

impl CdtNode {
    const fn empty() -> Self {
        Self {
            slot: SlotAddress {
                cnode_id: 0,
                slot_idx: 0,
            },
            parent: CDT_NONE,
            first_child: CDT_NONE,
            next_sibling: CDT_NONE,
            prev_sibling: CDT_NONE,
            in_use: false,
        }
    }
}

struct CdtTable {
    nodes: Vec<CdtNode>,
    free_list: Vec<CdtNodeId>,
}

impl CdtTable {
    const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free_list: Vec::new(),
        }
    }

    fn alloc_node(&mut self, slot: SlotAddress, parent: CdtNodeId) -> CdtNodeId {
        let node = CdtNode {
            slot,
            parent,
            first_child: CDT_NONE,
            next_sibling: CDT_NONE,
            prev_sibling: CDT_NONE,
            in_use: true,
        };
        if let Some(id) = self.free_list.pop() {
            self.nodes[id as usize] = node;
            id
        } else {
            let id = self.nodes.len() as CdtNodeId;
            self.nodes.push(node);
            id
        }
    }

    fn insert_root(&mut self, slot: SlotAddress) -> CdtNodeId {
        self.alloc_node(slot, CDT_NONE)
    }

    fn insert_child(&mut self, parent_id: CdtNodeId, child_slot: SlotAddress) -> CdtNodeId {
        let child_id = self.alloc_node(child_slot, parent_id);
        if parent_id != CDT_NONE && (parent_id as usize) < self.nodes.len() {
            let old_first = self.nodes[parent_id as usize].first_child;
            self.nodes[child_id as usize].next_sibling = old_first;
            if old_first != CDT_NONE {
                self.nodes[old_first as usize].prev_sibling = child_id;
            }
            self.nodes[parent_id as usize].first_child = child_id;
        }
        child_id
    }

    /// Update the `SlotAddress` of an existing CDT node (used by `cap_move`).
    fn move_node(&mut self, node_id: CdtNodeId, new_slot: SlotAddress) {
        if node_id != CDT_NONE && (node_id as usize) < self.nodes.len() {
            self.nodes[node_id as usize].slot = new_slot;
        }
    }

    /// Remove a single node from the CDT, re-parenting its direct children to its
    /// parent so sibling/descendant revocation integrity is preserved.
    fn remove_node(&mut self, node_id: CdtNodeId) {
        if node_id == CDT_NONE || (node_id as usize) >= self.nodes.len() {
            return;
        }
        let node = self.nodes[node_id as usize];
        if !node.in_use {
            return;
        }

        // Unlink `node_id` from parent's child list
        if node.prev_sibling != CDT_NONE {
            self.nodes[node.prev_sibling as usize].next_sibling = node.next_sibling;
        } else if node.parent != CDT_NONE {
            self.nodes[node.parent as usize].first_child = node.next_sibling;
        }
        if node.next_sibling != CDT_NONE {
            self.nodes[node.next_sibling as usize].prev_sibling = node.prev_sibling;
        }

        // Re-parent all children of `node_id` to `node.parent`
        let mut child = node.first_child;
        while child != CDT_NONE {
            let next = self.nodes[child as usize].next_sibling;
            self.nodes[child as usize].parent = node.parent;
            self.nodes[child as usize].prev_sibling = CDT_NONE;
            self.nodes[child as usize].next_sibling = CDT_NONE;

            if node.parent != CDT_NONE {
                let old_first = self.nodes[node.parent as usize].first_child;
                self.nodes[child as usize].next_sibling = old_first;
                if old_first != CDT_NONE {
                    self.nodes[old_first as usize].prev_sibling = child;
                }
                self.nodes[node.parent as usize].first_child = child;
            }
            child = next;
        }

        self.nodes[node_id as usize] = CdtNode::empty();
        self.free_list.push(node_id);
    }

    /// Iteratively collect and unlink all descendant `SlotAddress`es under `root_id`.
    /// The `root_id` itself remains intact; only its derived subtree is revoked.
    fn detach_descendants(&mut self, root_id: CdtNodeId) -> Vec<SlotAddress> {
        let mut revoked_slots = Vec::new();
        if root_id == CDT_NONE || (root_id as usize) >= self.nodes.len() {
            return revoked_slots;
        }

        let mut stack: Vec<CdtNodeId> = Vec::new();
        let first_child = self.nodes[root_id as usize].first_child;
        self.nodes[root_id as usize].first_child = CDT_NONE;

        let mut cur = first_child;
        while cur != CDT_NONE {
            stack.push(cur);
            cur = self.nodes[cur as usize].next_sibling;
        }

        while let Some(nid) = stack.pop() {
            let n = self.nodes[nid as usize];
            if !n.in_use {
                continue;
            }
            revoked_slots.push(n.slot);

            let mut c = n.first_child;
            while c != CDT_NONE {
                stack.push(c);
                c = self.nodes[c as usize].next_sibling;
            }

            self.nodes[nid as usize] = CdtNode::empty();
            self.free_list.push(nid);
        }

        revoked_slots
    }

    fn is_original(&self, node_id: CdtNodeId) -> bool {
        if node_id == CDT_NONE || (node_id as usize) >= self.nodes.len() {
            return false;
        }
        let n = self.nodes[node_id as usize];
        n.in_use && n.parent == CDT_NONE
    }
}

static CDT: IrqSpinlock<CdtTable> = IrqSpinlock::new(CdtTable::new());

pub fn cdt_insert_root(slot: SlotAddress) -> CdtNodeId {
    CDT.lock().insert_root(slot)
}

pub fn cdt_insert_child(parent_id: CdtNodeId, child_slot: SlotAddress) -> CdtNodeId {
    CDT.lock().insert_child(parent_id, child_slot)
}

pub fn cdt_move_node(node_id: CdtNodeId, new_slot: SlotAddress) {
    CDT.lock().move_node(node_id, new_slot);
}

pub fn cdt_remove_node(node_id: CdtNodeId) {
    CDT.lock().remove_node(node_id);
}

pub fn cdt_detach_descendants(root_id: CdtNodeId) -> Vec<SlotAddress> {
    CDT.lock().detach_descendants(root_id)
}

pub fn cdt_is_original(node_id: CdtNodeId) -> bool {
    CDT.lock().is_original(node_id)
}
