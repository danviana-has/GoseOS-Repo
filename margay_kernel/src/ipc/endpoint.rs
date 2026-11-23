//! Synchronous Rendezvous IPC Endpoints (Fastpath Register Transfer)
//!
//! Supports `ipc_send`, `ipc_recv`, `ipc_call` (send + single-use Reply),
//! `ipc_reply`, and `ipc_reply_wait` (atomic reply + wait for next request).
//! Messages are transferred directly between sender and receiver TCB register
//! slots without allocating or copying intermediate kernel message buffers.

use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::object::{EndpointId, ThreadId};
use crate::cap::{self, CapRights, SlotAddress};
use crate::debug::telemetry::TELEMETRY;
use crate::ipc::{IpcError, IpcMessage};
use crate::sched::sync::IrqSpinlock;
use crate::sched::thread::ThreadState;

struct EndpointWaiter {
    tid: ThreadId,
    is_call: bool,
    badge: u64,
}

struct Endpoint {
    _id: EndpointId,
    send_queue: VecDeque<EndpointWaiter>,
    recv_queue: VecDeque<ThreadId>,
}

impl Endpoint {
    fn new(id: EndpointId) -> Self {
        Self {
            _id: id,
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
        }
    }
}

static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(1);
static ENDPOINTS: IrqSpinlock<BTreeMap<EndpointId, Endpoint>> = IrqSpinlock::new(BTreeMap::new());

/// Create a new synchronous IPC Endpoint and return its unique `EndpointId`.
pub fn create_endpoint() -> EndpointId {
    let id = NEXT_ENDPOINT_ID.fetch_add(1, Ordering::Relaxed);
    ENDPOINTS.lock().insert(id, Endpoint::new(id));
    id
}

/// Destroy an Endpoint and wake any waiting threads.
pub fn destroy_endpoint(id: EndpointId) {
    if let Some(mut ep) = ENDPOINTS.lock().remove(&id) {
        while let Some(w) = ep.send_queue.pop_front() {
            crate::sched::unblock_thread(w.tid);
        }
        while let Some(tid) = ep.recv_queue.pop_front() {
            crate::sched::unblock_thread(tid);
        }
    }
}

/// Optional capability transfer from sender's `cap_src` into receiver's free CSpace slot.
fn transfer_cap_if_present(msg: &IpcMessage, receiver_tid: ThreadId) {
    let Some(src_addr) = msg.cap_src else {
        return;
    };
    let Some(dst_cnode) = crate::sched::cnode_of_thread(receiver_tid) else {
        return;
    };
    if let Some(free_idx) = cap::cnode::find_free_slot(dst_cnode) {
        let dst_addr = SlotAddress {
            cnode_id: dst_cnode,
            slot_idx: free_idx,
        };
        let _ = cap::cap_copy(src_addr, dst_addr, CapRights::ALL);
    }
}

/// Synchronous send on `ep_id`.
///
/// Fastpath: if a receiver is already blocked on `ep_id`, transfer registers
/// directly into the receiver's TCB and unblock it without blocking the sender.
pub fn ipc_send(ep_id: EndpointId, mut msg: IpcMessage, badge: u64) -> Result<(), IpcError> {
    let cur_tid = crate::sched::current_tid();
    msg.badge = badge;

    let maybe_receiver = {
        let mut map = ENDPOINTS.lock();
        let ep = map.get_mut(&ep_id).ok_or(IpcError::InvalidEndpoint)?;
        if let Some(recv_tid) = ep.recv_queue.pop_front() {
            Some(recv_tid)
        } else {
            crate::sched::set_thread_ipc_msg(cur_tid, msg);
            ep.send_queue.push_back(EndpointWaiter {
                tid: cur_tid,
                is_call: false,
                badge,
            });
            None
        }
    };

    if let Some(recv_tid) = maybe_receiver {
        TELEMETRY.ipc_fastpath.fetch_add(1, Ordering::Relaxed);
        transfer_cap_if_present(&msg, recv_tid);
        crate::sched::deliver_ipc_to_thread(recv_tid, msg, None);
        crate::sched::unblock_thread(recv_tid);
        Ok(())
    } else {
        TELEMETRY.ipc_slowpath.fetch_add(1, Ordering::Relaxed);
        crate::sched::block_current(ThreadState::BlockedSend);
        Ok(())
    }
}

/// Synchronous receive on `ep_id`.
///
/// Fastpath: if a sender is already waiting on `ep_id`, pull registers directly
/// from the sender's TCB and unblock the sender (or keep it in `BlockedReply`
/// if it used `ipc_call`, recording it as our pending reply target).
pub fn ipc_recv(ep_id: EndpointId) -> Result<IpcMessage, IpcError> {
    let cur_tid = crate::sched::current_tid();

    let maybe_sender = {
        let mut map = ENDPOINTS.lock();
        let ep = map.get_mut(&ep_id).ok_or(IpcError::InvalidEndpoint)?;
        if let Some(waiter) = ep.send_queue.pop_front() {
            Some(waiter)
        } else {
            ep.recv_queue.push_back(cur_tid);
            None
        }
    };

    if let Some(sender) = maybe_sender {
        TELEMETRY.ipc_fastpath.fetch_add(1, Ordering::Relaxed);
        let mut msg = crate::sched::take_thread_ipc_msg(sender.tid);
        msg.badge = sender.badge;
        transfer_cap_if_present(&msg, cur_tid);

        if sender.is_call {
            // Caller stays blocked in BlockedReply until we call `ipc_reply`.
            crate::sched::set_thread_reply_caller(cur_tid, Some(sender.tid));
        } else {
            crate::sched::unblock_thread(sender.tid);
        }
        Ok(msg)
    } else {
        TELEMETRY.ipc_slowpath.fetch_add(1, Ordering::Relaxed);
        crate::sched::block_current(ThreadState::BlockedRecv);
        Ok(crate::sched::take_thread_ipc_msg(cur_tid))
    }
}

/// Synchronous RPC call (`ipc_call`): atomically send `msg` to a server on `ep_id`
/// and block in `BlockedReply` until the server replies via `ipc_reply`.
pub fn ipc_call(ep_id: EndpointId, mut msg: IpcMessage, badge: u64) -> Result<IpcMessage, IpcError> {
    let cur_tid = crate::sched::current_tid();
    msg.badge = badge;

    let maybe_receiver = {
        let mut map = ENDPOINTS.lock();
        let ep = map.get_mut(&ep_id).ok_or(IpcError::InvalidEndpoint)?;
        if let Some(recv_tid) = ep.recv_queue.pop_front() {
            Some(recv_tid)
        } else {
            crate::sched::set_thread_ipc_msg(cur_tid, msg);
            ep.send_queue.push_back(EndpointWaiter {
                tid: cur_tid,
                is_call: true,
                badge,
            });
            None
        }
    };

    if let Some(recv_tid) = maybe_receiver {
        TELEMETRY.ipc_fastpath.fetch_add(1, Ordering::Relaxed);
        transfer_cap_if_present(&msg, recv_tid);
        crate::sched::deliver_ipc_to_thread(recv_tid, msg, Some(cur_tid));
        crate::sched::unblock_thread(recv_tid);
    } else {
        TELEMETRY.ipc_slowpath.fetch_add(1, Ordering::Relaxed);
    }

    // Block waiting for the server's `ipc_reply`
    crate::sched::block_current(ThreadState::BlockedReply);
    Ok(crate::sched::take_thread_ipc_msg(cur_tid))
}

/// Reply to the caller currently waiting on this thread's single-use Reply capability.
pub fn ipc_reply(reply_msg: IpcMessage) -> Result<(), IpcError> {
    let cur_tid = crate::sched::current_tid();
    let caller_tid = crate::sched::take_thread_reply_caller(cur_tid)
        .ok_or(IpcError::NoReplyPending)?;

    TELEMETRY.ipc_fastpath.fetch_add(1, Ordering::Relaxed);
    transfer_cap_if_present(&reply_msg, caller_tid);
    crate::sched::set_thread_ipc_msg(caller_tid, reply_msg);
    crate::sched::unblock_thread(caller_tid);
    Ok(())
}

/// Atomic server loop primitive: reply to current caller (if any) and immediately
/// wait for the next request on `ep_id`.
pub fn ipc_reply_wait(ep_id: EndpointId, reply_msg: IpcMessage) -> Result<IpcMessage, IpcError> {
    let _ = ipc_reply(reply_msg);
    ipc_recv(ep_id)
}
