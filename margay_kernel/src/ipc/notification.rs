//! Asynchronous IPC Notifications (Atomic Bitmask Event Flags)
//!
//! Lightweight non-blocking signaling objects modeled after seL4 Notifications.
//! Used for server-to-server asynchronous signaling and hardware IRQ delivery
//! from Ring 0 ISR handlers directly to Ring 3 device driver servers.

use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::object::{NotificationId, ThreadId};
use crate::debug::telemetry::TELEMETRY;
use crate::ipc::IpcError;
use crate::sched::sync::IrqSpinlock;
use crate::sched::thread::ThreadState;

struct Notification {
    _id: NotificationId,
    word: AtomicU64,
    waiters: VecDeque<ThreadId>,
}

impl Notification {
    fn new(id: NotificationId) -> Self {
        Self {
            _id: id,
            word: AtomicU64::new(0),
            waiters: VecDeque::new(),
        }
    }
}

static NEXT_NOTIF_ID: AtomicU64 = AtomicU64::new(1);
static NOTIFICATIONS: IrqSpinlock<BTreeMap<NotificationId, Notification>> =
    IrqSpinlock::new(BTreeMap::new());

/// Create a new asynchronous Notification object.
pub fn create_notification() -> NotificationId {
    let id = NEXT_NOTIF_ID.fetch_add(1, Ordering::Relaxed);
    NOTIFICATIONS.lock().insert(id, Notification::new(id));
    id
}

/// Destroy a Notification object and wake any waiting threads.
pub fn destroy_notification(id: NotificationId) {
    if let Some(mut n) = NOTIFICATIONS.lock().remove(&id) {
        while let Some(tid) = n.waiters.pop_front() {
            crate::sched::unblock_thread(tid);
        }
    }
}

/// Signal a Notification by bitwise-ORing `bits` into its atomic notification word.
/// Safe to call from hardware IRQ context (never blocks).
pub fn signal(id: NotificationId, bits: u64) -> Result<(), IpcError> {
    let mask = if bits == 0 { 1 } else { bits };
    TELEMETRY.ipc_notifications.fetch_add(1, Ordering::Relaxed);

    let wake_target = {
        let mut map = NOTIFICATIONS.lock();
        let notif = map.get_mut(&id).ok_or(IpcError::InvalidNotification)?;
        notif.word.fetch_or(mask, Ordering::AcqRel);

        if let Some(waiter_tid) = notif.waiters.pop_front() {
            let delivered = notif.word.swap(0, Ordering::AcqRel);
            Some((waiter_tid, delivered))
        } else {
            None
        }
    };

    if let Some((waiter_tid, delivered)) = wake_target {
        crate::sched::set_thread_notif_word(waiter_tid, delivered);
        crate::sched::unblock_thread(waiter_tid);
    }

    Ok(())
}

/// Wait on a Notification, atomically consuming and returning its non-zero bitmask.
/// If the word is currently 0, blocks the calling thread until signaled.
pub fn wait(id: NotificationId) -> Result<u64, IpcError> {
    let cur_tid = crate::sched::current_tid();

    let immediate = {
        let mut map = NOTIFICATIONS.lock();
        let notif = map.get_mut(&id).ok_or(IpcError::InvalidNotification)?;
        let val = notif.word.swap(0, Ordering::AcqRel);
        if val != 0 {
            Some(val)
        } else {
            notif.waiters.push_back(cur_tid);
            None
        }
    };

    if let Some(val) = immediate {
        Ok(val)
    } else {
        crate::sched::block_current(ThreadState::BlockedNotification);
        Ok(crate::sched::take_thread_notif_word(cur_tid))
    }
}

/// Non-blocking poll: atomically consume and return the current bitmask (may be 0).
pub fn poll(id: NotificationId) -> Result<u64, IpcError> {
    let map = NOTIFICATIONS.lock();
    let notif = map.get(&id).ok_or(IpcError::InvalidNotification)?;
    Ok(notif.word.swap(0, Ordering::AcqRel))
}
