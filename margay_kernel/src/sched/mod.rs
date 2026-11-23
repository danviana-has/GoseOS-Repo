//! Scheduling, Process/Thread Management & Kernel Synchronization

pub mod process;
pub mod scheduler;
pub mod sync;
pub mod thread;

pub use process::{Process, ProcessId};
pub use scheduler::{
    ap_idle_loop, block_current, cnode_of_thread, current_cnode, current_pid, current_tid,
    deliver_ipc_to_thread, init, on_resched_ipi, on_timer_tick, pid_by_vspace, register_process,
    schedule_with_state, set_thread_ipc_msg, set_thread_notif_word, set_thread_reply_caller,
    spawn_in_current_process, spawn_user_thread, take_thread_ipc_msg, take_thread_notif_word,
    take_thread_reply_caller, terminate_current_thread, terminate_current_thread_on_fault,
    unblock_thread, with_process_mut, yield_now, WaitQueue,
};
pub use thread::{Thread, ThreadState, DEFAULT_PRIORITY};
