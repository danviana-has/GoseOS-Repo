//! Thread Control Block (TCB) & Kernel Stack Management
//!
//! Cleanly separates the unit of execution (`Thread`) from its resource
//! container (`Process` = VSpace + CSpace). Each TCB owns a 16 KiB kernel
//! stack (Buddy order 2), callee-saved `CpuContext`, 64-byte aligned
//! `FpuState`, FS/GS TLS bases, CPU affinity mask, and fastpath IPC slots.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::context::CpuContext;
use crate::arch::x86_64::fpu::FpuState;
use crate::cap::object::{NotificationId, ThreadId};
use crate::ipc::IpcMessage;
use crate::mm::frame::PAGE_SIZE;
use crate::mm::{phys_to_virt, pmm, PhysAddr};
use crate::sched::process::ProcessId;

/// Each thread receives a 16 KiB Ring 0 kernel stack (Buddy order 2 = 4 pages).
pub const THREAD_KSTACK_ORDER: usize = 2;
pub const THREAD_KSTACK_SIZE: usize = (1 << THREAD_KSTACK_ORDER) * PAGE_SIZE;

/// Priority levels: 0 = highest real-time, 16 = default user, 31 = lowest/idle.
pub const NUM_PRIORITIES: usize = 32;
pub const DEFAULT_PRIORITY: u8 = 16;
pub const IDLE_PRIORITY: u8 = 31;

/// Execution lifecycle state of a Thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    BlockedSend,
    BlockedRecv,
    BlockedReply,
    BlockedNotification,
    BlockedWaitQueue,
    Terminated,
}

static NEXT_TID: AtomicU64 = AtomicU64::new(1);

pub fn alloc_tid() -> ThreadId {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

/// Thread Control Block (TCB).
pub struct Thread {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub state: ThreadState,
    pub priority: u8,
    pub base_priority: u8,
    pub time_slice: u32,
    pub cpu_affinity: u64,
    pub last_cpu: usize,
    pub is_idle: bool,

    // Hardware execution context
    pub context: CpuContext,
    pub fpu: FpuState,
    pub kstack_pa: PhysAddr,
    pub kstack_top: u64,
    pub fs_base: u64,
    pub gs_base: u64,

    // Initial Ring 3 entry state (consumed by bootstrap trampoline on first schedule)
    pub user_entry: u64,
    pub user_rsp: u64,
    pub user_arg0: u64,

    // Fastpath IPC register transfer state
    pub ipc_msg: IpcMessage,
    pub ipc_reply_caller: Option<ThreadId>,
    pub notif_word: u64,
    pub bound_notification: Option<NotificationId>,

    // Accounting telemetry
    pub ticks_run: u64,
    pub switches: u64,
}

impl Thread {
    /// Allocate a new Ring 3 user thread belonging to `pid`.
    pub fn new_user(
        pid: ProcessId,
        user_entry: u64,
        user_rsp: u64,
        user_arg0: u64,
        priority: u8,
        trampoline_rip: u64,
    ) -> Option<Self> {
        let kstack_pa = pmm::alloc_order(THREAD_KSTACK_ORDER)?;
        let kstack_va = phys_to_virt(kstack_pa.as_u64());
        unsafe {
            core::ptr::write_bytes(kstack_va as *mut u8, 0, THREAD_KSTACK_SIZE);
        }
        let kstack_top = (kstack_va + THREAD_KSTACK_SIZE as u64) & !0xF;

        let mut ctx = CpuContext::default();
        ctx.rip = trampoline_rip;
        ctx.rsp = kstack_top - 8; // Maintain 16-byte ABI stack alignment on entry
        ctx.rflags = 0x002; // Interrupts disabled until `iretq` enters Ring 3

        let prio = priority.min((NUM_PRIORITIES - 2) as u8);

        Some(Self {
            tid: alloc_tid(),
            pid,
            state: ThreadState::Ready,
            priority: prio,
            base_priority: prio,
            time_slice: quantum_for_priority(prio),
            cpu_affinity: u64::MAX,
            last_cpu: 0,
            is_idle: false,
            context: ctx,
            fpu: FpuState::new_clean(),
            kstack_pa,
            kstack_top,
            fs_base: 0,
            gs_base: 0,
            user_entry,
            user_rsp,
            user_arg0,
            ipc_msg: IpcMessage::default(),
            ipc_reply_caller: None,
            notif_word: 0,
            bound_notification: None,
            ticks_run: 0,
            switches: 0,
        })
    }

    /// Create a per-CPU kernel idle thread (runs on the CPU's own boot stack).
    pub fn new_idle(cpu_id: usize, idle_rip: u64) -> Self {
        let mut ctx = CpuContext::default();
        ctx.rip = idle_rip;
        ctx.rflags = 0x202;

        Self {
            tid: alloc_tid(),
            pid: 0,
            state: ThreadState::Running,
            priority: IDLE_PRIORITY,
            base_priority: IDLE_PRIORITY,
            time_slice: 1,
            cpu_affinity: 1u64 << (cpu_id & 63),
            last_cpu: cpu_id,
            is_idle: true,
            context: ctx,
            fpu: FpuState::new_clean(),
            kstack_pa: PhysAddr::new(0),
            kstack_top: 0,
            fs_base: 0,
            gs_base: 0,
            user_entry: 0,
            user_rsp: 0,
            user_arg0: 0,
            ipc_msg: IpcMessage::default(),
            ipc_reply_caller: None,
            notif_word: 0,
            bound_notification: None,
            ticks_run: 0,
            switches: 0,
        }
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        if self.kstack_pa.as_u64() != 0 {
            pmm::free_order(self.kstack_pa, THREAD_KSTACK_ORDER);
        }
    }
}

/// Time-slice quantum (in APIC timer ticks) assigned per priority level.
#[inline]
pub const fn quantum_for_priority(prio: u8) -> u32 {
    if prio < 8 {
        2
    } else if prio < 16 {
        4
    } else if prio < 24 {
        6
    } else {
        8
    }
}
