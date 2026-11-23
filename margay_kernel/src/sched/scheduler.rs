//! Preemptive SMP Per-CPU Priority Scheduler (32-Level MLFQ / Priority RR)
//!
//! Features:
//! - O(1) highest-priority thread selection via 32-bit active-queue bitmask
//! - Per-CPU run queues with SMP work-stealing load balancing
//! - CPU affinity bitmask enforcement
//! - Cross-CPU Reschedule IPIs when unblocking threads on remote cores
//! - Full CR3, FPU/XSAVE, TSS.RSP0, TSS.IOPB, and FS_BASE context switching
//! - `WaitQueue` abstraction for blocking kernel primitives

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::apic;
use crate::arch::x86_64::context::{margay_context_switch, margay_enter_userspace, CpuContext};
use crate::arch::x86_64::fpu::FpuState;
use crate::arch::x86_64::msr::{self, IA32_FS_BASE};
use crate::arch::x86_64::smp;
use crate::arch::x86_64::tss::{self, IOPB_BYTES, MAX_CPUS};
use crate::cap::object::{CNodeId, ThreadId};
use crate::debug::telemetry::TELEMETRY;
use crate::ipc::IpcMessage;
use crate::mm::vspace;
use crate::sched::process::{Process, ProcessId};
use crate::sched::sync::{irq_restore, irq_save, IrqSpinlock};
use crate::sched::thread::{
    quantum_for_priority, Thread, ThreadState, DEFAULT_PRIORITY, NUM_PRIORITIES,
};

/// Per-CPU 32-level priority run queue with O(1) bitmask lookup.
struct CpuRunQueue {
    queues: [VecDeque<ThreadId>; NUM_PRIORITIES],
    active_bitmap: u32,
    queued_count: usize,
    idle_tid: ThreadId,
    current_tid: ThreadId,
}

impl CpuRunQueue {
    fn new() -> Self {
        Self {
            queues: core::array::from_fn(|_| VecDeque::new()),
            active_bitmap: 0,
            queued_count: 0,
            idle_tid: 0,
            current_tid: 0,
        }
    }

    fn enqueue(&mut self, tid: ThreadId, priority: u8) {
        let p = (priority as usize).min(NUM_PRIORITIES - 1);
        self.queues[p].push_back(tid);
        self.active_bitmap |= 1u32 << p;
        self.queued_count += 1;
    }

    fn dequeue_highest(&mut self) -> Option<ThreadId> {
        if self.active_bitmap == 0 {
            return None;
        }
        let highest = self.active_bitmap.trailing_zeros() as usize;
        let tid = self.queues[highest].pop_front()?;
        if self.queues[highest].is_empty() {
            self.active_bitmap &= !(1u32 << highest);
        }
        self.queued_count -= 1;
        Some(tid)
    }

    /// Steal one ready thread from the back of the highest-priority non-empty queue
    /// whose CPU affinity allows `dst_cpu`.
    fn steal_for_cpu(
        &mut self,
        dst_cpu: usize,
        threads: &BTreeMap<ThreadId, Box<Thread>>,
    ) -> Option<ThreadId> {
        if self.queued_count <= 1 {
            return None;
        }
        let mut mask = self.active_bitmap;
        while mask != 0 {
            let p = mask.trailing_zeros() as usize;
            mask &= !(1u32 << p);
            if let Some(pos) = self.queues[p].iter().rposition(|&tid| {
                threads
                    .get(&tid)
                    .map(|t| !t.is_idle && (t.cpu_affinity & (1u64 << (dst_cpu & 63))) != 0)
                    .unwrap_or(false)
            }) {
                let tid = self.queues[p].remove(pos)?;
                if self.queues[p].is_empty() {
                    self.active_bitmap &= !(1u32 << p);
                }
                self.queued_count -= 1;
                return Some(tid);
            }
        }
        None
    }
}

struct SchedulerState {
    processes: BTreeMap<ProcessId, Box<Process>>,
    threads: BTreeMap<ThreadId, Box<Thread>>,
    run_queues: [Option<CpuRunQueue>; MAX_CPUS],
    initialized: bool,
}

impl SchedulerState {
    const fn new() -> Self {
        Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            run_queues: [const { None }; MAX_CPUS],
            initialized: false,
        }
    }

    /// Choose the least-loaded online CPU permitted by `affinity`.
    fn pick_target_cpu(&self, affinity: u64, preferred: usize) -> usize {
        let online = smp::online_cpus().max(1) as usize;
        let mut best_cpu = preferred % online;
        let mut best_load = usize::MAX;

        for cpu in 0..online.min(MAX_CPUS) {
            if (affinity & (1u64 << (cpu & 63))) == 0 {
                continue;
            }
            if let Some(rq) = &self.run_queues[cpu] {
                if rq.queued_count < best_load {
                    best_load = rq.queued_count;
                    best_cpu = cpu;
                }
            }
        }
        best_cpu
    }
}

static SCHEDULER: IrqSpinlock<SchedulerState> = IrqSpinlock::new(SchedulerState::new());
static SCHED_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Initialize per-CPU run queues and idle threads for all online CPUs.
pub fn init() {
    let total = smp::total_cpus().max(1) as usize;
    let mut sched = SCHEDULER.lock();

    for cpu in 0..total.min(MAX_CPUS) {
        let idle = Box::new(Thread::new_idle(cpu, idle_loop_entry as *const () as u64));
        let idle_tid = idle.tid;
        sched.threads.insert(idle_tid, idle);

        let mut rq = CpuRunQueue::new();
        rq.idle_tid = idle_tid;
        rq.current_tid = idle_tid;
        sched.run_queues[cpu] = Some(rq);
    }

    sched.initialized = true;
    drop(sched);

    // Anchor BSP's PerCpu current_tid to its idle thread
    let bsp_idle = SCHEDULER.lock().run_queues[0].as_ref().unwrap().idle_tid;
    smp::current_cpu().current_tid.store(bsp_idle, Ordering::Release);

    SCHED_ACTIVE.store(true, Ordering::Release);
    crate::kinfo!(
        "SCHED",
        "SMP Preemptive Scheduler online ({} CPUs, {} priority levels, MLFQ/RR)",
        total,
        NUM_PRIORITIES
    );
}

/// Register a newly constructed `Process` in the scheduler table.
pub fn register_process(proc: Process) -> ProcessId {
    let pid = proc.pid;
    SCHEDULER.lock().processes.insert(pid, Box::new(proc));
    pid
}

/// Execute a closure with exclusive mutable access to a Process's VSpace / metadata.
pub fn with_process_mut<F, R>(pid: ProcessId, f: F) -> Option<R>
where
    F: FnOnce(&mut Process) -> R,
{
    let mut sched = SCHEDULER.lock();
    let proc = sched.processes.get_mut(&pid)?;
    Some(f(proc))
}

/// Resolve a `VSpaceId` to its owning `ProcessId`.
pub fn pid_by_vspace(vspace_id: crate::mm::vspace::VSpaceId) -> Option<ProcessId> {
    let sched = SCHEDULER.lock();
    for (&pid, proc) in &sched.processes {
        if proc.vspace.id == vspace_id {
            return Some(pid);
        }
    }
    None
}

/// Spawn a new Ring 3 user thread inside `pid` and enqueue it on the least-loaded CPU.
pub fn spawn_user_thread(
    pid: ProcessId,
    user_entry: u64,
    user_rsp: u64,
    user_arg0: u64,
    priority: u8,
) -> Option<ThreadId> {
    let thread = Box::new(Thread::new_user(
        pid,
        user_entry,
        user_rsp,
        user_arg0,
        priority,
        user_thread_bootstrap_trampoline as *const () as u64,
    )?);
    let tid = thread.tid;

    let notify_lapic = {
        let mut sched = SCHEDULER.lock();
        if let Some(proc) = sched.processes.get_mut(&pid) {
            proc.threads.push(tid);
        } else {
            return None;
        }
        let target_cpu = sched.pick_target_cpu(thread.cpu_affinity, smp::current_cpu_id());
        sched.threads.insert(tid, thread);
        if let Some(rq) = sched.run_queues[target_cpu].as_mut() {
            rq.enqueue(tid, priority);
        }
        if target_cpu != smp::current_cpu_id() {
            smp::cpu_by_id(target_cpu).map(|c| c.lapic_id)
        } else {
            None
        }
    };

    if let Some(lapic) = notify_lapic {
        apic::send_ipi(lapic, apic::VECTOR_IPI_RESCHED);
    }

    Some(tid)
}

/// Return the currently executing `ThreadId` on this CPU.
#[inline]
pub fn current_tid() -> ThreadId {
    smp::current_cpu().current_tid.load(Ordering::Acquire)
}

/// Return the currently executing `ProcessId` on this CPU.
#[inline]
pub fn current_pid() -> ProcessId {
    smp::current_cpu().current_pid.load(Ordering::Acquire)
}

/// Look up the root `CNodeId` of the process owning `tid`.
pub fn cnode_of_thread(tid: ThreadId) -> Option<CNodeId> {
    let sched = SCHEDULER.lock();
    let pid = sched.threads.get(&tid)?.pid;
    Some(sched.processes.get(&pid)?.root_cnode)
}

/// Look up the root `CNodeId` of the currently executing thread.
pub fn current_cnode() -> Option<CNodeId> {
    cnode_of_thread(current_tid())
}

// ---------------------------------------------------------------------------
// Fastpath IPC TCB Accessors
// ---------------------------------------------------------------------------

pub fn set_thread_ipc_msg(tid: ThreadId, msg: IpcMessage) {
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut(&tid) {
        t.ipc_msg = msg;
    }
}

pub fn take_thread_ipc_msg(tid: ThreadId) -> IpcMessage {
    let mut sched = SCHEDULER.lock();
    sched
        .threads
        .get_mut(&tid)
        .map(|t| t.ipc_msg)
        .unwrap_or_default()
}

pub fn deliver_ipc_to_thread(tid: ThreadId, msg: IpcMessage, reply_caller: Option<ThreadId>) {
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut(&tid) {
        t.ipc_msg = msg;
        if reply_caller.is_some() {
            t.ipc_reply_caller = reply_caller;
        }
    }
}

pub fn set_thread_reply_caller(tid: ThreadId, caller: Option<ThreadId>) {
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut(&tid) {
        t.ipc_reply_caller = caller;
    }
}

pub fn take_thread_reply_caller(tid: ThreadId) -> Option<ThreadId> {
    let mut sched = SCHEDULER.lock();
    sched.threads.get_mut(&tid)?.ipc_reply_caller.take()
}

pub fn set_thread_notif_word(tid: ThreadId, word: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut(&tid) {
        t.notif_word = word;
    }
}

pub fn take_thread_notif_word(tid: ThreadId) -> u64 {
    let mut sched = SCHEDULER.lock();
    sched
        .threads
        .get_mut(&tid)
        .map(|t| core::mem::replace(&mut t.notif_word, 0))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Core Context Switch & Scheduling Logic
// ---------------------------------------------------------------------------

struct SwitchPlan {
    old_ctx: *mut CpuContext,
    new_ctx: *const CpuContext,
    old_fpu: *mut FpuState,
    new_fpu: *const FpuState,
    new_cr3: u64,
    new_rsp0: u64,
    new_fs_base: u64,
    new_iopb: Option<*const [u8; IOPB_BYTES]>,
    next_tid: ThreadId,
    next_pid: ProcessId,
}

/// Core scheduling routine. Saves interrupts, picks the highest-priority runnable
/// thread (stealing from peer CPUs if local queue is empty), releases the
/// scheduler lock, and executes the hardware context switch.
pub fn schedule_with_state(outgoing_state: Option<ThreadState>) {
    if !SCHED_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let saved_rflags = irq_save();
    let cpu_id = smp::current_cpu_id();

    let plan: Option<SwitchPlan> = {
        let mut sched = SCHEDULER.lock();
        let cur_tid = match sched.run_queues[cpu_id].as_ref() {
            Some(rq) => rq.current_tid,
            None => 0,
        };
        if cur_tid == 0 {
            None
        } else {
            let idle_tid = sched.run_queues[cpu_id].as_ref().unwrap().idle_tid;

            // Update outgoing thread state and re-enqueue if still runnable
            if let Some(cur) = sched.threads.get_mut(&cur_tid) {
                if let Some(forced) = outgoing_state {
                    cur.state = forced;
                } else if cur.state == ThreadState::Running && !cur.is_idle {
                    cur.state = ThreadState::Ready;
                    let prio = cur.priority;
                    if let Some(rq) = sched.run_queues[cpu_id].as_mut() {
                        rq.enqueue(cur_tid, prio);
                    }
                }
            }

            // Pick highest-priority thread from local run queue
            let mut next_tid = sched.run_queues[cpu_id]
                .as_mut()
                .and_then(|rq| rq.dequeue_highest());

            // SMP Work-Stealing: if local queue is empty, try stealing from a busy peer CPU
            if next_tid.is_none() {
                let online = smp::online_cpus().max(1) as usize;
                for offset in 1..online {
                    let peer = (cpu_id + offset) % online;
                    // Split borrow via temporary take
                    if let Some(mut peer_rq) = sched.run_queues[peer].take() {
                        let stolen = peer_rq.steal_for_cpu(cpu_id, &sched.threads);
                        sched.run_queues[peer] = Some(peer_rq);
                        if stolen.is_some() {
                            next_tid = stolen;
                            break;
                        }
                    }
                }
            }

            let next_tid = next_tid.unwrap_or(idle_tid);

            if next_tid == cur_tid {
                if let Some(t) = sched.threads.get_mut(&cur_tid) {
                    if t.state == ThreadState::Ready {
                        t.state = ThreadState::Running;
                    }
                }
                None
            } else {
                sched.run_queues[cpu_id].as_mut().unwrap().current_tid = next_tid;

                let (old_ctx, old_fpu) = {
                    let t = sched.threads.get_mut(&cur_tid).unwrap();
                    (&mut t.context as *mut CpuContext, &mut t.fpu as *mut FpuState)
                };

                let (new_ctx, new_fpu, new_rsp0, new_fs_base, next_pid) = {
                    let t = sched.threads.get_mut(&next_tid).unwrap();
                    t.state = ThreadState::Running;
                    t.time_slice = quantum_for_priority(t.priority);
                    t.last_cpu = cpu_id;
                    t.switches += 1;
                    (
                        &t.context as *const CpuContext,
                        &t.fpu as *const FpuState,
                        t.kstack_top,
                        t.fs_base,
                        t.pid,
                    )
                };

                let (new_cr3, new_iopb) = if next_pid != 0 {
                    if let Some(proc) = sched.processes.get(&next_pid) {
                        let iopb = if proc.has_custom_iopb {
                            Some(&*proc.iopb as *const [u8; IOPB_BYTES])
                        } else {
                            None
                        };
                        (proc.vspace.cr3(), iopb)
                    } else {
                        (vspace::kernel_pml4().as_u64(), None)
                    }
                } else {
                    (vspace::kernel_pml4().as_u64(), None)
                };

                Some(SwitchPlan {
                    old_ctx,
                    new_ctx,
                    old_fpu,
                    new_fpu,
                    new_cr3,
                    new_rsp0,
                    new_fs_base,
                    new_iopb,
                    next_tid,
                    next_pid,
                })
            }
        }
    };

    if let Some(p) = plan {
        TELEMETRY.context_switches.fetch_add(1, Ordering::Relaxed);

        let percpu = smp::current_cpu();
        percpu.current_tid.store(p.next_tid, Ordering::Release);
        percpu.current_pid.store(p.next_pid, Ordering::Release);

        unsafe {
            // Save outgoing FPU/SSE state and restore incoming state
            (*p.old_fpu).save();
            (*p.new_fpu).restore();

            // Update kernel stack for syscall & interrupts if switching to a user thread
            if p.new_rsp0 != 0 {
                smp::set_kernel_stack(p.new_rsp0);
            }

            // Load per-process I/O Permission Bitmap into TSS if delegated
            let tss_ref = tss::tss_mut(cpu_id);
            if let Some(iopb_ptr) = p.new_iopb {
                tss_ref.load_iopb(&*iopb_ptr);
            } else {
                tss_ref.deny_all_io_ports();
            }

            // Restore user TLS FS_BASE
            msr::wrmsr(IA32_FS_BASE, p.new_fs_base);

            // Switch AddressSpace (CR3) only if different (avoids needless TLB flush)
            if crate::arch::x86_64::read_cr3() != p.new_cr3 {
                crate::arch::x86_64::write_cr3(p.new_cr3);
            }

            // Perform low-level callee-saved context switch
            margay_context_switch(p.old_ctx, p.new_ctx);
        }
    }

    irq_restore(saved_rflags);
}

/// Voluntary yield of the current thread's remaining time slice.
pub fn yield_now() {
    schedule_with_state(None);
}

/// Block the current thread with `state` and immediately switch to another thread.
pub fn block_current(state: ThreadState) {
    schedule_with_state(Some(state));
}

/// Unblock a previously blocked thread and place it on an eligible CPU run queue,
/// sending a Reschedule IPI if placed on a remote CPU.
pub fn unblock_thread(tid: ThreadId) {
    let notify_lapic = {
        let mut sched = SCHEDULER.lock();
        let (prio, affinity, last_cpu) = match sched.threads.get_mut(&tid) {
            Some(t) => {
                if t.state == ThreadState::Ready
                    || t.state == ThreadState::Running
                    || t.state == ThreadState::Terminated
                {
                    return;
                }
                t.state = ThreadState::Ready;
                (t.priority, t.cpu_affinity, t.last_cpu)
            }
            None => return,
        };

        let target_cpu = sched.pick_target_cpu(affinity, last_cpu);
        if let Some(rq) = sched.run_queues[target_cpu].as_mut() {
            rq.enqueue(tid, prio);
        }
        if target_cpu != smp::current_cpu_id() {
            smp::cpu_by_id(target_cpu).map(|c| c.lapic_id)
        } else {
            None
        }
    };

    if let Some(lapic) = notify_lapic {
        apic::send_ipi(lapic, apic::VECTOR_IPI_RESCHED);
    }
}

/// Terminate the currently executing thread cleanly and schedule the next thread.
pub fn terminate_current_thread() -> ! {
    schedule_with_state(Some(ThreadState::Terminated));
    // Fallback if idle
    ap_idle_loop()
}

/// Terminate a faulting Ring 3 thread without crashing the microkernel.
pub fn terminate_current_thread_on_fault(vector: u8, fault_addr: u64) {
    crate::kerror!(
        "SCHED",
        "Terminating faulting user thread tid={} pid={} (exc={}, addr={:#x})",
        current_tid(),
        current_pid(),
        vector,
        fault_addr
    );
    schedule_with_state(Some(ThreadState::Terminated));
}

/// Called from the Local APIC periodic timer ISR on every CPU.
pub fn on_timer_tick() {
    if !SCHED_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let cpu = smp::current_cpu();
    cpu.local_ticks.fetch_add(1, Ordering::Relaxed);
    let cur_tid = cpu.current_tid.load(Ordering::Acquire);

    let need_resched = {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut(&cur_tid) {
            t.ticks_run += 1;
            if t.is_idle {
                // Wake from idle immediately if work arrived
                sched.run_queues[cpu.cpu_id as usize]
                    .as_ref()
                    .map(|rq| rq.queued_count > 0)
                    .unwrap_or(false)
            } else if t.time_slice > 1 {
                t.time_slice -= 1;
                false
            } else {
                // MLFQ demotion: gently lower priority for CPU-bound threads
                if t.priority + 1 < (NUM_PRIORITIES - 1) as u8 {
                    t.priority += 1;
                }
                true
            }
        } else {
            false
        }
    };

    if need_resched {
        schedule_with_state(None);
    }
}

/// Called from `VECTOR_IPI_RESCHED` ISR when another CPU unblocked work for us.
pub fn on_resched_ipi() {
    if SCHED_ACTIVE.load(Ordering::Acquire) {
        schedule_with_state(None);
    }
}

/// Trampoline entered the very first time a newly created Ring 3 thread is scheduled.
extern "C" fn user_thread_bootstrap_trampoline() -> ! {
    let tid = current_tid();
    let (entry, rsp, arg0) = {
        let sched = SCHEDULER.lock();
        let t = sched.threads.get(&tid).expect("Missing TCB in trampoline");
        (t.user_entry, t.user_rsp, t.user_arg0)
    };
    unsafe {
        margay_enter_userspace(entry, rsp, 0x202, arg0);
    }
}

/// Idle loop executed by idle threads on BSP and all APs.
extern "C" fn idle_loop_entry() -> ! {
    ap_idle_loop()
}

pub fn ap_idle_loop() -> ! {
    loop {
        if SCHED_ACTIVE.load(Ordering::Acquire) {
            schedule_with_state(None);
        }
        crate::arch::x86_64::enable_interrupts();
        crate::arch::x86_64::halt_once();
    }
}

/// Generic blocking WaitQueue for kernel subsystems.
pub struct WaitQueue {
    waiters: IrqSpinlock<VecDeque<ThreadId>>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            waiters: IrqSpinlock::new(VecDeque::new()),
        }
    }

    pub fn wait(&self) {
        let tid = current_tid();
        self.waiters.lock().push_back(tid);
        block_current(ThreadState::BlockedWaitQueue);
    }

    pub fn wake_one(&self) -> bool {
        if let Some(tid) = self.waiters.lock().pop_front() {
            unblock_thread(tid);
            true
        } else {
            false
        }
    }

    pub fn wake_all(&self) -> usize {
        let mut count = 0;
        loop {
            let next = self.waiters.lock().pop_front();
            match next {
                Some(tid) => {
                    unblock_thread(tid);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// Convenience helper for spawning a thread inside the current process.
pub fn spawn_in_current_process(entry: u64, rsp: u64, arg0: u64) -> Option<ThreadId> {
    let pid = current_pid();
    if pid == 0 {
        return None;
    }
    spawn_user_thread(pid, entry, rsp, arg0, DEFAULT_PRIORITY)
}
