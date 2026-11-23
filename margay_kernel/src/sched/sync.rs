//! Kernel Synchronization Primitives & Lock-Free Ring Buffers
//!
//! Provides deadlock-free synchronization primitives tailored for an SMP
//! preemptive microkernel:
//! - `IrqSpinlock<T>`: Saves RFLAGS & masks local IRQs while locked
//! - `TicketLock<T>`: FIFO-fair spinlock preventing starvation across CPUs
//! - `RwLock<T>`: Writer-biased reader-writer spinlock
//! - `SeqLock<T>`: Lock-free reader / single-writer sequence lock
//! - `SpscRing<T, N>`: Wait-free Single-Producer Single-Consumer ring buffer
//! - `MpmcRing<T, N>`: Lock-free bounded Multi-Producer Multi-Consumer ring

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Interrupt Save / Restore Helpers
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn irq_save() -> u64 {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) rflags,
            options(nomem)
        );
    }
    rflags
}

#[inline(always)]
pub fn irq_restore(rflags: u64) {
    if (rflags & (1 << 9)) != 0 {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}

// ---------------------------------------------------------------------------
// IrqSpinlock<T>
// ---------------------------------------------------------------------------

/// Spinlock that disables local hardware interrupts while held, guaranteeing
/// that an interrupt handler on the same CPU cannot deadlock against it.
pub struct IrqSpinlock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for IrqSpinlock<T> {}
unsafe impl<T: Send> Send for IrqSpinlock<T> {}

pub struct IrqSpinlockGuard<'a, T> {
    lock: &'a IrqSpinlock<T>,
    saved_rflags: u64,
}

impl<T> IrqSpinlock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn lock(&self) -> IrqSpinlockGuard<'_, T> {
        let saved_rflags = irq_save();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        IrqSpinlockGuard {
            lock: self,
            saved_rflags,
        }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<IrqSpinlockGuard<'_, T>> {
        let saved_rflags = irq_save();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(IrqSpinlockGuard {
                lock: self,
                saved_rflags,
            })
        } else {
            irq_restore(saved_rflags);
            None
        }
    }

    /// Check lock state without acquiring (diagnostic only).
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl<T> Deref for IrqSpinlockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinlockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSpinlockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        irq_restore(self.saved_rflags);
    }
}

// ---------------------------------------------------------------------------
// TicketLock<T> (FIFO Fair Spinlock)
// ---------------------------------------------------------------------------

/// Fair FIFO ticket spinlock with IRQ masking. Prevents starvation under high
/// multi-core contention on SMP systems.
pub struct TicketLock<T> {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for TicketLock<T> {}
unsafe impl<T: Send> Send for TicketLock<T> {}

pub struct TicketLockGuard<'a, T> {
    lock: &'a TicketLock<T>,
    saved_rflags: u64,
}

impl<T> TicketLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
            data: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn lock(&self) -> TicketLockGuard<'_, T> {
        let saved_rflags = irq_save();
        let my_ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != my_ticket {
            core::hint::spin_loop();
        }
        TicketLockGuard {
            lock: self,
            saved_rflags,
        }
    }
}

impl<T> Deref for TicketLockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for TicketLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for TicketLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.now_serving.fetch_add(1, Ordering::Release);
        irq_restore(self.saved_rflags);
    }
}

// ---------------------------------------------------------------------------
// RwLock<T> (Reader-Writer Spinlock with Writer Preference)
// ---------------------------------------------------------------------------

const WRITER_BIT: u32 = 1 << 31;
const WRITER_WAIT_BIT: u32 = 1 << 30;
const READER_MASK: u32 = !(WRITER_BIT | WRITER_WAIT_BIT);

pub struct RwLock<T> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send + Sync> Sync for RwLock<T> {}
unsafe impl<T: Send> Send for RwLock<T> {}

pub struct RwReadGuard<'a, T> {
    lock: &'a RwLock<T>,
    saved_rflags: u64,
}

pub struct RwWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
    saved_rflags: u64,
}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(value),
        }
    }

    pub fn read(&self) -> RwReadGuard<'_, T> {
        let saved_rflags = irq_save();
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if (s & (WRITER_BIT | WRITER_WAIT_BIT)) != 0 {
                core::hint::spin_loop();
                continue;
            }
            if self
                .state
                .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwReadGuard {
                    lock: self,
                    saved_rflags,
                };
            }
        }
    }

    pub fn write(&self) -> RwWriteGuard<'_, T> {
        let saved_rflags = irq_save();
        // Mark writer waiting to prevent new readers from starving the writer.
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if (s & WRITER_BIT) != 0 {
                core::hint::spin_loop();
                continue;
            }
            if (s & READER_MASK) == 0 {
                if self
                    .state
                    .compare_exchange_weak(s, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return RwWriteGuard {
                        lock: self,
                        saved_rflags,
                    };
                }
            } else {
                let _ = self.state.compare_exchange_weak(
                    s,
                    s | WRITER_WAIT_BIT,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                core::hint::spin_loop();
            }
        }
    }
}

impl<T> Deref for RwReadGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> Drop for RwReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
        irq_restore(self.saved_rflags);
    }
}

impl<T> Deref for RwWriteGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for RwWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for RwWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        irq_restore(self.saved_rflags);
    }
}

// ---------------------------------------------------------------------------
// SeqLock<T> (Lock-Free Readers, Serialized Writer)
// ---------------------------------------------------------------------------

pub struct SeqLock<T: Copy> {
    seq: AtomicU64,
    write_lock: IrqSpinlock<()>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Copy + Send> Sync for SeqLock<T> {}
unsafe impl<T: Copy + Send> Send for SeqLock<T> {}

impl<T: Copy> SeqLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            seq: AtomicU64::new(0),
            write_lock: IrqSpinlock::new(()),
            data: UnsafeCell::new(value),
        }
    }

    /// Lock-free read of a consistent snapshot.
    pub fn read(&self) -> T {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if (s1 & 1) != 0 {
                core::hint::spin_loop();
                continue;
            }
            let val = unsafe { core::ptr::read_volatile(self.data.get()) };
            core::sync::atomic::fence(Ordering::Acquire);
            let s2 = self.seq.load(Ordering::Relaxed);
            if s1 == s2 {
                return val;
            }
        }
    }

    /// Exclusive write updating the sequence counter to odd during mutation.
    pub fn write(&self, new_val: T) {
        let _guard = self.write_lock.lock();
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s + 1, Ordering::Release);
        unsafe {
            core::ptr::write_volatile(self.data.get(), new_val);
        }
        self.seq.store(s + 2, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Lock-Free SPSC Ring Buffer (Power-of-Two Capacity)
// ---------------------------------------------------------------------------

#[repr(align(64))]
struct CachePadded<T>(T);

/// Wait-free Single-Producer Single-Consumer bounded ring buffer.
/// `N` MUST be a power of two.
pub struct SpscRing<T, const N: usize> {
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
    buf: [UnsafeCell<MaybeUninit<T>>; N],
}

unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}

impl<T, const N: usize> SpscRing<T, N> {
    pub const fn new() -> Self {
        assert!(N.is_power_of_two() && N >= 2);
        Self {
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
            buf: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
        }
    }

    pub fn push(&self, item: T) -> Result<(), T> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= N {
            return Err(item);
        }
        unsafe {
            (*self.buf[tail & (N - 1)].get()).write(item);
        }
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    pub fn pop(&self) -> Option<T> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let item = unsafe { (*self.buf[head & (N - 1)].get()).assume_init_read() };
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(item)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.tail
            .0
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.0.load(Ordering::Acquire))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Lock-Free Bounded MPMC Ring Buffer (Vyukov Algorithm)
// ---------------------------------------------------------------------------

struct MpmcCell<T> {
    seq: AtomicUsize,
    val: UnsafeCell<MaybeUninit<T>>,
}

/// Bounded lock-free Multi-Producer Multi-Consumer queue (Dmitry Vyukov's
/// sequence-numbered ring buffer). `N` MUST be a power of two.
pub struct MpmcRing<T, const N: usize> {
    enqueue_pos: CachePadded<AtomicUsize>,
    dequeue_pos: CachePadded<AtomicUsize>,
    cells: [MpmcCell<T>; N],
}

unsafe impl<T: Send, const N: usize> Sync for MpmcRing<T, N> {}
unsafe impl<T: Send, const N: usize> Send for MpmcRing<T, N> {}

impl<T, const N: usize> MpmcRing<T, N> {
    pub fn new() -> Self {
        assert!(N.is_power_of_two() && N >= 2);
        let cells = core::array::from_fn(|i| MpmcCell {
            seq: AtomicUsize::new(i),
            val: UnsafeCell::new(MaybeUninit::uninit()),
        });
        Self {
            enqueue_pos: CachePadded(AtomicUsize::new(0)),
            dequeue_pos: CachePadded(AtomicUsize::new(0)),
            cells,
        }
    }

    pub fn push(&self, item: T) -> Result<(), T> {
        let mask = N - 1;
        let mut pos = self.enqueue_pos.0.load(Ordering::Relaxed);
        loop {
            let cell = &self.cells[pos & mask];
            let seq = cell.seq.load(Ordering::Acquire);
            let diff = seq as isize - pos as isize;
            if diff == 0 {
                match self.enqueue_pos.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        unsafe {
                            (*cell.val.get()).write(item);
                        }
                        cell.seq.store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(next) => pos = next,
                }
            } else if diff < 0 {
                return Err(item);
            } else {
                pos = self.enqueue_pos.0.load(Ordering::Relaxed);
            }
        }
    }

    pub fn pop(&self) -> Option<T> {
        let mask = N - 1;
        let mut pos = self.dequeue_pos.0.load(Ordering::Relaxed);
        loop {
            let cell = &self.cells[pos & mask];
            let seq = cell.seq.load(Ordering::Acquire);
            let diff = seq as isize - pos.wrapping_add(1) as isize;
            if diff == 0 {
                match self.dequeue_pos.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let item = unsafe { (*cell.val.get()).assume_init_read() };
                        cell.seq.store(pos.wrapping_add(N), Ordering::Release);
                        return Some(item);
                    }
                    Err(next) => pos = next,
                }
            } else if diff < 0 {
                return None;
            } else {
                pos = self.dequeue_pos.0.load(Ordering::Relaxed);
            }
        }
    }
}
