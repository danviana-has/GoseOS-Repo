//! Per-CPU 64-bit Task State Segment (TSS), Interrupt Stack Tables (IST),
//! and 8 KiB I/O Permission Bitmap (IOPB) for Ring 3 I/O Port Delegation.

pub const MAX_CPUS: usize = 32;
pub const IST_STACK_SIZE: usize = 16 * 1024;
pub const IOPB_BYTES: usize = 8192; // 65536 I/O ports (1 bit per port; 1 = denied, 0 = allowed)

/// IST indices stored in IDT gate descriptors (1-based; 0 = use RSP0/current stack).
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
pub const IST_DEBUG: u8 = 4;

/// Architectural x86_64 64-bit Task State Segment with embedded IOPB.
#[repr(C, packed)]
pub struct TaskStateSegment {
    pub reserved0: u32,
    /// Privilege level stack pointers (RSP0 used on Ring 3 -> Ring 0 interrupt/exception).
    pub rsp: [u64; 3],
    pub reserved1: u64,
    /// Interrupt Stack Table entries (IST1..IST7).
    pub ist: [u64; 7],
    pub reserved2: u64,
    pub reserved3: u16,
    /// Offset from start of TSS to I/O Permission Bitmap.
    pub iomap_base: u16,
    /// 65,536-bit I/O Permission Bitmap (all 1s = Ring 3 denied by default).
    pub iopb: [u8; IOPB_BYTES],
    /// Architectural terminating 0xFF byte required by x86_64 CPU.
    pub iopb_end: u8,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap_base: 104, // Standard size of 64-bit TSS header before IOPB
            iopb: [0xFF; IOPB_BYTES],
            iopb_end: 0xFF,
        }
    }

    /// Update kernel Ring 0 stack pointer used when transitioning from Ring 3.
    #[inline]
    pub fn set_rsp0(&mut self, rsp0: u64) {
        self.rsp[0] = rsp0;
    }

    /// Set an IST stack top (1-based index 1..=7).
    #[inline]
    pub fn set_ist(&mut self, index: u8, stack_top: u64) {
        assert!((1..=7).contains(&index));
        self.ist[(index - 1) as usize] = stack_top;
    }

    /// Grant Ring 3 access to a single I/O port by clearing its IOPB bit.
    pub fn allow_io_port(&mut self, port: u16) {
        let byte_idx = (port as usize) >> 3;
        let bit = port & 7;
        self.iopb[byte_idx] &= !(1u8 << bit);
    }

    /// Revoke Ring 3 access to a single I/O port by setting its IOPB bit.
    pub fn deny_io_port(&mut self, port: u16) {
        let byte_idx = (port as usize) >> 3;
        let bit = port & 7;
        self.iopb[byte_idx] |= 1u8 << bit;
    }

    /// Grant Ring 3 access to an inclusive I/O port range `[start..=end]`.
    pub fn allow_io_range(&mut self, start: u16, end: u16) {
        if start > end {
            return;
        }
        for port in start..=end {
            self.allow_io_port(port);
        }
    }

    /// Revoke Ring 3 access to an inclusive I/O port range `[start..=end]`.
    pub fn deny_io_range(&mut self, start: u16, end: u16) {
        if start > end {
            return;
        }
        for port in start..=end {
            self.deny_io_port(port);
        }
    }

    /// Reset all 65,536 ports to denied (default isolated Ring 3 state).
    pub fn deny_all_io_ports(&mut self) {
        self.iopb.fill(0xFF);
    }

    /// Load a process-specific IOPB snapshot into this CPU's TSS on context switch.
    pub fn load_iopb(&mut self, bitmap: &[u8; IOPB_BYTES]) {
        self.iopb.copy_from_slice(bitmap);
    }
}

/// 16-byte aligned dedicated IST stack buffer.
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

impl IstStack {
    const fn new() -> Self {
        Self([0; IST_STACK_SIZE])
    }

    fn top(&self) -> u64 {
        (self.0.as_ptr() as u64 + IST_STACK_SIZE as u64) & !0xF
    }
}

/// Per-CPU TSS storage and dedicated IST stacks (Double Fault, NMI, MCE, Debug).
static mut CPU_TSS: [TaskStateSegment; MAX_CPUS] = [const { TaskStateSegment::new() }; MAX_CPUS];
static mut IST1_STACKS: [IstStack; MAX_CPUS] = [const { IstStack::new() }; MAX_CPUS];
static mut IST2_STACKS: [IstStack; MAX_CPUS] = [const { IstStack::new() }; MAX_CPUS];
static mut IST3_STACKS: [IstStack; MAX_CPUS] = [const { IstStack::new() }; MAX_CPUS];
static mut IST4_STACKS: [IstStack; MAX_CPUS] = [const { IstStack::new() }; MAX_CPUS];

/// Initialize the TSS and its 4 dedicated IST stacks for `cpu_id`.
/// Returns a raw pointer to the initialized TSS.
pub unsafe fn init_tss_for_cpu(cpu_id: usize, initial_rsp0: u64) -> *const TaskStateSegment {
    assert!(cpu_id < MAX_CPUS, "CPU ID exceeds MAX_CPUS");
    let tss = &mut CPU_TSS[cpu_id];
    tss.set_rsp0(initial_rsp0);
    tss.set_ist(IST_DOUBLE_FAULT, IST1_STACKS[cpu_id].top());
    tss.set_ist(IST_NMI, IST2_STACKS[cpu_id].top());
    tss.set_ist(IST_MACHINE_CHECK, IST3_STACKS[cpu_id].top());
    tss.set_ist(IST_DEBUG, IST4_STACKS[cpu_id].top());
    tss.deny_all_io_ports();
    tss as *const TaskStateSegment
}

/// Get a mutable reference to `cpu_id`'s TSS (for RSP0 / IOPB updates on context switch).
#[inline]
pub unsafe fn tss_mut(cpu_id: usize) -> &'static mut TaskStateSegment {
    debug_assert!(cpu_id < MAX_CPUS);
    &mut CPU_TSS[cpu_id]
}
