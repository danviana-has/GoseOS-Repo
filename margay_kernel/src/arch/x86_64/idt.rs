//! 64-bit Interrupt Descriptor Table (IDT) & Full x86_64 Exception/IRQ Stubs
//!
//! Implements all 32 architectural x86_64 exceptions with full register frame
//! capture, detailed Page Fault error-code & CR2 decoding, dedicated IST
//! stacks for Double Fault / NMI / Machine Check / Debug, plus Local APIC
//! timer, IPI, spurious, and hardware IRQ routing into `crate::irq`.

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::mem::size_of;
use core::sync::atomic::Ordering;

use crate::arch::x86_64::apic::{
    self, IRQ_VECTOR_BASE, VECTOR_APIC_ERROR, VECTOR_APIC_SPURIOUS, VECTOR_APIC_TIMER,
    VECTOR_IPI_HALT, VECTOR_IPI_RESCHED, VECTOR_IPI_TLB_SHOOTDOWN,
};
use crate::arch::x86_64::gdt::KERNEL_CS;
use crate::arch::x86_64::tss::{IST_DEBUG, IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI};
use crate::debug::serial::EmergencySerial;
use crate::debug::telemetry::TELEMETRY;
use crate::debug::unwind;

/// 16-byte 64-bit Interrupt/Trap Gate Descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            zero: 0,
        }
    }

    fn set_handler(&mut self, handler: u64, ist: u8, dpl: u8, is_trap: bool) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.selector = KERNEL_CS;
        self.ist = ist & 0x7;
        let gate_type = if is_trap { 0x0F } else { 0x0E };
        self.type_attr = 0x80 | ((dpl & 0x3) << 5) | gate_type;
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = ((handler >> 32) & 0xFFFF_FFFF) as u32;
        self.zero = 0;
    }
}

#[repr(C, align(16))]
struct IdtTable {
    entries: [IdtEntry; 256],
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

static mut IDT: IdtTable = IdtTable {
    entries: [IdtEntry::missing(); 256],
};

/// Saved CPU register frame pushed by the common ISR trampoline.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InterruptFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    // Pushed automatically by the x86_64 CPU on interrupt/exception:
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl InterruptFrame {
    #[inline]
    pub fn from_userspace(&self) -> bool {
        (self.cs & 3) == 3
    }
}

// ---------------------------------------------------------------------------
// Assembly ISR Stubs (All 32 Exceptions + IRQs + APIC/IPI Vectors)
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text
.macro ISR_NOERR vec
.global isr_stub_\vec
isr_stub_\vec:
    push 0
    push \vec
    jmp isr_common_trampoline
.endm

.macro ISR_ERR vec
.global isr_stub_\vec
isr_stub_\vec:
    push \vec
    jmp isr_common_trampoline
.endm

// All 32 x86_64 Architectural Exceptions
ISR_NOERR 0    // #DE Divide Error
ISR_NOERR 1    // #DB Debug
ISR_NOERR 2    // NMI
ISR_NOERR 3    // #BP Breakpoint
ISR_NOERR 4    // #OF Overflow
ISR_NOERR 5    // #BR Bound Range Exceeded
ISR_NOERR 6    // #UD Invalid Opcode
ISR_NOERR 7    // #NM Device Not Available
ISR_ERR   8    // #DF Double Fault
ISR_NOERR 9    // Coprocessor Segment Overrun
ISR_ERR   10   // #TS Invalid TSS
ISR_ERR   11   // #NP Segment Not Present
ISR_ERR   12   // #SS Stack-Segment Fault
ISR_ERR   13   // #GP General Protection Fault
ISR_ERR   14   // #PF Page Fault
ISR_NOERR 15   // Reserved
ISR_NOERR 16   // #MF x87 Floating-Point Exception
ISR_ERR   17   // #AC Alignment Check
ISR_NOERR 18   // #MC Machine Check
ISR_NOERR 19   // #XM SIMD Floating-Point Exception
ISR_NOERR 20   // #VE Virtualization Exception
ISR_ERR   21   // #CP Control Protection Exception
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28   // #HV Hypervisor Injection
ISR_ERR   29   // #VC VMM Communication
ISR_ERR   30   // #SX Security Exception
ISR_NOERR 31

// Hardware IRQ vectors 32..63 (GSI 0..31)
ISR_NOERR 32
ISR_NOERR 33
ISR_NOERR 34
ISR_NOERR 35
ISR_NOERR 36
ISR_NOERR 37
ISR_NOERR 38
ISR_NOERR 39
ISR_NOERR 40
ISR_NOERR 41
ISR_NOERR 42
ISR_NOERR 43
ISR_NOERR 44
ISR_NOERR 45
ISR_NOERR 46
ISR_NOERR 47
ISR_NOERR 48
ISR_NOERR 49
ISR_NOERR 50
ISR_NOERR 51
ISR_NOERR 52
ISR_NOERR 53
ISR_NOERR 54
ISR_NOERR 55
ISR_NOERR 56
ISR_NOERR 57
ISR_NOERR 58
ISR_NOERR 59
ISR_NOERR 60
ISR_NOERR 61
ISR_NOERR 62
ISR_NOERR 63

// Local APIC & IPI Vectors
ISR_NOERR 224  // 0xE0: APIC Timer
ISR_NOERR 225  // 0xE1: IPI Reschedule
ISR_NOERR 226  // 0xE2: IPI TLB Shootdown
ISR_NOERR 227  // 0xE3: IPI Halt
ISR_NOERR 254  // 0xFE: APIC Error
ISR_NOERR 255  // 0xFF: APIC Spurious

.global isr_common_trampoline
isr_common_trampoline:
    // If interrupted from Ring 3 (CS & 3 != 0), swap GS to kernel per-CPU base.
    test qword ptr [rsp + 24], 3
    jz 1f
    swapgs
1:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    cld
    call margay_interrupt_dispatch

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    // Skip vector + error_code
    add rsp, 16

    // If returning to Ring 3, swap GS back to user GS base.
    test qword ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq
"#
);

extern "C" {
    fn isr_stub_0();  fn isr_stub_1();  fn isr_stub_2();  fn isr_stub_3();
    fn isr_stub_4();  fn isr_stub_5();  fn isr_stub_6();  fn isr_stub_7();
    fn isr_stub_8();  fn isr_stub_9();  fn isr_stub_10(); fn isr_stub_11();
    fn isr_stub_12(); fn isr_stub_13(); fn isr_stub_14(); fn isr_stub_15();
    fn isr_stub_16(); fn isr_stub_17(); fn isr_stub_18(); fn isr_stub_19();
    fn isr_stub_20(); fn isr_stub_21(); fn isr_stub_22(); fn isr_stub_23();
    fn isr_stub_24(); fn isr_stub_25(); fn isr_stub_26(); fn isr_stub_27();
    fn isr_stub_28(); fn isr_stub_29(); fn isr_stub_30(); fn isr_stub_31();

    fn isr_stub_32(); fn isr_stub_33(); fn isr_stub_34(); fn isr_stub_35();
    fn isr_stub_36(); fn isr_stub_37(); fn isr_stub_38(); fn isr_stub_39();
    fn isr_stub_40(); fn isr_stub_41(); fn isr_stub_42(); fn isr_stub_43();
    fn isr_stub_44(); fn isr_stub_45(); fn isr_stub_46(); fn isr_stub_47();
    fn isr_stub_48(); fn isr_stub_49(); fn isr_stub_50(); fn isr_stub_51();
    fn isr_stub_52(); fn isr_stub_53(); fn isr_stub_54(); fn isr_stub_55();
    fn isr_stub_56(); fn isr_stub_57(); fn isr_stub_58(); fn isr_stub_59();
    fn isr_stub_60(); fn isr_stub_61(); fn isr_stub_62(); fn isr_stub_63();

    fn isr_stub_224();
    fn isr_stub_225();
    fn isr_stub_226();
    fn isr_stub_227();
    fn isr_stub_254();
    fn isr_stub_255();
}

const EXCEPTION_NAMES: [&str; 32] = [
    "#DE Divide Error",
    "#DB Debug",
    "NMI Non-Maskable Interrupt",
    "#BP Breakpoint",
    "#OF Overflow",
    "#BR Bound Range Exceeded",
    "#UD Invalid Opcode",
    "#NM Device Not Available",
    "#DF Double Fault",
    "Coprocessor Segment Overrun",
    "#TS Invalid TSS",
    "#NP Segment Not Present",
    "#SS Stack-Segment Fault",
    "#GP General Protection Fault",
    "#PF Page Fault",
    "Reserved (15)",
    "#MF x87 Floating-Point",
    "#AC Alignment Check",
    "#MC Machine Check",
    "#XM SIMD Floating-Point",
    "#VE Virtualization Exception",
    "#CP Control Protection",
    "Reserved (22)",
    "Reserved (23)",
    "Reserved (24)",
    "Reserved (25)",
    "Reserved (26)",
    "Reserved (27)",
    "#HV Hypervisor Injection",
    "#VC VMM Communication",
    "#SX Security Exception",
    "Reserved (31)",
];

/// Populate the global 256-entry IDT once during BSP initialization.
pub unsafe fn init_table() {
    let exc_stubs: [unsafe extern "C" fn(); 32] = [
        isr_stub_0,  isr_stub_1,  isr_stub_2,  isr_stub_3,
        isr_stub_4,  isr_stub_5,  isr_stub_6,  isr_stub_7,
        isr_stub_8,  isr_stub_9,  isr_stub_10, isr_stub_11,
        isr_stub_12, isr_stub_13, isr_stub_14, isr_stub_15,
        isr_stub_16, isr_stub_17, isr_stub_18, isr_stub_19,
        isr_stub_20, isr_stub_21, isr_stub_22, isr_stub_23,
        isr_stub_24, isr_stub_25, isr_stub_26, isr_stub_27,
        isr_stub_28, isr_stub_29, isr_stub_30, isr_stub_31,
    ];

    for (vec, stub) in exc_stubs.iter().enumerate() {
        let ist = match vec {
            1 => IST_DEBUG,
            2 => IST_NMI,
            8 => IST_DOUBLE_FAULT,
            18 => IST_MACHINE_CHECK,
            _ => 0,
        };
        let dpl = if vec == 3 { 3 } else { 0 }; // Allow Ring 3 `int3` breakpoint
        IDT.entries[vec].set_handler(*stub as u64, ist, dpl, false);
    }

    let irq_stubs: [unsafe extern "C" fn(); 32] = [
        isr_stub_32, isr_stub_33, isr_stub_34, isr_stub_35,
        isr_stub_36, isr_stub_37, isr_stub_38, isr_stub_39,
        isr_stub_40, isr_stub_41, isr_stub_42, isr_stub_43,
        isr_stub_44, isr_stub_45, isr_stub_46, isr_stub_47,
        isr_stub_48, isr_stub_49, isr_stub_50, isr_stub_51,
        isr_stub_52, isr_stub_53, isr_stub_54, isr_stub_55,
        isr_stub_56, isr_stub_57, isr_stub_58, isr_stub_59,
        isr_stub_60, isr_stub_61, isr_stub_62, isr_stub_63,
    ];

    for (i, stub) in irq_stubs.iter().enumerate() {
        IDT.entries[IRQ_VECTOR_BASE as usize + i].set_handler(*stub as u64, 0, 0, false);
    }

    IDT.entries[VECTOR_APIC_TIMER as usize].set_handler(isr_stub_224 as *const () as u64, 0, 0, false);
    IDT.entries[VECTOR_IPI_RESCHED as usize].set_handler(isr_stub_225 as *const () as u64, 0, 0, false);
    IDT.entries[VECTOR_IPI_TLB_SHOOTDOWN as usize].set_handler(isr_stub_226 as *const () as u64, 0, 0, false);
    IDT.entries[VECTOR_IPI_HALT as usize].set_handler(isr_stub_227 as *const () as u64, 0, 0, false);
    IDT.entries[VECTOR_APIC_ERROR as usize].set_handler(isr_stub_254 as *const () as u64, 0, 0, false);
    IDT.entries[VECTOR_APIC_SPURIOUS as usize].set_handler(isr_stub_255 as *const () as u64, 0, 0, false);
}

/// Load the shared IDT into the current CPU's IDTR register.
pub unsafe fn load_for_current_cpu() {
    let idtr = IdtPointer {
        limit: (size_of::<IdtTable>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
}

/// Central C-ABI interrupt and exception dispatcher called from `isr_common_trampoline`.
#[no_mangle]
extern "C" fn margay_interrupt_dispatch(frame: &mut InterruptFrame) {
    let vec = frame.vector as u8;

    match vec {
        // CPU Exceptions (0..=31)
        0..=31 => handle_exception(frame),

        // Local APIC Timer Tick
        VECTOR_APIC_TIMER => {
            TELEMETRY.timer_ticks.fetch_add(1, Ordering::Relaxed);
            apic::eoi();
            crate::sched::on_timer_tick();
        }

        // Cross-CPU Reschedule IPI
        VECTOR_IPI_RESCHED => {
            apic::eoi();
            crate::sched::on_resched_ipi();
        }

        // Cross-CPU TLB Shootdown IPI
        VECTOR_IPI_TLB_SHOOTDOWN => {
            crate::mm::vspace::handle_tlb_shootdown_ipi();
            apic::eoi();
        }

        // Cross-CPU Halt IPI (panic broadcast)
        VECTOR_IPI_HALT => {
            apic::eoi();
            crate::debug::panic::halt_forever();
        }

        // Local APIC Error
        VECTOR_APIC_ERROR => {
            crate::kwarn!("APIC", "Local APIC error interrupt on LAPIC {}", apic::lapic_id());
            apic::eoi();
        }

        // Spurious interrupt — MUST NOT send EOI!
        VECTOR_APIC_SPURIOUS => {}

        // Hardware IRQs (0x20..=0x3F) -> delegated to Ring 3 via `crate::irq`
        v if v >= IRQ_VECTOR_BASE && v < IRQ_VECTOR_BASE + 32 => {
            let irq_num = v - IRQ_VECTOR_BASE;
            crate::irq::dispatch_hardware_irq(irq_num);
            apic::eoi();
        }

        _ => {
            crate::kwarn!("IDT", "Unhandled interrupt vector {:#x}", vec);
            apic::eoi();
        }
    }
}

fn handle_exception(frame: &mut InterruptFrame) {
    let vec = frame.vector as usize;

    // #PF (14): Attempt Copy-on-Write / demand resolution before faulting.
    if vec == 14 {
        TELEMETRY.page_faults.fetch_add(1, Ordering::Relaxed);
        let cr2 = crate::arch::x86_64::read_cr2();
        if crate::mm::vspace::handle_page_fault(cr2, frame.error_code, frame.from_userspace()) {
            return;
        }
        dump_page_fault(frame, cr2);
        if frame.from_userspace() {
            crate::sched::terminate_current_thread_on_fault(vec as u8, cr2);
            return;
        }
        crate::debug::panic::halt_forever();
    }

    // #BP (3): Non-fatal breakpoint log
    if vec == 3 {
        crate::kinfo!("EXC", "#BP Breakpoint at RIP={:#018x} (CPL={})", frame.rip, frame.cs & 3);
        return;
    }

    // #NM (7): Lazy FPU/SSE restore if ever triggered
    if vec == 7 {
        crate::arch::x86_64::fpu::clear_ts();
        return;
    }

    // All other exceptions: full diagnostic dump
    dump_exception_frame(frame);

    if frame.from_userspace() {
        crate::sched::terminate_current_thread_on_fault(vec as u8, frame.rip);
        return;
    }

    crate::debug::panic::halt_forever();
}

fn dump_page_fault(frame: &InterruptFrame, cr2: u64) {
    let err = frame.error_code;
    let present = (err & (1 << 0)) != 0;
    let write = (err & (1 << 1)) != 0;
    let user = (err & (1 << 2)) != 0;
    let rsvd = (err & (1 << 3)) != 0;
    let instr = (err & (1 << 4)) != 0;
    let pk = (err & (1 << 5)) != 0;
    let ss = (err & (1 << 6)) != 0;

    let mut w = EmergencySerial;
    let _ = writeln!(w, "\n==================== #PF PAGE FAULT ====================");
    let _ = writeln!(w, "  Faulting Addr (CR2): {:#018x}", cr2);
    let _ = writeln!(
        w,
        "  Error Code         : {:#x} [{} | {} | {} | RSVD={} | EXEC={} | PK={} | SS={}]",
        err,
        if present { "PROTECTION" } else { "NOT-PRESENT" },
        if write { "WRITE" } else { "READ" },
        if user { "USER(Ring3)" } else { "KERNEL(Ring0)" },
        rsvd,
        instr,
        pk,
        ss
    );
    dump_registers(&mut w, frame);
    unwind::print_stack_trace_from(frame.rbp);
    let _ = writeln!(w, "========================================================");
}

fn dump_exception_frame(frame: &InterruptFrame) {
    let vec = (frame.vector as usize).min(31);
    let mut w = EmergencySerial;
    let _ = writeln!(
        w,
        "\n==================== CPU EXCEPTION {} ({}) ====================",
        vec, EXCEPTION_NAMES[vec]
    );
    let _ = writeln!(
        w,
        "  Error Code: {:#018x}  CPL={}  LAPIC={}",
        frame.error_code,
        frame.cs & 3,
        apic::lapic_id()
    );
    dump_registers(&mut w, frame);
    unwind::print_stack_trace_from(frame.rbp);
    let _ = writeln!(w, "================================================================");
}

fn dump_registers(w: &mut EmergencySerial, f: &InterruptFrame) {
    let cr3 = crate::arch::x86_64::read_cr3();
    let _ = writeln!(w, "  RIP={:#018x}  CS={:#06x}  RFLAGS={:#018x}", f.rip, f.cs, f.rflags);
    let _ = writeln!(w, "  RSP={:#018x}  SS={:#06x}  CR3   ={:#018x}", f.rsp, f.ss, cr3);
    let _ = writeln!(w, "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}", f.rax, f.rbx, f.rcx);
    let _ = writeln!(w, "  RDX={:#018x}  RSI={:#018x}  RDI={:#018x}", f.rdx, f.rsi, f.rdi);
    let _ = writeln!(w, "  RBP={:#018x}  R8 ={:#018x}  R9 ={:#018x}", f.rbp, f.r8, f.r9);
    let _ = writeln!(w, "  R10={:#018x}  R11={:#018x}  R12={:#018x}", f.r10, f.r11, f.r12);
    let _ = writeln!(w, "  R13={:#018x}  R14={:#018x}  R15={:#018x}", f.r13, f.r14, f.r15);
}
