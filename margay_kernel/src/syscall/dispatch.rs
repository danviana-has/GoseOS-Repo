//! Typed System Call Dispatcher (`margay_syscall_dispatch`)
//!
//! Validates Ring 3 capabilities, user-space memory ranges, and arguments
//! before invoking microkernel IPC, Capability, Memory, Thread, and Hardware
//! Delegation primitives.

use core::sync::atomic::Ordering;

use crate::arch::x86_64::context::SyscallFrame;
use crate::arch::x86_64::smp;
use crate::cap::cnode;
use crate::cap::object::{CapObject, Capability};
use crate::cap::{self, CapRights, RetypeKind, SlotAddress};
use crate::debug::telemetry::TELEMETRY;
use crate::ipc::{endpoint, notification, shmem, IpcMessage};
use crate::mm::frame::{frame_ref_inc, PAGE_SIZE};
use crate::mm::paging::PageFlags;
use crate::mm::vspace::{VmaKind, VmaRegion, USER_SPACE_LIMIT};
use crate::mm::{pmm, PhysAddr, VirtAddr};
use crate::sched::process::Process;
use crate::sched::DEFAULT_PRIORITY;
use crate::syscall::*;

/// Central C-ABI entry point called from `margay_syscall_entry` in `context.rs`.
///
/// Register ABI:
/// - `rax`: syscall number -> return value (0 or positive value on success, negative `SyscallError` on error)
/// - `rdi`: arg0
/// - `rsi`: arg1
/// - `rdx`: arg2
/// - `r10`: arg3
/// - `r8` : arg4
/// - `r9` : arg5
#[no_mangle]
pub extern "C" fn margay_syscall_dispatch(frame: &mut SyscallFrame) {
    TELEMETRY.syscalls_total.fetch_add(1, Ordering::Relaxed);

    let num = frame.rax;
    let a0 = frame.rdi;
    let a1 = frame.rsi;
    let a2 = frame.rdx;
    let a3 = frame.r10;
    let a4 = frame.r8;
    let a5 = frame.r9;

    let ret: u64 = match num {
        SYS_DEBUG_PRINT => sys_debug_print(a0, a1),
        SYS_YIELD => {
            crate::sched::yield_now();
            SyscallError::Ok.as_u64()
        }
        SYS_THREAD_EXIT => {
            crate::sched::terminate_current_thread();
        }
        SYS_GET_TID => crate::sched::current_tid(),
        SYS_IPC_SEND => sys_ipc_send(a0, a1, a2, a3, a4, a5),
        SYS_IPC_RECV => sys_ipc_recv(frame, a0),
        SYS_IPC_CALL => sys_ipc_call(frame, a0, a1, a2, a3, a4, a5),
        SYS_IPC_REPLY => sys_ipc_reply(a0, a1, a2, a3, a4),
        SYS_IPC_REPLY_WAIT => sys_ipc_reply_wait(frame, a0, a1, a2, a3, a4),
        SYS_NOTIFY_SIGNAL => sys_notify_signal(a0, a1),
        SYS_NOTIFY_WAIT => sys_notify_wait(a0),
        SYS_NOTIFY_POLL => sys_notify_poll(a0),
        SYS_CAP_INVOKE => sys_cap_invoke(a0, a1, a2, a3, a4, a5),
        SYS_SHMEM_CREATE => sys_shmem_create(a0),
        SYS_SHMEM_MAP => sys_shmem_map(a0, a1),
        SYS_THREAD_SPAWN => sys_thread_spawn(a0, a1, a2),
        SYS_SYSINFO => sys_sysinfo(a0),
        SYS_PROCESS_CREATE => sys_process_create(a0, a1, a2),
        SYS_VSPACE_MAP_FRAME => sys_vspace_map_frame(a0, a1, a2, a3),
        SYS_THREAD_CREATE_IN => sys_thread_create_in(a0, a1, a2, a3),
        _ => SyscallError::InvalidSyscall.as_u64(),
    };

    frame.rax = ret;
}

/// `SYS_DEBUG_PRINT(ptr, len)`: validate user slice and emit to COM1 serial.
fn sys_debug_print(ptr: u64, len: u64) -> u64 {
    let len = (len as usize).min(1024);
    if len == 0 {
        return 0;
    }

    let pid = crate::sched::current_pid();
    let valid = crate::sched::with_process_mut(pid, |proc| {
        proc.vspace.validate_user_range(ptr, len, false)
    })
    .unwrap_or(false);

    if !valid {
        return SyscallError::Fault.as_u64();
    }

    let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    if let Ok(s) = core::str::from_utf8(slice) {
        crate::debug::serial::write_str(s);
        len as u64
    } else {
        SyscallError::InvalidArg.as_u64()
    }
}

/// `SYS_IPC_SEND(ep_cptr, tag, r0, r1, r2, r3)`
fn sys_ipc_send(ep_cptr: u64, tag: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, ep_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::WRITE) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Endpoint { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let msg = IpcMessage {
        tag,
        regs: [r0, r1, r2, r3],
        badge: cap.badge,
        cap_src: None,
    };

    match endpoint::ipc_send(id, msg, cap.badge) {
        Ok(()) => SyscallError::Ok.as_u64(),
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_IPC_RECV(ep_cptr)` -> returns `tag` in `rax`, `r0..r3` in `rdi/rsi/rdx/r10`, `badge` in `r8`.
fn sys_ipc_recv(frame: &mut SyscallFrame, ep_cptr: u64) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, ep_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::READ) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Endpoint { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    match endpoint::ipc_recv(id) {
        Ok(msg) => {
            frame.rdi = msg.regs[0];
            frame.rsi = msg.regs[1];
            frame.rdx = msg.regs[2];
            frame.r10 = msg.regs[3];
            frame.r8 = msg.badge;
            msg.tag
        }
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_IPC_CALL(ep_cptr, tag, r0, r1, r2, r3)` -> returns reply `tag` in `rax`, `r0..r3` in `rdi/rsi/rdx/r10`.
fn sys_ipc_call(
    frame: &mut SyscallFrame,
    ep_cptr: u64,
    tag: u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, ep_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::WRITE) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Endpoint { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let msg = IpcMessage {
        tag,
        regs: [r0, r1, r2, r3],
        badge: cap.badge,
        cap_src: None,
    };

    match endpoint::ipc_call(id, msg, cap.badge) {
        Ok(reply) => {
            frame.rdi = reply.regs[0];
            frame.rsi = reply.regs[1];
            frame.rdx = reply.regs[2];
            frame.r10 = reply.regs[3];
            frame.r8 = reply.badge;
            reply.tag
        }
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_IPC_REPLY(tag, r0, r1, r2, r3)`
fn sys_ipc_reply(tag: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> u64 {
    let msg = IpcMessage {
        tag,
        regs: [r0, r1, r2, r3],
        badge: 0,
        cap_src: None,
    };
    match endpoint::ipc_reply(msg) {
        Ok(()) => SyscallError::Ok.as_u64(),
        Err(_) => SyscallError::NotFound.as_u64(),
    }
}

/// `SYS_IPC_REPLY_WAIT(ep_cptr, tag, r0, r1, r2)`
fn sys_ipc_reply_wait(
    frame: &mut SyscallFrame,
    ep_cptr: u64,
    tag: u64,
    r0: u64,
    r1: u64,
    r2: u64,
) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, ep_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::READ) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Endpoint { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let reply_msg = IpcMessage {
        tag,
        regs: [r0, r1, r2, 0],
        badge: 0,
        cap_src: None,
    };
    match endpoint::ipc_reply_wait(id, reply_msg) {
        Ok(msg) => {
            frame.rdi = msg.regs[0];
            frame.rsi = msg.regs[1];
            frame.rdx = msg.regs[2];
            frame.r10 = msg.regs[3];
            frame.r8 = msg.badge;
            msg.tag
        }
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_NOTIFY_SIGNAL(notif_cptr, bits)`
fn sys_notify_signal(notif_cptr: u64, bits: u64) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, notif_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::WRITE) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Notification { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let effective_bits = if cap.badge != 0 { cap.badge } else { bits };
    match notification::signal(id, effective_bits) {
        Ok(()) => SyscallError::Ok.as_u64(),
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_NOTIFY_WAIT(notif_cptr)` -> returns consumed bitmask word.
fn sys_notify_wait(notif_cptr: u64) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, notif_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::READ) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Notification { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    match notification::wait(id) {
        Ok(word) => word,
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_NOTIFY_POLL(notif_cptr)` -> non-blocking bitmask consume.
fn sys_notify_poll(notif_cptr: u64) -> u64 {
    let Some(cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode, notif_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !cap.has_rights(CapRights::READ) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Notification { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    match notification::poll(id) {
        Ok(word) => word,
        Err(_) => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_CAP_INVOKE(op, a1, a2, a3, a4, a5)`: generic capability method invocation.
/// Supports both flat (`depth == 0`) and hierarchical (`depth > 0` in bits 63..56) CPtrs.
fn sys_cap_invoke(op: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let Some(cnode_id) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };

    match op {
        CAP_OP_MINT => {
            let Some(src) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let Some(dst) = cnode::resolve_cptr(cnode_id, a2) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let rights = CapRights::from_bits(a3 as u32);
            let badge = a4;
            match cap::cap_mint(src, dst, rights, badge) {
                Ok(()) => SyscallError::Ok.as_u64(),
                Err(_) => SyscallError::InvalidCap.as_u64(),
            }
        }
        CAP_OP_COPY => {
            let Some(src) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let Some(dst) = cnode::resolve_cptr(cnode_id, a2) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let rights = CapRights::from_bits(a3 as u32);
            match cap::cap_copy(src, dst, rights) {
                Ok(()) => SyscallError::Ok.as_u64(),
                Err(_) => SyscallError::InvalidCap.as_u64(),
            }
        }
        CAP_OP_MOVE => {
            let Some(src) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let Some(dst) = cnode::resolve_cptr(cnode_id, a2) else {
                return SyscallError::InvalidCap.as_u64();
            };
            match cap::cap_move(src, dst) {
                Ok(()) => SyscallError::Ok.as_u64(),
                Err(_) => SyscallError::InvalidCap.as_u64(),
            }
        }
        CAP_OP_DELETE => {
            let Some(target) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            match cap::cap_delete(target) {
                Ok(()) => SyscallError::Ok.as_u64(),
                Err(_) => SyscallError::InvalidCap.as_u64(),
            }
        }
        CAP_OP_REVOKE => {
            let Some(target) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            match cap::cap_revoke(target) {
                Ok(revoked_count) => revoked_count as u64,
                Err(_) => SyscallError::InsufficientRights.as_u64(),
            }
        }
        CAP_OP_RETYPE => {
            // a1 = untyped_cptr, a2 = dst_cptr, a3 = RetypeKind (1..=5), a4 = size_param
            let Some(untyped_src) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let Some(dst) = cnode::resolve_cptr(cnode_id, a2) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let Some(kind) = RetypeKind::from_u64(a3) else {
                return SyscallError::InvalidArg.as_u64();
            };
            match cap::cap_retype(untyped_src, dst, kind, a4) {
                Ok(_) => SyscallError::Ok.as_u64(),
                Err(cap::CapError::OutOfMemory) => SyscallError::OutOfMemory.as_u64(),
                Err(cap::CapError::InsufficientRights) => SyscallError::InsufficientRights.as_u64(),
                Err(_) => SyscallError::InvalidCap.as_u64(),
            }
        }
        CAP_OP_COPY_TO_CNODE => {
            // Copy/mint a capability from caller's `a1` into target CNode `a2` at slot `a3`
            // with attenuated `rights = a4` and optional `badge = a5`.
            let Some(src) = cnode::resolve_cptr(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let Some(dst_cnode_cap) = cnode::lookup_cap(cnode_id, a2) else {
                return SyscallError::InvalidCap.as_u64();
            };
            if !dst_cnode_cap.has_rights(CapRights::WRITE) {
                return SyscallError::InsufficientRights.as_u64();
            }
            let CapObject::CNode { id: target_cnode_id, .. } = dst_cnode_cap.object else {
                return SyscallError::InvalidCap.as_u64();
            };
            let dst = SlotAddress {
                cnode_id: target_cnode_id,
                slot_idx: a3 as usize,
            };
            let rights = if a4 == 0 { CapRights::ALL } else { CapRights::from_bits(a4 as u32) };
            match cap::cap_mint(src, dst, rights, a5) {
                Ok(()) => SyscallError::Ok.as_u64(),
                Err(_) => SyscallError::InvalidCap.as_u64(),
            }
        }
        CAP_OP_IOPORT_GRANT => {
            let Some(cap) = cnode::lookup_cap(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            if let CapObject::IoPort { start_port, end_port } = cap.object {
                let pid = crate::sched::current_pid();
                if crate::irq::grant_ioport_range(pid, start_port, end_port) {
                    SyscallError::Ok.as_u64()
                } else {
                    SyscallError::InvalidArg.as_u64()
                }
            } else {
                SyscallError::InvalidCap.as_u64()
            }
        }
        CAP_OP_IRQ_BIND => {
            // a1 = IrqControl or IrqHandler cptr, a2 = irq_num, a3 = notif_cptr, a4 = badge
            let Some(irq_cap) = cnode::lookup_cap(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let irq_num = match irq_cap.object {
                CapObject::IrqControl => a2 as u8,
                CapObject::IrqHandler { irq_num } => irq_num,
                _ => return SyscallError::InvalidCap.as_u64(),
            };
            let Some(notif_cap) = cnode::lookup_cap(cnode_id, a3) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let CapObject::Notification { id: notif_id } = notif_cap.object else {
                return SyscallError::InvalidCap.as_u64();
            };
            if crate::irq::bind_irq_to_notification(irq_num, notif_id, a4, false, false) {
                SyscallError::Ok.as_u64()
            } else {
                SyscallError::InvalidArg.as_u64()
            }
        }
        CAP_OP_IRQ_ACK => {
            let Some(irq_cap) = cnode::lookup_cap(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let irq_num = match irq_cap.object {
                CapObject::IrqControl => a2 as u8,
                CapObject::IrqHandler { irq_num } => irq_num,
                _ => return SyscallError::InvalidCap.as_u64(),
            };
            if crate::irq::ack_irq(irq_num) {
                SyscallError::Ok.as_u64()
            } else {
                SyscallError::InvalidArg.as_u64()
            }
        }
        CAP_OP_MMIO_MAP => {
            // a1 = Frame(is_device=true) cptr, a2 = target_vaddr, a3 = num_pages
            let Some(frame_cap) = cnode::lookup_cap(cnode_id, a1) else {
                return SyscallError::InvalidCap.as_u64();
            };
            let CapObject::Frame { paddr, is_device: true, .. } = frame_cap.object else {
                return SyscallError::InvalidCap.as_u64();
            };
            let pid = crate::sched::current_pid();
            if crate::irq::map_mmio_for_process(pid, paddr, a2, a3 as usize) {
                SyscallError::Ok.as_u64()
            } else {
                SyscallError::InvalidArg.as_u64()
            }
        }
        _ => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_SHMEM_CREATE(num_pages)` -> creates SharedMemory and installs capability in a free CSpace slot, returning its CPtr.
fn sys_shmem_create(num_pages: u64) -> u64 {
    let Some(cnode_id) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(slot_idx) = cnode::find_free_slot(cnode_id) else {
        return SyscallError::OutOfMemory.as_u64();
    };
    let Ok(shmem_id) = shmem::create_shared_memory(num_pages as usize) else {
        return SyscallError::OutOfMemory.as_u64();
    };
    let cap = Capability::new(CapObject::SharedMem { id: shmem_id }, CapRights::ALL);
    if cap::cap_insert_root(cnode_id, slot_idx, cap).is_err() {
        shmem::destroy_shared_memory(shmem_id);
        return SyscallError::OutOfMemory.as_u64();
    }
    slot_idx as u64
}

/// `SYS_SHMEM_MAP(shmem_cptr, target_vaddr)` -> maps SharedMemory into current process VSpace.
fn sys_shmem_map(shmem_cptr: u64, target_vaddr: u64) -> u64 {
    let Some(cnode_id) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cap) = cnode::lookup_cap(cnode_id, shmem_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    let CapObject::SharedMem { id } = cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let pid = crate::sched::current_pid();
    let res = crate::sched::with_process_mut(pid, |proc| {
        shmem::map_into_vspace(id, &mut proc.vspace, target_vaddr, cap.rights)
    });

    match res {
        Some(Ok(bytes)) => bytes as u64,
        _ => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_THREAD_SPAWN(entry_rip, user_rsp, arg0)` -> spawns a Ring 3 thread in current process.
fn sys_thread_spawn(entry_rip: u64, user_rsp: u64, arg0: u64) -> u64 {
    if entry_rip == 0
        || entry_rip >= crate::mm::vspace::USER_SPACE_LIMIT
        || user_rsp == 0
        || user_rsp >= crate::mm::vspace::USER_SPACE_LIMIT
    {
        return SyscallError::InvalidArg.as_u64();
    }
    match crate::sched::spawn_in_current_process(entry_rip, user_rsp, arg0) {
        Some(tid) => tid,
        None => SyscallError::OutOfMemory.as_u64(),
    }
}

/// `SYS_SYSINFO(query)`:
///   0 -> online CPU count
///   1 -> free physical pages
///   2 -> total timer ticks
///   3 -> total usable physical pages
fn sys_sysinfo(query: u64) -> u64 {
    match query {
        0 => smp::online_cpus() as u64,
        1 => pmm::stats().free_pages as u64,
        2 => TELEMETRY.timer_ticks.load(Ordering::Relaxed),
        3 => pmm::stats().total_pages as u64,
        _ => SyscallError::InvalidArg.as_u64(),
    }
}

/// `SYS_PROCESS_CREATE(cnode_radix, vspace_dst_cptr, cnode_dst_cptr)`:
/// Creates a new isolated Ring 3 Process (new PML4 `AddressSpace` + new root `CNode`)
/// and installs capabilities to its `VSpace` and `CNode` in the caller's CSpace.
/// Returns the new `ProcessId` in `rax`.
fn sys_process_create(cnode_radix: u64, vspace_dst_cptr: u64, cnode_dst_cptr: u64) -> u64 {
    let Some(caller_cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(vspace_slot) = cnode::resolve_cptr(caller_cnode, vspace_dst_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(cnode_slot) = cnode::resolve_cptr(caller_cnode, cnode_dst_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };

    let radix = (cnode_radix as u8).clamp(4, 10);
    let Ok(proc) = Process::new("user_server", radix) else {
        return SyscallError::OutOfMemory.as_u64();
    };
    let vspace_id = proc.vspace.id;
    let child_cnode_id = proc.root_cnode;
    let pid = crate::sched::register_process(proc);

    let vspace_cap = Capability::new(CapObject::VSpace { id: vspace_id }, CapRights::ALL);
    let cnode_cap = Capability::new(
        CapObject::CNode {
            id: child_cnode_id,
            radix_bits: radix,
        },
        CapRights::ALL,
    );

    if cap::cap_insert_root(vspace_slot.cnode_id, vspace_slot.slot_idx, vspace_cap).is_err() {
        return SyscallError::Busy.as_u64();
    }
    if cap::cap_insert_root(cnode_slot.cnode_id, cnode_slot.slot_idx, cnode_cap).is_err() {
        let _ = cap::cap_delete(vspace_slot);
        return SyscallError::Busy.as_u64();
    }

    pid
}

/// `SYS_VSPACE_MAP_FRAME(vspace_cptr, frame_cptr, target_vaddr, perm_bits)`:
/// Maps a `CapObject::Frame` capability into a target `CapObject::VSpace` at `target_vaddr`,
/// enforcing strict **W^X** (`perm_bits`: bit 0 = READ, bit 1 = WRITE, bit 2 = EXECUTE).
fn sys_vspace_map_frame(
    vspace_cptr: u64,
    frame_cptr: u64,
    target_vaddr: u64,
    perm_bits: u64,
) -> u64 {
    if target_vaddr == 0
        || target_vaddr >= USER_SPACE_LIMIT
        || (target_vaddr & (PAGE_SIZE as u64 - 1)) != 0
    {
        return SyscallError::InvalidArg.as_u64();
    }

    let want_write = (perm_bits & 0x2) != 0;
    let want_exec = (perm_bits & 0x4) != 0;
    // Strict W^X enforcement
    if want_write && want_exec {
        return SyscallError::PermissionDenied.as_u64();
    }

    let Some(caller_cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(vs_cap) = cnode::lookup_cap(caller_cnode, vspace_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !vs_cap.has_rights(CapRights::WRITE) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::VSpace { id: vspace_id } = vs_cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let Some(fr_cap) = cnode::lookup_cap(caller_cnode, frame_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !fr_cap.has_rights(CapRights::READ)
        || (want_write && !fr_cap.has_rights(CapRights::WRITE))
        || (want_exec && !fr_cap.has_rights(CapRights::EXECUTE))
    {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::Frame { paddr, is_device, .. } = fr_cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let Some(target_pid) = crate::sched::pid_by_vspace(vspace_id) else {
        return SyscallError::NotFound.as_u64();
    };

    let mut flags = PageFlags::PRESENT.union(PageFlags::USER);
    if want_write {
        flags = flags.union(PageFlags::WRITABLE);
    }
    if !want_exec {
        flags = flags.union(PageFlags::NO_EXECUTE);
    }
    if is_device {
        flags = flags
            .union(PageFlags::NO_CACHE)
            .union(PageFlags::WRITE_THROUGH);
    }

    let kind = if is_device {
        VmaKind::MmioDevice
    } else if want_exec {
        VmaKind::Code
    } else {
        VmaKind::Anonymous
    };

    let mapped = crate::sched::with_process_mut(target_pid, |proc| {
        let _ = proc.vspace.register_vma(VmaRegion {
            start: target_vaddr,
            length: PAGE_SIZE as u64,
            flags,
            kind,
        });
        frame_ref_inc(paddr);
        if proc
            .vspace
            .map_page(VirtAddr::new(target_vaddr), PhysAddr::new(paddr), flags)
            .is_err()
        {
            pmm::release_frame(PhysAddr::new(paddr));
            false
        } else {
            true
        }
    })
    .unwrap_or(false);

    if mapped {
        SyscallError::Ok.as_u64()
    } else {
        SyscallError::Busy.as_u64()
    }
}

/// `SYS_THREAD_CREATE_IN(vspace_cptr, entry_rip, user_rsp, arg0)`:
/// Spawns a new Ring 3 execution thread inside the target Process identified
/// by `vspace_cptr` (its own isolated CR3 + CSpace).
fn sys_thread_create_in(vspace_cptr: u64, entry_rip: u64, user_rsp: u64, arg0: u64) -> u64 {
    if entry_rip == 0
        || entry_rip >= USER_SPACE_LIMIT
        || user_rsp == 0
        || user_rsp >= USER_SPACE_LIMIT
    {
        return SyscallError::InvalidArg.as_u64();
    }

    let Some(caller_cnode) = crate::sched::current_cnode() else {
        return SyscallError::InvalidCap.as_u64();
    };
    let Some(vs_cap) = cnode::lookup_cap(caller_cnode, vspace_cptr) else {
        return SyscallError::InvalidCap.as_u64();
    };
    if !vs_cap.has_rights(CapRights::WRITE) {
        return SyscallError::InsufficientRights.as_u64();
    }
    let CapObject::VSpace { id: vspace_id } = vs_cap.object else {
        return SyscallError::InvalidCap.as_u64();
    };

    let Some(target_pid) = crate::sched::pid_by_vspace(vspace_id) else {
        return SyscallError::NotFound.as_u64();
    };

    match crate::sched::spawn_user_thread(target_pid, entry_rip, user_rsp, arg0, DEFAULT_PRIORITY) {
        Some(tid) => tid,
        None => SyscallError::OutOfMemory.as_u64(),
    }
}
