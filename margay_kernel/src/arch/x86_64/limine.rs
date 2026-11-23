//! Limine Boot Protocol (v8/v9) Native Rust Interface
//!
//! Zero-dependency implementation of the Limine boot protocol structures.
//! Requests ONLY the minimal information required by a pure microkernel:
//! - Higher Half Direct Map (HHDM) offset
//! - Physical Memory Map
//! - Kernel physical/virtual base addresses
//! - ACPI RSDP pointer
//! - SMP processor list (BSP + APs)
//! - Bootloader identity & kernel stack size
//!
//! Deliberately does NOT request any framebuffer or graphical display.

use core::ffi::CStr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

const LIMINE_COMMON_MAGIC_0: u64 = 0xC7B1_DD30_DF4C_8B88;
const LIMINE_COMMON_MAGIC_1: u64 = 0x0A82_E883_A194_F07B;

// ---------------------------------------------------------------------------
// Request Markers & Base Revision
// ---------------------------------------------------------------------------

#[used]
#[link_section = ".limine_requests_start"]
static LIMINE_REQUESTS_START_MARKER: [u64; 4] = [
    0xF6B8_F4B3_9DE7_D1AE,
    0xFAB9_1A69_40FC_B9CF,
    0x785C_6ED0_15D3_E316,
    0x181E_920A_7852_B9D9,
];

#[used]
#[link_section = ".limine_requests"]
static LIMINE_BASE_REVISION: [u64; 3] = [
    0xF956_2B2D_5C95_A6C8,
    0x6A7B_3849_4453_6BDC,
    2, // Limine Base Revision 2 (supported by Limine v7/v8/v9)
];

#[used]
#[link_section = ".limine_requests_end"]
static LIMINE_REQUESTS_END_MARKER: [u64; 2] = [
    0xADC0_E053_1BB1_0D03,
    0x9572_709F_3176_4C62,
];

// ---------------------------------------------------------------------------
// Bootloader Info Request
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct BootloaderInfoResponse {
    pub revision: u64,
    pub name: *const i8,
    pub version: *const i8,
}

#[repr(C)]
struct BootloaderInfoRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<BootloaderInfoResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static BOOTLOADER_INFO_REQ: BootloaderInfoRequest = BootloaderInfoRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0xF550_38D8_E2A1_202F,
        0x2794_26FC_F5F5_9740,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// Stack Size Request (request 64 KiB BSP stack)
// ---------------------------------------------------------------------------

#[repr(C)]
struct StackSizeRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<u8>,
    stack_size: u64,
}

#[used]
#[link_section = ".limine_requests"]
static STACK_SIZE_REQ: StackSizeRequest = StackSizeRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x224E_F046_0A8E_8926,
        0xE1CB_0FC2_5F46_EA3D,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
    stack_size: 64 * 1024,
};

// ---------------------------------------------------------------------------
// Higher Half Direct Map (HHDM) Request
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct HhdmResponse {
    pub revision: u64,
    pub offset: u64,
}

#[repr(C)]
struct HhdmRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<HhdmResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static HHDM_REQ: HhdmRequest = HhdmRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x48DC_F1CB_8AD2_B852,
        0x6398_4E95_9A98_244B,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// Physical Memory Map Request
// ---------------------------------------------------------------------------

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryMapType {
    Usable = 0,
    Reserved = 1,
    AcpiReclaimable = 2,
    AcpiNvs = 3,
    BadMemory = 4,
    BootloaderReclaimable = 5,
    KernelAndModules = 6,
    Framebuffer = 7,
}

impl MemoryMapType {
    pub fn from_raw(v: u64) -> Self {
        match v {
            0 => Self::Usable,
            1 => Self::Reserved,
            2 => Self::AcpiReclaimable,
            3 => Self::AcpiNvs,
            4 => Self::BadMemory,
            5 => Self::BootloaderReclaimable,
            6 => Self::KernelAndModules,
            7 => Self::Framebuffer,
            _ => Self::Reserved,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    pub base: u64,
    pub length: u64,
    pub entry_type: u64,
}

impl MemoryMapEntry {
    pub fn kind(&self) -> MemoryMapType {
        MemoryMapType::from_raw(self.entry_type)
    }
}

#[repr(C)]
pub struct MemoryMapResponse {
    pub revision: u64,
    pub entry_count: u64,
    pub entries: *const *const MemoryMapEntry,
}

#[repr(C)]
struct MemoryMapRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<MemoryMapResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static MEMORY_MAP_REQ: MemoryMapRequest = MemoryMapRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x67CF_3D9D_378A_806F,
        0xE304_ACDF_C50C_3C62,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// Kernel Address Request
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct KernelAddressResponse {
    pub revision: u64,
    pub physical_base: u64,
    pub virtual_base: u64,
}

#[repr(C)]
struct KernelAddressRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<KernelAddressResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static KERNEL_ADDRESS_REQ: KernelAddressRequest = KernelAddressRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x71BA_7686_3CC5_5F63,
        0xB264_4A48_C516_A487,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// ACPI RSDP Request
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct RsdpResponse {
    pub revision: u64,
    pub address: *const u8,
}

#[repr(C)]
struct RsdpRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<RsdpResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static RSDP_REQ: RsdpRequest = RsdpRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0xC5E7_7B6B_397E_7B43,
        0x2763_7845_ACCD_CF3C,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// SMP Request
// ---------------------------------------------------------------------------

pub type SmpGotoAddress = unsafe extern "C" fn(*const LimineSmpInfo) -> !;

#[repr(C)]
pub struct LimineSmpInfo {
    pub processor_id: u32,
    pub lapic_id: u32,
    pub reserved: u64,
    pub goto_address: AtomicU64,
    pub extra_argument: AtomicU64,
}

#[repr(C)]
pub struct SmpResponse {
    pub revision: u64,
    pub flags: u32,
    pub bsp_lapic_id: u32,
    pub cpu_count: u64,
    pub cpus: *const *mut LimineSmpInfo,
}

#[repr(C)]
struct SmpRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<SmpResponse>,
    flags: u64,
}

#[used]
#[link_section = ".limine_requests"]
static SMP_REQ: SmpRequest = SmpRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x95A6_7B81_9A1B_857E,
        0xA0B6_1B72_3B6A_73E0,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
    flags: 0, // Do not force x2APIC in bootloader; kernel probes & selects cleanly
};

// ---------------------------------------------------------------------------
// Module Request (External User-Space Servers / Init ELF)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct LimineFile {
    pub revision: u64,
    pub address: *const u8,
    pub size: u64,
    pub path: *const i8,
    pub string: *const i8,
    pub media_type: u32,
    pub unused: u32,
    pub tftp_ip: u32,
    pub tftp_port: u32,
    pub partition_index: u32,
    pub mbr_disk_id: u32,
    pub gpt_disk_uuid: [u8; 16],
    pub gpt_part_uuid: [u8; 16],
    pub part_uuid: [u8; 16],
}

#[repr(C)]
pub struct ModuleResponse {
    pub revision: u64,
    pub module_count: u64,
    pub modules: *const *const LimineFile,
}

#[repr(C)]
struct ModuleRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<ModuleResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static MODULE_REQ: ModuleRequest = ModuleRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x3E7E_2797_02BE_32AF,
        0xCA1C_4F3B_D128_0CEE,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// Framebuffer Request (Raw Hardware Info Delegated to Ring 3 GOSE GOP)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct LimineFramebuffer {
    pub address: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub unused: [u8; 7],
    pub edid_size: u64,
    pub edid: *const u8,
}

#[repr(C)]
pub struct FramebufferResponse {
    pub revision: u64,
    pub framebuffer_count: u64,
    pub framebuffers: *const *const LimineFramebuffer,
}

#[repr(C)]
struct FramebufferRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<FramebufferResponse>,
}

#[used]
#[link_section = ".limine_requests"]
static FRAMEBUFFER_REQ: FramebufferRequest = FramebufferRequest {
    id: [
        LIMINE_COMMON_MAGIC_0,
        LIMINE_COMMON_MAGIC_1,
        0x9D58_27DC_D881_DD75,
        0xA314_8604_F6FA_B11B,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

// ---------------------------------------------------------------------------
// Safe Accessors
// ---------------------------------------------------------------------------

pub fn base_revision_supported() -> bool {
    unsafe { core::ptr::read_volatile(&LIMINE_BASE_REVISION[2]) == 0 }
}

pub fn bootloader_info() -> Option<(&'static str, &'static str)> {
    let ptr = BOOTLOADER_INFO_REQ.response.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    unsafe {
        let resp = &*ptr;
        let name = if !resp.name.is_null() {
            CStr::from_ptr(resp.name).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        };
        let ver = if !resp.version.is_null() {
            CStr::from_ptr(resp.version).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        };
        Some((name, ver))
    }
}

pub fn hhdm_offset() -> u64 {
    let ptr = HHDM_REQ.response.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "Limine HHDM response missing");
    unsafe { (*ptr).offset }
}

pub fn kernel_address() -> (u64, u64) {
    let ptr = KERNEL_ADDRESS_REQ.response.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "Limine KernelAddress response missing");
    unsafe { ((*ptr).physical_base, (*ptr).virtual_base) }
}

pub fn memory_map_entries() -> &'static [*const MemoryMapEntry] {
    let ptr = MEMORY_MAP_REQ.response.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "Limine MemoryMap response missing");
    unsafe {
        let resp = &*ptr;
        core::slice::from_raw_parts(resp.entries, resp.entry_count as usize)
    }
}

pub fn rsdp_address() -> Option<u64> {
    let ptr = RSDP_REQ.response.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    unsafe {
        let addr = (*ptr).address as u64;
        if addr == 0 { None } else { Some(addr) }
    }
}

pub fn smp_response() -> Option<&'static SmpResponse> {
    let ptr = SMP_REQ.response.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// Return slice of bootloader-loaded module files (e.g. `gose_init.elf`).
pub fn modules() -> &'static [*const LimineFile] {
    let ptr = MODULE_REQ.response.load(Ordering::Acquire);
    if ptr.is_null() {
        return &[];
    }
    unsafe {
        let resp = &*ptr;
        if resp.module_count == 0 || resp.modules.is_null() {
            &[]
        } else {
            core::slice::from_raw_parts(resp.modules, resp.module_count as usize)
        }
    }
}

/// Return raw hardware framebuffer descriptor (if provided by Limine) so the
/// microkernel can delegate its MMIO capability to Ring 3 `GOSE GOP`.
pub fn primary_framebuffer() -> Option<&'static LimineFramebuffer> {
    let ptr = FRAMEBUFFER_REQ.response.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    unsafe {
        let resp = &*ptr;
        if resp.framebuffer_count == 0 || resp.framebuffers.is_null() {
            return None;
        }
        let fb_ptr = *resp.framebuffers;
        if fb_ptr.is_null() {
            None
        } else {
            Some(&*fb_ptr)
        }
    }
}
