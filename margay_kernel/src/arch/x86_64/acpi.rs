//! Minimal ACPI Parser (RSDP, RSDT/XSDT, MADT)
//!
//! Extracts hardware interrupt topology (Local APICs, I/O APICs, Interrupt
//! Source Overrides, and NMI pins) from the ACPI Multiple APIC Description
//! Table (MADT) without any external crate or heap allocation.

use core::ptr;

pub const MAX_MADT_LAPICS: usize = 64;
pub const MAX_MADT_IOAPICS: usize = 8;
pub const MAX_MADT_ISOS: usize = 32;

#[repr(C, packed)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

#[repr(C, packed)]
struct RsdpV2 {
    v1: RsdpV1,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

#[repr(C, packed)]
struct MadtHeader {
    sdt: SdtHeader,
    lapic_addr: u32,
    flags: u32,
}

#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MadtLapic {
    pub processor_id: u8,
    pub apic_id: u8,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MadtIoApic {
    pub ioapic_id: u8,
    pub address: u64,
    pub gsi_base: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MadtIso {
    pub bus_source: u8,
    pub irq_source: u8,
    pub gsi: u32,
    pub flags: u16,
}

impl MadtIso {
    /// True if active-low polarity is requested.
    pub fn active_low(&self) -> bool {
        (self.flags & 0x03) == 0x03
    }

    /// True if level-triggered mode is requested.
    pub fn level_triggered(&self) -> bool {
        ((self.flags >> 2) & 0x03) == 0x03
    }
}

/// Parsed ACPI MADT topology.
pub struct AcpiInfo {
    pub lapic_phys_base: u64,
    pub has_legacy_pic: bool,
    pub lapics: [MadtLapic; MAX_MADT_LAPICS],
    pub lapic_count: usize,
    pub ioapics: [MadtIoApic; MAX_MADT_IOAPICS],
    pub ioapic_count: usize,
    pub isos: [MadtIso; MAX_MADT_ISOS],
    pub iso_count: usize,
}

impl AcpiInfo {
    pub const fn empty() -> Self {
        Self {
            lapic_phys_base: 0xFEE0_0000,
            has_legacy_pic: true,
            lapics: [MadtLapic {
                processor_id: 0,
                apic_id: 0,
                enabled: false,
            }; MAX_MADT_LAPICS],
            lapic_count: 0,
            ioapics: [MadtIoApic {
                ioapic_id: 0,
                address: 0,
                gsi_base: 0,
            }; MAX_MADT_IOAPICS],
            ioapic_count: 0,
            isos: [MadtIso {
                bus_source: 0,
                irq_source: 0,
                gsi: 0,
                flags: 0,
            }; MAX_MADT_ISOS],
            iso_count: 0,
        }
    }

    /// Resolve a legacy ISA IRQ (0..15) to its Global System Interrupt (GSI)
    /// and trigger/polarity flags using MADT Interrupt Source Overrides.
    pub fn resolve_isa_irq(&self, isa_irq: u8) -> (u32, bool, bool) {
        for i in 0..self.iso_count {
            if self.isos[i].bus_source == 0 && self.isos[i].irq_source == isa_irq {
                return (
                    self.isos[i].gsi,
                    self.isos[i].active_low(),
                    self.isos[i].level_triggered(),
                );
            }
        }
        (isa_irq as u32, false, false)
    }
}

fn validate_checksum(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

#[inline]
fn phys_to_virt_early(phys: u64, hhdm: u64) -> u64 {
    if phys >= hhdm {
        phys
    } else {
        phys.wrapping_add(hhdm)
    }
}

/// Parse ACPI tables starting from the Limine-provided RSDP address.
pub fn parse_acpi(rsdp_addr: u64, hhdm: u64) -> AcpiInfo {
    let mut info = AcpiInfo::empty();

    let rsdp_virt = phys_to_virt_early(rsdp_addr, hhdm) as *const RsdpV1;
    let sig = unsafe { ptr::read_unaligned(ptr::addr_of!((*rsdp_virt).signature)) };
    if &sig != b"RSD PTR " {
        crate::kwarn!("ACPI", "Invalid RSDP signature");
        return info;
    }

    if !validate_checksum(rsdp_virt as *const u8, core::mem::size_of::<RsdpV1>()) {
        crate::kwarn!("ACPI", "RSDP v1 checksum failed");
        return info;
    }

    let rev = unsafe { ptr::read_unaligned(ptr::addr_of!((*rsdp_virt).revision)) };
    let madt_ptr = if rev >= 2 {
        let rsdp2 = rsdp_virt as *const RsdpV2;
        let xsdt_phys = unsafe { ptr::read_unaligned(ptr::addr_of!((*rsdp2).xsdt_address)) };
        if xsdt_phys != 0 {
            find_sdt_in_xsdt(xsdt_phys, hhdm, b"APIC")
        } else {
            let rsdt_phys = unsafe { ptr::read_unaligned(ptr::addr_of!((*rsdp_virt).rsdt_address)) } as u64;
            find_sdt_in_rsdt(rsdt_phys, hhdm, b"APIC")
        }
    } else {
        let rsdt_phys = unsafe { ptr::read_unaligned(ptr::addr_of!((*rsdp_virt).rsdt_address)) } as u64;
        find_sdt_in_rsdt(rsdt_phys, hhdm, b"APIC")
    };

    if let Some(madt_virt) = madt_ptr {
        parse_madt(madt_virt, &mut info);
    } else {
        crate::kwarn!("ACPI", "MADT (APIC) table not found; using defaults");
    }

    crate::kinfo!(
        "ACPI",
        "Rev={} LAPIC={:#x} CPUs={} IOAPICs={} ISOs={}",
        rev,
        info.lapic_phys_base,
        info.lapic_count,
        info.ioapic_count,
        info.iso_count
    );

    info
}

fn find_sdt_in_rsdt(rsdt_phys: u64, hhdm: u64, target: &[u8; 4]) -> Option<*const u8> {
    let rsdt_virt = phys_to_virt_early(rsdt_phys, hhdm) as *const SdtHeader;
    let hdr = unsafe { ptr::read_unaligned(rsdt_virt) };
    if &hdr.signature != b"RSDT" {
        return None;
    }
    let header_sz = core::mem::size_of::<SdtHeader>();
    if (hdr.length as usize) < header_sz {
        return None;
    }
    let count = (hdr.length as usize - header_sz) / 4;
    let entries_base = unsafe { (rsdt_virt as *const u8).add(header_sz) as *const u32 };
    for i in 0..count {
        let entry_phys = unsafe { ptr::read_unaligned(entries_base.add(i)) } as u64;
        let entry_virt = phys_to_virt_early(entry_phys, hhdm) as *const SdtHeader;
        let eh = unsafe { ptr::read_unaligned(entry_virt) };
        if &eh.signature == target && validate_checksum(entry_virt as *const u8, eh.length as usize) {
            return Some(entry_virt as *const u8);
        }
    }
    None
}

fn find_sdt_in_xsdt(xsdt_phys: u64, hhdm: u64, target: &[u8; 4]) -> Option<*const u8> {
    let xsdt_virt = phys_to_virt_early(xsdt_phys, hhdm) as *const SdtHeader;
    let hdr = unsafe { ptr::read_unaligned(xsdt_virt) };
    if &hdr.signature != b"XSDT" {
        return None;
    }
    let header_sz = core::mem::size_of::<SdtHeader>();
    if (hdr.length as usize) < header_sz {
        return None;
    }
    let count = (hdr.length as usize - header_sz) / 8;
    let entries_base = unsafe { (xsdt_virt as *const u8).add(header_sz) as *const u64 };
    for i in 0..count {
        let entry_phys = unsafe { ptr::read_unaligned(entries_base.add(i)) };
        let entry_virt = phys_to_virt_early(entry_phys, hhdm) as *const SdtHeader;
        let eh = unsafe { ptr::read_unaligned(entry_virt) };
        if &eh.signature == target && validate_checksum(entry_virt as *const u8, eh.length as usize) {
            return Some(entry_virt as *const u8);
        }
    }
    None
}

fn parse_madt(madt_ptr: *const u8, info: &mut AcpiInfo) {
    let madt = unsafe { ptr::read_unaligned(madt_ptr as *const MadtHeader) };
    info.lapic_phys_base = madt.lapic_addr as u64;
    info.has_legacy_pic = (madt.flags & 1) != 0;

    let total_len = madt.sdt.length as usize;
    let mut offset = core::mem::size_of::<MadtHeader>();

    while offset + 2 <= total_len {
        let eh = unsafe { ptr::read_unaligned(madt_ptr.add(offset) as *const MadtEntryHeader) };
        if eh.length < 2 || offset + (eh.length as usize) > total_len {
            break;
        }
        let base = unsafe { madt_ptr.add(offset) };

        match eh.entry_type {
            // Type 0: Processor Local APIC
            0 if eh.length >= 8 => {
                if info.lapic_count < MAX_MADT_LAPICS {
                    let proc_id = unsafe { *base.add(2) };
                    let apic_id = unsafe { *base.add(3) };
                    let flags = unsafe { ptr::read_unaligned(base.add(4) as *const u32) };
                    let enabled = (flags & 0x03) != 0;
                    info.lapics[info.lapic_count] = MadtLapic {
                        processor_id: proc_id,
                        apic_id,
                        enabled,
                    };
                    info.lapic_count += 1;
                }
            }
            // Type 1: I/O APIC
            1 if eh.length >= 12 => {
                if info.ioapic_count < MAX_MADT_IOAPICS {
                    let ioapic_id = unsafe { *base.add(2) };
                    let addr = unsafe { ptr::read_unaligned(base.add(4) as *const u32) } as u64;
                    let gsi_base = unsafe { ptr::read_unaligned(base.add(8) as *const u32) };
                    info.ioapics[info.ioapic_count] = MadtIoApic {
                        ioapic_id,
                        address: addr,
                        gsi_base,
                    };
                    info.ioapic_count += 1;
                }
            }
            // Type 2: Interrupt Source Override
            2 if eh.length >= 10 => {
                if info.iso_count < MAX_MADT_ISOS {
                    let bus_source = unsafe { *base.add(2) };
                    let irq_source = unsafe { *base.add(3) };
                    let gsi = unsafe { ptr::read_unaligned(base.add(4) as *const u32) };
                    let flags = unsafe { ptr::read_unaligned(base.add(8) as *const u16) };
                    info.isos[info.iso_count] = MadtIso {
                        bus_source,
                        irq_source,
                        gsi,
                        flags,
                    };
                    info.iso_count += 1;
                }
            }
            // Type 5: 64-bit Local APIC Address Override
            5 if eh.length >= 12 => {
                let addr64 = unsafe { ptr::read_unaligned(base.add(4) as *const u64) };
                info.lapic_phys_base = addr64;
            }
            _ => {}
        }

        offset += eh.length as usize;
    }
}
