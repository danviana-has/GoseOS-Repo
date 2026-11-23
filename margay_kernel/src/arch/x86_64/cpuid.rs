//! x86_64 CPUID Feature & Topology Detection
//!
//! Queries processor vendor, brand string, architectural extensions
//! (APIC, x2APIC, XSAVE, AVX, SMEP, SMAP, NX, 1GiB pages, FSGSBASE,
//! PCID, INVPCID, TSC-Deadline, Invariant TSC), and physical/virtual
//! address widths.

use core::arch::asm;

/// Raw 4-register output of the `cpuid` instruction.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Execute `cpuid` for a given leaf and subleaf.
///
/// Note: LLVM reserves `rbx` in some code models, so we save/restore `rbx`
/// around `cpuid` using a scratch register (`rdi`).
#[inline]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            ebx_out = out(reg) ebx,
            out("edx") edx,
            options(preserves_flags)
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

/// Decoded processor capabilities used by the Margay Microkernel.
#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    pub max_basic_leaf: u32,
    pub max_ext_leaf: u32,
    pub vendor: [u8; 12],
    pub brand: [u8; 48],
    pub has_apic: bool,
    pub has_x2apic: bool,
    pub has_tsc_deadline: bool,
    pub has_invariant_tsc: bool,
    pub has_fxsr: bool,
    pub has_sse: bool,
    pub has_sse2: bool,
    pub has_xsave: bool,
    pub has_osxsave: bool,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_nx: bool,
    pub has_1gib_pages: bool,
    pub has_rdtscp: bool,
    pub has_smep: bool,
    pub has_smap: bool,
    pub has_fsgsbase: bool,
    pub has_pcid: bool,
    pub has_invpcid: bool,
    pub has_umip: bool,
    pub phys_addr_bits: u8,
    pub virt_addr_bits: u8,
    pub xsave_area_size: u32,
    pub initial_apic_id: u8,
}

impl CpuFeatures {
    /// Detect all CPU features on the current processor via CPUID.
    pub fn detect() -> Self {
        let leaf0 = cpuid(0, 0);
        let max_basic_leaf = leaf0.eax;

        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

        let leaf1 = if max_basic_leaf >= 1 {
            cpuid(1, 0)
        } else {
            CpuidResult::default()
        };

        let leaf7 = if max_basic_leaf >= 7 {
            cpuid(7, 0)
        } else {
            CpuidResult::default()
        };

        let ext0 = cpuid(0x8000_0000, 0);
        let max_ext_leaf = ext0.eax;

        let ext1 = if max_ext_leaf >= 0x8000_0001 {
            cpuid(0x8000_0001, 0)
        } else {
            CpuidResult::default()
        };

        let ext7 = if max_ext_leaf >= 0x8000_0007 {
            cpuid(0x8000_0007, 0)
        } else {
            CpuidResult::default()
        };

        let ext8 = if max_ext_leaf >= 0x8000_0008 {
            cpuid(0x8000_0008, 0)
        } else {
            CpuidResult::default()
        };

        let mut brand = [0u8; 48];
        if max_ext_leaf >= 0x8000_0004 {
            for (i, leaf_id) in [0x8000_0002u32, 0x8000_0003, 0x8000_0004].iter().enumerate() {
                let r = cpuid(*leaf_id, 0);
                let off = i * 16;
                brand[off..off + 4].copy_from_slice(&r.eax.to_le_bytes());
                brand[off + 4..off + 8].copy_from_slice(&r.ebx.to_le_bytes());
                brand[off + 8..off + 12].copy_from_slice(&r.ecx.to_le_bytes());
                brand[off + 12..off + 16].copy_from_slice(&r.edx.to_le_bytes());
            }
        }

        let has_xsave = (leaf1.ecx & (1 << 26)) != 0;
        let xsave_area_size = if has_xsave && max_basic_leaf >= 0x0D {
            let xd = cpuid(0x0D, 0);
            xd.ecx.max(512)
        } else {
            512
        };

        let phys_addr_bits = if ext8.eax != 0 { (ext8.eax & 0xFF) as u8 } else { 36 };
        let virt_addr_bits = if ext8.eax != 0 { ((ext8.eax >> 8) & 0xFF) as u8 } else { 48 };

        Self {
            max_basic_leaf,
            max_ext_leaf,
            vendor,
            brand,
            has_apic: (leaf1.edx & (1 << 9)) != 0,
            has_x2apic: (leaf1.ecx & (1 << 21)) != 0,
            has_tsc_deadline: (leaf1.ecx & (1 << 24)) != 0,
            has_invariant_tsc: (ext7.edx & (1 << 8)) != 0,
            has_fxsr: (leaf1.edx & (1 << 24)) != 0,
            has_sse: (leaf1.edx & (1 << 25)) != 0,
            has_sse2: (leaf1.edx & (1 << 26)) != 0,
            has_xsave,
            has_osxsave: (leaf1.ecx & (1 << 27)) != 0,
            has_avx: (leaf1.ecx & (1 << 28)) != 0,
            has_avx2: (leaf7.ebx & (1 << 5)) != 0,
            has_nx: (ext1.edx & (1 << 20)) != 0,
            has_1gib_pages: (ext1.edx & (1 << 26)) != 0,
            has_rdtscp: (ext1.edx & (1 << 27)) != 0,
            has_smep: (leaf7.ebx & (1 << 7)) != 0,
            has_smap: (leaf7.ebx & (1 << 20)) != 0,
            has_fsgsbase: (leaf7.ebx & (1 << 0)) != 0,
            has_pcid: (leaf1.ecx & (1 << 17)) != 0,
            has_invpcid: (leaf7.ebx & (1 << 10)) != 0,
            has_umip: (leaf7.ecx & (1 << 2)) != 0,
            phys_addr_bits,
            virt_addr_bits,
            xsave_area_size,
            initial_apic_id: ((leaf1.ebx >> 24) & 0xFF) as u8,
        }
    }

    pub fn vendor_str(&self) -> &str {
        core::str::from_utf8(&self.vendor).unwrap_or("Unknown")
    }

    pub fn brand_str(&self) -> &str {
        let end = self.brand.iter().position(|&b| b == 0).unwrap_or(self.brand.len());
        core::str::from_utf8(&self.brand[..end]).unwrap_or("Unknown CPU").trim()
    }

    pub fn log_summary(&self) {
        crate::kinfo!(
            "CPUID",
            "Vendor='{}' Brand='{}' Phys={}b Virt={}b",
            self.vendor_str(),
            self.brand_str(),
            self.phys_addr_bits,
            self.virt_addr_bits
        );
        crate::kinfo!(
            "CPUID",
            "Features: APIC={} x2APIC={} NX={} 1GiB={} XSAVE={}({}B) AVX={} SMEP={} SMAP={} FSGSBASE={} PCID={}",
            self.has_apic,
            self.has_x2apic,
            self.has_nx,
            self.has_1gib_pages,
            self.has_xsave,
            self.xsave_area_size,
            self.has_avx,
            self.has_smep,
            self.has_smap,
            self.has_fsgsbase,
            self.has_pcid
        );
    }
}
