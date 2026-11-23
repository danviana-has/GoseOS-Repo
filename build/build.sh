#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
ISO_ROOT="${BUILD_DIR}/iso_root"
LIMINE_DIR="${BUILD_DIR}/limine"
KERNEL_ELF="${ROOT_DIR}/margay_kernel/target/x86_64-unknown-none/release/margay_kernel"
ISO_OUT="${BUILD_DIR}/margay_microkernel.iso"

echo "[1/4] Building Margay Microkernel (x86_64-unknown-none, release)..."
(cd "${ROOT_DIR}/margay_kernel" && cargo build --release)

echo "[2/4] Ensuring Limine v8.x-binary bootloader files..."
if [ ! -d "${LIMINE_DIR}" ]; then
    git clone https://github.com/limine-bootloader/limine.git --branch=v8.x-binary --depth=1 "${LIMINE_DIR}"
fi

echo "[3/4] Staging ISO root..."
rm -rf "${ISO_ROOT}"
mkdir -p "${ISO_ROOT}/boot/limine" "${ISO_ROOT}/EFI/BOOT"

cp "${KERNEL_ELF}" "${ISO_ROOT}/boot/margay_kernel"
cp "${BUILD_DIR}/limine.conf" "${ISO_ROOT}/boot/limine/limine.conf"
cp "${LIMINE_DIR}/limine-bios.sys" \
   "${LIMINE_DIR}/limine-bios-cd.bin" \
   "${LIMINE_DIR}/limine-uefi-cd.bin" \
   "${ISO_ROOT}/boot/limine/"
cp "${LIMINE_DIR}/BOOTX64.EFI" "${ISO_ROOT}/EFI/BOOT/"

echo "[4/4] Packaging bootable ISO (${ISO_OUT})..."
xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "${ISO_ROOT}" -o "${ISO_OUT}"

if [ -x "${LIMINE_DIR}/limine" ]; then
    "${LIMINE_DIR}/limine" bios-install "${ISO_OUT}" || true
fi

echo "[OK] Built ${ISO_OUT}"
echo "Run in QEMU:"
echo "  qemu-system-x86_64 -cdrom \"${ISO_OUT}\" -m 256M -smp 4 -nographic -serial mon:stdio -no-reboot"
