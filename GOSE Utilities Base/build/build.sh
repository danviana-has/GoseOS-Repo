#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOSE_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${GOSE_DIR}/.." && pwd)"
ISO_ROOT="${BUILD_DIR}/iso_root"
LIMINE_DIR="${REPO_ROOT}/build/limine"
KERNEL_ELF="${REPO_ROOT}/margay_kernel/target/x86_64-unknown-none/release/margay_kernel"
BIN_DIR="${GOSE_DIR}/target/x86_64-unknown-none/release"
ISO_OUT="${BUILD_DIR}/gose_os.iso"
DISK_IMG="${BUILD_DIR}/gose_disk.img"

echo "[1/5] Building Margay Microkernel (margaymk.elf)..."
(cd "${REPO_ROOT}/margay_kernel" && cargo build --release)

echo "[2/5] Building Modular GOSE ELF Servers..."
(cd "${GOSE_DIR}" && cargo build --release --bins)

echo "[3/5] Generating real 32 MiB FAT32 disk image (with HELLO.ELF)..."
python3 "${BUILD_DIR}/mk_fat32.py" "${DISK_IMG}" "${BIN_DIR}/hello"

echo "[4/5] Staging separate GOSE OS ISO..."
if [ ! -d "${LIMINE_DIR}" ]; then
    git clone https://github.com/limine-bootloader/limine.git --branch=v8.x-binary --depth=1 "${LIMINE_DIR}"
fi
rm -rf "${ISO_ROOT}"
mkdir -p "${ISO_ROOT}/boot/limine" "${ISO_ROOT}/EFI/BOOT"

cp "${KERNEL_ELF}"          "${ISO_ROOT}/boot/margaymk.elf"
cp "${BIN_DIR}/goseinit"   "${ISO_ROOT}/boot/goseinit.elf"
cp "${BIN_DIR}/drivergop"  "${ISO_ROOT}/boot/drivergop.elf"
cp "${BIN_DIR}/driverps2"  "${ISO_ROOT}/boot/driverps2.elf"
cp "${BIN_DIR}/driverfs"   "${ISO_ROOT}/boot/driverfs.elf"
cp "${BIN_DIR}/gosebi"     "${ISO_ROOT}/boot/gosebi.elf"

cp "${BUILD_DIR}/limine.conf" "${ISO_ROOT}/boot/limine/limine.conf"
cp "${LIMINE_DIR}/limine-bios.sys" \
   "${LIMINE_DIR}/limine-bios-cd.bin" \
   "${LIMINE_DIR}/limine-uefi-cd.bin" \
   "${ISO_ROOT}/boot/limine/"
cp "${LIMINE_DIR}/BOOTX64.EFI" "${ISO_ROOT}/EFI/BOOT/"

echo "[5/5] Packaging ${ISO_OUT}..."
xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "${ISO_ROOT}" -o "${ISO_OUT}"

echo "[OK] Built modular ${ISO_OUT}"
