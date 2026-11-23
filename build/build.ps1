#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$RootDir   = Split-Path -Parent $PSScriptRoot
$BuildDir  = $PSScriptRoot
$IsoRoot   = Join-Path $BuildDir "iso_root"
$LimineDir = Join-Path $BuildDir "limine"
$KernelElf = Join-Path $RootDir "margay_kernel\target\x86_64-unknown-none\release\margay_kernel"
$IsoOut    = Join-Path $BuildDir "margay_microkernel.iso"

Write-Host "[1/4] Building Margay Microkernel (x86_64-unknown-none, release)..."
Push-Location (Join-Path $RootDir "margay_kernel")
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed" }
} finally {
    Pop-Location
}

Write-Host "[2/4] Ensuring Limine v8.x-binary bootloader..."
if (-not (Test-Path $LimineDir)) {
    git clone https://github.com/limine-bootloader/limine.git --branch=v8.x-binary --depth=1 $LimineDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone Limine" }
}

Write-Host "[3/4] Staging ISO directory..."
if (Test-Path $IsoRoot) { Remove-Item -Recurse -Force $IsoRoot }
New-Item -ItemType Directory -Force -Path (Join-Path $IsoRoot "boot\limine") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $IsoRoot "EFI\BOOT") | Out-Null

Copy-Item $KernelElf (Join-Path $IsoRoot "boot\margay_kernel")
Copy-Item (Join-Path $BuildDir "limine.conf") (Join-Path $IsoRoot "boot\limine\limine.conf")
Copy-Item (Join-Path $LimineDir "limine-bios.sys") (Join-Path $IsoRoot "boot\limine\")
Copy-Item (Join-Path $LimineDir "limine-bios-cd.bin") (Join-Path $IsoRoot "boot\limine\")
Copy-Item (Join-Path $LimineDir "limine-uefi-cd.bin") (Join-Path $IsoRoot "boot\limine\")
Copy-Item (Join-Path $LimineDir "BOOTX64.EFI") (Join-Path $IsoRoot "EFI\BOOT\")

Write-Host "[4/4] Packaging bootable ISO ($IsoOut)..."
Push-Location $BuildDir
try {
    xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin `
        -no-emul-boot -boot-load-size 4 -boot-info-table `
        --efi-boot boot/limine/limine-uefi-cd.bin `
        -efi-boot-part --efi-boot-image --protective-msdos-label `
        iso_root -o margay_microkernel.iso
    if ($LASTEXITCODE -ne 0) { throw "xorriso failed" }
} finally {
    Pop-Location
}

$LimineExe = Join-Path $LimineDir "limine.exe"
if (Test-Path $LimineExe) {
    & $LimineExe bios-install $IsoOut
}

Write-Host "[OK] Built $IsoOut"
Write-Host "Run in QEMU:"
Write-Host "  `"C:\Program Files\qemu\qemu-system-x86_64.exe`" -cdrom `"$IsoOut`" -m 256M -smp 4 -nographic -serial mon:stdio -no-reboot"
