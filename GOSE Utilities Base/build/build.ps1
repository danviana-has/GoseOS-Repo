#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$GoseDir   = Split-Path -Parent $PSScriptRoot
$RepoRoot  = Split-Path -Parent $GoseDir
$BuildDir  = $PSScriptRoot
$IsoRoot   = Join-Path $BuildDir "iso_root"
$LimineDir = Join-Path $RepoRoot "build\limine"
$KernelElf = Join-Path $RepoRoot "margay_kernel\target\x86_64-unknown-none\release\margay_kernel"
$BinDir    = Join-Path $GoseDir "target\x86_64-unknown-none\release"
$IsoOut    = Join-Path $BuildDir "gose_os.iso"
$DiskImg   = Join-Path $BuildDir "gose_disk.img"

Write-Host "[1/5] Building Margay Microkernel (margaymk.elf, release)..."
Push-Location (Join-Path $RepoRoot "margay_kernel")
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "Kernel build failed" }
} finally {
    Pop-Location
}

Write-Host "[2/5] Building Modular GOSE ELF Servers (goseinit, drivergop, driverps2, driverfs, gosebi, hello)..."
Push-Location $GoseDir
try {
    cargo build --release --bins
    if ($LASTEXITCODE -ne 0) { throw "GOSE Utilities Base build failed" }
} finally {
    Pop-Location
}

Write-Host "[3/5] Generating real 32 MiB FAT32 disk image (gose_disk.img with HELLO.ELF)..."
$HelloElf = Join-Path $BinDir "hello"
python (Join-Path $BuildDir "mk_fat32.py") $DiskImg $HelloElf
if ($LASTEXITCODE -ne 0) { throw "mk_fat32.py failed" }

Write-Host "[4/5] Staging separate GOSE OS ISO directory..."
if (-not (Test-Path $LimineDir)) {
    git clone https://github.com/limine-bootloader/limine.git --branch=v8.x-binary --depth=1 $LimineDir
}
if (Test-Path $IsoRoot) { Remove-Item -Recurse -Force $IsoRoot }
New-Item -ItemType Directory -Force -Path (Join-Path $IsoRoot "boot\limine") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $IsoRoot "EFI\BOOT") | Out-Null

Copy-Item $KernelElf                    (Join-Path $IsoRoot "boot\margaymk.elf")
Copy-Item (Join-Path $BinDir "goseinit")  (Join-Path $IsoRoot "boot\goseinit.elf")
Copy-Item (Join-Path $BinDir "drivergop") (Join-Path $IsoRoot "boot\drivergop.elf")
Copy-Item (Join-Path $BinDir "driverps2") (Join-Path $IsoRoot "boot\driverps2.elf")
Copy-Item (Join-Path $BinDir "driverfs")  (Join-Path $IsoRoot "boot\driverfs.elf")
Copy-Item (Join-Path $BinDir "gosebi")    (Join-Path $IsoRoot "boot\gosebi.elf")

Copy-Item (Join-Path $BuildDir "limine.conf") (Join-Path $IsoRoot "boot\limine\limine.conf")
Copy-Item (Join-Path $LimineDir "limine-bios.sys") (Join-Path $IsoRoot "boot\limine\")
Copy-Item (Join-Path $LimineDir "limine-bios-cd.bin") (Join-Path $IsoRoot "boot\limine\")
Copy-Item (Join-Path $LimineDir "limine-uefi-cd.bin") (Join-Path $IsoRoot "boot\limine\")
Copy-Item (Join-Path $LimineDir "BOOTX64.EFI") (Join-Path $IsoRoot "EFI\BOOT\")

Write-Host "[5/5] Packaging separate GOSE OS ISO ($IsoOut)..."
Push-Location $BuildDir
try {
    xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin `
        -no-emul-boot -boot-load-size 4 -boot-info-table `
        --efi-boot boot/limine/limine-uefi-cd.bin `
        -efi-boot-part --efi-boot-image --protective-msdos-label `
        iso_root -o gose_os.iso
    if ($LASTEXITCODE -ne 0) { throw "xorriso failed" }
} finally {
    Pop-Location
}

$LimineExe = Join-Path $LimineDir "limine.exe"
if (Test-Path $LimineExe) {
    & $LimineExe bios-install $IsoOut
}

Write-Host "[OK] Built modular GOSE OS ISO: $IsoOut"
Write-Host "Run in QEMU:"
Write-Host "  `"C:\Program Files\qemu\qemu-system-x86_64.exe`" -boot d -cdrom `"$IsoOut`" -drive file=`"$DiskImg`",format=raw,if=ide -m 256M -smp 4 -cpu qemu64,+x2apic -vga std -serial stdio -no-reboot"
