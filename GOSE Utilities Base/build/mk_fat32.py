"""
Generate a real 32 MiB FAT32 disk image (`gose_disk.img`) with initial
directories and files for GOSE FS / GOSE BI / GOSE BSI / GOSE Editor.
Zero external dependencies (pure Python 3 stdlib).
"""
import os
import struct
import sys

SECTOR_SIZE = 512
TOTAL_SECTORS = 65536  # 32 MiB
RESERVED_SECTORS = 32
NUM_FATS = 2
SECTORS_PER_CLUSTER = 1
FAT_SIZE_SECTORS = 512  # Covers 65536 clusters * 4 bytes = 262144 bytes = 512 sectors
ROOT_CLUSTER = 2
FIRST_DATA_SECTOR = RESERVED_SECTORS + NUM_FATS * FAT_SIZE_SECTORS

def encode_8_3(name: str) -> bytes:
    if "." in name:
        base, ext = name.rsplit(".", 1)
    else:
        base, ext = name, ""
    base = base.upper().encode("ascii")[:8].ljust(8, b" ")
    ext = ext.upper().encode("ascii")[:3].ljust(3, b" ")
    return base + ext

def make_dir_entry(short_name: bytes, attr: int, cluster: int, size: int) -> bytes:
    ent = bytearray(32)
    ent[0:11] = short_name
    ent[11] = attr
    ent[20:22] = struct.pack("<H", (cluster >> 16) & 0xFFFF)
    ent[26:28] = struct.pack("<H", cluster & 0xFFFF)
    ent[28:32] = struct.pack("<I", size)
    return bytes(ent)

def build_fat32_image(out_path: str, hello_elf_path: str = None):
    img = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    # Boot Sector / BPB (LBA 0)
    bpb = bytearray(512)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"GOSEFS32"
    struct.pack_into("<H", bpb, 11, SECTOR_SIZE)
    bpb[13] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", bpb, 14, RESERVED_SECTORS)
    bpb[16] = NUM_FATS
    struct.pack_into("<H", bpb, 17, 0)
    struct.pack_into("<H", bpb, 19, 0)
    bpb[21] = 0xF8
    struct.pack_into("<H", bpb, 22, 0)
    struct.pack_into("<H", bpb, 24, 63)
    struct.pack_into("<H", bpb, 26, 255)
    struct.pack_into("<I", bpb, 28, 0)
    struct.pack_into("<I", bpb, 32, TOTAL_SECTORS)
    struct.pack_into("<I", bpb, 36, FAT_SIZE_SECTORS)
    struct.pack_into("<H", bpb, 40, 0)
    struct.pack_into("<H", bpb, 42, 0)
    struct.pack_into("<I", bpb, 44, ROOT_CLUSTER)
    struct.pack_into("<H", bpb, 48, 1)
    struct.pack_into("<H", bpb, 50, 6)
    bpb[64] = 0x80
    bpb[66] = 0x29
    struct.pack_into("<I", bpb, 67, 0x474F5345)
    bpb[71:82] = b"GOSE_DISK  "
    bpb[82:90] = b"FAT32   "
    bpb[510] = 0x55
    bpb[511] = 0xAA
    img[0:512] = bpb

    fat = [0] * (FAT_SIZE_SECTORS * (SECTOR_SIZE // 4))
    fat[0] = 0x0FFFFFF8
    fat[1] = 0x0FFFFFFF
    fat[ROOT_CLUSTER] = 0x0FFFFFFF
    next_cluster = 3

    def alloc_cluster_with_data(data: bytes) -> int:
        nonlocal next_cluster
        if len(data) == 0:
            c = next_cluster
            next_cluster += 1
            fat[c] = 0x0FFFFFFF
            return c
        first = 0
        prev = 0
        for off in range(0, len(data), SECTOR_SIZE):
            c = next_cluster
            next_cluster += 1
            if first == 0:
                first = c
            if prev != 0:
                fat[prev] = c
            fat[c] = 0x0FFFFFFF
            sec_lba = FIRST_DATA_SECTOR + (c - 2) * SECTORS_PER_CLUSTER
            chunk = data[off : off + SECTOR_SIZE]
            img[sec_lba * SECTOR_SIZE : sec_lba * SECTOR_SIZE + len(chunk)] = chunk
            prev = c
        return first

    # Create files
    readme_bytes = (
        b"Welcome to GOSE (Guilherme's Operating System Ecosystem)!\n"
        b"Running on the pure x86_64 Margay Microkernel.\n"
        b"Commands: ls, cd, cat, echo, memoryinfo, cpuinfo, hostname, adduser, gouser, goseeditor, bsi\n"
    )
    readme_c = alloc_cluster_with_data(readme_bytes)

    demo_bsi_bytes = (
        b"# Ordered GOSE BSI demo script\n"
        b"2 command:\n"
        b"hostname\n"
        b"1 command:\n"
        b"echo [DEMO.BSI] Step 1 executes BEFORE Step 2!\n"
        b"3 command:\n"
        b"memoryinfo\n"
    )
    demo_c = alloc_cluster_with_data(demo_bsi_bytes)

    users_bytes = b"root:gose\nguimfb:1234\n"
    users_c = alloc_cluster_with_data(users_bytes)

    # Create DOCS directory
    docs_c = next_cluster
    next_cluster += 1
    fat[docs_c] = 0x0FFFFFFF

    info_bytes = b"GOSE FS is a real Ring 3 FAT32 driver communicating over ATA PIO (0x1F0..0x1F7).\n"
    info_c = alloc_cluster_with_data(info_bytes)

    docs_dir = bytearray(SECTOR_SIZE)
    docs_entries = [
        make_dir_entry(b".          ", 0x10, docs_c, 0),
        make_dir_entry(b"..         ", 0x10, ROOT_CLUSTER, 0),
        make_dir_entry(encode_8_3("INFO.TXT"), 0x20, info_c, len(info_bytes)),
    ]
    for i, e in enumerate(docs_entries):
        docs_dir[i * 32 : (i + 1) * 32] = e
    docs_lba = FIRST_DATA_SECTOR + (docs_c - 2) * SECTORS_PER_CLUSTER
    img[docs_lba * SECTOR_SIZE : (docs_lba + 1) * SECTOR_SIZE] = docs_dir

    # Populate Root Directory
    root_entries = [
        make_dir_entry(encode_8_3("README.TXT"), 0x20, readme_c, len(readme_bytes)),
        make_dir_entry(encode_8_3("DEMO.BSI"), 0x20, demo_c, len(demo_bsi_bytes)),
        make_dir_entry(encode_8_3("USERS.TXT"), 0x20, users_c, len(users_bytes)),
        make_dir_entry(encode_8_3("DOCS"), 0x10, docs_c, 0),
    ]
    if hello_elf_path and os.path.exists(hello_elf_path):
        with open(hello_elf_path, "rb") as hf:
            hello_bytes = hf.read()
        hello_c = alloc_cluster_with_data(hello_bytes)
        root_entries.append(make_dir_entry(encode_8_3("HELLO.ELF"), 0x20, hello_c, len(hello_bytes)))

    root_dir = bytearray(SECTOR_SIZE)
    for i, e in enumerate(root_entries):
        root_dir[i * 32 : (i + 1) * 32] = e
    root_lba = FIRST_DATA_SECTOR + (ROOT_CLUSTER - 2) * SECTORS_PER_CLUSTER
    img[root_lba * SECTOR_SIZE : (root_lba + 1) * SECTOR_SIZE] = root_dir

    # Write FAT1 and FAT2
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    for f_idx in range(NUM_FATS):
        off = (RESERVED_SECTORS + f_idx * FAT_SIZE_SECTORS) * SECTOR_SIZE
        img[off : off + len(fat_bytes)] = fat_bytes

    with open(out_path, "wb") as f:
        f.write(img)
    print(f"[OK] Created real 32 MiB FAT32 image: {out_path}")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "gose_disk.img"
    hello = sys.argv[2] if len(sys.argv) > 2 else None
    build_fat32_image(out, hello)
