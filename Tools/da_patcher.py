#!/usr/bin/env python3
# (c) B.Kerler 2021 MIT License
"""
DA Patcher Tool - Patches DA (Download Agent) binaries to match a reference
DA version and disables anti-rollback checks.

Usage:
    python da_patcher.py <reference_da> <target_da> [<target_da2> ...]

Example:
    python da_patcher.py DA_A15_lamu_FORBID_SIGNED.bin DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin

This tool:
  1. Parses the reference DA to extract its version string
  2. For each target DA:
     - Replaces the version string to match the reference
     - Disables anti-rollback version check (0xC0020053) in DA1 and DA2
     - Patches DA version check in DA1
     - Updates the DA2 hash stored in DA1
  3. Writes patched files as <original_name>.patched
"""
import os
import sys
import hashlib
from struct import unpack, pack

import inspect

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from mtkclient.Library.utils import find_binary

# DA header field structure (from da_parser.py)
entry_region = [
    ('m_buf', 'I'),
    ('m_len', 'I'),
    ('m_start_addr', 'I'),
    ('m_start_offset', 'I'),
    ('m_sig_len', 'I')]

DA = [
    ('magic', 'H'),
    ('hw_code', 'H'),
    ('hw_sub_code', 'H'),
    ('hw_version', 'H'),
    ('sw_version', 'H'),
    ('reserved1', 'H'),
    ('pagesize', 'H'),
    ('reserved3', 'H'),
    ('entry_region_index', 'H'),
    ('entry_region_count', 'H')
]

VERSION_STRING_OFFSET = 0x20
VERSION_STRING_MAX_LEN = 0x40


def read_da_header(data):
    """Parse DA header and entry regions from binary data."""
    count_da = unpack("<I", data[0x68:0x6C])[0]
    entries = []
    for i in range(count_da):
        offset = 0x6C + (i * 0xDC)
        hdr = {}
        pos = offset
        for name, stype in DA:
            size = 2  # All fields are 'H' (unsigned short)
            hdr[name] = unpack('<' + stype, data[pos:pos + size])[0]
            pos += size
        regions = []
        for m in range(hdr['entry_region_count']):
            entry = {}
            for name, stype in entry_region:
                size = 4  # All fields are 'I' (unsigned int)
                entry[name] = unpack('<' + stype, data[pos:pos + size])[0]
                pos += size
            regions.append(entry)
        entries.append((hdr, regions))
    return entries


def get_version_string(data):
    """Extract the version string from a DA binary."""
    raw = data[VERSION_STRING_OFFSET:VERSION_STRING_OFFSET + VERSION_STRING_MAX_LEN]
    return raw.split(b'\x00')[0]


def patch_version_string(data, new_version):
    """Replace the version string in a DA binary."""
    old_version = get_version_string(data)
    old_len = len(old_version)
    new_len = len(new_version)
    if new_len > VERSION_STRING_MAX_LEN:
        print(f"Error: New version string too long ({new_len} > {VERSION_STRING_MAX_LEN})")
        return data
    # Clear the old version string area and write the new one
    data[VERSION_STRING_OFFSET:VERSION_STRING_OFFSET + VERSION_STRING_MAX_LEN] = \
        b'\x00' * VERSION_STRING_MAX_LEN
    data[VERSION_STRING_OFFSET:VERSION_STRING_OFFSET + new_len] = new_version
    print(f"  Version string: {old_version.decode('ascii', errors='replace')} -> "
          f"{new_version.decode('ascii', errors='replace')}")
    return data


def patch_antirollback(region_data, region_name):
    """Disable anti-rollback version check by patching all 0xC0020053 occurrences
    to zeros."""
    pattern = int.to_bytes(0xC0020053, 4, 'little')
    count = 0
    idx = 0
    while True:
        pos = region_data.find(pattern, idx)
        if pos == -1:
            break
        region_data[pos:pos + 4] = int.to_bytes(0, 4, 'little')
        print(f"  Anti-rollback (0xC0020053) patched in {region_name} at offset 0x{pos:X}")
        count += 1
        idx = pos + 4
    if count == 0:
        print(f"  Anti-rollback pattern not found in {region_name}")
        return False
    return True


def patch_da_version_check(da1_data):
    """Patch DA version check in DA1 (MOV R0, #0; BX LR)."""
    pattern = b"\x1F\xB5\x00\x23\x01\xA8\x00\x93\x00\xF0"
    idx = find_binary(da1_data, pattern)
    if idx is not None:
        da1_data[idx:idx + 4] = b"\x00\x20\x70\x47"
        print(f"  DA1 version check patched at offset 0x{idx:X}")
        return True
    else:
        print("  DA1 version check pattern not found")
        return False


def compute_hash_pos(da1, da2):
    """Find the position and type of the DA2 hash stored in DA1
    (from patch_legacy.py)."""
    hashdigestmd5 = hashlib.md5(da2).digest()
    hashdigest = hashlib.sha1(da2).digest()
    hashdigest256 = hashlib.sha256(da2).digest()
    idx = da1.find(hashdigestmd5)
    hashmode = 0
    if idx == -1:
        idx = da1.find(hashdigest)
        hashmode = 1
    if idx == -1:
        idx = da1.find(hashdigest256)
        hashmode = 2
    if idx != -1:
        return idx, hashmode
    return None, None


def fix_hash(da1, da2, hashpos, hashmode):
    """Update the DA2 hash in DA1 after DA2 has been modified
    (from patch_legacy.py)."""
    da1 = bytearray(da1)
    dahash = None
    if hashmode == 0:
        dahash = hashlib.md5(da2).digest()
    elif hashmode == 1:
        dahash = hashlib.sha1(da2).digest()
    elif hashmode == 2:
        dahash = hashlib.sha256(da2).digest()
    if dahash is not None:
        da1[hashpos:hashpos + len(dahash)] = dahash
    return da1


def print_da_info(name, data, entries):
    """Print DA information similar to da_parser.py output."""
    ver = get_version_string(data).decode('ascii', errors='replace')
    hdr = entries[0][0]
    regions = entries[0][1]
    print(f"  File: {name}")
    print(f"  Version: {ver}")
    print(f"  hwcode: 0x{hdr['hw_code']:04X}")
    print(f"  hw_sub_code: 0x{hdr['hw_sub_code']:04X}")
    print(f"  hw_version: 0x{hdr['hw_version']:04X}")
    print(f"  sw_version: 0x{hdr['sw_version']:04X}")
    for i, r in enumerate(regions):
        print(f"  Region {i}: buf=0x{r['m_buf']:08X} len=0x{r['m_len']:08X} "
              f"addr=0x{r['m_start_addr']:08X} sig_len=0x{r['m_sig_len']:08X}")


def patch_da(reference_data, target_data, target_name):
    """Patch a target DA binary using reference DA information."""
    print(f"\nPatching: {target_name}")

    target = bytearray(target_data)
    ref_version = get_version_string(reference_data)
    ref_entries = read_da_header(reference_data)
    tgt_entries = read_da_header(target_data)

    if not tgt_entries:
        print("  Error: Could not parse target DA header")
        return None

    tgt_hdr = tgt_entries[0][0]
    tgt_regions = tgt_entries[0][1]

    # Region indices: 0=EMI, 1=DA1, 2=DA2
    da1_buf = tgt_regions[1]['m_buf']
    da1_len = tgt_regions[1]['m_len']
    da1_sig_len = tgt_regions[1]['m_sig_len']
    da2_buf = tgt_regions[2]['m_buf']
    da2_len = tgt_regions[2]['m_len']
    da2_sig_len = tgt_regions[2]['m_sig_len']

    # Extract DA1 and DA2 regions
    da1 = bytearray(target[da1_buf:da1_buf + da1_len])
    da2 = bytearray(target[da2_buf:da2_buf + da2_len])

    # Step 1: Find DA2 hash position in DA1 BEFORE any modifications
    da2_for_hash = bytes(da2[:da2_len - da2_sig_len])
    hash_pos, hash_mode = compute_hash_pos(bytes(da1), da2_for_hash)
    if hash_pos is not None:
        hash_names = {0: "MD5", 1: "SHA1", 2: "SHA256"}
        print(f"  DA2 hash found in DA1 at offset 0x{hash_pos:X} (type: {hash_names.get(hash_mode, 'unknown')})")
    else:
        print("  Warning: DA2 hash not found in DA1 (hash update will be skipped)")

    # Step 2: Patch version string in file header
    target = patch_version_string(target, ref_version)

    # Step 3: Patch anti-rollback in DA1
    patch_antirollback(da1, "DA1")

    # Step 4: Patch DA version check in DA1
    patch_da_version_check(da1)

    # Step 5: Patch anti-rollback in DA2
    patch_antirollback(da2, "DA2")

    # Step 6: Write patched DA1 and DA2 back to file
    target[da1_buf:da1_buf + da1_len] = da1
    target[da2_buf:da2_buf + da2_len] = da2

    # Step 7: Update DA2 hash in DA1 if it was found
    if hash_pos is not None:
        da2_patched_for_hash = bytes(da2[:da2_len - da2_sig_len])
        da1 = fix_hash(da1, da2_patched_for_hash, hash_pos, hash_mode)
        target[da1_buf:da1_buf + da1_len] = da1
        print(f"  DA2 hash updated in DA1")

    return bytes(target)


def main():
    if len(sys.argv) < 3:
        print("DA Patcher Tool - Patches DA binaries to match a reference version "
              "and disables anti-rollback")
        print(f"\nUsage: {sys.argv[0]} <reference_da> <target_da> [<target_da2> ...]")
        print(f"\nExample: {sys.argv[0]} DA_A15_lamu_FORBID_SIGNED.bin "
              "DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin")
        sys.exit(1)

    reference_path = sys.argv[1]
    target_paths = sys.argv[2:]

    # Read reference DA
    if not os.path.exists(reference_path):
        print(f"Error: Reference DA not found: {reference_path}")
        sys.exit(1)

    with open(reference_path, 'rb') as f:
        reference_data = f.read()

    ref_entries = read_da_header(reference_data)
    print("=" * 60)
    print("Reference DA:")
    print_da_info(os.path.basename(reference_path), reference_data, ref_entries)
    print("=" * 60)

    # Process each target DA
    for target_path in target_paths:
        if not os.path.exists(target_path):
            print(f"\nError: Target DA not found: {target_path}")
            continue

        with open(target_path, 'rb') as f:
            target_data = f.read()

        tgt_entries = read_da_header(target_data)
        print("\nTarget DA (before patching):")
        print_da_info(os.path.basename(target_path), target_data, tgt_entries)

        patched = patch_da(reference_data, target_data, os.path.basename(target_path))
        if patched is None:
            print(f"  Failed to patch {target_path}")
            continue

        # Write patched file
        output_path = target_path + ".patched"
        with open(output_path, 'wb') as f:
            f.write(patched)
        print(f"  Patched file written to: {output_path}")

        # Verify patched file
        print("\nVerification (after patching):")
        patched_entries = read_da_header(patched)
        print_da_info(os.path.basename(output_path), patched, patched_entries)

        # Verify anti-rollback is disabled
        tgt_regions = patched_entries[0][1]
        da1 = patched[tgt_regions[1]['m_buf']:tgt_regions[1]['m_buf'] + tgt_regions[1]['m_len']]
        da2 = patched[tgt_regions[2]['m_buf']:tgt_regions[2]['m_buf'] + tgt_regions[2]['m_len']]
        arb_pattern = int.to_bytes(0xC0020053, 4, 'little')
        da1_arb = find_binary(da1, arb_pattern)
        da2_arb = find_binary(da2, arb_pattern)
        if da1_arb is None and da2_arb is None:
            print("  ✓ Anti-rollback checks disabled in both DA1 and DA2")
        else:
            if da1_arb is not None:
                print("  ✗ Anti-rollback still present in DA1!")
            if da2_arb is not None:
                print("  ✗ Anti-rollback still present in DA2!")


if __name__ == "__main__":
    main()
