#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Script to patch DA agents: disable anti-rollback and match versions
# Usage: python3 patch_da_agents.py <working_da> <target_da1> <target_da2>

import sys
import os
import hashlib
from struct import unpack, pack
import inspect

# Add parent directory to path
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from mtkclient.Library.utils import find_binary


def read_da_header(data):
    """Read DA header structure"""
    if len(data) < 0x6C:
        print("Error: File too small to be a valid DA")
        return None

    # Read count_da at offset 0x68
    count_da = unpack("<I", data[0x68:0x6C])[0]
    print(f"Number of DA entries: {count_da}")

    return count_da


def read_da_info(data, index=0):
    """Read DA information for a specific index"""
    offset = 0x6C + (index * 0xDC)

    # DA header structure
    magic = unpack("<H", data[offset:offset+2])[0]
    hw_code = unpack("<H", data[offset+2:offset+4])[0]
    hw_sub_code = unpack("<H", data[offset+4:offset+6])[0]
    hw_version = unpack("<H", data[offset+6:offset+8])[0]
    sw_version = unpack("<H", data[offset+8:offset+10])[0]
    reserved1 = unpack("<H", data[offset+10:offset+12])[0]
    pagesize = unpack("<H", data[offset+12:offset+14])[0]
    reserved3 = unpack("<H", data[offset+14:offset+16])[0]
    entry_region_index = unpack("<H", data[offset+16:offset+18])[0]
    entry_region_count = unpack("<H", data[offset+18:offset+20])[0]

    da_info = {
        'magic': magic,
        'hw_code': hw_code,
        'hw_sub_code': hw_sub_code,
        'hw_version': hw_version,
        'sw_version': sw_version,
        'reserved1': reserved1,
        'pagesize': pagesize,
        'reserved3': reserved3,
        'entry_region_index': entry_region_index,
        'entry_region_count': entry_region_count,
        'regions': []
    }

    # Read entry regions
    region_offset = offset + 0x14
    for i in range(entry_region_count):
        m_buf = unpack("<I", data[region_offset:region_offset+4])[0]
        m_len = unpack("<I", data[region_offset+4:region_offset+8])[0]
        m_start_addr = unpack("<I", data[region_offset+8:region_offset+12])[0]
        m_start_offset = unpack("<I", data[region_offset+12:region_offset+16])[0]
        m_sig_len = unpack("<I", data[region_offset+16:region_offset+20])[0]

        da_info['regions'].append({
            'm_buf': m_buf,
            'm_len': m_len,
            'm_start_addr': m_start_addr,
            'm_start_offset': m_start_offset,
            'm_sig_len': m_sig_len
        })
        region_offset += 20

    return da_info


def patch_sw_version(data, new_sw_version, index=0):
    """Patch the sw_version in DA header"""
    offset = 0x6C + (index * 0xDC) + 8  # sw_version is at offset +8 in DA header
    data = bytearray(data)
    data[offset:offset+2] = pack("<H", new_sw_version)
    return bytes(data)


def extract_da_region(data, region_info):
    """Extract a DA region from the main binary"""
    m_buf = region_info['m_buf']
    m_len = region_info['m_len']
    return data[m_buf:m_buf + m_len]


def patch_antirollback(da_data):
    """Patch anti-rollback check in DA"""
    da_patched = bytearray(da_data)
    patched = False
    patch_count = 0

    # Find and patch ALL occurrences of error code 0xC0020053 (anti-rollback error)
    error_code = int.to_bytes(0xC0020053, 4, 'little')
    idx = 0
    while True:
        antirollback = da_patched.find(error_code, idx)
        if antirollback == -1:
            break
        da_patched[antirollback:antirollback + 4] = int.to_bytes(0, 4, 'little')
        print(f"  Anti-rollback check patched at offset {hex(antirollback)}")
        patched = True
        patch_count += 1
        idx = antirollback + 4

    if patch_count == 0:
        print("  Anti-rollback check pattern (0xC0020053) not found")
    else:
        print(f"  Total anti-rollback patches applied: {patch_count}")

    # Additional anti-rollback patterns
    # Pattern 1: Version check pattern
    pattern1 = find_binary(da_patched, b"\x00\x28\x00\xD0")  # CMP R0, #0; BEQ
    if pattern1 is not None:
        # Try to find version comparison nearby
        search_start = max(0, pattern1 - 50)
        search_end = min(len(da_patched), pattern1 + 50)
        version_check = da_patched[search_start:search_end].find(b"\x88\x42")  # CMP R0, R1
        if version_check != -1:
            actual_offset = search_start + version_check
            print(f"  Found potential version check at {hex(actual_offset)}")

    return bytes(da_patched), patched


def compute_hash(data, hashmode):
    """Compute hash based on mode"""
    if hashmode == 0:
        return hashlib.md5(data).digest()
    elif hashmode == 1:
        return hashlib.sha1(data).digest()
    elif hashmode == 2:
        return hashlib.sha256(data).digest()
    return None


def find_hash_in_da1(da1, da2):
    """Find where da2's hash is stored in da1"""
    # Try different hash modes
    for hashmode in [0, 1, 2]:  # MD5, SHA1, SHA256
        dahash = compute_hash(da2, hashmode)
        idx = da1.find(dahash)
        if idx != -1:
            return idx, hashmode
    return None, None


def fix_hash(da1, da2, hashpos, hashmode):
    """Fix the hash in da1 to match da2"""
    da1 = bytearray(da1)
    dahash = compute_hash(da2, hashmode)
    if dahash:
        da1[hashpos:hashpos + len(dahash)] = dahash
        print(f"  Hash fixed at offset {hex(hashpos)} using mode {hashmode}")
    return bytes(da1)


def patch_da_binary(da_path, reference_da_info=None, output_path=None):
    """Main patching function for a DA binary"""
    print(f"\n{'='*60}")
    print(f"Processing: {os.path.basename(da_path)}")
    print(f"{'='*60}")

    # Read DA binary
    with open(da_path, 'rb') as f:
        da_data = f.read()

    # Read DA info
    count_da = read_da_header(da_data)
    if count_da is None or count_da == 0:
        print("Error: Invalid DA binary")
        return False

    da_info = read_da_info(da_data, 0)
    print(f"\nCurrent DA Info:")
    print(f"  HW Code:      0x{da_info['hw_code']:04X}")
    print(f"  HW Sub Code:  0x{da_info['hw_sub_code']:04X}")
    print(f"  HW Version:   0x{da_info['hw_version']:04X}")
    print(f"  SW Version:   0x{da_info['sw_version']:04X}")
    print(f"  Regions:      {da_info['entry_region_count']}")

    modified = False

    # Step 1: Patch sw_version if reference provided
    if reference_da_info and da_info['sw_version'] != reference_da_info['sw_version']:
        print(f"\nPatching SW version from 0x{da_info['sw_version']:04X} to 0x{reference_da_info['sw_version']:04X}")
        da_data = patch_sw_version(da_data, reference_da_info['sw_version'], 0)
        modified = True
    else:
        print(f"\nSW version already matches: 0x{da_info['sw_version']:04X}")

    # Step 2: Extract and patch DA regions
    # Region 1 is usually DA1 (loader at 0x200000)
    # Region 2 is usually DA2 (loader at 0x40000000)
    if len(da_info['regions']) >= 2:
        # Patch DA1 (region 1)
        print(f"\nProcessing DA1 (region 1 - addr 0x{da_info['regions'][1]['m_start_addr']:X}):")
        da1_region = da_info['regions'][1]
        print(f"  Offset: 0x{da1_region['m_buf']:X}, Length: 0x{da1_region['m_len']:X}, Sig: 0x{da1_region['m_sig_len']:X}")
        da1_data_orig = extract_da_region(da_data, da1_region)
        # Remove signature for patching
        da1_data = da1_data_orig[:-da1_region['m_sig_len']] if da1_region['m_sig_len'] > 0 else da1_data_orig

        # Patch DA2 (region 2)
        if len(da_info['regions']) >= 3:
            print(f"\nProcessing DA2 (region 2 - addr 0x{da_info['regions'][2]['m_start_addr']:X}):")
            da2_region = da_info['regions'][2]
            print(f"  Offset: 0x{da2_region['m_buf']:X}, Length: 0x{da2_region['m_len']:X}, Sig: 0x{da2_region['m_sig_len']:X}")
            da2_data_orig = extract_da_region(da_data, da2_region)
            # Remove signature for patching
            da2_data = da2_data_orig[:-da2_region['m_sig_len']] if da2_region['m_sig_len'] > 0 else da2_data_orig

            # Patch anti-rollback in DA2
            print("\nPatching anti-rollback in DA2...")
            da2_patched, ar_patched_da2 = patch_antirollback(da2_data)

            # Also patch anti-rollback in DA1
            print("\nPatching anti-rollback in DA1...")
            da1_patched, ar_patched_da1 = patch_antirollback(da1_data)

            if ar_patched_da2 or ar_patched_da1:
                modified = True

                # Fix the hash in DA1 if DA2 was patched
                if ar_patched_da2:
                    print("\nFixing DA2 hash in DA1...")
                    hashpos, hashmode = find_hash_in_da1(da1_patched, da2_patched)
                    if hashpos is not None:
                        da1_patched = fix_hash(da1_patched, da2_patched, hashpos, hashmode)
                    else:
                        print("  Warning: Could not find DA2 hash in DA1 - trying alternative methods...")
                        # Try to find hash at known location for V5 DA
                        idx1 = da1_patched.find(b"MMU MAP: VA")
                        if idx1 != -1:
                            # SHA256 hash is typically 0x30 bytes before this string
                            hashpos = idx1 - 0x30
                            hashmode = 2
                            print(f"  Found MMU MAP marker, trying hash at offset {hex(hashpos)}")
                            da1_patched = fix_hash(da1_patched, da2_patched, hashpos, hashmode)

                # Add signatures back and update in main binary
                da1_with_sig = da1_patched + da1_data_orig[-da1_region['m_sig_len']:] if da1_region['m_sig_len'] > 0 else da1_patched
                da2_with_sig = da2_patched + da2_data_orig[-da2_region['m_sig_len']:] if da2_region['m_sig_len'] > 0 else da2_patched

                da_data = bytearray(da_data)
                da_data[da1_region['m_buf']:da1_region['m_buf'] + len(da1_with_sig)] = da1_with_sig
                da_data[da2_region['m_buf']:da2_region['m_buf'] + len(da2_with_sig)] = da2_with_sig
                da_data = bytes(da_data)

    # Save patched binary
    if modified:
        if output_path is None:
            output_path = da_path.replace('.bin', '_patched.bin')

        with open(output_path, 'wb') as f:
            f.write(da_data)
        print(f"\n✓ Patched binary saved to: {output_path}")
        return True
    else:
        print(f"\n○ No modifications needed")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patch_da_agents.py <working_da> [target_da1] [target_da2] ...")
        print("\nExample:")
        print("  python3 patch_da_agents.py DA_A15_lamu_FORBID_SIGNED.bin DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin")
        return 1

    # Read reference DA (the working one)
    reference_da = sys.argv[1]
    if not os.path.exists(reference_da):
        print(f"Error: Reference DA not found: {reference_da}")
        return 1

    print(f"Using reference DA: {reference_da}")
    with open(reference_da, 'rb') as f:
        ref_data = f.read()

    ref_info = read_da_info(ref_data, 0)
    print(f"Reference SW Version: 0x{ref_info['sw_version']:04X}")

    # Process target DAs
    if len(sys.argv) > 2:
        for target_da in sys.argv[2:]:
            if os.path.exists(target_da):
                patch_da_binary(target_da, ref_info)
            else:
                print(f"Warning: Target DA not found: {target_da}")
    else:
        print("\nNo target DAs specified. Only analyzed reference DA.")

    print(f"\n{'='*60}")
    print("Patching complete!")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
