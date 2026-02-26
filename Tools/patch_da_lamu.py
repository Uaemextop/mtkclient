#!/usr/bin/env python3
# (c) 2025 MIT License
#
# patch_da_lamu.py - Patches lamu DA agents to use the FORBID_SIGNED version and
#                    disable anti-rollback / security checks.
#
# Depends on (Tools folder):
#   da_parser.py  - DA file structure constants and parsing approach
#   patch_legacy.py  - binary patch helpers (fix_hash, compute_hash_pos)
#   patch_preloader.py  - preloader-security patch patterns
#
# Usage:
#   python3 patch_da_lamu.py <forbid_signed.bin> <target.bin> [<target2.bin> ...]
#
# Example:
#   python3 patch_da_lamu.py DA_A15_lamu_FORBID_SIGNED.bin \
#           DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin

import os
import sys
import struct
import inspect

# ---------------------------------------------------------------------------
# Path setup – identical to da_parser.py / patch_legacy.py so we can reuse
# the shared mtkclient utilities they depend on.
# ---------------------------------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from mtkclient.Library.utils import find_binary

# ---------------------------------------------------------------------------
# DA file layout constants  (mirror of da_parser.py)
# ---------------------------------------------------------------------------
VERSION_OFFSET = 0x20       # offset of "MTK_AllInOne_DA_v3.XXXX" string
VERSION_LENGTH = 0x30       # 48 bytes reserved for the version string
COUNT_DA_OFFSET = 0x68      # offset of count_da field
DA_TABLE_OFFSET = 0x6C      # offset of first DA entry
DA_HEADER_SIZE = 0x14       # sizeof DA header struct (10 x uint16)
ENTRY_REGION_SIZE = 0x14    # sizeof entry_region struct (5 x uint32)
DA_ENTRY_STRIDE = 0xDC      # stride between DA entries in the table


# ---------------------------------------------------------------------------
# DA structure parser  (logic from da_parser.py, generalised)
# ---------------------------------------------------------------------------
def parse_da_file(data):
    """Return (version_str, list_of_da_descriptors)."""
    version = (data[VERSION_OFFSET:VERSION_OFFSET + VERSION_LENGTH]
               .rstrip(b'\x00').decode('ascii', errors='replace'))
    count_da = struct.unpack('<I', data[COUNT_DA_OFFSET:COUNT_DA_OFFSET + 4])[0]

    das = []
    for i in range(count_da):
        base = DA_TABLE_OFFSET + i * DA_ENTRY_STRIDE
        (magic, hw_code, hw_sub_code, hw_version, sw_version,
         res1, pagesize, res3, entry_idx, entry_count) = struct.unpack(
            '<10H', data[base:base + DA_HEADER_SIZE])

        entries = []
        off = base + DA_HEADER_SIZE
        for _ in range(entry_count):
            m_buf, m_len, m_start_addr, m_start_offset, m_sig_len = struct.unpack(
                '<5I', data[off:off + ENTRY_REGION_SIZE])
            entries.append({
                'm_buf': m_buf,
                'm_len': m_len,
                'm_start_addr': m_start_addr,
                'm_start_offset': m_start_offset,
                'm_sig_len': m_sig_len,
            })
            off += ENTRY_REGION_SIZE

        das.append({
            'magic': magic,
            'hw_code': hw_code,
            'hw_sub_code': hw_sub_code,
            'hw_version': hw_version,
            'sw_version': sw_version,
            'pagesize': pagesize,
            'entry_count': entry_count,
            'entries': entries,
            'base_offset': base,
        })
    return version, das


def print_da_info(label, version, das):
    print(f"  [{label}] version : {version}")
    for i, da in enumerate(das):
        print(f"  DA[{i}] hw_code=0x{da['hw_code']:04X}  "
              f"hw_sub=0x{da['hw_sub_code']:04X}  "
              f"hw_ver=0x{da['hw_version']:04X}  "
              f"sw_ver=0x{da['sw_version']:04X}  "
              f"entries={da['entry_count']}")
        for j, e in enumerate(da['entries']):
            print(f"    entry[{j}]: m_buf=0x{e['m_buf']:08X}  "
                  f"m_len=0x{e['m_len']:08X}  "
                  f"m_start_addr=0x{e['m_start_addr']:08X}")


# ---------------------------------------------------------------------------
# DA1 patcher  (pattern from xflash extension patch_da1)
# ---------------------------------------------------------------------------
def patch_da1_version_check(da1):
    """Disable the DA1 internal version / compatibility check."""
    da1p = bytearray(da1)
    idx = find_binary(da1, b"\x1F\xB5\x00\x23\x01\xA8\x00\x93\x00\xF0")
    if idx is not None:
        da1p[idx:idx + 4] = b"\x00\x20\x70\x47"
        print("    DA1 version check patched")
    else:
        print("    DA1 version check: pattern not found (skipped)")
    return bytes(da1p)


# ---------------------------------------------------------------------------
# DA2 patcher  (patterns from xflash extension patch_da2 / patch_legacy.py)
# ---------------------------------------------------------------------------
def patch_da2_security(da2):
    """Apply all DA2 security / anti-rollback patches."""
    da2p = bytearray(da2)

    # 1. Anti-rollback version check  (xflash extension patch_da2)
    arb = find_binary(da2, int.to_bytes(0xC0020053, 4, 'little'))
    if arb is not None:
        da2p[arb:arb + 4] = int.to_bytes(0, 4, 'little')
        print(f"    DA2 anti-rollback (0xC0020053) patched @ 0x{arb:X}")
    else:
        print("    DA2 anti-rollback: pattern not found (skipped)")

    # 2. Security / hash-binding check  (xflash extension patch_da2)
    sec = find_binary(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5")
    if sec is not None:
        da2p[sec:sec + 2] = b"\x00\x23"
        print(f"    DA2 security check patched @ 0x{sec:X}")
    else:
        print("    DA2 security check: pattern not found (skipped)")

    # 3. hash cmd_boot_to (0xC0070004)  (xflash extension patch_da2)
    hcmd = find_binary(da2, int.to_bytes(0xC0070004, 4, 'little'))
    if hcmd is not None:
        da2p[hcmd:hcmd + 4] = int.to_bytes(0, 4, 'little')
        print(f"    DA2 hash cmd_boot (0xC0070004) patched @ 0x{hcmd:X}")
    else:
        print("    DA2 hash cmd_boot: pattern not found (skipped)")

    # 4. Register read/write restriction (0xC004000D)  (xflash extension patch_da2)
    rrw = find_binary(da2, int.to_bytes(0xC004000D, 4, 'little'))
    if rrw is not None:
        da2p[rrw:rrw + 4] = int.to_bytes(0, 4, 'little')
        print(f"    DA2 register read/write (0xC004000D) patched @ 0x{rrw:X}")
    else:
        print("    DA2 register read/write: pattern not found (skipped)")

    # 5. SBC (Secure Boot Check) disable  (xflash extension patch_da2)
    sbc = find_binary(da2, b"\x02\x4B\x18\x68\xC0\xF3\x40\x00\x70\x47")
    if sbc is not None:
        da2p[sbc + 4:sbc + 8] = b"\x4F\xF0\x00\x00"
        print(f"    DA2 SBC patched @ 0x{sbc:X}")
    else:
        print("    DA2 SBC: pattern not found (skipped)")

    # 6. Motorola SLA disable  (xflash extension patch_da2)
    sla = find_binary(da2, b"\x01\x00\x01\xC0\x01\x20\x70\x47")
    if sla is not None:
        da2p[sla + 4:sla + 6] = b"\x00\x20"
        print(f"    DA2 moto SLA patched @ 0x{sla:X}")
    else:
        print("    DA2 moto SLA: pattern not found (skipped)")

    return bytes(da2p)


# ---------------------------------------------------------------------------
# Main patcher
# ---------------------------------------------------------------------------
def patch_target(ref_data, ref_version, ref_das, target_path):
    """Patch one target DA file using the FORBID_SIGNED reference."""
    with open(target_path, 'rb') as f:
        tgt_data = f.read()

    tgt_version, tgt_das = parse_da_file(tgt_data)
    print(f"\n  Target  : {os.path.basename(target_path)}")
    print_da_info("original", tgt_version, tgt_das)

    if not tgt_das or not ref_das:
        print("  ERROR: failed to parse DA entries – skipping.")
        return

    tgt_da = tgt_das[0]
    ref_da = ref_das[0]
    tgt_entries = tgt_da['entries']
    ref_entries = ref_da['entries']

    # -----------------------------------------------------------------------
    # Extract payloads
    # -----------------------------------------------------------------------
    # entry[0] – DA0 (tiny init stub loaded at 0x50000000) – keep from target
    da0 = tgt_data[tgt_entries[0]['m_buf']:
                   tgt_entries[0]['m_buf'] + tgt_entries[0]['m_len']]

    # entry[1] – DA1 (auth / download-agent stage-1) – take from FORBID_SIGNED
    #   then patch the internal version check so it does not reject older firmware
    ref_da1_raw = ref_data[ref_entries[1]['m_buf']:
                           ref_entries[1]['m_buf'] + ref_entries[1]['m_len']]
    print("\n  Patching DA1 (from FORBID_SIGNED reference):")
    new_da1 = patch_da1_version_check(ref_da1_raw)

    # entry[2] – DA2 (bulk download agent) – take from target, apply patches
    tgt_da2_raw = tgt_data[tgt_entries[2]['m_buf']:
                            tgt_entries[2]['m_buf'] + tgt_entries[2]['m_len']]
    print("\n  Patching DA2 (from target, security + anti-rollback disabled):")
    new_da2 = patch_da2_security(tgt_da2_raw)

    # -----------------------------------------------------------------------
    # Rebuild file layout:   [header | DA0 | new_DA1 | patched_DA2]
    # -----------------------------------------------------------------------
    header_size = tgt_entries[0]['m_buf']  # everything before DA0 = 0x376C

    da0_start  = header_size
    da1_start  = da0_start + len(da0)
    da2_start  = da1_start + len(new_da1)

    # Build updated header
    new_header = bytearray(tgt_data[:header_size])

    # Update version string → FORBID_SIGNED version
    ver_bytes = ref_version.encode('ascii')
    ver_bytes = ver_bytes + b'\x00' * (VERSION_LENGTH - len(ver_bytes))
    new_header[VERSION_OFFSET:VERSION_OFFSET + VERSION_LENGTH] = ver_bytes[:VERSION_LENGTH]

    # Rewrite entry[0] (DA0) – same data, new absolute offset (unchanged here)
    e0_off = DA_TABLE_OFFSET + DA_HEADER_SIZE
    struct.pack_into('<5I', new_header, e0_off,
                     da0_start,
                     len(da0),
                     tgt_entries[0]['m_start_addr'],
                     tgt_entries[0]['m_start_offset'],
                     tgt_entries[0]['m_sig_len'])

    # Rewrite entry[1] (DA1) – new data (from ref), new offset & length
    e1_off = e0_off + ENTRY_REGION_SIZE
    new_da1_sig_len = ref_entries[1]['m_sig_len']
    new_da1_payload_offset = len(new_da1) - new_da1_sig_len  # executable payload before signature
    struct.pack_into('<5I', new_header, e1_off,
                     da1_start,
                     len(new_da1),
                     ref_entries[1]['m_start_addr'],
                     new_da1_payload_offset,
                     new_da1_sig_len)

    # Rewrite entry[2] (DA2) – patched data, new offset
    e2_off = e1_off + ENTRY_REGION_SIZE
    new_da2_sig_len = tgt_entries[2]['m_sig_len']
    new_da2_payload_offset = len(new_da2) - new_da2_sig_len  # executable payload before signature
    struct.pack_into('<5I', new_header, e2_off,
                     da2_start,
                     len(new_da2),
                     tgt_entries[2]['m_start_addr'],
                     new_da2_payload_offset,
                     new_da2_sig_len)

    # Assemble final binary
    result = bytes(new_header) + da0 + new_da1 + new_da2

    # -----------------------------------------------------------------------
    # Write output
    # -----------------------------------------------------------------------
    base, ext = os.path.splitext(target_path)
    out_path = base + "_patched" + ext
    with open(out_path, 'wb') as f:
        f.write(result)

    # Quick verification
    out_version, out_das = parse_da_file(result)
    print(f"\n  Output  : {os.path.basename(out_path)}  ({len(result)} bytes)")
    print_da_info("patched", out_version, out_das)
    print(f"  OK – written to {out_path}")


def main():
    if len(sys.argv) < 3:
        print("Usage: patch_da_lamu.py <FORBID_SIGNED.bin> <target.bin> [<target2.bin> ...]")
        sys.exit(1)

    ref_path = sys.argv[1]
    target_paths = sys.argv[2:]

    if not os.path.isfile(ref_path):
        print(f"ERROR: reference file not found: {ref_path}")
        sys.exit(1)

    print(f"\n=== Loading reference (FORBID_SIGNED): {os.path.basename(ref_path)} ===")
    with open(ref_path, 'rb') as f:
        ref_data = f.read()

    ref_version, ref_das = parse_da_file(ref_data)
    print_da_info("reference", ref_version, ref_das)

    print("\n=== Patching targets ===")
    for target_path in target_paths:
        if not os.path.isfile(target_path):
            print(f"  WARNING: target not found: {target_path} – skipping")
            continue
        try:
            patch_target(ref_data, ref_version, ref_das, target_path)
        except Exception as exc:
            print(f"  ERROR patching {target_path}: {exc}")
            raise

    print("\nDone.")


if __name__ == "__main__":
    main()
