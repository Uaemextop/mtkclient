#!/usr/bin/env python3
# (c) B.Kerler 2021 MIT License
"""
DA Analyzer Tool - Comprehensive analysis and comparison of DA (Download Agent)
binaries. Examines headers, security features, partition access, operation
permissions, anti-rollback, and all differences between DA files.

Usage:
    python da_analyzer.py <da_file1> <da_file2> [<da_file3> ...]

Example:
    python da_analyzer.py DA_A15_lamu_FORBID_SIGNED.bin \
        DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin
"""
import os
import sys
import re
import hashlib
from struct import unpack, pack
import inspect

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from mtkclient.Library.utils import find_binary
from mtkclient.config.brom_config import hwconfig

# ── Build HW code → chip name mapping from brom_config ────────────────
DACODE_TO_CHIP = {}
for _key, _cfg in hwconfig.items():
    if hasattr(_cfg, 'dacode') and _cfg.dacode is not None and hasattr(_cfg, 'name'):
        dc = _cfg.dacode
        if dc not in DACODE_TO_CHIP:
            DACODE_TO_CHIP[dc] = {
                'name': _cfg.name,
                'description': getattr(_cfg, 'description', ''),
                'loader': getattr(_cfg, 'loader', ''),
            }

# ── DA header structures (from da_parser.py) ──────────────────────────
entry_region_fields = [
    ('m_buf', 'I'), ('m_len', 'I'), ('m_start_addr', 'I'),
    ('m_start_offset', 'I'), ('m_sig_len', 'I')]

da_header_fields = [
    ('magic', 'H'), ('hw_code', 'H'), ('hw_sub_code', 'H'),
    ('hw_version', 'H'), ('sw_version', 'H'), ('reserved1', 'H'),
    ('pagesize', 'H'), ('reserved3', 'H'),
    ('entry_region_index', 'H'), ('entry_region_count', 'H')]

VERSION_STRING_OFFSET = 0x20
VERSION_STRING_MAX_LEN = 0x40

# ── Known error / security codes ──────────────────────────────────────
ERROR_CODES = {
    0xC0010001: "SLA_VERIFY_FAIL",
    0xC0010002: "SLA_CUSTOMER_DISABLED",
    0xC0020004: "HASH_BINDING_VERIFY_FAIL",
    0xC0020005: "HASH_BINDING_NOT_MATCH",
    0xC002002D: "ANTI_ROLLBACK_VIOLATION",
    0xC0020039: "DOWNLOAD_ERROR",
    0xC0020053: "ANTI_ROLLBACK_CHECK",
    0xC0030007: "SECURITY_ERROR",
    0xC004000D: "REGISTER_RW_NOT_ALLOWED",
    0xC0050001: "WRITE_FORBIDDEN",
    0xC0050002: "READ_FORBIDDEN",
    0xC0050003: "ERASE_FORBIDDEN",
    0xC0050004: "FORMAT_FORBIDDEN",
    0xC0060001: "DOWNLOAD_FORBIDDEN",
    0xC0060002: "NEED_VERIFICATION",
    0xC0060003: "HASH_BINDING_BLOCK",
    0xC0070004: "AUTH_HASH_CHECK",
}

# ── Binary security patterns (from xflash.py) ────────────────────────
SECURITY_PATTERNS = {
    "Motorola SLA check":    b"\x01\x00\x01\xC0\x01\x20\x70\x47",
    "Hash binding (Thumb)":  b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5",
    "Hash binding (ARM)":    b"\x01\x10\xA0\xE3\x00\x10\x80\xE5\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1",
    "Write forbidden v1":    b"\x37\xB5\x00\x23\x04\x46\x02\xA8",
    "Write forbidden v2":    b"\x0C\x23\xCC\xF2\x02\x03",
    "SBC check":             b"\x02\x4B\x18\x68\xC0\xF3\x40\x00\x70\x47",
    "Carbonara v5 patch":    b"\x06\x9B\x4F\xF0\x80\x40\x02\xA9",
    "Carbonara v6 patch1":   b"\x01\x01\x54\xE3\x01\x14\xA0\xE3",
    "Carbonara v6 patch2":   b"\x08\x00\xa8\x52\xff\x02\x08\xeb",
    "DA version check":      b"\x1F\xB5\x00\x23\x01\xA8\x00\x93\x00\xF0",
    "Huawei security":       b"\x01\x2B\x03\xD1\x01\x23",
    "Oppo security":         b"\x01\x3B\x01\x2B\x08\xD9",
    "Oppo auth flag":        b"\x0A\x00\x00\xE0",
}

# ── Known partition names ─────────────────────────────────────────────
PARTITION_NAMES = [
    "preloader", "preloader_a", "preloader_b", "preloader_backup",
    "boot", "boot_a", "boot_b",
    "init_boot", "init_boot_a", "init_boot_b",
    "vendor_boot", "vendor_boot_a", "vendor_boot_b",
    "recovery", "recovery_a", "recovery_b",
    "system", "system_a", "system_b",
    "vendor", "vendor_a", "vendor_b",
    "product", "product_a", "product_b",
    "odm", "odm_a", "odm_b",
    "super", "userdata", "metadata", "cache",
    "lk", "lk_a", "lk_b", "lk2",
    "logo", "para", "misc",
    "seccfg", "secro", "sec1",
    "md1img", "md1img_a", "md1img_b",
    "md3img", "md3img_a", "md3img_b",
    "tee", "tee_a", "tee_b", "tee1", "tee2",
    "spmfw", "sspm", "mcupm", "dpm",
    "vbmeta", "vbmeta_a", "vbmeta_b",
    "vbmeta_system", "vbmeta_vendor",
    "dtbo", "dtbo_a", "dtbo_b",
    "otp", "flashinfo", "nvcfg",
    "protect1", "protect2",
    "nvram", "nvdata",
    "persist", "frp",
    "efuse", "proinfo", "bootctrl",
    "expdb", "scp", "gz", "gpueb",
]

# ── Operation permission strings to search ────────────────────────────
PERMISSION_STRINGS = [
    b"storage write operation is forbidden",
    b"storage read operation is forbidden",
    b"storage erase operation is forbidden",
    b"cmd_write_data is not allowed(dl forbidden)",
    b"cmd_write_data is not allowed(need verification)",
    b"cmd_write_data is not allowed(hash binding)",
    b"cmd_format is not allowed(dl forbidden)",
    b"Register Read is not allowed",
    b"Register Write is not allowed",
    b"Write DRAM repair address is allowed",
    b"Write DRAM repair address is forbidden",
    b"DA SLA Customer Disabled",
    b"Security Boot Check is enable",
    b"DA verify pass and jump to DRAM",
    b"boot up to home screen",
    b"boot up to fastboot mode",
    b"reboot to fastboot mode",
    b"2nd DA address is invalid",
]

# ── Brand / OEM detection patterns ───────────────────────────────────
BRAND_PATTERNS = {
    "Motorola":  [b"\x01\x00\x01\xC0\x01\x20\x70\x47", b"moto"],
    "Oppo/Realme": [b"[oplus]", b"[OPPO]"],
    "Huawei":    [b"\x01\x2B\x03\xD1\x01\x23"],
    "Tecno":     [b"Tecno", b"TECNO"],
    "Samsung":   [b"samsung", b"Samsung"],
    "Xiaomi":    [b"xiaomi", b"Xiaomi"],
}


def read_da_header(data):
    """Parse DA file header and entry regions."""
    count_da = unpack("<I", data[0x68:0x6C])[0]
    entries = []
    for i in range(count_da):
        offset = 0x6C + (i * 0xDC)
        hdr = {}
        pos = offset
        for name, stype in da_header_fields:
            size = 2
            hdr[name] = unpack('<' + stype, data[pos:pos + size])[0]
            pos += size
        regions = []
        for m in range(hdr['entry_region_count']):
            entry = {}
            for name, stype in entry_region_fields:
                size = 4
                entry[name] = unpack('<' + stype, data[pos:pos + size])[0]
                pos += size
            regions.append(entry)
        entries.append((hdr, regions))
    return entries


def get_version_string(data):
    """Extract the version string from a DA binary."""
    raw = data[VERSION_STRING_OFFSET:VERSION_STRING_OFFSET + VERSION_STRING_MAX_LEN]
    return raw.split(b'\x00')[0].decode('ascii', errors='replace')


def extract_strings(data, min_len=6):
    """Extract printable ASCII strings of minimum length from binary data."""
    strings = []
    current = b''
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                start = i
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append((start, current.decode('ascii', errors='replace')))
            current = b''
    if len(current) >= min_len:
        strings.append((start, current.decode('ascii', errors='replace')))
    return strings


def count_pattern(data, pattern):
    """Count all occurrences of a pattern in data."""
    count = 0
    idx = 0
    while True:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        count += 1
        idx = pos + 1
    return count


def find_partitions(data):
    """Find known partition names present in binary data."""
    found = set()
    for pname in PARTITION_NAMES:
        search = pname.encode() + b'\x00'
        if data.find(search) != -1:
            found.add(pname)
    return found


def analyze_da(filepath):
    """Full analysis of a single DA binary. Returns analysis dict."""
    with open(filepath, 'rb') as f:
        data = f.read()

    name = os.path.basename(filepath)
    entries = read_da_header(data)
    hdr = entries[0][0]
    regions = entries[0][1]

    # Extract regions
    da1 = data[regions[1]['m_buf']:regions[1]['m_buf'] + regions[1]['m_len']] \
        if len(regions) > 1 else b''
    da2 = data[regions[2]['m_buf']:regions[2]['m_buf'] + regions[2]['m_len']] \
        if len(regions) > 2 else b''

    analysis = {
        'name': name,
        'file_size': len(data),
        'version': get_version_string(data),
        'header': hdr,
        'regions': regions,
        'da1_size': len(da1),
        'da2_size': len(da2),
        'error_codes': {},
        'security_patterns': {},
        'permissions': {},
        'partitions_da2': find_partitions(da2),
        'partitions_da1': find_partitions(da1),
        'da2_strings': set(s for _, s in extract_strings(da2, 8)),
        'da1_strings': set(s for _, s in extract_strings(da1, 8)),
        'da2_hash_sha256': hashlib.sha256(da2).hexdigest() if da2 else None,
        'da1_hash_sha256': hashlib.sha256(da1).hexdigest() if da1 else None,
    }

    # Count error codes in both DA1 and DA2
    for code, desc in ERROR_CODES.items():
        pattern = int.to_bytes(code, 4, 'little')
        c1 = count_pattern(da1, pattern)
        c2 = count_pattern(da2, pattern)
        if c1 > 0 or c2 > 0:
            analysis['error_codes'][desc] = {'da1': c1, 'da2': c2}

    # Check security patterns
    for pname, pattern in SECURITY_PATTERNS.items():
        in_da1 = find_binary(da1, pattern) is not None
        in_da2 = find_binary(da2, pattern) is not None
        if in_da1 or in_da2:
            analysis['security_patterns'][pname] = {'da1': in_da1, 'da2': in_da2}

    # Check permission strings
    for ps in PERMISSION_STRINGS:
        in_da1 = da1.find(ps) != -1
        in_da2 = da2.find(ps) != -1
        if in_da1 or in_da2:
            analysis['permissions'][ps.decode('ascii')] = {'da1': in_da1, 'da2': in_da2}

    # ── Target device / chip info ─────────────────────────────────────
    hw = hdr['hw_code']
    chip = DACODE_TO_CHIP.get(hw)
    analysis['chip_name'] = chip['name'] if chip else f"Unknown (0x{hw:04X})"
    analysis['chip_desc'] = chip['description'] if chip else ""
    analysis['chip_loader'] = chip['loader'] if chip else ""

    # ── DA type / version classification ──────────────────────────────
    ver = analysis['version']
    da_type = "MTK_AllInOne_DA"
    da_ver = ""
    da_build = ""
    da_date = ""
    if "AllInOne" in ver:
        da_type = "AllInOne (multi-target)"
    parts = ver.split("_v")
    if len(parts) > 1:
        rest = parts[1]  # e.g. "3.3001.2025/11/07.14:24_654171"
        da_ver = rest.split(".")[0] + "." + rest.split(".")[1] if "." in rest else rest
        # Extract date
        date_m = re.search(r'(\d{4}/\d{2}/\d{2}\.\d{2}:\d{2})', rest)
        if date_m:
            da_date = date_m.group(1)
        build_m = re.search(r'_(\d+)$', rest)
        if build_m:
            da_build = build_m.group(1)

    analysis['da_type'] = da_type
    analysis['da_ver'] = da_ver
    analysis['da_build'] = da_build
    analysis['da_date'] = da_date

    # ── Brand / OEM detection ─────────────────────────────────────────
    detected_brands = []
    combined = da1 + da2
    for brand, patterns in BRAND_PATTERNS.items():
        for pat in patterns:
            if combined.find(pat) != -1:
                detected_brands.append(brand)
                break
    analysis['brands'] = detected_brands if detected_brands else ["Generic (no OEM patches)"]

    # ── Protection type classification ────────────────────────────────
    protections = []
    if 'ANTI_ROLLBACK_CHECK' in analysis['error_codes']:
        protections.append("Anti-Rollback Version Check")
    if 'ANTI_ROLLBACK_VIOLATION' in analysis['error_codes']:
        protections.append("Anti-Rollback Violation Enforcement")
    if 'SLA_VERIFY_FAIL' in analysis['error_codes']:
        protections.append("SLA (Secure Loader Authentication)")
    if 'Motorola SLA check' in analysis['security_patterns']:
        protections.append("Motorola SLA (moto_disable_sla)")
    if 'Hash binding (Thumb)' in analysis['security_patterns'] or \
       'Hash binding (ARM)' in analysis['security_patterns']:
        protections.append("Hash Binding Verification")
    if 'AUTH_HASH_CHECK' in analysis['error_codes']:
        protections.append("Auth Hash Check (cmd_boot_to)")
    if 'SBC check' in analysis['security_patterns']:
        protections.append("Secure Boot Check (SBC)")
    if 'Carbonara v5 patch' in analysis['security_patterns']:
        protections.append("Carbonara v5 Anti-Exploit")
    if 'Carbonara v6 patch1' in analysis['security_patterns'] or \
       'Carbonara v6 patch2' in analysis['security_patterns']:
        protections.append("Carbonara v6 Anti-Exploit")
    if 'DA version check' in analysis['security_patterns']:
        protections.append("DA Version Check (DA1)")
    if 'Write forbidden v1' in analysis['security_patterns'] or \
       'Write forbidden v2' in analysis['security_patterns']:
        protections.append("Write Operation Restriction")
    if da2.find(b"storage erase operation is forbidden") != -1:
        protections.append("Erase Operation Restriction")
    if da2.find(b"Register Read is not allowed") != -1:
        protections.append("Register Read/Write Restriction")
    if 'DOWNLOAD_FORBIDDEN' in analysis['error_codes'] or \
       da2.find(b"dl_forbidden") != -1:
        protections.append("Download Forbidden Flag")

    analysis['protections'] = protections if protections else ["None detected"]

    return analysis


def print_single_analysis(a):
    """Print detailed analysis of a single DA."""
    print(f"\n{'━' * 70}")
    print(f"  {a['name']}")
    print(f"{'━' * 70}")

    print(f"\n  ┌─ DA Identity")
    print(f"  │  DA Type:     {a['da_type']}")
    print(f"  │  DA Version:  {a['da_ver']}")
    print(f"  │  Build:       {a['da_build']}")
    print(f"  │  Build Date:  {a['da_date']}")
    print(f"  │  Full String: {a['version']}")
    print(f"  │")
    print(f"  ├─ Target Device")
    print(f"  │  Chip:        {a['chip_name']}")
    print(f"  │  Description: {a['chip_desc']}")
    print(f"  │  HW Code:     0x{a['header']['hw_code']:04X}")
    print(f"  │  HW Sub Code: 0x{a['header']['hw_sub_code']:04X}")
    print(f"  │  HW Version:  0x{a['header']['hw_version']:04X}")
    print(f"  │  SW Version:  0x{a['header']['sw_version']:04X}")
    print(f"  │  Payload:     {a['chip_loader']}")
    print(f"  │  OEM/Brand:   {', '.join(a['brands'])}")
    print(f"  │")
    print(f"  ├─ File Info")
    print(f"  │  Size:    {a['file_size']} bytes ({a['file_size'] / 1024:.1f} KB)")
    print(f"  │  DA1 SHA256: {a['da1_hash_sha256'][:16]}...")
    print(f"  │  DA2 SHA256: {a['da2_hash_sha256'][:16]}...")

    hdr = a['header']
    print(f"  │")
    print(f"  ├─ Regions ({len(a['regions'])} entries)")
    region_names = {0: "EMI", 1: "DA1", 2: "DA2"}
    for i, r in enumerate(a['regions']):
        rn = region_names.get(i, f"R{i}")
        print(f"  │  {rn}: buf=0x{r['m_buf']:08X}  len=0x{r['m_len']:08X}  "
              f"addr=0x{r['m_start_addr']:08X}  sig=0x{r['m_sig_len']:08X}")

    print(f"  │")
    print(f"  ├─ Protection Types ({len(a['protections'])} active)")
    for p in a['protections']:
        print(f"  │  🛡 {p}")

    print(f"  │")
    print(f"  ├─ Security Error Codes")
    if a['error_codes']:
        for desc, counts in sorted(a['error_codes'].items()):
            print(f"  │  {desc:<35} DA1={counts['da1']:>2}  DA2={counts['da2']:>2}")
    else:
        print(f"  │  (none found)")

    print(f"  │")
    print(f"  ├─ Security Patterns")
    if a['security_patterns']:
        for pname, where in sorted(a['security_patterns'].items()):
            da1_s = "✓" if where['da1'] else "·"
            da2_s = "✓" if where['da2'] else "·"
            print(f"  │  {pname:<30} DA1={da1_s}  DA2={da2_s}")
    else:
        print(f"  │  (none found)")

    print(f"  │")
    print(f"  ├─ Operation Permissions / Messages")
    if a['permissions']:
        for msg, where in sorted(a['permissions'].items()):
            locs = []
            if where['da1']:
                locs.append("DA1")
            if where['da2']:
                locs.append("DA2")
            print(f"  │  [{','.join(locs):>7}] {msg}")
    else:
        print(f"  │  (none found)")

    print(f"  │")
    all_parts = sorted(a['partitions_da1'] | a['partitions_da2'])
    print(f"  └─ Partitions Referenced ({len(all_parts)} total)")
    for p in all_parts:
        locs = []
        if p in a['partitions_da1']:
            locs.append("DA1")
        if p in a['partitions_da2']:
            locs.append("DA2")
        print(f"     [{','.join(locs):>7}] {p}")


def print_comparison(analyses):
    """Print side-by-side comparison of multiple DAs."""
    names = [a['name'] for a in analyses]
    short = [n[:20] for n in names]

    print(f"\n{'═' * 80}")
    print(f"  COMPARISON OF {len(analyses)} DA BINARIES")
    print(f"{'═' * 80}")

    # ── Identity & Target ─────────────────────────────────────────────
    print(f"\n{'─' * 80}")
    print(f"  DA IDENTITY & TARGET DEVICE")
    print(f"{'─' * 80}")
    max_name = max(len(n) for n in names)
    for a in analyses:
        print(f"\n  {a['name']}")
        print(f"    Type:       {a['da_type']}")
        print(f"    Version:    {a['da_ver']}  Build: {a['da_build']}  "
              f"Date: {a['da_date']}")
        print(f"    Target:     {a['chip_name']}  ({a['chip_desc']})")
        h = a['header']
        print(f"    HW:         0x{h['hw_code']:04X}  sub=0x{h['hw_sub_code']:04X}  "
              f"hw_ver=0x{h['hw_version']:04X}  sw_ver=0x{h['sw_version']:04X}")
        print(f"    OEM/Brand:  {', '.join(a['brands'])}")
        print(f"    File Size:  {a['file_size']} bytes ({a['file_size'] / 1024:.1f} KB)")

    # ── Protection Types Comparison ───────────────────────────────────
    all_prots = set()
    for a in analyses:
        all_prots.update(a['protections'])

    print(f"\n{'─' * 80}")
    print(f"  PROTECTION TYPES")
    print(f"{'─' * 80}")
    header = f"  {'Protection':<40}"
    for n in short:
        header += f" {n:<22}"
    print(header)
    for prot in sorted(all_prots):
        row = f"  {prot:<40}"
        vals = []
        for a in analyses:
            val = "✓" if prot in a['protections'] else "·"
            vals.append(val)
        diff = len(set(vals)) > 1
        for v in vals:
            row += f" {v:<22}"
        if diff:
            row += " ← DIFFERENT"
        print(row)

    # ── Region Sizes ──────────────────────────────────────────────────
    print(f"\n{'─' * 80}")
    print(f"  REGION SIZES")
    print(f"{'─' * 80}")
    for a in analyses:
        for i, r in enumerate(a['regions']):
            rn = {0: "EMI", 1: "DA1", 2: "DA2"}.get(i, f"R{i}")
            print(f"  {a['name']:<{max_name}}  {rn}: "
                  f"len=0x{r['m_len']:08X} ({r['m_len']:>7} bytes)  "
                  f"sig=0x{r['m_sig_len']:08X}")

    # ── Error Codes Comparison ────────────────────────────────────────
    all_codes = set()
    for a in analyses:
        all_codes.update(a['error_codes'].keys())

    if all_codes:
        print(f"\n{'─' * 80}")
        print(f"  ERROR / SECURITY CODES  (DA1 count, DA2 count)")
        print(f"{'─' * 80}")
        header = f"  {'Code':<35}"
        for n in short:
            header += f" {n:<22}"
        print(header)
        for code in sorted(all_codes):
            row = f"  {code:<35}"
            vals = []
            for a in analyses:
                c = a['error_codes'].get(code, {'da1': 0, 'da2': 0})
                val = f"DA1={c['da1']:>2} DA2={c['da2']:>2}"
                vals.append(val)
            diff = len(set(vals)) > 1
            for v in vals:
                row += f" {v:<22}"
            if diff:
                row += " ← DIFFERENT"
            print(row)

    # ── Security Patterns Comparison ──────────────────────────────────
    all_patterns = set()
    for a in analyses:
        all_patterns.update(a['security_patterns'].keys())

    if all_patterns:
        print(f"\n{'─' * 80}")
        print(f"  SECURITY PATTERNS")
        print(f"{'─' * 80}")
        header = f"  {'Pattern':<30}"
        for n in short:
            header += f" {n:<22}"
        print(header)
        for pname in sorted(all_patterns):
            row = f"  {pname:<30}"
            vals = []
            for a in analyses:
                w = a['security_patterns'].get(pname, {'da1': False, 'da2': False})
                da1_s = "✓" if w['da1'] else "·"
                da2_s = "✓" if w['da2'] else "·"
                val = f"DA1={da1_s} DA2={da2_s}"
                vals.append(val)
            diff = len(set(vals)) > 1
            for v in vals:
                row += f" {v:<22}"
            if diff:
                row += " ← DIFFERENT"
            print(row)

    # ── Operation Permissions Comparison ──────────────────────────────
    all_perms = set()
    for a in analyses:
        all_perms.update(a['permissions'].keys())

    if all_perms:
        print(f"\n{'─' * 80}")
        print(f"  OPERATION PERMISSIONS / MESSAGES")
        print(f"{'─' * 80}")
        for msg in sorted(all_perms):
            vals = []
            for a in analyses:
                w = a['permissions'].get(msg, {'da1': False, 'da2': False})
                locs = []
                if w['da1']:
                    locs.append("DA1")
                if w['da2']:
                    locs.append("DA2")
                vals.append(",".join(locs) if locs else "·")
            diff = len(set(vals)) > 1
            parts = "  "
            for i, v in enumerate(vals):
                parts += f"[{v:>7}] "
            parts += msg
            if diff:
                parts += "  ← DIFFERENT"
            print(parts)

    # ── Partition Comparison ──────────────────────────────────────────
    all_parts = set()
    for a in analyses:
        all_parts.update(a['partitions_da1'] | a['partitions_da2'])

    print(f"\n{'─' * 80}")
    print(f"  PARTITION REFERENCES")
    print(f"{'─' * 80}")
    header = f"  {'Partition':<25}"
    for n in short:
        header += f" {n:<22}"
    print(header)
    for p in sorted(all_parts):
        row = f"  {p:<25}"
        vals = []
        for a in analyses:
            locs = []
            if p in a['partitions_da1']:
                locs.append("DA1")
            if p in a['partitions_da2']:
                locs.append("DA2")
            val = ",".join(locs) if locs else "·"
            vals.append(val)
        diff = len(set(vals)) > 1
        for v in vals:
            row += f" {v:<22}"
        if diff:
            row += " ← DIFFERENT"
        print(row)

    # ── String Differences (DA2) ──────────────────────────────────────
    print(f"\n{'─' * 80}")
    print(f"  UNIQUE STRINGS PER DA (DA2 only, len≥10)")
    print(f"{'─' * 80}")
    all_da2_strings = [a['da2_strings'] for a in analyses]
    for i, a in enumerate(analyses):
        others = set()
        for j, a2 in enumerate(analyses):
            if j != i:
                others |= a2['da2_strings']
        unique = a['da2_strings'] - others
        unique_filtered = sorted(s for s in unique if len(s) >= 10)
        if unique_filtered:
            print(f"\n  Only in {a['name']}:")
            for s in unique_filtered[:30]:
                print(f"    {s}")
            if len(unique_filtered) > 30:
                print(f"    ... and {len(unique_filtered) - 30} more")

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'═' * 80}")
    print(f"  SUMMARY OF KEY DIFFERENCES")
    print(f"{'═' * 80}")

    # Version differences
    versions = [a['version'] for a in analyses]
    if len(set(versions)) > 1:
        print(f"\n  ⚠ Version strings differ:")
        for a in analyses:
            print(f"    {a['name']}: {a['version']}")

    # Brand/OEM differences
    brands = [tuple(sorted(a['brands'])) for a in analyses]
    if len(set(brands)) > 1:
        print(f"\n  ⚠ Detected OEM/brand differs:")
        for a in analyses:
            print(f"    {a['name']}: {', '.join(a['brands'])}")

    # Protection type differences
    for prot in sorted(all_prots):
        vals = [prot in a['protections'] for a in analyses]
        if len(set(vals)) > 1:
            has = [a['name'] for a, v in zip(analyses, vals) if v]
            hasnt = [a['name'] for a, v in zip(analyses, vals) if not v]
            print(f"\n  ⚠ Protection '{prot}':")
            print(f"    Active in:   {', '.join(has)}")
            print(f"    Inactive in: {', '.join(hasnt)}")

    # Security pattern differences
    for pname in sorted(all_patterns):
        vals = []
        for a in analyses:
            w = a['security_patterns'].get(pname, {'da1': False, 'da2': False})
            vals.append((w['da1'], w['da2']))
        if len(set(vals)) > 1:
            print(f"\n  ⚠ Security pattern '{pname}' differs:")
            for a in analyses:
                w = a['security_patterns'].get(pname, {'da1': False, 'da2': False})
                print(f"    {a['name']}: DA1={'Yes' if w['da1'] else 'No'}, "
                      f"DA2={'Yes' if w['da2'] else 'No'}")

    # Partition differences
    for p in sorted(all_parts):
        vals = []
        for a in analyses:
            present = p in a['partitions_da1'] or p in a['partitions_da2']
            vals.append(present)
        if len(set(vals)) > 1:
            present_in = [a['name'] for a, v in zip(analyses, vals) if v]
            absent_in = [a['name'] for a, v in zip(analyses, vals) if not v]
            print(f"\n  ⚠ Partition '{p}':")
            print(f"    Present in: {', '.join(present_in)}")
            print(f"    Absent in:  {', '.join(absent_in)}")

    # Error code count differences
    for code in sorted(all_codes):
        vals = []
        for a in analyses:
            c = a['error_codes'].get(code, {'da1': 0, 'da2': 0})
            vals.append((c['da1'], c['da2']))
        if len(set(vals)) > 1:
            print(f"\n  ⚠ Error code '{code}' count differs:")
            for a in analyses:
                c = a['error_codes'].get(code, {'da1': 0, 'da2': 0})
                print(f"    {a['name']}: DA1={c['da1']}, DA2={c['da2']}")

    print()


def main():
    if len(sys.argv) < 2:
        print("DA Analyzer Tool - Comprehensive DA binary analysis and comparison")
        print(f"\nUsage: {sys.argv[0]} <da_file1> [<da_file2> ...]")
        print(f"\nExample: {sys.argv[0]} DA_A15_lamu_FORBID_SIGNED.bin "
              "DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin")
        sys.exit(1)

    da_files = sys.argv[1:]
    analyses = []

    for f in da_files:
        if not os.path.exists(f):
            print(f"Error: File not found: {f}")
            sys.exit(1)
        print(f"Analyzing {os.path.basename(f)} ...")
        analyses.append(analyze_da(f))

    # Print individual analyses
    for a in analyses:
        print_single_analysis(a)

    # Print comparison if multiple files
    if len(analyses) > 1:
        print_comparison(analyses)


if __name__ == "__main__":
    main()
