# DA Agent Patching Tool

This document describes the DA agent patching tool (`patch_da_agents.py`) that can be used to patch MediaTek DA (Download Agent) binaries to disable anti-rollback protection and match versions between different DA agents.

## Overview

The `patch_da_agents.py` script is designed to:
1. Extract DA loader information from MTK DA binaries
2. Match SW version between a reference DA and target DAs
3. Disable anti-rollback protection by patching error code 0xC0020053
4. Fix hash values in DA1 to match the patched DA2

## Usage

```bash
python3 Tools/patch_da_agents.py <reference_da> <target_da1> [target_da2] ...
```

### Example

```bash
python3 Tools/patch_da_agents.py DA_A15_lamu_FORBID_SIGNED.bin DA_SWSEC_2404_lamu_dl_forbidden.bin DA_A15_lamu.bin
```

## What It Does

### 1. Version Matching
The script reads the SW version from the reference DA (the working one) and patches target DAs to match this version.

### 2. Anti-Rollback Patching
The script searches for and patches all occurrences of the anti-rollback error code `0xC0020053` in both DA1 and DA2 regions, replacing them with `0x00000000` to disable the anti-rollback check.

### 3. Hash Fixing
After patching DA2, the script recalculates the hash and updates it in DA1 to maintain integrity checks between the two loaders.

## DA Binary Structure

MTK DA binaries typically contain:
- **Region 0**: Boot/initialization code (address 0x50000000)
- **Region 1**: DA1 loader (address 0x200000)
- **Region 2**: DA2 loader (address 0x40000000)

Each region has:
- `m_buf`: Offset in the file where the region data starts
- `m_len`: Length of the region data
- `m_start_addr`: Load address in memory
- `m_sig_len`: Length of signature (typically 0x100 bytes)

## Analysis Tools

### da_parser.py
Use this tool to analyze DA binaries and extract information:

```bash
python3 Tools/da_parser.py <da_binary>
```

This will show:
- Hardware code, sub-code, version
- Software version
- Region information
- Hash check status
- Security patch status

## Example Output

When patching DA agents, you'll see output like:

```
Processing: DA_SWSEC_2404_lamu_dl_forbidden.bin
============================================================
Current DA Info:
  HW Code:      0x6768
  SW Version:   0x0000
  Regions:      3

Patching anti-rollback in DA2...
  Anti-rollback check patched at offset 0x8dc4
  Anti-rollback check patched at offset 0x3d9f4
  Total anti-rollback patches applied: 2

Patching anti-rollback in DA1...
  Anti-rollback check patched at offset 0x2c744
  Total anti-rollback patches applied: 1

Fixing DA2 hash in DA1...
  Hash fixed at offset 0x2decc using mode 2

✓ Patched binary saved to: DA_SWSEC_2404_lamu_dl_forbidden_patched.bin
```

## Verification

To verify that anti-rollback patches were applied successfully:

```python
python3 -c "
data = open('DA_patched.bin', 'rb').read()
error_code = int.to_bytes(0xC0020053, 4, 'little')
count = data.count(error_code)
print(f'Anti-rollback error code occurrences: {count}')
print('✓ Success!' if count == 0 else '✗ Still present')
"
```

## Technical Details

### Anti-Rollback Error Code
The anti-rollback protection in MTK DA agents uses error code `0xC0020053` to indicate a version mismatch. By replacing this with `0x00000000`, the check effectively becomes a success condition.

### Hash Algorithms
The script supports three hash modes:
- Mode 0: MD5
- Mode 1: SHA1
- Mode 2: SHA256 (most common in modern DAs)

The hash is typically stored in DA1 and is used to verify DA2 integrity.

### MMU MAP Marker
For V5 DA loaders, the hash is typically located 0x30 bytes before the "MMU MAP: VA" string marker in DA1.

## Safety Notes

- Always keep backups of original DA binaries
- Test patched DAs in a safe environment before production use
- Patched binaries are saved with `_patched.bin` suffix
- The original files are never modified

## Related Tools

- `da_parser.py`: Analyze DA binary structure
- `patch_legacy.py`: Legacy DA patching functions
- `patch_preloader.py`: Preloader patching utilities

## Author

This tool uses functions and structures from the mtkclient library by B.Kerler.
