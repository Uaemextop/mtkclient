# DA Agent Patching Example

This directory demonstrates the use of the `patch_da_agents.py` tool to patch MTK DA agents.

## Example: Patching Motorola Lamu DA Agents

### Original DA Agents
1. `DA_A15_lamu_FORBID_SIGNED.bin` - Working reference DA
2. `DA_SWSEC_2404_lamu_dl_forbidden.bin` - Needs patching
3. `DA_A15_lamu.bin` - Needs patching

### Command Used
```bash
cd /tmp/da_agents
# Download the DA agents
wget https://github.com/EduardoA3677/com_motorola_ccc_ota/releases/download/v1/DA_A15_lamu_FORBID_SIGNED.bin
wget https://github.com/EduardoA3677/com_motorola_ccc_ota/releases/download/v1/DA_SWSEC_2404_lamu_dl_forbidden.bin
wget https://github.com/EduardoA3677/com_motorola_ccc_ota/releases/download/v1/DA_A15_lamu.bin

# Patch the DA agents
python3 /path/to/mtkclient/Tools/patch_da_agents.py \
    DA_A15_lamu_FORBID_SIGNED.bin \
    DA_SWSEC_2404_lamu_dl_forbidden.bin \
    DA_A15_lamu.bin
```

### Results

#### DA_SWSEC_2404_lamu_dl_forbidden_patched.bin
- **SW Version**: 0x0000 (matches reference)
- **Anti-rollback patches applied**: 3 total
  - DA2: 2 patches at offsets 0x8dc4, 0x3d9f4
  - DA1: 1 patch at offset 0x2c744
- **Hash fixed**: DA2 hash updated in DA1 at offset 0x2decc (SHA256)
- **Verification**: ✓ No anti-rollback error codes (0xC0020053) remaining

#### DA_A15_lamu_patched.bin
- **SW Version**: 0x0000 (matches reference)
- **Anti-rollback patches applied**: 3 total
  - DA2: 2 patches at offsets 0x8dc4, 0x3d9f4
  - DA1: 1 patch at offset 0x2c744
- **Hash fixed**: DA2 hash updated in DA1 at offset 0x2decc (SHA256)
- **Verification**: ✓ No anti-rollback error codes (0xC0020053) remaining

### Notes
- The patched binaries are **not** included in this repository (they are in .gitignore)
- You must download the original DA agents and run the patching tool yourself
- Always test patched DAs in a safe environment before use
- Keep backups of original DA binaries

### Further Analysis
To analyze any DA binary:
```bash
python3 Tools/da_parser.py <da_binary>
```

### See Also
- `Tools/README_DA_PATCHING.md` - Complete documentation
- `Tools/patch_da_agents.py` - The patching tool
- `Tools/da_parser.py` - DA analysis tool
