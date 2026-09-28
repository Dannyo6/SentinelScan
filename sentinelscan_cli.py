#!/usr/bin/env python3
"""
SentinelScan - Principal Systems Security & Reverse Engineering Forensic CLI
Production-Grade PE32/PE32+ Binary Header, Section Entropy, and Heuristic Inspector.

Usage:
    python sentinelscan_cli.py --target <path_to_binary> [--verbose] [--export-json <output.json>]
"""

import sys
import os
import math
import struct
import hashlib
import json
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

# Shannon Entropy formula: H(X) = -sum( p(x) * log2(p(x)) )
def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    log2 = math.log(2)
    for count in frequencies:
        if count > 0:
            p = count / length
            entropy -= p * (math.log(p) / log2)
    return round(entropy, 4)


def get_entropy_classification(entropy: float) -> Dict[str, str]:
    if entropy < 5.5:
        return {
            "level": "Benign Code",
            "threshold": "0.0 - 5.5",
            "description": "Standard compiled executable code or plain data assets."
        }
    elif entropy < 6.8:
        return {
            "level": "Lightweight Assets",
            "threshold": "5.5 - 6.8",
            "description": "Compressed resources, string tables, or high-density constants."
        }
    elif entropy < 7.2:
        return {
            "level": "Elevated Density",
            "threshold": "6.8 - 7.19",
            "description": "Heavily compressed or obfuscated section bytes."
        }
    else:
        return {
            "level": "Packed / Encrypted",
            "threshold": ">= 7.2",
            "description": "Near-maximal randomness characteristic of polymorphic packers or cryptographic payloads."
        }


KNOWN_PACKER_SECTIONS = [
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "PEC2", ".mpress",
    ".nsp", ".themida", ".vmp", "FSG!", "pecompact", ".petite", ".enigma"
]

MITRE_API_CLUSTERS = {
    "process_hollowing": {
        "tactic": "T1055 - Process Injection (Process Hollowing)",
        "severity": "CRITICAL",
        "apis": [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
            "SetThreadContext", "ResumeThread"
        ],
        "description": "APIs used to carve hollow process memory, write unmapped payloads, and spawn hijacked threads."
    },
    "dynamic_resolution": {
        "tactic": "T1027.007 - Dynamic API Resolution & Evasion",
        "severity": "HIGH",
        "apis": [
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"
        ],
        "description": "Obfuscates static IAT dependencies by resolving malicious Windows functions at runtime."
    },
    "keylogging": {
        "tactic": "T1056.001 - Input Capture (Keylogging / Hooking)",
        "severity": "HIGH",
        "apis": [
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState"
        ],
        "description": "Intercepts global desktop messages and hardware keystroke states."
    },
    "anti_analysis": {
        "tactic": "T1497 - Virtualization/Sandbox Evasion",
        "severity": "MEDIUM",
        "apis": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter"
        ],
        "description": "Detects hypervisors, sandboxes, and attached debuggers before executing real payload."
    },
    "persistence": {
        "tactic": "T1547 - Boot or Logon Autostart Execution",
        "severity": "MEDIUM",
        "apis": [
            "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW", "AdjustTokenPrivileges"
        ],
        "description": "Installs persistence via registry autorun or service registration."
    }
}


def rva_to_offset(rva: int, sections: List[Dict[str, Any]]) -> Optional[int]:
    for s in sections:
        va = s["virtualAddressInt"]
        vsize = s["virtualSize"]
        raw_ptr = s["pointerToRawData"]
        if va <= rva < va + max(vsize, s["sizeOfRawData"]):
            return (rva - va) + raw_ptr
    return None


def read_null_terminated_ascii(data: bytes, offset: int, max_len: int = 128) -> str:
    end = offset
    limit = min(len(data), offset + max_len)
    while end < limit and data[end] != 0:
        end += 1
    try:
        return data[offset:end].decode("ascii", errors="replace")
    except Exception:
        return ""


class PEInspector:
    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, "rb") as f:
            self.raw_data = f.read()
        self.size = len(self.raw_data)

    def compute_hashes(self) -> Dict[str, str]:
        return {
            "sha256": hashlib.sha256(self.raw_data).hexdigest(),
            "sha1": hashlib.sha1(self.raw_data).hexdigest(),
            "md5": hashlib.md5(self.raw_data).hexdigest()
        }

    def inspect(self) -> Dict[str, Any]:
        if self.size < 64:
            raise ValueError(f"Target '{self.file_path}' is too small ({self.size} bytes) for a valid PE DOS header.")

        # 1. DOS Header Validation
        e_magic = struct.unpack_from("<H", self.raw_data, 0)[0]
        if e_magic != 0x5A4D: # 'MZ'
            raise ValueError(f"Invalid DOS magic signature 0x{e_magic:04X} (expected 0x5A4D 'MZ'). Not a valid PE executable.")

        e_lfanew = struct.unpack_from("<I", self.raw_data, 0x3C)[0]
        if e_lfanew + 24 > self.size:
            raise ValueError(f"e_lfanew (0x{e_lfanew:X}) points outside binary boundaries.")

        # 2. PE Signature Validation
        pe_sig = struct.unpack_from("<I", self.raw_data, e_lfanew)[0]
        if pe_sig != 0x00004550: # 'PE\0\0'
            raise ValueError(f"Invalid PE signature 0x{pe_sig:08X} (expected 0x00004550 'PE\\0\\0').")

        # 3. COFF File Header
        coff_offset = e_lfanew + 4
        machine, num_sections, time_date_stamp, ptr_symbols, num_symbols, size_opt_header, characteristics = struct.unpack_from(
            "<HHIIIHH", self.raw_data, coff_offset
        )

        machine_map = {
            0x014C: "x86 (PE32 / i386)",
            0x8664: "x64 (PE32+ / AMD64)",
            0x0200: "Intel Itanium (IA-64)",
            0xAA64: "ARM64 (Little Endian)"
        }
        architecture = machine_map.get(machine, f"Unknown (0x{machine:04X})")

        try:
            dt = datetime.fromtimestamp(time_date_stamp, tz=timezone.utc)
            compile_timestamp = dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
        except Exception:
            compile_timestamp = "Invalid/Epoch"

        # 4. Optional Header
        opt_offset = coff_offset + 20
        if size_opt_header == 0 or opt_offset + size_opt_header > self.size:
            raise ValueError("Optional header missing or corrupt.")

        opt_magic = struct.unpack_from("<H", self.raw_data, opt_offset)[0]
        is_64bit = (opt_magic == 0x020B)
        format_name = "PE32+ (64-bit)" if is_64bit else ("PE32 (32-bit)" if opt_magic == 0x010B else f"0x{opt_magic:04X}")

        entry_point = struct.unpack_from("<I", self.raw_data, opt_offset + 16)[0]

        if is_64bit:
            image_base = struct.unpack_from("<Q", self.raw_data, opt_offset + 24)[0]
            section_alignment = struct.unpack_from("<I", self.raw_data, opt_offset + 32)[0]
            file_alignment = struct.unpack_from("<I", self.raw_data, opt_offset + 36)[0]
            size_of_image = struct.unpack_from("<I", self.raw_data, opt_offset + 56)[0]
            size_of_headers = struct.unpack_from("<I", self.raw_data, opt_offset + 60)[0]
            subsystem = struct.unpack_from("<H", self.raw_data, opt_offset + 68)[0]
            dll_characteristics = struct.unpack_from("<H", self.raw_data, opt_offset + 70)[0]
            num_rva_and_sizes = struct.unpack_from("<I", self.raw_data, opt_offset + 108)[0]
            data_dir_offset = opt_offset + 112
        else:
            image_base = struct.unpack_from("<I", self.raw_data, opt_offset + 28)[0]
            section_alignment = struct.unpack_from("<I", self.raw_data, opt_offset + 32)[0]
            file_alignment = struct.unpack_from("<I", self.raw_data, opt_offset + 36)[0]
            size_of_image = struct.unpack_from("<I", self.raw_data, opt_offset + 56)[0]
            size_of_headers = struct.unpack_from("<I", self.raw_data, opt_offset + 60)[0]
            subsystem = struct.unpack_from("<H", self.raw_data, opt_offset + 68)[0]
            dll_characteristics = struct.unpack_from("<H", self.raw_data, opt_offset + 70)[0]
            num_rva_and_sizes = struct.unpack_from("<I", self.raw_data, opt_offset + 92)[0]
            data_dir_offset = opt_offset + 96

        subsystem_map = {
            1: "Native / Device Driver",
            2: "Windows GUI",
            3: "Windows CUI (Console)",
            7: "POSIX CUI"
        }
        subsystem_name = subsystem_map.get(subsystem, f"Subsystem {subsystem}")

        security_mitigations = {
            "aslr": bool(dll_characteristics & 0x0040),
            "dep_nx": bool(dll_characteristics & 0x0100),
            "no_seh": bool(dll_characteristics & 0x0400),
            "cfg": bool(dll_characteristics & 0x4000),
            "high_entropy_va": bool(dll_characteristics & 0x0020)
        }

        # Data directory imports
        import_dir_rva = 0
        import_dir_size = 0
        if num_rva_and_sizes > 1 and data_dir_offset + 16 <= opt_offset + size_opt_header:
            import_dir_rva, import_dir_size = struct.unpack_from("<II", self.raw_data, data_dir_offset + 8)

        # 5. Section Headers Traversal
        sec_table_offset = opt_offset + size_opt_header
        sections = []
        highest_entropy = 0.0
        packed_sections = []
        wx_sections = []

        for i in range(num_sections):
            s_offset = sec_table_offset + (i * 40)
            if s_offset + 40 > self.size:
                break

            name_raw = self.raw_data[s_offset:s_offset + 8]
            sec_name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace")

            virtual_size, virtual_address, size_raw_data, ptr_raw_data, _, _, _, _, sec_characteristics = struct.unpack_from(
                "<IIIIIIHHI", self.raw_data, s_offset + 8
            )

            is_readable = bool(sec_characteristics & 0x40000000)
            is_writable = bool(sec_characteristics & 0x80000000)
            is_executable = bool(sec_characteristics & 0x20000000)
            is_wx = is_writable and is_executable

            # Shannon entropy calculation
            sec_entropy = 0.0
            if ptr_raw_data < self.size and size_raw_data > 0:
                raw_bytes = self.raw_data[ptr_raw_data:ptr_raw_data + min(size_raw_data, self.size - ptr_raw_data)]
                sec_entropy = calculate_shannon_entropy(raw_bytes)

            highest_entropy = max(highest_entropy, sec_entropy)

            is_known_packer = any(p.lower() in sec_name.lower() for p in KNOWN_PACKER_SECTIONS)
            if is_known_packer:
                packed_sections.append(sec_name)
            if is_wx:
                wx_sections.append(sec_name)

            sections.append({
                "name": sec_name,
                "virtualSize": virtual_size,
                "virtualAddress": f"0x{virtual_address:08X}",
                "virtualAddressInt": virtual_address,
                "sizeOfRawData": size_raw_data,
                "pointerToRawData": ptr_raw_data,
                "rawPointerHex": f"0x{ptr_raw_data:08X}",
                "entropy": sec_entropy,
                "classification": get_entropy_classification(sec_entropy),
                "isReadable": is_readable,
                "isWritable": is_writable,
                "isExecutable": is_executable,
                "isWX": is_wx,
                "isPackedName": is_known_packer
            })

        # 6. Import Table (IAT) Parsing
        imported_modules = []
        found_apis = set()

        if import_dir_rva > 0 and import_dir_size > 0:
            import_offset = rva_to_offset(import_dir_rva, sections)
            if import_offset is not None and import_offset < self.size:
                for idx in range(64):
                    desc_offset = import_offset + (idx * 20)
                    if desc_offset + 20 > self.size:
                        break

                    orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", self.raw_data, desc_offset)
                    if name_rva == 0 and first_thunk == 0:
                        break

                    name_offset = rva_to_offset(name_rva, sections)
                    mod_name = read_null_terminated_ascii(self.raw_data, name_offset) if name_offset else "UNKNOWN.DLL"

                    thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                    thunk_offset = rva_to_offset(thunk_rva, sections)
                    apis = []

                    if thunk_offset is not None:
                        step = 8 if is_64bit else 4
                        for k in range(128):
                            entry_off = thunk_offset + (k * step)
                            if entry_off + step > self.size:
                                break

                            val = struct.unpack_from("<Q" if is_64bit else "<I", self.raw_data, entry_off)[0]
                            if val == 0:
                                break

                            ord_mask = 0x8000000000000000 if is_64bit else 0x80000000
                            if not (val & ord_mask):
                                hint_rva = val & 0x7FFFFFFF
                                hint_offset = rva_to_offset(hint_rva + 2, sections)
                                if hint_offset:
                                    api_str = read_null_terminated_ascii(self.raw_data, hint_offset)
                                    if api_str:
                                        apis.append(api_str)
                                        found_apis.add(api_str)

                    imported_modules.append({
                        "module": mod_name,
                        "apiCount": len(apis),
                        "apis": apis[:30]
                    })

        # 7. MITRE ATT&CK Cross-Referencing & Scoring
        threat_score = 0
        detected_threats = []

        for key, sig in MITRE_API_CLUSTERS.items():
            matched = [api for api in sig["apis"] if api in found_apis]
            if matched:
                weight = 35 if sig["severity"] == "CRITICAL" else (25 if sig["severity"] == "HIGH" else 15)
                threat_score += weight
                detected_threats.append({
                    "id": key,
                    "tactic": sig["tactic"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "matchedApis": matched
                })

        if highest_entropy >= 7.2:
            threat_score += 30
            detected_threats.append({
                "id": "high_entropy",
                "tactic": "T1027 - Obfuscated Files: High Entropy Section",
                "severity": "HIGH",
                "description": f"Section entropy ({highest_entropy:.4f}) exceeds 7.2 baseline, indicating packing or encryption.",
                "matchedApis": []
            })

        if packed_sections:
            threat_score += 25
            detected_threats.append({
                "id": "packed_section",
                "tactic": "T1027.002 - Software Packing (Known Packer Signature)",
                "severity": "HIGH",
                "description": f"Identified known packer section names: {', '.join(packed_sections)}",
                "matchedApis": []
            })

        if wx_sections:
            threat_score += 25
            detected_threats.append({
                "id": "wx_violation",
                "tactic": "T1055 - Self-Modifying Code / W^X Memory Violation",
                "severity": "HIGH",
                "description": f"Section contains simultaneous WRITE and EXECUTE flags: {', '.join(wx_sections)}",
                "matchedApis": []
            })

        if not security_mitigations["aslr"] or not security_mitigations["dep_nx"]:
            threat_score += 10

        threat_score = min(100, threat_score)

        if threat_score > 60:
            verdict = "MALICIOUS / HIGH RISK"
            verdict_color = "rose"
        elif threat_score > 25:
            verdict = "SUSPICIOUS"
            verdict_color = "amber"
        else:
            verdict = "BENIGN / LOW RISK"
            verdict_color = "emerald"

        total_binary_entropy = calculate_shannon_entropy(self.raw_data)

        return {
            "meta": {
                "fileName": os.path.basename(self.file_path),
                "fileSize": self.size,
                "architecture": architecture,
                "formatName": format_name,
                "is64Bit": is_64bit,
                "compileTimestamp": compile_timestamp,
                "subsystem": subsystem_name
            },
            "headers": {
                "dos": {
                    "e_magic": f"0x{e_magic:04X}",
                    "e_lfanew": f"0x{e_lfanew:04X}"
                },
                "fileHeader": {
                    "machine": f"0x{machine:04X}",
                    "numberOfSections": num_sections,
                    "timeDateStamp": time_date_stamp,
                    "characteristics": f"0x{characteristics:04X}"
                },
                "optionalHeader": {
                    "magic": f"0x{opt_magic:04X}",
                    "addressOfEntryPoint": f"0x{entry_point:08X}",
                    "imageBase": f"0x{image_base:016X}" if is_64bit else f"0x{image_base:08X}",
                    "sectionAlignment": section_alignment,
                    "fileAlignment": file_alignment,
                    "sizeOfImage": size_of_image,
                    "sizeOfHeaders": size_of_headers,
                    "subsystem": subsystem,
                    "dllCharacteristics": f"0x{dll_characteristics:04X}"
                }
            },
            "mitigations": security_mitigations,
            "entropy": {
                "overall": total_binary_entropy,
                "highest": highest_entropy,
                "classification": get_entropy_classification(highest_entropy)
            },
            "sections": sections,
            "imports": imported_modules,
            "heuristics": {
                "score": threat_score,
                "verdict": verdict,
                "verdictColor": verdict_color,
                "detectedThreats": detected_threats,
                "packedSections": packed_sections,
                "wxSections": wx_sections
            }
        }


def print_banner():
    print(r"""
========================================================================
   ____ ____ _  _ ___ _ _  _ ____ _    ____ ____ ____ _  _ 
   [__  |___ |\ |  |  | |\ | |___ |    [__  |    |__| |\ | 
   ___] |___ | \|  |  | | \| |___ |___ ___] |___ |  | | \| 
   Autonomous Systems Security & Static Binary Forensic Engine v2.4
========================================================================
""")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelScan: Static PE32/PE32+ Binary Header, Section Entropy & Heuristic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", "-t", required=True, help="Absolute or relative path to target PE binary (.exe, .dll, .sys)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose forensic telemetry output in terminal")
    parser.add_argument("--export-json", "-o", help="Export full structured forensic telemetry to JSON file")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[-] Error: Target file '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print_banner()
    print(f"[*] Ingesting binary target: {args.target}")

    try:
        inspector = PEInspector(args.target)
        hashes = inspector.compute_hashes()
        report = inspector.inspect()

        full_telemetry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "engine": "SentinelScan v2.4 (Python CLI Forensic Core)",
            "hashes": hashes,
            **report
        }

        # Print Executive Summary
        meta = report["meta"]
        heuristics = report["heuristics"]
        entropy = report["entropy"]

        print(f"[*] Hashes:")
        print(f"    SHA-256 : {hashes['sha256']}")
        print(f"    SHA-1   : {hashes['sha1']}")
        print(f"    MD5     : {hashes['md5']}")
        print(f"[*] Architecture : {meta['architecture']} ({meta['formatName']})")
        print(f"[*] Subsystem    : {meta['subsystem']}")
        print(f"[*] Compiled     : {meta['compileTimestamp']}")
        print(f"[*] Peak Entropy : {entropy['highest']:.4f} / 8.0000 ({entropy['classification']['level']})")
        print("-" * 72)
        print(f"[*] HEURISTIC RISK SCORE : {heuristics['score']} / 100")
        print(f"[*] VERDICT              : {heuristics['verdict']}")
        print("-" * 72)

        if heuristics["detectedThreats"]:
            print("[!] Triggered Threat Detections:")
            for threat in heuristics["detectedThreats"]:
                print(f"    [{threat['severity']}] {threat['tactic']}")
                print(f"        -> {threat['description']}")
                if threat["matchedApis"]:
                    print(f"        -> Matched APIs: {', '.join(threat['matchedApis'])}")
            print("-" * 72)

        if args.verbose:
            print("[+] Section Table & Entropy Breakdown:")
            print(f"    {'Name':<10} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12} {'Entropy':<10} {'Flags'}")
            for sec in report["sections"]:
                flags = ("R" if sec["isReadable"] else "-") + ("W" if sec["isWritable"] else "-") + ("X" if sec["isExecutable"] else "-")
                if sec["isWX"]:
                    flags += " [W^X!]"
                if sec["isPackedName"]:
                    flags += " [PACKED]"
                print(f"    {sec['name']:<10} {sec['virtualAddress']:<12} {sec['virtualSize']:<12} {sec['sizeOfRawData']:<12} {sec['entropy']:<10.4f} {flags}")
            print("-" * 72)

            if report["imports"]:
                print("[+] Import Address Table (IAT) Modules:")
                for imp in report["imports"]:
                    print(f"    - {imp['module']} ({imp['apiCount']} symbols): {', '.join(imp['apis'][:6])}...")
            print("-" * 72)

        if args.export_json:
            with open(args.export_json, "w", encoding="utf-8") as f:
                json.dump(full_telemetry, f, indent=2)
            print(f"[+] Structured forensic telemetry exported to: {args.export_json}")

        print("[+] Forensic analysis complete.\n")

    except Exception as e:
        print(f"[-] Forensic Analysis Exception: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
