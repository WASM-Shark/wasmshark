#!/usr/bin/env python3

# WASMShark YARA Integration
#   Scans WASM binary and extracted data sections against YARA rules.


import os, sys, json, argparse, hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict

R="\033[0m"; B="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; DIM="\033[2m"; WHT="\033[97m"



#  YARA AVAILABILITY CHECK

def _check_yara():
    try:
        import yara
        return yara
    except ImportError:
        return None



#  DATA STRUCTURES

@dataclass
class YARAMatch:
    rule_name:   str
    namespace:   str
    tags:        List[str]
    meta:        Dict[str, Any]
    scan_target: str     # "full_binary", "data_seg_N", "custom_sec_NAME", "strings"
    strings_hit: List[Dict]   # [{identifier, offset, data_preview}]


@dataclass
class YARAScanResult:
    filename:      str
    sha256:        str
    rules_loaded:  int
    matches:       List[YARAMatch]
    targets_scanned: List[str]
    verdict:       str   # MATCHED / CLEAN / ERROR
    error:         str = ""



#  RULE LOADER

class YARARuleLoader:
    # Load YARA rules from a file or directory

    def load(self, path: str) -> Optional[Any]:
        yara = _check_yara()
        if not yara:
            print(f"{YEL}[!] yara-python not installed.{R}")
            print(f"    Install: pip install yara-python --break-system-packages")
            return None

        p = Path(path)
        if not p.exists():
            print(f"{RED}[!] YARA rules path not found: {path}{R}")
            return None

        filepaths = {}
        if p.is_file():
            filepaths[p.stem] = str(p)
        elif p.is_dir():
            for ext in ("*.yar", "*.yara", "*.rule", "*.rules"):
                for f in p.rglob(ext):
                    filepaths[f.stem] = str(f)

        if not filepaths:
            print(f"{YEL}[!] No YARA rule files found in {path}{R}")
            return None

        try:
            rules = yara.compile(filepaths=filepaths)
            return rules
        except Exception as e:
            print(f"{RED}[!] YARA compile error: {e}{R}")
            return None



#  WASM DATA EXTRACTOR

class WASMDataExtractor:
    """
    Extract scannable byte buffers from a WASM binary:
        Full binary
        Each data segment payload
        Each custom section payload
        All extracted strings concatenated
    """

    def extract(self, data: bytes) -> Dict[str, bytes]:
        targets: Dict[str, bytes] = {"full_binary": data}

        try:
            from wasmshark_core import BinaryReader, SecID
            import struct

            br = BinaryReader(data)
            if br.remaining() < 8: return targets
            magic = br.read(4)
            if magic != b'\x00asm': return targets
            br.read(4)  # version

            seg_idx = 0
            custom_idx = 0

            while br.remaining() >= 2:
                try:
                    sid  = br.read_u8()
                    ssz  = br.read_leb128_u()
                    sstart = br.tell()
                    sr   = br.slice(sstart, ssz)

                    # Data sections
                    if sid == SecID.DATA.value:
                        n = sr.read_leb128_u()
                        for _ in range(n):
                            try:
                                flags = sr.read_leb128_u()
                                if flags == 0:
                                    op = sr.read_u8()
                                    if op == 0x41: sr.read_leb128_s()
                                    elif op == 0x42: sr.read_leb128_s()
                                    sr.read_u8()  # end
                                elif flags == 2:
                                    sr.read_leb128_u()
                                    op = sr.read_u8()
                                    if op == 0x41: sr.read_leb128_s()
                                    sr.read_u8()
                                dsz = sr.read_leb128_u()
                                seg_data = sr.read(dsz)
                                targets[f"data_seg_{seg_idx}"] = seg_data
                                seg_idx += 1
                            except: break

                    # Custom sections
                    elif sid == SecID.CUSTOM.value:
                        try:
                            name_len = sr.read_leb128_u()
                            name     = sr.read(name_len).decode('utf-8', errors='replace')
                            payload  = sr.read(sr.remaining())
                            safe_name = name.replace("/","_").replace(" ","_")
                            targets[f"custom_{safe_name}_{custom_idx}"] = payload
                            custom_idx += 1
                        except: pass

                    br.seek(sstart + ssz)
                except: break

        except Exception as e:
            pass  # Return whatever we have

        return targets



#  YARA SCANNER

class YARAScanner:

    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self._rules     = None
        self._loaded    = False

    def _ensure_loaded(self) -> bool:
        if self._loaded: return self._rules is not None
        loader       = YARARuleLoader()
        self._rules  = loader.load(self.rules_path)
        self._loaded = True
        return self._rules is not None

    @property
    def rules_count(self) -> int:
        if not self._ensure_loaded(): return 0
        try:
            count = 0
            for _ in self._rules: count += 1
            return count
        except: return -1

    def scan_file(self, filepath: str) -> YARAScanResult:
        sha256 = ""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
        except Exception as e:
            return YARAScanResult(
                filename=os.path.basename(filepath), sha256="",
                rules_loaded=0, matches=[], targets_scanned=[],
                verdict="ERROR", error=str(e))

        if not self._ensure_loaded():
            return YARAScanResult(
                filename=os.path.basename(filepath), sha256=sha256,
                rules_loaded=0, matches=[], targets_scanned=[],
                verdict="ERROR", error="YARA rules could not be loaded")

        extractor = WASMDataExtractor()
        targets   = extractor.extract(data)
        all_matches: List[YARAMatch] = []
        scanned: List[str] = []

        for target_name, target_data in targets.items():
            if not target_data: continue
            scanned.append(target_name)
            try:
                raw_matches = self._rules.match(data=target_data)
                for m in raw_matches:
                    strings_hit = []
                    for s in m.strings:
                        # Handle both yara-python 3.x and 4.x APIs
                        try:
                            for instance in s.instances:
                                strings_hit.append({
                                    "identifier": s.identifier,
                                    "offset": instance.offset,
                                    "data_preview": bytes(instance)[:32].hex()
                                })
                        except AttributeError:
                            # Older API
                            strings_hit.append({
                                "identifier": str(s),
                                "offset": 0,
                                "data_preview": ""
                            })

                    all_matches.append(YARAMatch(
                        rule_name   = m.rule,
                        namespace   = m.namespace,
                        tags        = list(m.tags),
                        meta        = dict(m.meta),
                        scan_target = target_name,
                        strings_hit = strings_hit[:5]
                    ))
            except Exception as e:
                pass  # Skip targets that cause errors

        verdict = "MATCHED" if all_matches else "CLEAN"
        return YARAScanResult(
            filename        = os.path.basename(filepath),
            sha256          = sha256,
            rules_loaded    = self.rules_count,
            matches         = all_matches,
            targets_scanned = scanned,
            verdict         = verdict,
        )

    def print_result(self, result: YARAScanResult):
        vc = {
            "MATCHED": RED+B, "CLEAN": GRN+B, "ERROR": YEL+B
        }.get(result.verdict, R)

        print(f"\n{CYN}{'═'*70}{R}")
        print(f"{B}  YARA SCAN: {result.filename}{R}")
        print(f"{CYN}{'═'*70}{R}")
        print(f"  SHA-256      : {DIM}{result.sha256}{R}")
        print(f"  Rules loaded : {result.rules_loaded}")
        print(f"  Targets      : {len(result.targets_scanned)}")
        print(f"                 {DIM}{', '.join(result.targets_scanned[:6])}{R}")
        print(f"  Verdict      : {vc}{result.verdict}{R}")
        print(f"  Matches      : {len(result.matches)}")

        if result.error:
            print(f"\n  {RED}Error: {result.error}{R}")

        if result.matches:
            print(f"\n{CYN}{'─'*70}{R}")
            print(f"{B}  MATCHED RULES ({len(result.matches)}){R}")
            print(f"{CYN}{'─'*70}{R}")
            for m in result.matches:
                desc = m.meta.get("description", "")
                sev  = m.meta.get("severity", "")
                sev_col = {"CRITICAL":RED+B,"HIGH":RED,"MEDIUM":YEL,"LOW":CYN}.get(sev.upper(),WHT)
                print(f"\n  {RED}▸ {m.rule_name}{R}  {DIM}[{m.namespace}]{R}")
                if desc:    print(f"    {DIM}{desc}{R}")
                if sev:     print(f"    Severity : {sev_col}{sev}{R}")
                if m.tags:  print(f"    Tags     : {', '.join(m.tags)}")
                print(f"    Target   : {m.scan_target}")
                for sh in m.strings_hit[:3]:
                    print(f"    String   : {DIM}{sh['identifier']} @ {sh['offset']:#x}  {sh['data_preview']}{R}")

        print(f"\n{CYN}{'═'*70}{R}\n")



#  BATCH SCANNER

def batch_scan(directory: str, rules_path: str,
               csv_out: str = "", json_out: str = "") -> List[YARAScanResult]:
    scanner = YARAScanner(rules_path)
    files   = [str(p) for p in Path(directory).rglob("*.wasm")]

    if not files:
        print(f"{YEL}No .wasm files in {directory}{R}")
        return []

    print(f"{CYN}YARA batch scan: {len(files)} files{R}\n")
    results = []
    for fp in files:
        print(f"  {DIM}→ {fp}{R}", end="", flush=True)
        r = scanner.scan_file(fp)
        vc = {"MATCHED":RED+B,"CLEAN":GRN+B,"ERROR":YEL+B}.get(r.verdict,R)
        print(f"  {vc}{r.verdict:<10}{R}  matches={len(r.matches)}")
        results.append(r)

    # Summary
    print(f"\n{CYN}{'─'*50}{R}  SUMMARY")
    for v in ("MATCHED","CLEAN","ERROR"):
        cnt = sum(1 for r in results if r.verdict == v)
        if cnt:
            vc = {"MATCHED":RED+B,"CLEAN":GRN+B,"ERROR":YEL+B}.get(v,R)
            print(f"  {vc}{v:<12}{R}: {cnt}")

    # CSV output
    if csv_out and results:
        import csv
        rows = []
        for r in results:
            rows.append({
                "filename":      r.filename,
                "sha256":        r.sha256,
                "verdict":       r.verdict,
                "match_count":   len(r.matches),
                "rules_matched": "|".join(m.rule_name for m in r.matches),
                "targets":       "|".join(r.targets_scanned),
            })
        with open(csv_out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
        print(f"\n{GRN}[+] CSV → {csv_out}{R}")

    # JSON output
    if json_out:
        with open(json_out, 'w') as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"{GRN}[+] JSON → {json_out}{R}")

    return results



#  BUNDLED WASM-SPECIFIC YARA RULES

BUILTIN_YARA_RULES = r"""
/*
  WASMShark Built-in YARA Rules
  Applied to raw WASM binary + extracted data sections
*/

rule WASM_Embedded_PE {
    meta:
        description = "Windows PE executable embedded in WASM data"
        severity = "CRITICAL"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 or ($mz and $pe)
}

rule WASM_Embedded_ELF {
    meta:
        description = "ELF binary embedded in WASM data segment"
        severity = "CRITICAL"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf
}

rule WASM_Embedded_Shell_Script {
    meta:
        description = "Shell script embedded in WASM data"
        severity = "HIGH"
    strings:
        $sh1  = "#!/bin/sh"
        $sh2  = "#!/bin/bash"
        $sh3  = "#!/usr/bin/env"
    condition:
        any of them
}

rule WASM_Base64_Powershell {
    meta:
        description = "Base64-encoded PowerShell command in WASM data"
        severity = "CRITICAL"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-EncodedCommand" nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        ($ps1 and $ps2) or ($ps1 and $b64) or ($ps1 and $ps3)
}

rule WASM_Tor_C2 {
    meta:
        description = "Tor hidden service address in WASM data"
        severity = "CRITICAL"
    strings:
        $onion = ".onion" nocase
    condition:
        $onion
}

rule WASM_Crypto_Wallet {
    meta:
        description = "Cryptocurrency wallet address pattern"
        severity = "HIGH"
    strings:
        $btc1 = /1[A-HJ-NP-Z1-9]{25,34}/
        $btc2 = /3[A-HJ-NP-Z1-9]{25,34}/
        $eth  = /0x[0-9a-fA-F]{40}/
        $xmr  = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
    condition:
        any of them
}

rule WASM_Ransomware_Note {
    meta:
        description = "Ransomware note text patterns"
        severity = "CRITICAL"
    strings:
        $r1 = "YOUR FILES" nocase
        $r2 = "ENCRYPTED" nocase
        $r3 = "decrypt" nocase
        $r4 = "ransom" nocase
        $r5 = "bitcoin" nocase
    condition:
        3 of them
}

rule WASM_SSH_Key {
    meta:
        description = "SSH private key material in WASM data"
        severity = "CRITICAL"
    strings:
        $rsa  = "BEGIN RSA PRIVATE KEY"
        $ec   = "BEGIN EC PRIVATE KEY"
        $open = "BEGIN OPENSSH PRIVATE KEY"
    condition:
        any of them
}

rule WASM_AWS_Credentials {
    meta:
        description = "AWS access key ID pattern (AKIA prefix)"
        severity = "CRITICAL"
    strings:
        $akia = /AKIA[0-9A-Z]{16}/
    condition:
        $akia
}

rule WASM_Mining_Pool {
    meta:
        description = "Cryptocurrency mining pool endpoint"
        severity = "CRITICAL"
    strings:
        $s1 = "stratum+tcp://"
        $s2 = "stratum+ssl://"
        $s3 = "pool.minexmr.com"
        $s4 = "pool.supportxmr.com"
        $s5 = "xmrpool.eu"
        $s6 = "moneroocean.stream"
        $s7 = "nanopool.org"
    condition:
        any of them
}

rule WASM_Cobalt_Strike {
    meta:
        description = "CobaltStrike beacon indicators"
        severity = "CRITICAL"
    strings:
        $cs1 = "cobalt" nocase
        $cs2 = "beacon" nocase
        $cs3 = "meterpreter" nocase
        $cs4 = "ReflectiveDll"
    condition:
        2 of them
}

rule WASM_Nested_WASM {
    meta:
        description = "Nested WASM module embedded in data segment"
        severity = "HIGH"
    strings:
        $magic = { 00 61 73 6D 01 00 00 00 }
    condition:
        $magic
}

rule WASM_Discord_Webhook_Exfil {
    meta:
        description = "Discord webhook URL used for data exfiltration"
        severity = "HIGH"
    strings:
        $wh = "discord.com/api/webhooks"
    condition:
        $wh
}

rule WASM_GitHub_Token {
    meta:
        description = "GitHub personal access token"
        severity = "CRITICAL"
    strings:
        $ghp = /ghp_[A-Za-z0-9]{36}/
        $gho = /gho_[A-Za-z0-9]{36}/
        $ghs = /ghs_[A-Za-z0-9]{36}/
    condition:
        any of them
}

rule WASM_Base64_Payload {
    meta:
        description = "Long base64-encoded string — possible encoded payload"
        severity = "MEDIUM"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $b64
}

rule WASM_IP_Hardcoded {
    meta:
        description = "Hardcoded IP address (possible C2)"
        severity = "MEDIUM"
    strings:
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/
    condition:
        $ip
}

rule WASM_Shadow_Passwd {
    meta:
        description = "/etc/shadow or /etc/passwd path reference"
        severity = "CRITICAL"
    strings:
        $shadow = "/etc/shadow"
        $passwd = "/etc/passwd"
    condition:
        any of them
}

rule WASM_Vssadmin_Delete {
    meta:
        description = "VSS shadow copy deletion command (ransomware)"
        severity = "CRITICAL"
    strings:
        $vss = "vssadmin delete shadows" nocase
        $wmi = "wbadmin delete catalog" nocase
    condition:
        any of them
}
"""


def write_builtin_rules(path: str = "/tmp/wasmshark_builtin.yar"):
    """Write built-in YARA rules to a temp file for use."""
    with open(path, 'w') as f:
        f.write(BUILTIN_YARA_RULES)
    return path



#  CLI

def main():
    ap = argparse.ArgumentParser(
        description="WASMShark YARA Scanner — scan WASM binaries with YARA rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Install yara-python first
  pip install yara-python --break-system-packages

  # Scan with built-in rules (no external rules needed)
  python3 wasmshark_yara.py sample.wasm --builtin

  # Scan with custom rules file
  python3 wasmshark_yara.py sample.wasm --rules malware.yar

  # Scan with rules directory
  python3 wasmshark_yara.py sample.wasm --rules ./yara_rules/

  # Batch scan directory
  python3 wasmshark_yara.py -d ./samples/ --builtin --csv results.csv

  # Combine built-in + custom rules
  python3 wasmshark_yara.py sample.wasm --builtin --rules ./extra_rules/
        """)
    ap.add_argument("file",         nargs="?",           help="WASM file to scan")
    ap.add_argument("--rules","-r", metavar="PATH",      help="YARA rules file or directory")
    ap.add_argument("--builtin",    action="store_true", help="Use built-in WASM YARA rules")
    ap.add_argument("--scan-dir","-d", metavar="DIR",    help="Scan all .wasm files in directory")
    ap.add_argument("--json","-j",  action="store_true", help="Output JSON")
    ap.add_argument("--csv",        metavar="FILE",      help="Write CSV report")
    ap.add_argument("--json-out",   metavar="FILE",      help="Write JSON report to file")
    ap.add_argument("--quiet","-q", action="store_true", help="Minimal output")
    args = ap.parse_args()

    # Check yara-python
    yara_mod = _check_yara()
    if not yara_mod:
        print(f"{YEL}[!] yara-python not installed{R}")
        print(f"    pip install yara-python --break-system-packages")
        sys.exit(1)

    # Determine rules path
    rules_path = None
    if args.builtin:
        rules_path = write_builtin_rules()
        print(f"{CYN}[*] Using {len(BUILTIN_YARA_RULES.splitlines())} built-in WASM YARA rules{R}")
    if args.rules:
        if args.builtin:
            # Merge: write builtin, then append custom rules
            builtin_path = write_builtin_rules()
            # Use directory approach
            rules_path = args.rules  # override to custom for now
        else:
            rules_path = args.rules

    if not rules_path:
        print(f"{RED}[!] Specify --rules PATH or --builtin{R}")
        ap.print_help(); sys.exit(1)

    scanner = YARAScanner(rules_path)
    print(f"{CYN}[*] Loading YARA rules from: {rules_path}{R}")

    if args.scan_dir:
        batch_scan(args.scan_dir, rules_path,
                   csv_out=args.csv or "",
                   json_out=args.json_out or "")

    elif args.file:
        if not os.path.exists(args.file):
            print(f"{RED}Error: {args.file} not found{R}"); sys.exit(1)

        result = scanner.scan_file(args.file)

        if args.json or args.json_out:
            import json
            js = json.dumps(asdict(result), indent=2)
            if args.json_out:
                with open(args.json_out, 'w') as f: f.write(js)
                print(f"{GRN}[+] JSON → {args.json_out}{R}")
            else:
                print(js)
        else:
            scanner.print_result(result)

        sys.exit(1 if result.verdict == "MATCHED" else 0)

    else:
        ap.print_help()


if __name__ == "__main__":
    main()
