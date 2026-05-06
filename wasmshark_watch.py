#!/usr/bin/env python3

# WASMShark Watch Mode
#   Watches a file or directory for changes and automatically rescans.

import os, sys, time, argparse, subprocess, hashlib, json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

R="\033[0m"; B="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; DIM="\033[2m"; WHT="\033[97m"

def vc(v):
    return {"MALICIOUS":RED+B,"SUSPICIOUS":YEL+B,
            "POTENTIALLY_UNWANTED":YEL,"CLEAN":GRN+B}.get(v,R)

def file_hash(path: str) -> str:
    try:
        with open(path,"rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return ""

def scan_file(path: str, rules_dir: Optional[str], plugins_dir: Optional[str],
              quiet: bool = False) -> Optional[Dict]:

    # Run wasmshark.py on a file and return parsed JSON result
    cmd = [sys.executable, "wasmshark.py", path, "--json", "-q"]
    if rules_dir:   cmd += ["--rules-dir", rules_dir]
    if plugins_dir: cmd += ["--plugins-dir", plugins_dir]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        # Extract JSON from output (wasmshark -q --json prints JSON)
        for line in result.stdout.splitlines():
            if line.strip().startswith("{"):
                return json.loads(line)
        # Try stderr too
        return None
    except Exception as e:
        if not quiet:
            print(f"  {RED}Scan error: {e}{R}")
        return None

class FileWatcher:
    # Watches files for content changes using MD5 polling

    def __init__(self, paths: list, interval: float = 1.0,
                 rules_dir: str = "", plugins_dir: str = "",
                 on_malicious: str = "", json_out: str = ""):
        self.paths        = paths
        self.interval     = interval
        self.rules_dir    = rules_dir or None
        self.plugins_dir  = plugins_dir or None
        self.on_malicious = on_malicious
        self.json_out     = json_out
        self._hashes: Dict[str, str] = {}
        self._results: list = []

    def _collect_wasm_files(self) -> list:
        files = []
        for p in self.paths:
            path = Path(p)
            if path.is_file() and path.suffix == ".wasm":
                files.append(str(path))
            elif path.is_dir():
                files.extend(str(f) for f in path.rglob("*.wasm"))
        return files

    def _scan_and_report(self, filepath: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{CYN}[{ts}] Change detected: {filepath}{R}")
        print(f"{DIM}  Scanning...{R}", end="", flush=True)

        # Run static analysis
        cmd = [sys.executable, "wasmshark.py", filepath]
        if self.rules_dir:   cmd += ["--rules-dir",   self.rules_dir]
        if self.plugins_dir: cmd += ["--plugins-dir",  self.plugins_dir]

        try:
            result = subprocess.run(cmd, capture_output=False, timeout=60)
            verdict_code = result.returncode

            if verdict_code == 1:  # MALICIOUS or SUSPICIOUS
                print(f"\n  {RED}{B}⚠  THREAT DETECTED in {filepath}{R}")
                if self.on_malicious:
                    try:
                        subprocess.run(self.on_malicious.replace("{file}", filepath),
                                       shell=True, timeout=10)
                    except: pass
            else:
                print(f"\n  {GRN}✓  Clean: {filepath}{R}")

        except subprocess.TimeoutExpired:
            print(f"\n  {YEL}Scan timed out: {filepath}{R}")
        except Exception as e:
            print(f"\n  {RED}Error: {e}{R}")

    def run(self):
        print(f"""
{CYN}{B}
  ╔═══════════════════════════════════════════════╗
  ║   WASMShark Watch Mode                        ║
  ║   Auto-rescan on file change                  ║
  ╚═══════════════════════════════════════════════╝
{R}""")
        print(f"  Watching : {', '.join(str(p) for p in self.paths)}")
        print(f"  Interval : {self.interval}s")
        if self.rules_dir:    print(f"  Rules    : {self.rules_dir}")
        if self.plugins_dir:  print(f"  Plugins  : {self.plugins_dir}")
        if self.on_malicious: print(f"  On threat: {self.on_malicious}")
        print(f"\n{DIM}  Waiting for changes... (Ctrl+C to stop){R}\n")

        # Initial scan of all files
        files = self._collect_wasm_files()
        for f in files:
            self._hashes[f] = file_hash(f)
            print(f"  {DIM}Tracking: {f}{R}")
        if not files:
            print(f"  {YEL}No .wasm files found yet — watching for new files{R}")

        try:
            while True:
                current_files = set(self._collect_wasm_files())

                # Detect new files
                known = set(self._hashes.keys())
                for new_file in current_files - known:
                    self._hashes[new_file] = ""
                    print(f"\n{GRN}[+] New file detected: {new_file}{R}")

                # Check for changes
                for filepath in sorted(current_files):
                    current_hash = file_hash(filepath)
                    prev_hash    = self._hashes.get(filepath, "")
                    if current_hash != prev_hash:
                        self._hashes[filepath] = current_hash
                        if prev_hash:  # Don't scan on first detection
                            self._scan_and_report(filepath)
                        else:
                            # First time seeing this file — scan it
                            self._hashes[filepath] = current_hash
                            self._scan_and_report(filepath)

                # Detect deleted files
                for gone in known - current_files:
                    del self._hashes[gone]
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"\n{YEL}[{ts}] File removed: {gone}{R}")

                time.sleep(self.interval)

        except KeyboardInterrupt:
            print(f"\n\n{CYN}Watch mode stopped.{R}\n")


def main():
    ap = argparse.ArgumentParser(
        description="WASMShark Watch Mode — auto-rescan on file change",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 wasmshark_watch.py sample.wasm
  python3 wasmshark_watch.py ./samples/ --rules ./rules/
  python3 wasmshark_watch.py sample.wasm --interval 2
  python3 wasmshark_watch.py sample.wasm --on-malicious "echo ALERT: {file}"
        """)
    ap.add_argument("paths",         nargs="+",          help="Files or directories to watch")
    ap.add_argument("--rules-dir",   metavar="DIR",      help="Rules directory")
    ap.add_argument("--plugins-dir", metavar="DIR",      help="Plugins directory")
    ap.add_argument("--interval","-i",type=float,default=1.0, help="Poll interval in seconds (default 1.0)")
    ap.add_argument("--on-malicious",metavar="CMD",      help="Shell command to run on MALICIOUS verdict. Use {file} for filepath.")
    ap.add_argument("--json-out",    metavar="FILE",     help="Append all results to JSON file")
    args = ap.parse_args()

    watcher = FileWatcher(
        paths        = args.paths,
        interval     = args.interval,
        rules_dir    = args.rules_dir or "",
        plugins_dir  = args.plugins_dir or "",
        on_malicious = args.on_malicious or "",
        json_out     = args.json_out or "",
    )
    watcher.run()


if __name__ == "__main__":
    main()
