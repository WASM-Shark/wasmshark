#!/usr/bin/env python3

# Plugin: String Deobfuscator
#   Attempts to decode obfuscated strings (XOR, base64, rot13, hex)

import base64, re, codecs
from wasmshark_core import AnalysisReport

class WASMPlugin:
    name        = "string_deobfuscator"
    description = "Decode obfuscated strings: base64, hex, rot13, XOR-1"
    version     = "1.0"

    def analyze(self, report: AnalysisReport) -> dict:
        decoded = []
        raw = report.strings

        for s in raw:
            # Base64
            try:
                if len(s) >= 16 and len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', s):
                    dec = base64.b64decode(s).decode('utf-8', errors='ignore')
                    if len(dec) > 4 and dec.isprintable():
                        decoded.append({"original": s[:60], "method": "base64", "decoded": dec[:80]})
            except: pass

            # Hex string
            try:
                if len(s) >= 8 and re.match(r'^[0-9a-fA-F]+$', s) and len(s) % 2 == 0:
                    dec = bytes.fromhex(s).decode('utf-8', errors='ignore')
                    if len(dec) > 3 and all(32 <= ord(c) < 127 for c in dec):
                        decoded.append({"original": s[:60], "method": "hex", "decoded": dec[:80]})
            except: pass

            # ROT13
            try:
                rot = codecs.encode(s, 'rot_13')
                if any(kw in rot.lower() for kw in ["http","exec","shell","pass","key","secret"]):
                    decoded.append({"original": s[:60], "method": "rot13", "decoded": rot[:80]})
            except: pass

            # XOR with byte 1 (common trivial obfuscation)
            try:
                xored = ''.join(chr(ord(c) ^ 1) for c in s if ord(c) ^ 1 < 128)
                if len(xored) > 5 and xored.isprintable():
                    if any(kw in xored.lower() for kw in ["http","exec","shell","cmd","eval"]):
                        decoded.append({"original": s[:60], "method": "xor1", "decoded": xored[:80]})
            except: pass

        return {
            "decoded_count": len(decoded),
            "decoded_strings": decoded[:20],
            "summary": f"Found {len(decoded)} potentially obfuscated strings"
        }
