#!/usr/bin/env python3

# WASMShark Analysis Engine

import math, re, hashlib, struct
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Set, Optional, Any
from dataclasses import dataclass, field


#  WASI CAPABILITY ANALYZER

# Maps WASI function names to symbolic capability names
WASI_CAP_MAP: Dict[str, str] = {
    "fd_read":               "READ_FILES",
    "fd_write":              "WRITE_FILES",
    "fd_seek":               "SEEK_FILES",
    "fd_close":              "CLOSE_FILES",
    "fd_sync":               "SYNC_FILES",
    "fd_stat":               "STAT_FILES",
    "path_open":             "OPEN_PATHS",
    "path_create_directory": "CREATE_DIRS",
    "path_rename":           "RENAME_FILES",
    "path_unlink_file":      "DELETE_FILES",
    "path_symlink":          "CREATE_SYMLINKS",
    "path_readlink":         "READ_SYMLINKS",
    "path_remove_directory": "REMOVE_DIRS",
    "sock_open":             "OPEN_SOCKETS",
    "sock_recv":             "RECEIVE_DATA",
    "sock_send":             "SEND_DATA",
    "sock_accept":           "ACCEPT_CONNECTIONS",
    "sock_bind":             "BIND_PORTS",
    "sock_connect":          "CONNECT_NETWORK",
    "sock_shutdown":         "SHUTDOWN_SOCKETS",
    "sock_getlocaladdr":     "GET_LOCAL_ADDR",
    "sock_getpeeraddr":      "GET_PEER_ADDR",
    "proc_exit":             "EXIT_PROCESS",
    "proc_raise":            "RAISE_SIGNALS",
    "environ_get":           "READ_ENVIRONMENT",
    "environ_sizes_get":     "READ_ENVIRONMENT",
    "args_get":              "READ_ARGUMENTS",
    "args_sizes_get":        "READ_ARGUMENTS",
    "random_get":            "GET_RANDOMNESS",
    "clock_time_get":        "READ_CLOCK",
    "clock_res_get":         "READ_CLOCK",
    "poll_oneoff":           "POLL_IO",
    "sched_yield":           "YIELD_CPU",
}

# Dangerous capability combinations with threat classification
DANGEROUS_CAP_COMBOS = [
    (
        {"WRITE_FILES", "GET_RANDOMNESS"},
        "RANSOMWARE_CAPABILITY",
        "CRITICAL",
        "File write + randomness generation = ransomware encryption capability"
    ),
    (
        {"WRITE_FILES", "DELETE_FILES"},
        "DESTRUCTIVE_WIPER",
        "HIGH",
        "Write + delete files = destructive wiper or data destruction tool"
    ),
    (
        {"RENAME_FILES", "GET_RANDOMNESS", "WRITE_FILES"},
        "RANSOMWARE_TRIAD",
        "CRITICAL",
        "Rename + random + write = classic ransomware file encryption pattern"
    ),
    (
        {"OPEN_PATHS", "SEND_DATA"},
        "DATA_EXFILTRATION",
        "HIGH",
        "File access + network send = data exfiltration capability"
    ),
    (
        {"ACCEPT_CONNECTIONS", "OPEN_PATHS"},
        "BACKDOOR_CAPABILITY",
        "CRITICAL",
        "Accept connections + file access = backdoor/RAT capability"
    ),
    (
        {"BIND_PORTS", "RECEIVE_DATA", "SEND_DATA"},
        "NETWORK_LISTENER",
        "HIGH",
        "Bind + recv + send = network server or C2 listener"
    ),
    (
        {"READ_ENVIRONMENT", "SEND_DATA"},
        "CREDENTIAL_EXFILTRATION",
        "CRITICAL",
        "Read environment variables + send data = credential theft + exfil"
    ),
    (
        {"READ_ENVIRONMENT", "OPEN_PATHS"},
        "CREDENTIAL_ACCESS",
        "HIGH",
        "Read environment + file access = credential file harvesting"
    ),
    (
        {"CONNECT_NETWORK", "READ_ENVIRONMENT"},
        "C2_CREDENTIAL_THEFT",
        "HIGH",
        "Network connect + environment access = C2 with credential theft"
    ),
    (
        {"WRITE_FILES", "OPEN_PATHS", "CREATE_DIRS"},
        "DROPPER_CAPABILITY",
        "HIGH",
        "Write + open + create dirs = dropper/installer capability"
    ),
    (
        {"EXIT_PROCESS", "WRITE_FILES", "RECEIVE_DATA"},
        "STAGING_PAYLOAD",
        "HIGH",
        "Receive + write + exit = staged payload delivery"
    ),
]

@dataclass
class WASIAnalysisResult:
    is_wasi:              bool
    wasi_import_count:    int
    claimed_capabilities: List[str]
    dangerous_combos:     List[Dict]
    risk_level:           int   # 0=clean 1=low 2=med 3=high 4=critical
    risk_label:           str
    capability_summary:   str


class WASICapabilityAnalyzer:
    # Analyze WASI imports to determine what host capabilities
    # the module claims, then flag dangerous combinations.

    def analyze(self, imports: list) -> WASIAnalysisResult:
        claimed: Set[str] = set()
        wasi_imports = []

        for imp in imports:
            if imp.module.startswith("wasi"):
                wasi_imports.append(imp)
                cap = WASI_CAP_MAP.get(imp.name.lower())
                if cap:
                    claimed.add(cap)

        dangerous = []
        for required, name, severity, desc in DANGEROUS_CAP_COMBOS:
            if required.issubset(claimed):
                dangerous.append({
                    "name":                name,
                    "severity":            severity,
                    "description":         desc,
                    "capabilities_matched": sorted(required),
                })

        sev_w = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        risk  = max((sev_w.get(d["severity"], 0) for d in dangerous), default=0)
        label_map = {0:"CLEAN", 1:"LOW", 2:"MEDIUM", 3:"HIGH", 4:"CRITICAL"}

        summary_parts = []
        if "READ_FILES" in claimed or "WRITE_FILES" in claimed:
            summary_parts.append("filesystem")
        if "CONNECT_NETWORK" in claimed or "SEND_DATA" in claimed:
            summary_parts.append("network")
        if "READ_ENVIRONMENT" in claimed:
            summary_parts.append("environment")
        if "GET_RANDOMNESS" in claimed:
            summary_parts.append("randomness")
        summary = f"WASI capabilities: {', '.join(summary_parts) or 'minimal'}"

        return WASIAnalysisResult(
            is_wasi              = len(wasi_imports) > 0,
            wasi_import_count    = len(wasi_imports),
            claimed_capabilities = sorted(claimed),
            dangerous_combos     = dangerous,
            risk_level           = risk,
            risk_label           = label_map.get(risk, "UNKNOWN"),
            capability_summary   = summary,
        )



#  LOOP CHARACTERIZER

@dataclass
class LoopProfile:
    loop_count:     int
    tight_loops:    int
    has_crypto_loop: bool
    has_mining_loop: bool
    has_decode_loop: bool
    has_memcpy_loop: bool
    dominant_type:   str
    xor_density:     float
    rotate_density:  float
    mem_op_density:  float


class LoopCharacterizer:

    # Classify loop patterns in WASM functions to identify:
    #   Crypto loops (XOR + rotate heavy)
    #   Mining loops (hash rounds)
    #   String/data decode loops (XOR + load + store)
    #   Memory copy loops (load + store, no XOR)


    def characterize(self, instructions: list) -> LoopProfile:
        if not instructions:
            return LoopProfile(0,0,False,False,False,False,"NONE",0,0,0)

        opcodes = [i.opcode for i in instructions]
        n       = len(opcodes)

        loop_count  = opcodes.count(0x03)
        br_count    = sum(1 for op in opcodes if op in (0x0C, 0x0D))
        xor_count   = sum(1 for op in opcodes if op in (0x73, 0x85))
        rot_count   = sum(1 for op in opcodes if op in (0x77, 0x78, 0x89, 0x8A))
        mem_loads   = sum(1 for op in opcodes if 0x28 <= op <= 0x35)
        mem_stores  = sum(1 for op in opcodes if 0x36 <= op <= 0x3E)
        add_count   = sum(1 for op in opcodes if op in (0x6A, 0x7C))
        const_count = sum(1 for op in opcodes if op in (0x41, 0x42))

        xor_d  = xor_count  / max(1, n)
        rot_d  = rot_count  / max(1, n)
        mem_d  = (mem_loads + mem_stores) / max(1, n)

        # Tight loops: loop opcode followed by br within 15 instructions
        tight = 0
        for i, op in enumerate(opcodes):
            if op == 0x03:
                for j in range(i+1, min(i+15, n)):
                    if opcodes[j] == 0x0C:
                        tight += 1
                        break
                    if opcodes[j] == 0x0B:
                        break

        # Classification heuristics
        is_crypto  = (xor_d > 0.08 and rot_d > 0.03 and loop_count > 0)
        is_mining  = (xor_d > 0.10 and rot_d > 0.05 and add_count > 10 and loop_count > 0)
        is_decode  = (xor_d > 0.05 and mem_loads > 3 and mem_stores > 3 and loop_count > 0)
        is_memcpy  = (mem_loads > 10 and mem_stores > 10 and xor_d < 0.02 and loop_count > 0)

        if is_mining:   dominant = "MINING_HASH"
        elif is_crypto: dominant = "CRYPTO_OP"
        elif is_decode: dominant = "DECODE_LOOP"
        elif is_memcpy: dominant = "MEMCPY_LOOP"
        elif loop_count > 0: dominant = "GENERIC_LOOP"
        else:           dominant = "NO_LOOPS"

        return LoopProfile(
            loop_count      = loop_count,
            tight_loops     = tight,
            has_crypto_loop  = is_crypto,
            has_mining_loop  = is_mining,
            has_decode_loop  = is_decode,
            has_memcpy_loop  = is_memcpy,
            dominant_type    = dominant,
            xor_density      = round(xor_d, 4),
            rotate_density   = round(rot_d, 4),
            mem_op_density   = round(mem_d, 4),
        )



#  OBFUSCATION CLASSIFIER

@dataclass
class ObfuscationResult:
    techniques: List[Dict]
    score:      float
    dominant:   str


class ObfuscationClassifier:

    # Classify specific obfuscation techniques by detecting instruction sequence patterns.
 

    def classify(self, instructions: list) -> ObfuscationResult:
        if not instructions:
            return ObfuscationResult([], 0.0, "NONE")

        opcodes = [i.opcode for i in instructions]
        n       = len(opcodes)
        results = []

        # Opaque predicate: xor self -> branch
        # Pattern: local.get X, local.get X, xor -> always 0
        for i in range(n - 3):
            if (opcodes[i]   == 0x20 and
                opcodes[i+1] == 0x20 and
                opcodes[i+2] == 0x73 and
                opcodes[i+3] in (0x45, 0x04)):
                results.append({
                    "technique":   "OPAQUE_PREDICATE",
                    "severity":    "HIGH",
                    "description": "XOR-self opaque predicate — always-zero branch condition",
                    "location":    f"instr[{i}]"
                })
                break

        # Control flow flattening: high indirect call ratio
        indirect = sum(1 for op in opcodes if op == 0x11)
        if n > 80 and indirect > 3:
            ratio = indirect / n
            if ratio > 0.015:
                results.append({
                    "technique":   "CONTROL_FLOW_FLATTEN",
                    "severity":    "HIGH",
                    "description": f"Indirect call ratio {ratio*100:.1f}% — dispatcher-based flattening",
                    "location":    "function-wide",
                    "evidence":    f"{indirect} call_indirect in {n} instructions"
                })

        # String decryption: XOR + load + store in tight loop
        xors   = sum(1 for op in opcodes if op == 0x73)
        stores = sum(1 for op in opcodes if op in (0x36, 0x3A))
        loads  = sum(1 for op in opcodes if op in (0x28, 0x2C))
        loops  = opcodes.count(0x03)
        if xors > 8 and stores > 4 and loads > 4 and loops > 0:
            results.append({
                "technique":   "STRING_DECRYPTION",
                "severity":    "HIGH",
                "description": "XOR + load + store loop pattern — in-memory string decryption",
                "location":    "function-wide",
                "evidence":    f"xors={xors} loads={loads} stores={stores} loops={loops}"
            })

        # Mixed boolean arithmetic: heavy bit-op density
        bit_ops = sum(1 for op in opcodes if op in
                      (0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                       0x83, 0x84, 0x85, 0x86, 0x87, 0x88))
        if n > 40 and bit_ops / n > 0.22:
            results.append({
                "technique":   "MIXED_BOOLEAN_ARITHMETIC",
                "severity":    "MEDIUM",
                "description": f"Bit-op density {bit_ops/n*100:.0f}% — possible MBA obfuscation",
                "location":    "function-wide",
                "evidence":    f"bit_ops={bit_ops}/{n}"
            })

        # Dead code after return
        for i in range(n - 5):
            if opcodes[i] == 0x0F:   # return
                following = [op for op in opcodes[i+1:i+8]
                             if op not in (0x0B, 0x05)]
                if len(following) >= 3:
                    results.append({
                        "technique":   "DEAD_CODE_INSERTION",
                        "severity":    "MEDIUM",
                        "description": "Instructions after unconditional return — dead code padding",
                        "location":    f"after instr[{i}]"
                    })
                    break

        # Junk arithmetic: a+b-b, a*1, a^0
        junk = 0
        for i in range(n - 2):
            # add and then sub (a+b-b = a)
            if opcodes[i] == 0x6A and opcodes[i+1] == 0x6B:
                junk += 1
            # mul by 1 (using i32.const 1)
            if opcodes[i] == 0x41 and opcodes[i+1] == 0x6C:
                junk += 1
            # xor 0 (using i32.const 0)
            if opcodes[i] == 0x41 and opcodes[i+1] == 0x73:
                junk += 1
        if junk > 5:
            results.append({
                "technique":   "JUNK_ARITHMETIC",
                "severity":    "LOW",
                "description": f"Junk arithmetic sequences ×{junk} — add/sub pairs, mul-1, xor-0",
                "location":    "function-wide"
            })

        # NOP sled
        nop_run = max_nop = 0
        for op in opcodes:
            if op == 0x01:
                nop_run += 1
                max_nop = max(max_nop, nop_run)
            else:
                nop_run = 0
        if max_nop > 30:
            results.append({
                "technique":   "NOP_SLED",
                "severity":    "HIGH" if max_nop > 50 else "MEDIUM",
                "description": f"NOP sled of {max_nop} — code padding or alignment obfuscation",
                "location":    "function-wide"
            })

        # Score is weighted sum
        sev_w = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4}
        score = sum(sev_w.get(r.get("severity","LOW"), 4) for r in results)
        dominant = results[0]["technique"] if results else "NONE"

        return ObfuscationResult(
            techniques = results,
            score      = min(100.0, float(score)),
            dominant   = dominant,
        )



#  FUNCTION CLUSTERER

class FunctionClusterer:
    
    # Group functions by opcode fingerprint (normalized opcode frequency vector).
    # Functions in the same cluster share similar code structure — useful for
    # finding families of related routines (e.g. multiple XOR decryptors).

    def cluster(self, functions: list, n_clusters: int = 5) -> List[Dict]:
        if not functions: return []

        # Build opcode frequency fingerprint per function
        fingerprints = []
        for fn in functions:
            if not fn.disassembly: continue
            opcodes = [i.opcode for i in fn.disassembly]
            if not opcodes: continue
            freq = Counter(opcodes)
            total = len(opcodes)
            # Normalize to 0-100 per opcode
            fp = {op: round(count/total*100, 1) for op, count in freq.items()}
            fingerprints.append((fn.index, fp))

        if not fingerprints: return []

        # Simple greedy clustering by cosine similarity
        clusters: List[List[int]] = []
        assigned = set()

        for i, (idx_i, fp_i) in enumerate(fingerprints):
            if i in assigned: continue
            cluster = [idx_i]
            assigned.add(i)
            for j, (idx_j, fp_j) in enumerate(fingerprints):
                if j in assigned: continue
                sim = self._cosine_sim(fp_i, fp_j)
                if sim > 0.90:
                    cluster.append(idx_j)
                    assigned.add(j)
            clusters.append(cluster)

        # Return clusters with >1 member (interesting) sorted by size
        multi = sorted([c for c in clusters if len(c) > 1],
                       key=len, reverse=True)
        return [{"cluster_id": i, "size": len(c), "func_indices": c[:20]}
                for i, c in enumerate(multi[:10])]

    def _cosine_sim(self, a: Dict, b: Dict) -> float:
        keys = set(a) | set(b)
        dot  = sum(a.get(k,0) * b.get(k,0) for k in keys)
        magA = math.sqrt(sum(v**2 for v in a.values()))
        magB = math.sqrt(sum(v**2 for v in b.values()))
        return dot / (magA * magB) if magA and magB else 0.0



#  TIMELINE

@dataclass
class EntropyTimeline:
    block_size:    int
    blocks:        List[Dict]   # [{offset, entropy, label}]
    peak_entropy:  float
    peak_offset:   int
    anomalous_blocks: List[Dict]


def compute_entropy_timeline(data: bytes, block_size: int = 256) -> EntropyTimeline:
    
    # Compute Shannon entropy for every block_size chunk.
    # Returns a timeline useful for spotting encrypted blobs.

    def ent(chunk):
        if not chunk: return 0.0
        c = Counter(chunk); n = len(chunk)
        return -sum((v/n)*math.log2(v/n) for v in c.values() if v)

    blocks = []
    peak_ent = 0.0; peak_off = 0
    for off in range(0, len(data), block_size):
        chunk = data[off:off+block_size]
        e = round(ent(chunk), 3)
        label = ("ENCRYPTED" if e > 7.5
                 else "COMPRESSED" if e > 7.0
                 else "OBFUSCATED"  if e > 6.0
                 else "NORMAL"      if e > 3.0
                 else "ZERO_PADDED")
        blocks.append({"offset": off, "entropy": e, "label": label})
        if e > peak_ent:
            peak_ent = e; peak_off = off

    anomalous = [b for b in blocks if b["entropy"] > 7.0]

    return EntropyTimeline(
        block_size       = block_size,
        blocks           = blocks,
        peak_entropy     = peak_ent,
        peak_offset      = peak_off,
        anomalous_blocks = anomalous,
    )



#  STRING ANOMALY SCORER

def score_string(s: str) -> Tuple[float, str]:

    # Returns (score, reason).
    
    score = 0.0; reasons = []
    sl = s.lower()

    # High entropy suggests encoding
    ent = -sum((s.count(c)/len(s))*math.log2(s.count(c)/len(s))
               for c in set(s) if s.count(c)) if len(s) > 1 else 0
    if ent > 5.0:
        score += 20; reasons.append(f"high entropy ({ent:.1f})")

    # Base64-like
    if len(s) >= 20 and len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', s):
        score += 15; reasons.append("base64-like")

    # URL with suspicious TLD / path
    if re.search(r'https?://', sl):
        score += 10
        if ".onion" in sl: score += 30; reasons.append("tor URL")
        if any(x in sl for x in ["c2","beacon","payload","stage","drop"]):
            score += 20; reasons.append("C2 URL path")

    # Shell command patterns
    if any(x in sl for x in ["cmd.exe", "/bin/sh", "/bin/bash", "powershell"]):
        score += 25; reasons.append("shell command")

    # Crypto
    if any(x in sl for x in ["bitcoin", "monero", "wallet", "ransom", "decrypt"]):
        score += 20; reasons.append("crypto/ransom keyword")

    # Credential paths
    if any(x in sl for x in ["id_rsa", ".aws", "passwd", "shadow", "credentials"]):
        score += 25; reasons.append("credential path")

    # IPv4 address
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        score += 10; reasons.append("IP address")

    # Long hex string (possible hash or key)
    if re.match(r'^[0-9a-fA-F]{32,}$', s):
        score += 15; reasons.append(f"hex string len={len(s)}")

    return min(100.0, round(score, 1)), "; ".join(reasons) or "benign"



#  API ABUSE SCORER

# (pattern, individual_score, description)
API_ABUSE_TABLE: List[Tuple[str, int, str]] = [
    ("random_get",    30, "Randomness for crypto key generation"),
    ("fd_write",      40, "Filesystem write capability"),
    ("fd_read",       35, "Filesystem read capability"),
    ("path_open",     50, "Arbitrary path open"),
    ("path_rename",   60, "File rename (ransomware)"),
    ("path_unlink",   65, "File deletion (wiper/ransomware)"),
    ("sock_recv",     70, "Network receive (C2)"),
    ("sock_send",     70, "Network send (exfil/C2)"),
    ("sock_accept",   80, "Accept connections (backdoor)"),
    ("sock_bind",     75, "Bind port (listener)"),
    ("environ_get",   55, "Environment access (credential theft)"),
    ("connect",       75, "Network connect (C2)"),
    ("socket",        70, "Socket creation"),
    ("exec",          95, "Process execution (RCE)"),
    ("system",        95, "Shell execution (RCE)"),
    ("eval",          90, "Dynamic eval (code injection)"),
    ("sha256",        45, "Cryptographic hash"),
    ("sha3",          50, "SHA-3 / Keccak hash"),
    ("keccak",        55, "Keccak (mining)"),
    ("randomx",       90, "RandomX mining algorithm"),
    ("mmap",          60, "Memory mapping"),
    ("mprotect",      70, "Memory permission change"),
    ("VirtualAlloc",  80, "Windows memory allocation"),
    ("memfd_create",  85, "Anonymous memory (fileless)"),
    ("sleep",         25, "Timing / evasion"),
    ("nanosleep",     25, "High-precision timing"),
]


def compute_api_abuse_score(imports: list) -> Tuple[float, List[Dict]]:
   
    total    = 0.0
    details  = []
    names    = [i.name.lower() for i in imports]

    for name in names:
        for pattern, score, reason in API_ABUSE_TABLE:
            if pattern.lower() in name:
                total += score
                details.append({"api": name, "score": score, "reason": reason})
                break

    # Combination bonuses
    has_net  = any(k in n for n in names for k in ("sock","connect","send","recv","fetch"))
    has_fsw  = any(k in n for n in names for k in ("fd_write","path_open","write"))
    has_rng  = any(k in n for n in names for k in ("random","getrandom"))
    has_cry  = any(k in n for n in names for k in ("sha","keccak","aes","encrypt","hash","chacha"))
    has_exec = any(k in n for n in names for k in ("exec","system","spawn","fork"))
    has_env  = any("environ" in n for n in names)

    if has_fsw and has_rng and has_cry:
        total += 35
        details.append({"combo": "RANSOMWARE_TRIAD", "score": 35,
                         "reason": "File-write + randomness + crypto = ransomware"})
    if has_net and has_exec:
        total += 40
        details.append({"combo": "C2_SHELL", "score": 40,
                         "reason": "Network + execution = C2 shell"})
    if has_env and has_net:
        total += 30
        details.append({"combo": "CREDENTIAL_EXFIL", "score": 30,
                         "reason": "Environment + network = credential exfiltration"})
    if has_cry and has_rng and not has_fsw:
        total += 20
        details.append({"combo": "MINER_PATTERN", "score": 20,
                         "reason": "Crypto + random without file access = mining"})

    normalized = min(100.0, round(total / max(1, len(names)) * 2.5, 1))
    return normalized, details



#  SECTION ANOMALY DETECTOR

@dataclass
class SectionAnomaly:
    anomaly_type: str
    severity:     str
    description:  str
    evidence:     str


def detect_section_anomalies(sections: list, file_size: int) -> List[SectionAnomaly]:

    # Detect anomalous section layout patterns:
    #   Out-of-order sections (spec requires specific ordering)
    #   Duplicate section IDs
    #   Oversized sections (>80% of file)
    #   Gaps between sections (hidden data)
    #   Sections with impossible sizes

    anomalies = []
    SPEC_ORDER = [0,1,2,3,4,5,6,7,8,9,10,11,12]  # Section ID's in spec order

    seen_ids = []
    prev_end  = 8  # After WASM header

    for sec in sections:
        # Duplicate section (except custom=0)
        if sec.id != 0 and sec.id in seen_ids:
            anomalies.append(SectionAnomaly(
                "DUPLICATE_SECTION", "HIGH",
                f"Duplicate section ID {sec.id} ({sec.name})",
                f"offset={sec.offset:#x}"
            ))
        seen_ids.append(sec.id)

        # Gap detection (more than 16 bytes between sections)
        gap = sec.offset - prev_end
        if gap > 16:
            anomalies.append(SectionAnomaly(
                "SECTION_GAP", "MEDIUM",
                f"Unexpected {gap}-byte gap before {sec.name} section",
                f"gap_at={prev_end:#x} size={gap}"
            ))

        # Oversized section
        if file_size > 0 and sec.size / file_size > 0.85:
            anomalies.append(SectionAnomaly(
                "OVERSIZED_SECTION", "MEDIUM",
                f"Section {sec.name} occupies {sec.size/file_size*100:.0f}% of file",
                f"size={sec.size:,} / file={file_size:,}"
            ))

        # Zero-size non-custom section
        if sec.size == 0 and sec.id != 0:
            anomalies.append(SectionAnomaly(
                "EMPTY_SECTION", "LOW",
                f"Empty section: {sec.name}",
                f"offset={sec.offset:#x}"
            ))

        prev_end = sec.offset + sec.size + 2  # approx section header overhead

    # Out-of-order non-custom sections
    non_custom = [s.id for s in sections if s.id != 0]
    for i in range(len(non_custom) - 1):
        if non_custom[i] > non_custom[i+1]:
            anomalies.append(SectionAnomaly(
                "OUT_OF_ORDER_SECTIONS", "MEDIUM",
                f"Section ID {non_custom[i]} appears before {non_custom[i+1]} (spec violation)",
                f"expected order: {SPEC_ORDER}"
            ))
            break

    return anomalies



#  SCAN HISTORY TRACKER

import json, os
from datetime import datetime


class ScanHistory:
    
    # Accumulates scan results in a JSON file for trend analysis.

    def __init__(self, history_file: str = "wasmshark_history.json"):
        self.path = history_file
        self._data: List[Dict] = []
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path) as f:
                    self._data = json.load(f)
        except: self._data = []

    def _save(self):
        try:
            with open(self.path, 'w') as f:
                json.dump(self._data, f, indent=2)
        except: pass

    def record(self, report) -> Dict:
        # Add a scan result to history. Returns delta from previous scan of same file
        entry = {
            "timestamp":        datetime.now().isoformat(),
            "filename":         report.filename,
            "sha256":           report.sha256,
            "verdict":          report.verdict,
            "malice_score":     report.malice_score,
            "obfuscation_score":report.obfuscation_score,
            "file_size":        report.file_size,
            "entropy":          report.file_entropy,
            "imphash":          report.imphash,
            "rules_matched":    [r["name"] for r in report.matched_rules],
            "finding_count":    len(report.findings),
            "ioc_count":        len(report.iocs),
        }

        # Find previous scan of same file
        prev = next((e for e in reversed(self._data)
                     if e["filename"] == report.filename), None)
        delta = {}
        if prev:
            delta = {
                "verdict_changed":  prev["verdict"] != entry["verdict"],
                "malice_delta":     round(entry["malice_score"] - prev["malice_score"], 1),
                "size_delta":       entry["file_size"] - prev["file_size"],
                "imphash_changed":  prev["imphash"] != entry["imphash"],
                "new_rules":        list(set(entry["rules_matched"]) - set(prev["rules_matched"])),
            }

        self._data.append(entry)
        # Keep last 500 entries
        if len(self._data) > 500:
            self._data = self._data[-500:]
        self._save()
        return delta

    def get_history(self, filename: str) -> List[Dict]:
        return [e for e in self._data if e["filename"] == filename]

    def get_summary(self) -> Dict:
        if not self._data: return {}
        verdicts = Counter(e["verdict"] for e in self._data)
        return {
            "total_scans":    len(self._data),
            "unique_files":   len(set(e["filename"] for e in self._data)),
            "verdict_counts": dict(verdicts),
            "last_scan":      self._data[-1]["timestamp"] if self._data else None,
            "most_malicious": sorted(
                [e for e in self._data if e["verdict"] == "MALICIOUS"],
                key=lambda x: x["malice_score"], reverse=True)[:5],
        }


"""
Detection-focused analysis modules:

    WASICapabilityAnalyzer  : maps WASI imports to host capabilities,
                               flags dangerous combinations
    LoopCharacterizer       : classifies loop patterns (crypto, mining, decode)
    ObfuscationClassifier   : identifies specific obfuscation techniques
                               from instruction sequences
    FunctionClusterer       : groups functions by opcode fingerprint
                               to find families of similar routines
    EntropyTimeline         : charts entropy block-by-block across the file
    StringAnomalyScorer     : scores each extracted string for suspicion
    APIAbuseScorer          : weights import combinations by abuse risk
    SectionAnomalyDetector  : detects section layout anomalies
"""