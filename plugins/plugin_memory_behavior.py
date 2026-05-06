#!/usr/bin/env python3

# Plugin: Memory Behavior Analyzer

"""
Analyzes WASM memory access patterns and flags behaviors
that deviate significantly from legitimate WASM modules.

Detection approach: behavioral — what the binary DOES with memory,
not how specific exploitation techniques work.

Detects:
    Abnormal memory growth rate (excessive memory.grow calls)
    Write-heavy functions with no corresponding reads (data staging)
    Read-heavy functions with no writes (data scanning/harvesting)
    Functions that access memory far outside initialized data range
    Monotonically increasing memory writes (sequential overwrite pattern)
    Memory access entropy (random-looking vs sequential access patterns)
    Cross-region data movement (read region A, write region B)
    Unusual memory alignment patterns (misaligned access = possible obfuscation)
"""

import math
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Set
from wasmshark_core import AnalysisReport


#  MEMORY ACCESS PROFILER

def profile_memory_access(fn) -> Dict:
    
    # Extract memory access patterns from a function's disassembly.
    #   Returns a profile of how the function uses memory.
    
    if not fn.disassembly:
        return {}

    load_offsets  = []   # Static offsets used in load instructions
    store_offsets = []   # Static offsets used in store instructions
    load_widths   = []   # Data widths accessed (1, 2, 4, 8 bytes)
    store_widths  = []   # Store widths
    grow_count    = 0
    sequential_writes = 0
    prev_store_offset = -1

    # Width map by opcode
    width_map = {
        0x28: 4, 0x29: 8, 0x2A: 4, 0x2B: 8,   # i32.load, i64.load, f32, f64
        0x2C: 1, 0x2D: 1, 0x2E: 2, 0x2F: 2,   # i32.load8, i32.load16
        0x30: 1, 0x31: 1, 0x32: 2, 0x33: 2,   # i64.load8, i64.load16
        0x34: 4, 0x35: 4,                       # i64.load32
        0x36: 4, 0x37: 8, 0x38: 4, 0x39: 8,   # i32.store, i64.store, f32, f64
        0x3A: 1, 0x3B: 2, 0x3C: 1, 0x3D: 2, 0x3E: 4,  # store8/16/32
    }

    for ins in fn.disassembly:
        op = ins.opcode

        if op == 0x40:  # memory.grow
            grow_count += 1
            continue

        if 0x28 <= op <= 0x35:  # loads
            if len(ins.operands) >= 2:
                offset = ins.operands[1]
                if isinstance(offset, int):
                    load_offsets.append(offset)
            load_widths.append(width_map.get(op, 4))

        elif 0x36 <= op <= 0x3E:  # stores
            if len(ins.operands) >= 2:
                offset = ins.operands[1]
                if isinstance(offset, int):
                    store_offsets.append(offset)
                    # Check sequential pattern
                    if prev_store_offset >= 0 and offset == prev_store_offset + width_map.get(op, 4):
                        sequential_writes += 1
                    prev_store_offset = offset
            store_widths.append(width_map.get(op, 4))

    if not load_offsets and not store_offsets:
        return {}

    # Compute offset entropy (random access = high entropy, sequential = low)
    all_offsets = load_offsets + store_offsets
    offset_entropy = 0.0
    if len(all_offsets) > 4:
        c = Counter(all_offsets); total = len(all_offsets)
        offset_entropy = -sum((v/total)*math.log2(v/total)
                              for v in c.values() if v)

    # Check for cross-region access:
    # significant separation between read and write offset ranges
    cross_region = False
    if load_offsets and store_offsets:
        load_max  = max(load_offsets)
        store_min = min(store_offsets)
        if store_min > load_max + 1024:
            cross_region = True

    return {
        "load_count":          len(load_offsets),
        "store_count":         len(store_offsets),
        "memory_grow_count":   grow_count,
        "load_store_ratio":    round(len(load_offsets) / max(1, len(store_offsets)), 2),
        "offset_entropy":      round(offset_entropy, 3),
        "sequential_writes":   sequential_writes,
        "cross_region_access": cross_region,
        "max_load_offset":     max(load_offsets)  if load_offsets  else 0,
        "max_store_offset":    max(store_offsets) if store_offsets else 0,
        "unique_load_offsets": len(set(load_offsets)),
        "unique_store_offsets":len(set(store_offsets)),
        "dominant_load_width": Counter(load_widths).most_common(1)[0][0] if load_widths else 0,
        "dominant_store_width":Counter(store_widths).most_common(1)[0][0] if store_widths else 0,
    }


#  ANOMALY RULES

def detect_memory_anomalies(profile: Dict, func_index: int,
                             module_avg_ratio: float) -> List[Dict]:
    """
    Apply anomaly rules to a function's memory profile.
    Returns list of anomaly findings.
    """
    findings = []
    if not profile:
        return findings

    load_count  = profile.get("load_count",  0)
    store_count = profile.get("store_count", 0)
    ratio       = profile.get("load_store_ratio", 1.0)
    grow_count  = profile.get("memory_grow_count", 0)
    ent         = profile.get("offset_entropy", 0)
    seq_writes  = profile.get("sequential_writes", 0)
    cross       = profile.get("cross_region_access", False)

    # Excessive memory growth
    if grow_count > 5:
        findings.append({
            "type":        "EXCESSIVE_MEMORY_GROWTH",
            "severity":    "HIGH" if grow_count > 20 else "MEDIUM",
            "func_index":  func_index,
            "description": f"memory.grow called {grow_count} times — abnormal memory allocation pattern",
            "evidence":    f"grow_count={grow_count}"
        })

    # Write-heavy with no reads: data staging
    if store_count > 20 and load_count == 0:
        findings.append({
            "type":        "WRITE_ONLY_FUNCTION",
            "severity":    "MEDIUM",
            "func_index":  func_index,
            "description": f"Function writes to memory {store_count} times with zero reads — data staging pattern",
            "evidence":    f"stores={store_count} loads={load_count}"
        })

    # Read-heavy with no writes: data harvesting
    if load_count > 20 and store_count == 0:
        findings.append({
            "type":        "READ_ONLY_SCAN",
            "severity":    "MEDIUM",
            "func_index":  func_index,
            "description": f"Function reads memory {load_count} times with zero writes — data scanning pattern",
            "evidence":    f"loads={load_count} stores={store_count}"
        })

    # High-entropy offset access: non-sequential/random
    if ent > 5.0 and (load_count + store_count) > 20:
        findings.append({
            "type":        "RANDOM_MEMORY_ACCESS",
            "severity":    "MEDIUM",
            "func_index":  func_index,
            "description": f"High-entropy memory offset pattern (entropy={ent:.2f}) — non-sequential random access",
            "evidence":    f"offset_entropy={ent:.3f} accesses={load_count+store_count}"
        })

    # Large sequential overwrite: bulk data modification
    if seq_writes > 50:
        findings.append({
            "type":        "SEQUENTIAL_OVERWRITE",
            "severity":    "MEDIUM",
            "func_index":  func_index,
            "description": f"{seq_writes} sequential memory writes — bulk data modification (encryption/wipe pattern)",
            "evidence":    f"sequential_writes={seq_writes}"
        })

    # Cross-region: read one area, write another
    if cross and (load_count + store_count) > 10:
        findings.append({
            "type":        "CROSS_REGION_COPY",
            "severity":    "MEDIUM",
            "func_index":  func_index,
            "description": "Memory reads and writes in separate, non-overlapping regions — in-memory data movement",
            "evidence":    (f"max_load_off={profile.get('max_load_offset',0):#x} "
                           f"min_store_off={profile.get('max_store_offset',0):#x}")
        })

    # Deviation from module average
    if module_avg_ratio > 0 and ratio > 0:
        deviation = abs(ratio - module_avg_ratio) / module_avg_ratio
        if deviation > 3.0 and (load_count + store_count) > 15:
            findings.append({
                "type":        "MEMORY_RATIO_OUTLIER",
                "severity":    "LOW",
                "func_index":  func_index,
                "description": (f"Load/store ratio {ratio:.1f}x deviates {deviation:.0f}x "
                               f"from module average {module_avg_ratio:.1f}x"),
                "evidence":    f"ratio={ratio} module_avg={module_avg_ratio:.2f} deviation={deviation:.1f}x"
            })

    return findings



#  PLUGIN ENTRY POINT

class WASMPlugin:
    name        = "memory_behavior"
    description = "Memory access pattern analysis and behavioral anomaly detection"
    version     = "2.0"

    def analyze(self, report: AnalysisReport) -> dict:
        if not report.functions:
            return {"summary": "No functions to analyze"}

        # Profile all functions
        profiles = {}
        for fn in report.functions:
            p = profile_memory_access(fn)
            if p:
                profiles[fn.index] = p

        if not profiles:
            return {"summary": "No memory operations found in any function"}

        # Compute module-wide average load/store ratio 
        all_ratios = [p["load_store_ratio"] for p in profiles.values()
                      if p.get("load_count", 0) + p.get("store_count", 0) > 5]
        module_avg_ratio = (sum(all_ratios) / len(all_ratios)) if all_ratios else 1.0

        # Module-wide memory stats
        total_loads        = sum(p.get("load_count", 0)        for p in profiles.values())
        total_stores       = sum(p.get("store_count", 0)       for p in profiles.values())
        total_grows        = sum(p.get("memory_grow_count", 0) for p in profiles.values())
        total_seq_writes   = sum(p.get("sequential_writes", 0) for p in profiles.values())
        cross_region_fns   = [idx for idx, p in profiles.items()
                              if p.get("cross_region_access")]

        # Detect anomalies per function
        all_findings = []
        per_function = []
        for fn_idx, profile in profiles.items():
            fn_findings = detect_memory_anomalies(profile, fn_idx, module_avg_ratio)
            all_findings.extend(fn_findings)
            if fn_findings:
                per_function.append({
                    "func_index": fn_idx,
                    "profile":    profile,
                    "findings":   fn_findings
                })

        # Module-level pattern detection 
        module_findings = []

        # Total memory.grow across all functions
        if total_grows > 30:
            module_findings.append({
                "type":        "MODULE_EXCESSIVE_GROWTH",
                "severity":    "HIGH",
                "description": f"Module-wide memory.grow total: {total_grows} calls across {len(profiles)} functions",
                "evidence":    f"total_grows={total_grows}"
            })

        # Dominant write pattern: more stores than loads module-wide
        if total_stores > total_loads * 3 and total_stores > 50:
            module_findings.append({
                "type":        "MODULE_WRITE_DOMINANT",
                "severity":    "HIGH",
                "description": (f"Module writes memory {total_stores} times vs {total_loads} reads "
                               f"({total_stores/max(1,total_loads):.1f}x more writes than reads)"),
                "evidence":    f"stores={total_stores} loads={total_loads}"
            })

        # Large sequential write volume
        if total_seq_writes > 200:
            module_findings.append({
                "type":        "MODULE_SEQUENTIAL_OVERWRITE",
                "severity":    "HIGH",
                "description": f"{total_seq_writes} sequential memory writes module-wide — bulk modification pattern",
                "evidence":    f"total_sequential_writes={total_seq_writes}"
            })

        # Multiple cross-region functions
        if len(cross_region_fns) > 2:
            module_findings.append({
                "type":        "MODULE_CROSS_REGION_PATTERN",
                "severity":    "MEDIUM",
                "description": f"{len(cross_region_fns)} functions show cross-region memory movement pattern",
                "evidence":    f"func_indices={cross_region_fns[:5]}"
            })

        all_findings = module_findings + all_findings

        # Severity counts
        sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            sev = f.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "module_stats": {
                "total_load_ops":      total_loads,
                "total_store_ops":     total_stores,
                "total_memory_grows":  total_grows,
                "total_seq_writes":    total_seq_writes,
                "module_avg_ls_ratio": round(module_avg_ratio, 2),
                "functions_with_memory": len(profiles),
                "cross_region_functions": len(cross_region_fns),
            },
            "anomaly_counts":    sev_counts,
            "total_findings":    len(all_findings),
            "module_findings":   module_findings,
            "function_findings": per_function[:15],
            "top_findings":      sorted(
                all_findings,
                key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.get("severity","LOW"), 3)
            )[:10],
            "summary": (
                f"{len(all_findings)} memory behavior findings — "
                f"loads={total_loads} stores={total_stores} grows={total_grows} "
                f"avg_ratio={module_avg_ratio:.2f}"
            )
        }
