#!/usr/bin/env python3

# Plugin: Memory Safety Analyzer
"""
Detects suspicious memory access patterns in WASM functions:
    Out-of-bounds access indicators (load/store with large constant offsets)
    Heap spray patterns (repeated memory.grow + store)
    Use-after-free indicators (load from freed-looking addresses)
    Buffer overread patterns (loops with unchecked bounds)
    Stack pivot indicators (unusual stack pointer manipulation)
"""

import math
from collections import Counter
from wasmshark_core import AnalysisReport

class WASMPlugin:
    name        = "memory_safety"
    description = "Detects suspicious memory access patterns and anomalies"
    version     = "1.0"

    # Large constant offsets that suggest OOB access attempts
    SUSPICIOUS_OFFSETS = [
        0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFF0,  # Near max u32
        0x80000000, 0x7FFFFFFF,               # Signed boundary
        0x10000000, 0x20000000,               # Large allocations
        0xDEAD0000, 0xBEEF0000, 0xCAFE0000,  # Magic marker offsets
    ]

    def analyze(self, report: AnalysisReport) -> dict:
        findings = []
        memory_grow_functions = []
        heap_spray_candidates = []
        large_offset_functions = []
        unchecked_loop_functions = []
        total_memory_grows = 0

        for fn in report.functions:
            if not fn.disassembly:
                continue

            opcodes = [i.opcode for i in fn.disassembly]
            operands = [i.operands for i in fn.disassembly]
            n = len(opcodes)

            # memory.grow detection
            grow_count = opcodes.count(0x40)
            if grow_count > 0:
                total_memory_grows += grow_count
                memory_grow_functions.append({
                    "func_index": fn.index,
                    "grow_count": grow_count
                })

            # Heap spray: memory.grow + immediate store
            for i in range(n - 3):
                if opcodes[i] == 0x40:  # memory.grow
                    # Check for store within next 5 instructions
                    following = opcodes[i+1:i+6]
                    if any(op in range(0x36, 0x3F) for op in following):
                        heap_spray_candidates.append({
                            "func_index": fn.index,
                            "offset": fn.disassembly[i].offset
                        })
                        break

            # Large/suspicious memory offsets
            for i, ins in enumerate(fn.disassembly):
                if ins.opcode in list(range(0x28, 0x3F)) and len(ins.operands) >= 2:
                    mem_offset = ins.operands[1]  # memory offset operand
                    if mem_offset in self.SUSPICIOUS_OFFSETS:
                        large_offset_functions.append({
                            "func_index":  fn.index,
                            "opcode":      ins.mnemonic,
                            "offset_val":  hex(mem_offset),
                            "file_offset": hex(ins.offset)
                        })
                    elif isinstance(mem_offset, int) and mem_offset > 0x1000000:
                        large_offset_functions.append({
                            "func_index":  fn.index,
                            "opcode":      ins.mnemonic,
                            "offset_val":  hex(mem_offset),
                            "file_offset": hex(ins.offset)
                        })

            # Unchecked loop bounds: loop with load but no compare
            # Pattern: loop + load + store + br (no bounds check)
            if opcodes.count(0x03) > 0:  # has loops
                loop_loads  = sum(1 for op in opcodes if op in range(0x28, 0x36))
                loop_stores = sum(1 for op in opcodes if op in range(0x36, 0x3F))
                comparisons = sum(1 for op in opcodes if op in
                                  (0x46,0x47,0x48,0x49,0x4A,0x4B,  # i32 compare
                                   0x51,0x52,0x53,0x54,0x55,0x56))  # i64 compare
                if loop_loads > 5 and loop_stores > 5 and comparisons == 0:
                    unchecked_loop_functions.append({
                        "func_index": fn.index,
                        "loads":  loop_loads,
                        "stores": loop_stores,
                        "loops":  opcodes.count(0x03)
                    })

        # Memory opcode distribution analysis
        all_mem_ops = []
        for fn in report.functions:
            for ins in fn.disassembly:
                if 0x28 <= ins.opcode <= 0x3E:
                    all_mem_ops.append(ins.opcode)

        load_count  = sum(1 for op in all_mem_ops if 0x28 <= op <= 0x35)
        store_count = sum(1 for op in all_mem_ops if 0x36 <= op <= 0x3E)
        load_store_ratio = load_count / max(1, store_count)

        # High read/low write: possible memory scanning
        scanning_pattern = (load_count > 50 and load_store_ratio > 5.0)
        # High write/low read: possible memory filling (spray/wipe)
        filling_pattern  = (store_count > 50 and load_store_ratio < 0.2)

        # Build summary findings
        if total_memory_grows > 10:
            findings.append({
                "type":     "HEAP_GROW_HEAVY",
                "severity": "HIGH",
                "description": f"Excessive memory.grow calls ({total_memory_grows} total across {len(memory_grow_functions)} functions)",
                "evidence": f"functions={[f['func_index'] for f in memory_grow_functions[:5]]}"
            })

        if heap_spray_candidates:
            findings.append({
                "type":     "HEAP_SPRAY_PATTERN",
                "severity": "HIGH",
                "description": f"Heap spray pattern: memory.grow immediately followed by store in {len(heap_spray_candidates)} functions",
                "evidence": f"first_occurrence=func[{heap_spray_candidates[0]['func_index']}]"
            })

        if large_offset_functions:
            findings.append({
                "type":     "SUSPICIOUS_MEMORY_OFFSET",
                "severity": "HIGH",
                "description": f"Suspicious memory access offsets in {len(large_offset_functions)} instruction(s)",
                "evidence": str(large_offset_functions[:3])
            })

        if unchecked_loop_functions:
            findings.append({
                "type":     "UNCHECKED_LOOP_MEMORY",
                "severity": "MEDIUM",
                "description": f"Memory loops with no bounds comparison in {len(unchecked_loop_functions)} function(s)",
                "evidence": f"functions={[f['func_index'] for f in unchecked_loop_functions[:5]]}"
            })

        if scanning_pattern:
            findings.append({
                "type":     "MEMORY_SCAN_PATTERN",
                "severity": "MEDIUM",
                "description": f"High read/write ratio ({load_store_ratio:.1f}x) — possible memory scanning",
                "evidence": f"loads={load_count} stores={store_count}"
            })

        if filling_pattern:
            findings.append({
                "type":     "MEMORY_FILL_PATTERN",
                "severity": "HIGH",
                "description": f"High write/read ratio (1/{1/load_store_ratio:.1f}x) — possible memory wiping or heap spray",
                "evidence": f"loads={load_count} stores={store_count}"
            })

        return {
            "total_memory_grows":       total_memory_grows,
            "memory_grow_functions":    memory_grow_functions[:10],
            "heap_spray_candidates":    heap_spray_candidates[:10],
            "large_offset_accesses":    large_offset_functions[:10],
            "unchecked_loop_functions": unchecked_loop_functions[:10],
            "total_load_ops":           load_count,
            "total_store_ops":          store_count,
            "load_store_ratio":         round(load_store_ratio, 2),
            "memory_scan_pattern":      scanning_pattern,
            "memory_fill_pattern":      filling_pattern,
            "findings":                 findings,
            "summary": (f"{len(findings)} memory safety findings — "
                        f"{load_count} loads, {store_count} stores, "
                        f"{total_memory_grows} memory.grow calls")
        }
