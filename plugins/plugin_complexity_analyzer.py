#!/usr/bin/env python3

# Plugin: Complexity Analyzer
#   Computes advanced complexity metrics per function

import math
from collections import Counter
from wasmshark_core import AnalysisReport, FunctionAnalysis

class WASMPlugin:
    name        = "complexity_analyzer"
    description = "Halstead complexity, opcode entropy, fan-in/fan-out per function"
    version     = "1.0"

    def analyze(self, report: AnalysisReport) -> dict:
        results = []
        call_graph: dict = {}  # func_idx -> set of callees

        for fn in report.functions:
            call_graph[fn.index] = set(fn.call_targets)

        # Fan-in per function
        fan_in: dict = {fn.index: 0 for fn in report.functions}
        for fn in report.functions:
            for callee in fn.call_targets:
                if callee in fan_in:
                    fan_in[callee] += 1

        for fn in report.functions:
            if fn.instruction_count < 5: continue

            # Opcode frequency entropy (Halstead approximation)
            opcodes = [ins.opcode for ins in fn.disassembly]
            if not opcodes: continue
            op_count = Counter(opcodes)
            n_ops    = len(opcodes)
            n_unique = len(op_count)
            ent      = -sum((c/n_ops)*math.log2(c/n_ops) for c in op_count.values() if c)

            # Halstead: η1=unique operators, η2=unique operands, N1+N2=total
            halstead_volume = n_ops * math.log2(max(n_unique, 1))
            halstead_effort = halstead_volume * n_unique / max(1, n_unique // 2)

            # Fan-out = number of distinct call targets
            fan_out = len(set(fn.call_targets))

            results.append({
                "func_index":       fn.index,
                "size_bytes":       fn.size,
                "opcode_entropy":   round(ent, 3),
                "halstead_volume":  round(halstead_volume, 1),
                "halstead_effort":  round(halstead_effort, 1),
                "cyclomatic":       fn.cyclomatic,
                "fan_in":           fan_in.get(fn.index, 0),
                "fan_out":          fan_out,
                "suspicious_score": fn.suspicious_score,
            })

        # Sort by halstead_effort descending
        results.sort(key=lambda x: x["halstead_effort"], reverse=True)

        # Identify god functions (high effort + high fan-in)
        god_funcs = [r for r in results
                     if r["halstead_effort"] > 5000 or r["cyclomatic"] > 30]

        return {
            "total_functions_analyzed": len(results),
            "top_complex_functions": results[:10],
            "god_functions": god_funcs[:5],
            "avg_cyclomatic": round(
                sum(r["cyclomatic"] for r in results) / max(1, len(results)), 2),
            "avg_opcode_entropy": round(
                sum(r["opcode_entropy"] for r in results) / max(1, len(results)), 3),
            "summary": f"{len(god_funcs)} high-complexity 'god' functions detected"
        }
