#!/usr/bin/env python3

# Plugin: Opcode Anomaly Scorer
#   Detects functions whose opcode distribution deviates significantly
#   from the module average — statistical outlier detection.

import math
from collections import Counter
from wasmshark_core import AnalysisReport

class WASMPlugin:
    name        = "opcode_anomaly"
    description = "Statistical opcode distribution anomaly detection per function"
    version     = "1.0"

    def analyze(self, report: AnalysisReport) -> dict:
        if len(report.functions) < 3:
            return {"summary": "Need ≥3 functions for anomaly detection"}

        # Build module-wide opcode frequency baseline
        module_counts: Counter = Counter()
        for fn in report.functions:
            for ins in fn.disassembly:
                module_counts[ins.opcode] += 1

        module_total = sum(module_counts.values())
        if module_total == 0:
            return {"summary": "No instructions to analyze"}

        module_freq = {op: count/module_total for op, count in module_counts.items()}

        # Score each function against the module baseline
        anomalies = []
        for fn in report.functions:
            if fn.instruction_count < 10:
                continue

            fn_counts: Counter = Counter(ins.opcode for ins in fn.disassembly)
            fn_total  = fn.instruction_count

            # KL divergence: how different is this function from module average
            kl = 0.0
            for op, fn_p in fn_counts.items():
                fn_prob  = fn_p / fn_total
                mod_prob = module_freq.get(op, 1e-9)
                if fn_prob > 0 and mod_prob > 0:
                    kl += fn_prob * math.log(fn_prob / mod_prob)

            # Chi-square distance from module distribution
            expected_counts = {op: module_freq.get(op, 0) * fn_total
                               for op in fn_counts}
            chi2 = sum(
                (fn_counts[op] - expected_counts.get(op, 0)) ** 2 / max(0.1, expected_counts.get(op, 0.1))
                for op in fn_counts)

            # Dominant opcode (what takes up most of this function)
            dominant_op, dominant_count = fn_counts.most_common(1)[0]
            dominant_pct = dominant_count / fn_total * 100
            dominant_name = {
                0x01:"nop", 0x73:"i32.xor", 0x6A:"i32.add", 0x6B:"i32.sub",
                0x6C:"i32.mul", 0x20:"local.get", 0x21:"local.set",
                0x28:"i32.load", 0x36:"i32.store", 0x10:"call", 0x0F:"return",
                0x41:"i32.const", 0x0B:"end", 0x04:"if", 0x03:"loop",
            }.get(dominant_op, f"0x{dominant_op:02x}")

            if kl > 0.5 or chi2 > 500:
                anomalies.append({
                    "func_index":    fn.index,
                    "kl_divergence": round(kl, 3),
                    "chi2_distance": round(chi2, 1),
                    "instruction_count": fn.instruction_count,
                    "dominant_opcode": dominant_name,
                    "dominant_pct":  round(dominant_pct, 1),
                    "suspicious_score": fn.suspicious_score,
                    "flags": fn.flags,
                })

        anomalies.sort(key=lambda x: x["kl_divergence"], reverse=True)

        # Flag top anomalies as suspicious
        flagged = [a for a in anomalies if a["kl_divergence"] > 1.0]

        return {
            "total_functions":     len(report.functions),
            "analyzed":            len([f for f in report.functions if f.instruction_count >= 10]),
            "anomalous_functions": len(anomalies),
            "high_anomaly_count":  len(flagged),
            "top_anomalies":       anomalies[:10],
            "module_opcode_diversity": len(module_counts),
            "summary": (f"{len(anomalies)} functions deviate from module opcode baseline. "
                        f"{len(flagged)} are high-anomaly (KL>1.0) — potential injection or obfuscation.")
        }
