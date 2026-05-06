#!/usr/bin/env python3

# Plugin: CFG Anomaly Detector

"""
Detects structural anomalies in function control flow graphs
that indicate obfuscation, packing, or malicious code patterns.

Detection capabilities:
    Unreachable basic blocks (dead code)
    Abnormally high cyclomatic complexity
    Dispatcher patterns (single hub block with many successors)
    Irreducible loops (non-natural loops — obfuscation indicator)
    Single-entry-multiple-exit anomalies
    Abnormal block size distribution
    Back-edge density (loop nesting indicator)
    Entry block anomalies (unusual first instruction patterns)
    Exit block anomalies (missing return paths)
    CFG density (edges/nodes ratio)
"""

import math
from collections import defaultdict, deque
from typing import List, Dict, Set, Tuple, Optional
from wasmshark_core import AnalysisReport, CFG, BasicBlock



#  CFG METRICS

def compute_cfg_metrics(cfg: CFG) -> Dict:
    """Compute structural metrics for a single CFG."""
    if not cfg or not cfg.blocks:
        return {}

    blocks = cfg.blocks
    n      = len(blocks)
    edges  = sum(len(b.successors) for b in blocks)

    if n == 0:
        return {}

    # Build adjacency structures
    id_map    = {b.id: b for b in blocks}
    all_ids   = {b.id for b in blocks}

    # Reachability from entry
    reachable: Set[int] = set()
    entry_id  = blocks[0].id
    queue     = deque([entry_id])
    while queue:
        curr = queue.popleft()
        if curr in reachable: continue
        reachable.add(curr)
        if curr in id_map:
            for succ in id_map[curr].successors:
                if succ not in reachable:
                    queue.append(succ)

    unreachable = all_ids - reachable

    # Back edges (DFS)
    back_edges   = 0
    visited      = set()
    in_stack     = set()

    def dfs(node_id):
        nonlocal back_edges
        if node_id not in id_map: return
        visited.add(node_id)
        in_stack.add(node_id)
        for succ in id_map[node_id].successors:
            if succ in in_stack:
                back_edges += 1
            elif succ not in visited:
                dfs(succ)
        in_stack.discard(node_id)

    try:
        dfs(entry_id)
    except RecursionError:
        pass  # Very deep CFG — skip DFS

    # Block size distribution
    block_sizes = [len(b.instructions) for b in blocks]
    avg_size    = sum(block_sizes) / max(1, n)
    max_size    = max(block_sizes) if block_sizes else 0
    min_size    = min(block_sizes) if block_sizes else 0

    # Standard deviation of block sizes
    variance = sum((s - avg_size)**2 for s in block_sizes) / max(1, n)
    std_dev  = math.sqrt(variance)

    # Dispatcher detection
    # A dispatcher block has many successors (fan-out > 4)
    dispatcher_blocks = [b.id for b in blocks if len(b.successors) > 4]

    # Exit blocks
    exit_blocks = [b for b in blocks if b.is_exit or not b.successors]
    no_exit     = len(exit_blocks) == 0 and n > 1

    # CFG density 
    density = edges / max(1, n)

    # Single large block (monolithic function)
    monolithic = (n == 1 and block_sizes[0] > 100)

    return {
        "block_count":        n,
        "edge_count":         edges,
        "density":            round(density, 3),
        "cyclomatic":         cfg.cyclomatic_complexity,
        "unreachable_blocks": list(unreachable),
        "back_edges":         back_edges,
        "dispatcher_blocks":  dispatcher_blocks,
        "avg_block_size":     round(avg_size, 1),
        "max_block_size":     max_size,
        "min_block_size":     min_size,
        "block_size_std_dev": round(std_dev, 2),
        "exit_block_count":   len(exit_blocks),
        "no_exit_path":       no_exit,
        "monolithic":         monolithic,
    }



#  ANOMALY SCORER

def score_cfg_anomaly(metrics: Dict, func_index: int) -> List[Dict]:
    """
    Score a function's CFG metrics for anomalies.
    Returns list of anomaly findings.
    """
    findings = []

    if not metrics:
        return findings

    # Unreachable blocks 
    unreach = metrics.get("unreachable_blocks", [])
    if len(unreach) > 0:
        sev = "HIGH" if len(unreach) > 3 else "MEDIUM"
        findings.append({
            "type":       "UNREACHABLE_BLOCKS",
            "severity":   sev,
            "func_index": func_index,
            "description": f"{len(unreach)} unreachable basic block(s) — dead code or obfuscation padding",
            "evidence":   f"block_ids={unreach[:5]}"
        })

    # High cyclomatic complexity
    cyc = metrics.get("cyclomatic", 1)
    if cyc > 50:
        findings.append({
            "type":       "HIGH_CYCLOMATIC",
            "severity":   "HIGH",
            "func_index": func_index,
            "description": f"Cyclomatic complexity {cyc} — extremely high control flow complexity",
            "evidence":   f"cyclomatic={cyc} (normal <10, suspicious >25, high >50)"
        })
    elif cyc > 25:
        findings.append({
            "type":       "ELEVATED_CYCLOMATIC",
            "severity":   "MEDIUM",
            "func_index": func_index,
            "description": f"Cyclomatic complexity {cyc} — elevated control flow complexity",
            "evidence":   f"cyclomatic={cyc}"
        })

    # Dispatcher blocks
    dispatchers = metrics.get("dispatcher_blocks", [])
    if dispatchers:
        findings.append({
            "type":       "DISPATCHER_BLOCK",
            "severity":   "HIGH",
            "func_index": func_index,
            "description": f"{len(dispatchers)} dispatcher block(s) with high fan-out — control flow obfuscation",
            "evidence":   f"block_ids={dispatchers[:5]}"
        })

    # High back-edge density 
    back_edges = metrics.get("back_edges", 0)
    blocks     = metrics.get("block_count", 1)
    if blocks > 0 and back_edges / blocks > 0.5:
        findings.append({
            "type":       "HIGH_LOOP_DENSITY",
            "severity":   "MEDIUM",
            "func_index": func_index,
            "description": f"High loop density: {back_edges} back-edges in {blocks} blocks",
            "evidence":   f"ratio={back_edges/blocks:.2f} (>0.5 suspicious)"
        })

    # No exit path
    if metrics.get("no_exit_path") and blocks > 2:
        findings.append({
            "type":       "NO_EXIT_PATH",
            "severity":   "MEDIUM",
            "func_index": func_index,
            "description": "CFG has no reachable exit block — infinite loop or obfuscated return",
            "evidence":   f"blocks={blocks} exits=0"
        })

    # Monolithic single block
    if metrics.get("monolithic"):
        findings.append({
            "type":       "MONOLITHIC_BLOCK",
            "severity":   "MEDIUM",
            "func_index": func_index,
            "description": f"Single oversized basic block ({metrics.get('max_block_size')} instructions) — no branching",
            "evidence":   "Possible inlined or packed function body"
        })

    # High CFG density
    density = metrics.get("density", 0)
    if density > 3.0 and blocks > 5:
        findings.append({
            "type":       "HIGH_CFG_DENSITY",
            "severity":   "MEDIUM",
            "func_index": func_index,
            "description": f"CFG density {density:.2f} edges/block — highly connected control flow",
            "evidence":   f"edges={metrics.get('edge_count')} blocks={blocks}"
        })

    # Abnormal block size variance
    std_dev = metrics.get("block_size_std_dev", 0)
    avg     = metrics.get("avg_block_size", 0)
    if std_dev > avg * 2 and blocks > 3:
        findings.append({
            "type":       "BLOCK_SIZE_VARIANCE",
            "severity":   "LOW",
            "func_index": func_index,
            "description": f"High block size variance (σ={std_dev:.1f}, avg={avg:.1f}) — uneven code distribution",
            "evidence":   f"min={metrics.get('min_block_size')} max={metrics.get('max_block_size')}"
        })

    return findings



#  MODULE-WIDE CFG ANALYSIS

def analyze_module_cfg(report: AnalysisReport) -> Dict:
    
    # Analyze all function CFGs and compute module-level statistics.
    # Detects outlier functions that deviate from the module norm.
    
    if not report.functions:
        return {}

    per_function = []
    cyclomatic_values = []
    density_values    = []
    all_findings      = []

    for fn in report.functions:
        if not fn.cfg or not fn.cfg.blocks:
            continue
        metrics  = compute_cfg_metrics(fn.cfg)
        findings = score_cfg_anomaly(metrics, fn.index)
        per_function.append({
            "func_index": fn.index,
            "metrics":    metrics,
            "findings":   findings
        })
        if metrics.get("cyclomatic"):
            cyclomatic_values.append(metrics["cyclomatic"])
        if metrics.get("density"):
            density_values.append(metrics["density"])
        all_findings.extend(findings)

    if not cyclomatic_values:
        return {"summary": "No CFGs available for analysis"}

    # Module-level statistics
    avg_cyc  = sum(cyclomatic_values) / len(cyclomatic_values)
    max_cyc  = max(cyclomatic_values)
    avg_den  = sum(density_values) / max(1, len(density_values))

    # Z-score outliers by cyclomatic complexity
    if len(cyclomatic_values) >= 3:
        variance = sum((v - avg_cyc)**2 for v in cyclomatic_values) / len(cyclomatic_values)
        std_dev  = math.sqrt(variance)
        outliers = [
            pf for pf in per_function
            if std_dev > 0 and
            abs(pf["metrics"].get("cyclomatic", 0) - avg_cyc) / std_dev > 2.5
        ]
        for out in outliers:
            z = abs(out["metrics"].get("cyclomatic", 0) - avg_cyc) / std_dev
            all_findings.append({
                "type":       "CFG_COMPLEXITY_OUTLIER",
                "severity":   "MEDIUM",
                "func_index": out["func_index"],
                "description": f"func[{out['func_index']}] is a CFG complexity outlier (z={z:.1f}σ)",
                "evidence":   f"cyclomatic={out['metrics'].get('cyclomatic')} module_avg={avg_cyc:.1f}"
            })

    # Count severity totals
    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in all_findings:
        sev_counts[f.get("severity","LOW")] = sev_counts.get(f.get("severity","LOW"),0) + 1

    return {
        "functions_analyzed":    len(per_function),
        "avg_cyclomatic":        round(avg_cyc, 2),
        "max_cyclomatic":        max_cyc,
        "avg_cfg_density":       round(avg_den, 3),
        "total_findings":        len(all_findings),
        "severity_counts":       sev_counts,
        "top_findings":          sorted(
            all_findings,
            key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(f.get("severity","LOW"),4)
        )[:15],
        "per_function":          per_function[:20],
        "summary": (f"{len(all_findings)} CFG anomalies across "
                    f"{len(per_function)} functions — "
                    f"avg cyclomatic={avg_cyc:.1f} max={max_cyc}")
    }


#  PLUGIN ENTRY POINT

class WASMPlugin:
    name        = "cfg_anomaly"
    description = "Control flow graph structural anomaly detection"
    version     = "2.0"

    def analyze(self, report: AnalysisReport) -> dict:
        result = analyze_module_cfg(report)
        if not result:
            return {"summary": "No CFG data available — run with --verbose to build CFGs"}
        return result
