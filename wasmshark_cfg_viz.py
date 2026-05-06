#!/usr/bin/env python3

# WASMShark CFG Anomaly Visualizer


import os
from typing import Dict, List, Set, Optional
from wasmshark_core import AnalysisReport, CFG, BasicBlock



#  COLOUR SCHEME

BLOCK_COLORS = {
    "entry":        "#2196F3",   # Blue
    "exit":         "#4CAF50",   # Green
    "unreachable":  "#F44336",   # Red
    "dispatcher":   "#FF9800",   # Orange
    "loop_header":  "#9C27B0",   # Purple
    "oversized":    "#FFEB3B",   # Yellow
    "normal":       "#37474F",   # Dark grey
}

TEXT_COLORS = {
    "entry":        "#FFFFFF",
    "exit":         "#FFFFFF",
    "unreachable":  "#FFFFFF",
    "dispatcher":   "#000000",
    "loop_header":  "#FFFFFF",
    "oversized":    "#000000",
    "normal":       "#ECEFF1",
}

EDGE_COLORS = {
    "back":     "#F44336",   # Red - back edge (loop)
    "forward":  "#90A4AE",   # Grey - normal forward edge
    "dispatch": "#FF9800",   # Orange - dispatch edge
}



#  DOT GENERATOR

def _classify_block(block: BasicBlock,
                    unreachable: Set[int],
                    dispatchers: Set[int],
                    loop_headers: Set[int]) -> str:
    """Return block type for coloring."""
    if block.is_entry:              return "entry"
    if block.id in unreachable:     return "unreachable"
    if block.id in dispatchers:     return "dispatcher"
    if block.id in loop_headers:    return "loop_header"
    if block.is_exit:               return "exit"
    if len(block.instructions) > 50: return "oversized"
    return "normal"


def _is_back_edge(from_id: int, to_id: int,
                  dom_order: Dict[int, int]) -> bool:

    # Simple back-edge detection: an edge u→v is a back edge if v has a lower DFS discovery order than u (i.e. v dominates u).

    return dom_order.get(to_id, 999) <= dom_order.get(from_id, 0)


def cfg_to_dot(cfg: CFG, func_index: int,
               anomaly_findings: List[Dict],
               show_instructions: bool = True,
               max_instrs_per_block: int = 8) -> str:
    
    # Convert a CFG to an annotated Graphviz DOT string. Blocks are coloured by anomaly type
    
    if not cfg or not cfg.blocks:
        return (f'digraph func_{func_index} {{\n'
                f'  label="func[{func_index}]: empty CFG";\n}}')

    blocks  = cfg.blocks
    id_map  = {b.id: b for b in blocks}

    # Identify anomalous block sets from findings
    unreachable:  Set[int] = set()
    dispatchers:  Set[int] = set()
    loop_headers: Set[int] = set()

    for f in anomaly_findings:
        if f.get("type") == "UNREACHABLE_BLOCKS":
            unreachable.update(f.get("evidence_ids", []))
        if f.get("type") == "DISPATCHER_BLOCK":
            dispatchers.update(
                b.id for b in blocks if len(b.successors) > 4)

    # DFS order for back-edge detection
    dfs_order: Dict[int, int] = {}
    counter   = [0]
    visited   = set()

    def dfs(bid):
        if bid in visited or bid not in id_map: return
        visited.add(bid)
        dfs_order[bid] = counter[0]
        counter[0] += 1
        for succ in id_map[bid].successors:
            dfs(succ)
    try:
        if blocks:
            dfs(blocks[0].id)
    except RecursionError:
        pass

    # Identify loop headers (targets of back edges)
    for b in blocks:
        for succ in b.successors:
            if _is_back_edge(b.id, succ, dfs_order):
                loop_headers.add(succ)

    # Build DOT
    anomaly_summary = "; ".join(
        f"{f.get('type','?')}" for f in anomaly_findings[:4])
    if anomaly_summary:
        anomaly_summary = f"\\nAnomalies: {anomaly_summary}"

    lines = [
        f'digraph func_{func_index} {{',
        f'  graph [',
        f'    label="func[{func_index}] — {len(blocks)} blocks, '
        f'cyclomatic={cfg.cyclomatic_complexity}{anomaly_summary}"',
        f'    labelloc=t fontname="Courier New" fontsize=11',
        f'    bgcolor="#1a1a2e" rankdir=TB',
        f'  ];',
        f'  node [fontname="Courier New" fontsize=9 style="filled,rounded" shape=box];',
        f'  edge [fontname="Courier New" fontsize=8];',
        '',
    ]

    # Legend
    lines += [
        '  subgraph cluster_legend {',
        '    label="Legend" fontcolor="#aaaaaa" color="#333333"',
        '    fontsize=9 style=dashed',
        '    leg_entry [label="Entry" fillcolor="#2196F3" fontcolor=white shape=oval style=filled fontsize=8]',
        '    leg_exit  [label="Exit"  fillcolor="#4CAF50" fontcolor=white shape=oval style=filled fontsize=8]',
        '    leg_unr   [label="Unreachable" fillcolor="#F44336" fontcolor=white shape=oval style=filled fontsize=8]',
        '    leg_disp  [label="Dispatcher"  fillcolor="#FF9800" fontcolor=black shape=oval style=filled fontsize=8]',
        '    leg_loop  [label="Loop header" fillcolor="#9C27B0" fontcolor=white shape=oval style=filled fontsize=8]',
        '    leg_over  [label="Oversized"   fillcolor="#FFEB3B" fontcolor=black shape=oval style=filled fontsize=8]',
        '    leg_entry -> leg_exit -> leg_unr -> leg_disp -> leg_loop -> leg_over [style=invis]',
        '  }',
        '',
    ]

    # Blocks
    for b in blocks:
        btype    = _classify_block(b, unreachable, dispatchers, loop_headers)
        fill_col = BLOCK_COLORS[btype]
        text_col = TEXT_COLORS[btype]

        # Build label
        header = f"BB{b.id}  off={b.start_offset:#x}"
        if b.is_entry:       header += "  [ENTRY]"
        if b.is_exit:        header += "  [EXIT]"
        if b.id in unreachable:  header += "  ⚠ UNREACHABLE"
        if b.id in dispatchers:  header += "  ⚠ DISPATCHER"
        if b.id in loop_headers: header += "  ↩ LOOP HEADER"

        label_parts = [header]

        if show_instructions and b.instructions:
            shown = b.instructions[:max_instrs_per_block]
            for ins in shown:
                ops = " ".join(str(o)[:8] for o in ins.operands[:2])
                taint_mark = " ★" if ins.tainted else ""
                label_parts.append(
                    f"{ins.mnemonic:<16} {ops}{taint_mark}")
            if len(b.instructions) > max_instrs_per_block:
                label_parts.append(
                    f"  ... +{len(b.instructions)-max_instrs_per_block} more")

        label_parts.append(
            f"[{len(b.instructions)} instrs | {len(b.successors)} succ]")

        label = "\\n".join(label_parts)

        lines.append(
            f'  bb{b.id} ['
            f'label="{label}" '
            f'fillcolor="{fill_col}" '
            f'fontcolor="{text_col}"'
            f'];')

    lines.append('')

    # Edges
    for b in blocks:
        is_dispatcher = b.id in dispatchers
        for succ in b.successors:
            is_back = _is_back_edge(b.id, succ, dfs_order)
            if is_back:
                color = EDGE_COLORS["back"]
                style = 'style=dashed penwidth=2'
                label = ' label="↩back"'
            elif is_dispatcher:
                color = EDGE_COLORS["dispatch"]
                style = 'penwidth=1.5'
                label = ''
            else:
                color = EDGE_COLORS["forward"]
                style = ''
                label = ''

            lines.append(
                f'  bb{b.id} -> bb{succ} '
                f'[color="{color}" {style}{label}];')

    lines.append('}')
    return '\n'.join(lines)



#  BATCH EXPORTER

def export_anomaly_cfgs(report: AnalysisReport,
                        cfg_results: Dict,
                        output_dir: str = "./cfgs/",
                        min_findings: int = 1,
                        render_svg: bool = True) -> List[str]:

    # Export DOT (and optionally SVG) files for all functions with at least minimum CFG anomalies defined Returns list of written file paths.

    os.makedirs(output_dir, exist_ok=True)
    written = []

    if not cfg_results or "per_function" not in cfg_results:
        return written

    for pf in cfg_results["per_function"]:
        findings = pf.get("findings", [])
        if len(findings) < min_findings:
            continue

        func_idx = pf["func_index"]

        # Find the function's CFG
        fn = next((f for f in report.functions if f.index == func_idx), None)
        if fn is None or fn.cfg is None:
            continue

        dot_str = cfg_to_dot(
            cfg        = fn.cfg,
            func_index = func_idx,
            anomaly_findings = findings,
            show_instructions = True,
            max_instrs_per_block = 6)

        # Write DOT file
        dot_path = os.path.join(output_dir, f"cfg_anomaly_func{func_idx}.dot")
        with open(dot_path, 'w') as f:
            f.write(dot_str)
        written.append(dot_path)

        # Write findings summary alongside
        txt_path = os.path.join(output_dir, f"cfg_anomaly_func{func_idx}.txt")
        with open(txt_path, 'w') as f:
            f.write(f"CFG Anomaly Report: func[{func_idx}]\n")
            f.write(f"{'='*50}\n")
            metrics = pf.get("metrics", {})
            f.write(f"Cyclomatic complexity : {metrics.get('cyclomatic',0)}\n")
            f.write(f"Block count           : {metrics.get('block_count',0)}\n")
            f.write(f"Edge count            : {metrics.get('edge_count',0)}\n")
            f.write(f"CFG density           : {metrics.get('density',0):.3f}\n")
            f.write(f"Unreachable blocks    : {metrics.get('unreachable_blocks',[])}\n")
            f.write(f"Dispatcher blocks     : {metrics.get('dispatcher_blocks',[])}\n")
            f.write(f"Back edges            : {metrics.get('back_edges',0)}\n")
            f.write(f"\nFindings ({len(findings)}):\n")
            for finding in findings:
                f.write(f"\n  [{finding.get('severity','?')}] {finding.get('type','?')}\n")
                f.write(f"  {finding.get('description','')}\n")
                f.write(f"  Evidence: {finding.get('evidence','')}\n")
        written.append(txt_path)

        # Try to render SVG if graphviz available
        if render_svg:
            svg_path = dot_path.replace('.dot', '.svg')
            try:
                import subprocess
                result = subprocess.run(
                    ["dot", "-Tsvg", dot_path, "-o", svg_path],
                    capture_output=True, timeout=10)
                if result.returncode == 0:
                    written.append(svg_path)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass  # graphviz not installed — DOT file still useful

    return written



#  SUMMARY DOT (module-level call + CFG overview)

def export_module_overview(report: AnalysisReport,
                           cfg_results: Dict,
                           output_path: str = "./cfgs/module_overview.dot") -> str:
    
    # Export a single DOT file showing ALL functions as nodes,
    # sized by cyclomatic complexity and colored by anomaly count.

    lines = [
        'digraph module_overview {',
        '  graph [label="WASMShark Module CFG Overview" '
        '         labelloc=t fontsize=12 bgcolor="#1a1a2e" rankdir=LR];',
        '  node [fontname="Courier New" fontsize=8 style="filled,rounded"];',
        '  edge [color="#555555" arrowsize=0.6];',
        '',
    ]

    per_fn_map = {
        pf["func_index"]: pf
        for pf in cfg_results.get("per_function", [])
    }

    for fn in report.functions:
        pf         = per_fn_map.get(fn.index, {})
        findings   = pf.get("findings", [])
        metrics    = pf.get("metrics", {})
        cyc        = metrics.get("cyclomatic", fn.cyclomatic)
        n_findings = len(findings)

        # Color by number of anomaly findings
        if n_findings >= 3:      fill = "#F44336"  # red
        elif n_findings == 2:    fill = "#FF9800"  # orange
        elif n_findings == 1:    fill = "#FFEB3B"  # yellow
        elif fn.suspicious_score > 10: fill = "#4FC3F7"  # light blue
        else:                    fill = "#37474F"  # dark grey

        text_col = "#000000" if fill in ("#FFEB3B",) else "#FFFFFF"

        # Node size reflects function size
        size  = max(0.3, min(2.0, fn.size / 5000))
        label = (f"func[{fn.index}]\\n"
                 f"cyc={cyc} sz={fn.size}\\n"
                 f"findings={n_findings}")

        if fn.flags:
            label += "\\n" + ",".join(fn.flags[:2])

        lines.append(
            f'  fn{fn.index} ['
            f'label="{label}" '
            f'fillcolor="{fill}" fontcolor="{text_col}" '
            f'width={size:.2f} height={size*0.6:.2f}'
            f'];')

    lines.append('')

    # Call edges
    for fn in report.functions:
        for target in fn.call_targets:
            if any(f.index == target for f in report.functions):
                lines.append(f'  fn{fn.index} -> fn{target};')

    lines.append('}')
    dot_str = '\n'.join(lines)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(dot_str)

    # Try SVG render
    svg_path = output_path.replace('.dot', '.svg')
    try:
        import subprocess
        subprocess.run(["dot", "-Tsvg", output_path, "-o", svg_path],
                       capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return output_path




"""
Exports annotated Graphviz DOT files for functions with CFG anomalies.
Anomalous blocks are color-coded by type:
    Red:    unreachable blocks
    Orange: dispatcher blocks (high fan-out)
    Purple: back-edge targets (loop headers)
    Yellow: oversized blocks
    Blue:   entry block
    Green:  exit blocks

Usage:
    from wasmshark_cfg_viz import export_anomaly_cfgs
    export_anomaly_cfgs(report, cfg_results, output_dir="./cfgs/")
"""