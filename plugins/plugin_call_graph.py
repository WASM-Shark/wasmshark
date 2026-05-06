#!/usr/bin/env python3

# Plugin: Call Graph Analyzer
#   Builds a function call graph and identifies suspicious call paths.

from wasmshark_core import AnalysisReport

class WASMPlugin:
    name        = "call_graph"
    description = "Function call graph with suspicious path detection"
    version     = "2.0"

    def analyze(self, report: AnalysisReport) -> dict:
        if not report.functions:
            return {"summary": "No functions to analyze"}

        import_count = sum(1 for i in report.imports if i.kind == "func")
        import_names = {i.index: f"{i.module}.{i.name}"
                        for i in report.imports if i.kind == "func"}

        # Build adjacency list
        call_graph = {}
        for fn in report.functions:
            call_graph[fn.index] = fn.call_targets

        # Fan-in (how many functions call each function)
        fan_in = {fn.index: 0 for fn in report.functions}
        for fn in report.functions:
            for target in fn.call_targets:
                if target in fan_in:
                    fan_in[target] += 1

        # Find call chains to suspicious imports
        suspicious_import_indices = set()
        suspicious_keywords = {"exec","shell","socket","connect","send","recv",
                                "crypto","hash","sha","keccak","random","mmap",
                                "write","open","rename","environ","eval"}
        for imp in report.imports:
            if imp.kind == "func":
                if any(kw in imp.name.lower() for kw in suspicious_keywords):
                    suspicious_import_indices.add(imp.index)

        # BFS from each function to find paths to suspicious imports
        suspicious_paths = []
        for start_fn in report.functions:
            visited = set(); queue = [(start_fn.index, [start_fn.index])]
            while queue:
                curr, path = queue.pop(0)
                if curr in visited: continue
                visited.add(curr)
                targets = call_graph.get(curr, [])
                for t in targets:
                    if t in suspicious_import_indices:
                        imp_name = import_names.get(t, f"import[{t}]")
                        suspicious_paths.append({
                            "from_func": start_fn.index,
                            "path": path + [t],
                            "reaches": imp_name,
                            "depth": len(path)
                        })
                        break
                    if t not in visited and t in call_graph:
                        queue.append((t, path + [t]))

        # Hub functions (high fan-in = dispatcher)
        hubs = sorted(
            [(idx, count) for idx, count in fan_in.items() if count >= 3],
            key=lambda x: x[1], reverse=True)[:10]

        # Isolated functions (no callers, not exported)
        exported = {e.index for e in report.exports if e.kind == "func"}
        isolated = [fn.index for fn in report.functions
                    if fan_in.get(fn.index, 0) == 0
                    and fn.index not in exported
                    and fn.index >= import_count]

        # Generate DOT graph (top 30 functions for readability)
        dot = _build_dot(report, call_graph, suspicious_import_indices,
                         import_names, fan_in, hubs)

        return {
            "total_functions":      len(report.functions),
            "total_edges":          sum(len(v) for v in call_graph.values()),
            "hub_functions":        [{"index": h[0], "callers": h[1]} for h in hubs],
            "isolated_functions":   isolated[:20],
            "suspicious_paths":     suspicious_paths[:15],
            "suspicious_path_count": len(suspicious_paths),
            "dot_graph":            dot,
            "summary": (f"{len(suspicious_paths)} suspicious call paths found, "
                        f"{len(hubs)} dispatcher hubs, {len(isolated)} isolated functions")
        }


def _build_dot(report, call_graph, sus_imports, import_names, fan_in, hubs) -> str:
    hub_set = {h[0] for h in hubs}
    lines = ["digraph wasmshark_callgraph {",
             '  rankdir=LR;',
             '  node [fontname="Courier" fontsize=10 style=filled];',
             '  graph [label="WASMShark Call Graph" fontsize=12];']

    # Import nodes
    for imp in report.imports:
        if imp.kind != "func": continue
        color = "#ff6666" if imp.index in sus_imports else "#ffcc99"
        label = f"{imp.module}\\n{imp.name}"
        lines.append(f'  n{imp.index} [label="{label}" fillcolor="{color}" shape=oval];')

    # Function nodes (top 40 by suspicion)
    shown = set(i.index for i in report.imports if i.kind == "func")
    top_fns = sorted(report.functions,
                     key=lambda f: f.suspicious_score, reverse=True)[:40]
    for fn in top_fns:
        if fn.index in hub_set:
            color = "#cc99ff"
        elif fn.suspicious_score > 20:
            color = "#ff9999"
        elif fn.suspicious_score > 5:
            color = "#ffee99"
        else:
            color = "#cceecc"
        label = f"func[{fn.index}]\\n{fn.size}B score={fn.suspicious_score:.0f}"
        if fn.flags:
            label += f"\\n{','.join(fn.flags[:2])}"
        lines.append(f'  n{fn.index} [label="{label}" fillcolor="{color}"];')
        shown.add(fn.index)

    # Edges
    for fn in top_fns:
        for target in fn.call_targets:
            if target in shown:
                style = 'color="#ff0000" penwidth=2' if target in sus_imports else 'color="#666666"'
                lines.append(f'  n{fn.index} -> n{target} [{style}];')

    lines.append("}")
    return "\n".join(lines)
