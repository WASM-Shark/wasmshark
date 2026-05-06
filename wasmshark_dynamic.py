#!/usr/bin/env python3

# WASMShark Dynamic State Machine & CFG Analysis


import math
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Any



#  STATE MACHINE EXTRACTION

@dataclass
class State:
    # A state in the extracted state machine
    func_index:   int
    entry_count:  int = 0
    exit_count:   int = 0
    transitions:  Dict[int, int] = field(default_factory=dict)  # target -> count


@dataclass
class StateMachine:
    # State machine extracted from Wasabi call sequence
    states:       Dict[int, State]       # func_index -> State
    transitions:  List[Tuple[int,int,int]]  # (from, to, count)
    initial:      Optional[int]          # first function observed
    terminal:     Set[int]               # functions with no outgoing calls
    hot_paths:    List[List[int]]        # most frequent call sequences
    anomalies:    List[Dict]             # unexpected transitions


def extract_state_machine(call_sequence: List[Dict],
                           func_call_counts: Dict[str,int]) -> StateMachine:

    # Build a state machine from the recorded call sequence. Each function is a state; each call edge is a transition
    
    states: Dict[int, State] = {}
    transition_counts: Dict[Tuple[int,int], int] = defaultdict(int)

    def get_state(idx: int) -> State:
        if idx not in states:
            states[idx] = State(func_index=idx)
        return states[idx]

    # Build transitions from call sequence
    for call in call_sequence:
        caller = call.get("caller")
        target = call.get("target")
        if caller is None or target is None:
            continue
        caller = int(caller); target = int(target)

        s = get_state(caller)
        s.exit_count += 1
        s.transitions[target] = s.transitions.get(target, 0) + 1
        get_state(target).entry_count += 1
        transition_counts[(caller, target)] += 1

    # Apply call counts to state entry counts
    for func_str, count in func_call_counts.items():
        try:
            fidx = int(func_str)
            if fidx in states:
                states[fidx].entry_count = max(states[fidx].entry_count, count)
        except (ValueError, TypeError):
            pass

    # Build transition list
    transitions = [
        (fr, to, cnt)
        for (fr, to), cnt in sorted(transition_counts.items(),
                                     key=lambda x: x[1], reverse=True)
    ]

    # Identify initial state
    initial = call_sequence[0].get("target") if call_sequence else None
    if initial is not None:
        initial = int(initial)

    # Identify terminal states (no outgoing transitions)
    terminal = {idx for idx, s in states.items() if not s.transitions}

    # Find hot paths (sequences appearing frequently)
    hot_paths = _find_hot_paths(call_sequence, top_n=5)

    # Detect anomalies
    anomalies = _detect_anomalies(states, transition_counts, call_sequence)

    return StateMachine(
        states      = states,
        transitions = transitions[:50],  # Top 50
        initial     = initial,
        terminal    = terminal,
        hot_paths   = hot_paths,
        anomalies   = anomalies,
    )


def _find_hot_paths(call_sequence: List[Dict],
                    window: int = 3, top_n: int = 5) -> List[List[int]]:
    # Find the most frequent call sequences of length `window`
    if len(call_sequence) < window:
        return []

    path_counts: Counter = Counter()
    calls = [int(c.get("target", 0)) for c in call_sequence
             if c.get("target") is not None]

    for i in range(len(calls) - window + 1):
        path = tuple(calls[i:i+window])
        path_counts[path] += 1

    return [list(p) for p, _ in path_counts.most_common(top_n)]


def _detect_anomalies(states: Dict[int, State],
                       transition_counts: Dict[Tuple[int,int], int],
                       call_sequence: List[Dict]) -> List[Dict]:

    """
    Detect anomalous transitions:
      Transitions that occur very rarely (possible rare code path)
      Functions called far more than their callers (possible loop anomaly)
      Indirect calls that resolve to unexpected targets
    """
    anomalies = []

    # Rare transitions: occur only once in a long sequence
    if len(call_sequence) > 50:
        for (fr, to), count in transition_counts.items():
            if count == 1:
                anomalies.append({
                    "type":        "RARE_TRANSITION",
                    "severity":    "LOW",
                    "description": f"func[{fr}] → func[{to}] occurred only once",
                    "evidence":    f"count=1 in {len(call_sequence)} total calls"
                })
                if len(anomalies) >= 5: break

    # High fan-out: a function calls many different targets
    for idx, state in states.items():
        if len(state.transitions) > 5:
            anomalies.append({
                "type":        "HIGH_FANOUT_STATE",
                "severity":    "MEDIUM",
                "description": f"func[{idx}] calls {len(state.transitions)} different functions",
                "evidence":    f"targets={list(state.transitions.keys())[:6]}"
            })

    return anomalies



#  DYNAMIC CFG RECONSTRUCTION

@dataclass
class DynamicCFG:
    # CFG reconstructed from runtime execution traces
    observed_funcs:    Set[int]      # Functions that actually executed
    observed_edges:    Set[Tuple[int,int]]  # Call edges observed at runtime
    edge_weights:      Dict[Tuple[int,int], int]  # How many times each edge taken
    never_executed:    Set[int]      # Functions in static CFG but never ran
    only_at_runtime:   Set[int]      # Functions ran but not in static call graph
    hot_edges:         List[Tuple[int,int,int]]  # Most-traversed edges


def reconstruct_dynamic_cfg(wasabi_result,
                              static_report) -> DynamicCFG:

    # Reconstruct a dynamic CFG from Wasabi results and compare against the static CFG Observed at runtime

    observed_funcs: Set[int] = set()
    observed_edges: Set[Tuple[int,int]] = set()
    edge_weights: Dict[Tuple[int,int], int] = defaultdict(int)

    call_graph = wasabi_result.call_graph or {}
    for caller_str, callees in call_graph.items():
        try:
            caller = int(caller_str)
            observed_funcs.add(caller)
            for callee in callees:
                callee = int(callee)
                observed_funcs.add(callee)
                observed_edges.add((caller, callee))
        except (ValueError, TypeError):
            pass

    # Edge weights from call sequence
    for call in (wasabi_result.call_sequence or []):
        try:
            caller = int(call.get("caller", -1))
            target = int(call.get("target", -1))
            if caller >= 0 and target >= 0:
                edge_weights[(caller, target)] += 1
        except (ValueError, TypeError):
            pass

    # Static CFG functions
    static_funcs = {fn.index for fn in static_report.functions}
    static_edges: Set[Tuple[int,int]] = set()
    for fn in static_report.functions:
        for target in fn.call_targets:
            static_edges.add((fn.index, target))

    # Divergences
    never_executed  = static_funcs - observed_funcs
    only_at_runtime = observed_funcs - static_funcs

    # Hot edges
    hot_edges = sorted(
        [(fr, to, cnt) for (fr, to), cnt in edge_weights.items()],
        key=lambda x: x[2], reverse=True)[:10]

    return DynamicCFG(
        observed_funcs   = observed_funcs,
        observed_edges   = observed_edges,
        edge_weights     = dict(edge_weights),
        never_executed   = never_executed,
        only_at_runtime  = only_at_runtime,
        hot_edges        = hot_edges,
    )



#  STATIC VS DYNAMIC DIVERGENCE ANALYSIS

@dataclass
class DivergenceResult:

    # Results of comparing static vs dynamic analysis
    static_only_funcs:    Set[int]   # Predicted by static, never ran
    dynamic_only_funcs:   Set[int]   # Ran but not in static CFG
    confirmed_edges:      Set[Tuple[int,int]]  # Static edges confirmed at runtime
    new_edges:            Set[Tuple[int,int]]  # Runtime edges not in static CFG
    dead_code_confirmed:  List[int]  # Functions static said exist, never ran
    hidden_paths:         List[Dict]  # Call paths not predicted by static
    coverage:             float       # % of static functions that actually ran
    findings:             List[Dict]


def analyze_divergence(static_report,
                        dynamic_cfg: DynamicCFG,
                        state_machine: StateMachine) -> DivergenceResult:
    
    # Compare static analysis predictions against dynamic observations. Find dead code, hidden paths, and coverage gaps.
    static_funcs = {fn.index for fn in static_report.functions}
    static_edges: Set[Tuple[int,int]] = set()
    for fn in static_report.functions:
        for target in fn.call_targets:
            static_edges.add((fn.index, target))

    # Divergence sets
    static_only  = static_funcs - dynamic_cfg.observed_funcs
    dynamic_only = dynamic_cfg.observed_funcs - static_funcs
    confirmed    = static_edges & dynamic_cfg.observed_edges
    new_edges    = dynamic_cfg.observed_edges - static_edges

    # Dead code: static predicted, never ran
    dead_code = sorted(static_only)

    # Hidden paths: runtime edges not predicted by static
    hidden_paths = []
    for (fr, to) in new_edges:
        weight = dynamic_cfg.edge_weights.get((fr, to), 0)
        hidden_paths.append({
            "from":   fr,
            "to":     to,
            "count":  weight,
            "desc":   f"Runtime edge func[{fr}]→func[{to}] not in static CFG"
        })
    hidden_paths.sort(key=lambda x: x["count"], reverse=True)

    # Coverage
    coverage = (len(dynamic_cfg.observed_funcs & static_funcs) /
                max(1, len(static_funcs))) * 100

    # Generate findings
    findings = []

    if dead_code and len(dead_code) > 2:
        findings.append({
            "severity":    "MEDIUM",
            "type":        "DEAD_CODE_CONFIRMED",
            "title":       f"{len(dead_code)} functions never executed at runtime",
            "description": "Static analysis found functions that never ran — possible dead code padding or conditional malware",
            "evidence":    f"funcs={dead_code[:8]}"
        })

    if hidden_paths:
        findings.append({
            "severity":    "HIGH",
            "type":        "HIDDEN_CALL_PATHS",
            "title":       f"{len(hidden_paths)} runtime call edges not in static CFG",
            "description": "Dynamic execution revealed call paths invisible to static analysis — obfuscated control flow",
            "evidence":    str(hidden_paths[:3])
        })

    if dynamic_only:
        findings.append({
            "severity":    "HIGH",
            "type":        "UNEXPECTED_FUNCTIONS",
            "title":       f"{len(dynamic_only)} functions executed outside static call graph",
            "description": "Functions ran that static analysis didn't predict — dynamically generated or injected code",
            "evidence":    f"funcs={sorted(dynamic_only)[:8]}"
        })

    if coverage < 30 and len(static_funcs) > 3:
        findings.append({
            "severity":    "MEDIUM",
            "type":        "LOW_COVERAGE",
            "title":       f"Only {coverage:.0f}% of static functions executed",
            "description": "Most code never ran — possible conditional malware or anti-analysis evasion",
            "evidence":    f"ran={len(dynamic_cfg.observed_funcs)} static={len(static_funcs)}"
        })

    if state_machine.anomalies:
        for anom in state_machine.anomalies[:3]:
            if anom.get("severity") in ("HIGH", "MEDIUM"):
                findings.append({
                    "severity":    anom["severity"],
                    "type":        f"STATE_ANOMALY_{anom['type']}",
                    "title":       anom["description"],
                    "description": "Anomalous state transition detected in runtime call sequence",
                    "evidence":    anom.get("evidence", "")
                })

    return DivergenceResult(
        static_only_funcs   = static_only,
        dynamic_only_funcs  = dynamic_only,
        confirmed_edges     = confirmed,
        new_edges           = new_edges,
        dead_code_confirmed = dead_code,
        hidden_paths        = hidden_paths[:10],
        coverage            = coverage,
        findings            = findings,
    )



#  DOT EXPORT FOR DYNAMIC CFG

def dynamic_cfg_to_dot(dynamic_cfg: DynamicCFG,
                        divergence: DivergenceResult,
                        static_report,
                        wasabi_result=None) -> str:

    # Export a rich annotated dynamic CFG DOT graph
    import_map = {i.index: i for i in static_report.imports if i.kind == "func"}
    static_map = {fn.index: fn for fn in static_report.functions}
    filename   = getattr(static_report, 'filename', 'unknown')
    verdict    = getattr(static_report, 'verdict', '?')
    mal_score  = getattr(static_report, 'malice_score', 0)
    start_idx  = getattr(static_report, 'start_idx', -1)
    has_start  = getattr(static_report, 'has_start', False)

    func_calls: Dict[int,int] = {}
    if wasabi_result and wasabi_result.func_call_counts:
        for k, v in wasabi_result.func_call_counts.items():
            try: func_calls[int(k)] = v
            except: pass

    total_instrs = getattr(wasabi_result, 'total_instrs', 0) if wasabi_result else 0
    xor_rt       = getattr(wasabi_result, 'xor_count', 0)    if wasabi_result else 0
    nop_rt       = getattr(wasabi_result, 'nop_count', 0)     if wasabi_result else 0

    lines = [
        'digraph wasmshark_dynamic_cfg {',
        f'  graph [label="WASMShark Dynamic CFG  |  {filename}  |  {verdict} {mal_score:.0f}/100"',
        f'    labelloc=t fontname="Helvetica-Bold" fontsize=13',
        f'    bgcolor="#0d1117" rankdir=TB splines=ortho',
        f'    pad=0.6 nodesep=0.9 ranksep=1.3];',
        '  node [fontname="Courier" fontsize=10 style=filled shape=box',
        '        margin="0.22,0.14" penwidth=2];',
        '  edge [fontname="Courier" fontsize=9 penwidth=2 arrowsize=0.9];',
        '',
        '  subgraph cluster_legend {',
        '    label="Legend" fontcolor="#8b949e" color="#30363d" fontsize=9 style=dashed',
        '    node [fontsize=8 margin="0.1,0.07"]',
        '    LA [label="Suspicious\nExecuted" fillcolor="#da3633" fontcolor=white color="#ff6b6b"]',
        '    LB [label="Clean\nExecuted" fillcolor="#238636" fontcolor=white color="#3fb950"]',
        '    LC [label="Import\nCalled" fillcolor="#1f6feb" fontcolor=white color="#58a6ff" shape=ellipse]',
        '    LD [label="Dead Code\nNever Ran" fillcolor="#161b22" fontcolor="#8b949e" color="#30363d" style="filled,dashed"]',
        '    LE [label="Runtime Only\nUnexpected" fillcolor="#9e6a03" fontcolor=white color="#e3b341"]',
        '    LA -> LB -> LC -> LD -> LE [style=invis]',
        '  }',
        '',
    ]

    all_funcs = (dynamic_cfg.observed_funcs | divergence.static_only_funcs)

    for fidx in sorted(all_funcs):
        fn    = static_map.get(fidx)
        imp   = import_map.get(fidx)
        size  = fn.size  if fn else 0
        susp  = fn.suspicious_score if fn else 0
        xors  = fn.xor_ops if fn else 0
        nops  = fn.nop_max_run if fn else 0
        flags = ",".join((fn.flags or [])[:2]) if fn else ""
        calls = func_calls.get(fidx, 0)
        is_start  = has_start and fidx == start_idx
        is_import = fidx in import_map
        is_dead   = fidx in divergence.static_only_funcs
        is_rt_only= fidx in divergence.dynamic_only_funcs

        star = "★ START  " if is_start else ""

        if is_import:
            name  = f"{imp.module}.{imp.name}" if imp else f"import[{fidx}]"
            label = f"{star}func[{fidx}]  IMPORT\n{name}\ncall-count={calls}"
            fill, border, text, shape = "#1f6feb","#58a6ff","white","ellipse"
        elif is_dead:
            label = f"func[{fidx}]  NEVER RAN\nsize={size}B  score={susp:.0f}\nxor={xors}  nop={nops}"
            fill, border, text, shape = "#161b22","#484f58","#6e7681","box"
            lines.append(f'  fn{fidx} [label="{label}" fillcolor="{fill}" '
                         f'fontcolor="{text}" color="{border}" shape={shape} style="filled,dashed"];')
            continue
        elif is_rt_only:
            label = f"{star}func[{fidx}]  RUNTIME ONLY\nsize={size}B\n⚠ Not in static CFG"
            fill, border, text, shape = "#9e6a03","#e3b341","white","box"
        elif susp > 20:
            label = f"{star}func[{fidx}]  EXECUTED\nsize={size}B  score={susp:.0f}\nxor={xors}  nop={nops}  calls={calls}"
            if flags: label += f"\n[{flags}]"
            fill, border, text, shape = "#da3633","#ff6b6b","white","box"
        else:
            label = f"{star}func[{fidx}]  EXECUTED\nsize={size}B  score={susp:.0f}\nxor={xors}  nop={nops}  calls={calls}"
            fill, border, text, shape = "#238636","#3fb950","white","box"

        bold = ' style="filled,bold"' if is_start else ''
        lines.append(f'  fn{fidx} [label="{label}" fillcolor="{fill}" '
                     f'fontcolor="{text}" color="{border}" shape={shape}{bold}];')

    lines.append('')

    max_w = max((w for w in dynamic_cfg.edge_weights.values()), default=1)
    for (fr, to) in sorted(dynamic_cfg.observed_edges):
        w     = dynamic_cfg.edge_weights.get((fr, to), 1)
        width = max(1.5, min(6.0, 1.5 + (w / max_w) * 4.5))
        is_new= (fr, to) in divergence.new_edges
        color = "#e3b341" if is_new else "#3fb950"
        lbl   = f' label="  {w}x  " fontcolor="{color}"' if w > 1 else ''
        lines.append(f'  fn{fr} -> fn{to} [color="{color}" penwidth={width:.1f}{lbl}];')

    for fidx in divergence.dead_code_confirmed[:10]:
        fn = static_map.get(fidx)
        if fn:
            for t in fn.call_targets:
                lines.append(f'  fn{fidx} -> fn{t} '
                             f'[color="#484f58" style=dashed penwidth=1 '
                             f'label="  static only  " fontcolor="#484f58"];')

    lines.append(
        f'  stats [label="Runtime Stats\n'
        f'Instructions executed: {total_instrs}\n'
        f'XOR ops: {xor_rt}   NOP ops: {nop_rt}\n'
        f'Coverage: {divergence.coverage:.0f}%   Dead funcs: {len(divergence.dead_code_confirmed)}"'
        f' shape=note fillcolor="#161b22" fontcolor="#8b949e" color="#30363d" fontsize=9];')

    lines.append('}')
    return "\n".join(lines)


#  TERMINAL REPORT

R="\033[0m"; B="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; DIM="\033[2m"

def print_dynamic_analysis(state_machine: StateMachine,
                            dynamic_cfg: DynamicCFG,
                            divergence: DivergenceResult):
    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  DYNAMIC STATE MACHINE & CFG ANALYSIS{R}")
    print(f"{CYN}{'─'*72}{R}")

    # State machine summary
    print(f"\n  {B}State Machine{R}")
    print(f"  States (unique functions)  : {len(state_machine.states)}")
    print(f"  Transitions observed       : {len(state_machine.transitions)}")
    print(f"  Initial state              : func[{state_machine.initial}]" if state_machine.initial is not None else "  Initial state              : unknown")
    print(f"  Terminal states            : {sorted(state_machine.terminal)[:8]}")

    if state_machine.hot_paths:
        print(f"\n  Hot execution paths:")
        for i, path in enumerate(state_machine.hot_paths[:3]):
            path_str = " → ".join(f"func[{f}]" for f in path)
            print(f"    {i+1}. {DIM}{path_str}{R}")

    # Dynamic CFG
    print(f"\n  {B}Dynamic CFG{R}")
    print(f"  Functions observed at runtime : {len(dynamic_cfg.observed_funcs)}")
    print(f"  Call edges observed           : {len(dynamic_cfg.observed_edges)}")

    if dynamic_cfg.hot_edges:
        print(f"\n  Hottest call edges:")
        for fr, to, cnt in dynamic_cfg.hot_edges[:5]:
            print(f"    func[{fr}] → func[{to}]  ×{cnt}")

    # Divergence
    print(f"\n  {B}Static vs Dynamic Divergence{R}")
    print(f"  Coverage                   : {divergence.coverage:.1f}% of static functions ran")
    print(f"  Dead code confirmed        : {len(divergence.dead_code_confirmed)} functions never ran")
    print(f"  Hidden call paths          : {len(divergence.hidden_paths)} runtime-only edges")
    print(f"  Unexpected functions       : {len(divergence.dynamic_only_funcs)} outside static CFG")
    print(f"  Confirmed static edges     : {len(divergence.confirmed_edges)}")

    if divergence.hidden_paths:
        print(f"\n  Hidden call paths (not in static CFG):")
        for hp in divergence.hidden_paths[:4]:
            print(f"    {RED}func[{hp['from']}] → func[{hp['to']}]{R}  ×{hp['count']}")

    # Findings
    if divergence.findings:
        print(f"\n  {B}Divergence Findings ({len(divergence.findings)}){R}")
        for f in divergence.findings:
            col = RED if f["severity"] == "HIGH" else YEL
            print(f"  {col}[{f['severity']}]{R} {f['title']}")
            print(f"         {DIM}{f['description']}{R}")



"""
This Builds a runtime state machine and dynamic CFG from Wasabi execution traces.
Compares against static CFG to find divergences : dead code, hidden paths,
and behaviors that only manifest at runtime.

Techniques:
    State machine extraction from call sequence traces
    Dynamic CFG reconstruction from observed transitions
    Static vs dynamic CFG comparison (divergence detection)
    Hot path identification (most-executed code paths)
    Anomalous transition detection (unexpected state changes)
"""
