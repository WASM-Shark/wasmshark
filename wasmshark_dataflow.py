#!/usr/bin/env python3

# WASMShark Inter-Procedural Data Flow Analyzer


from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque



#  TAINT SOURCE / SINK CLASSIFICATION

# Imports that introduce tainted (externally-controlled) data
TAINT_SOURCES: Dict[str, str] = {
    # WASI
    "fd_read":         "FILE_READ",
    "sock_recv":       "NETWORK_RECV",
    "sock_accept":     "NETWORK_ACCEPT",
    "environ_get":     "ENVIRONMENT",
    "args_get":        "CMDLINE_ARGS",
    "random_get":      "RANDOMNESS",
    "clock_time_get":  "TIMING",
    # General
    "recv":            "NETWORK_RECV",
    "read":            "FILE_READ",
    "fread":           "FILE_READ",
    "getenv":          "ENVIRONMENT",
    "fgets":           "FILE_READ",
    "scanf":           "STDIN",
    "XMLHttpRequest":  "NETWORK_XHR",
    "fetch":           "NETWORK_FETCH",
    "WebSocket":       "NETWORK_WS",
    "localStorage":    "BROWSER_STORAGE",
    "sessionStorage":  "BROWSER_STORAGE",
    "document.cookie": "BROWSER_COOKIE",
    "getrandom":       "RANDOMNESS",
}

# Imports that consume data in a dangerous way
TAINT_SINKS: Dict[str, Tuple[str, str]] = {
    # (category, severity)
    "fd_write":        ("FILE_WRITE",    "HIGH"),
    "path_rename":     ("FILE_RENAME",   "HIGH"),
    "path_unlink":     ("FILE_DELETE",   "HIGH"),
    "sock_send":       ("NETWORK_SEND",  "HIGH"),
    "send":            ("NETWORK_SEND",  "HIGH"),
    "sendto":          ("NETWORK_SEND",  "HIGH"),
    "write":           ("FILE_WRITE",    "MEDIUM"),
    "fwrite":          ("FILE_WRITE",    "MEDIUM"),
    "exec":            ("EXECUTION",     "CRITICAL"),
    "system":          ("EXECUTION",     "CRITICAL"),
    "popen":           ("EXECUTION",     "CRITICAL"),
    "eval":            ("CODE_EVAL",     "CRITICAL"),
    "XMLHttpRequest":  ("NETWORK_SEND",  "HIGH"),
    "fetch":           ("NETWORK_SEND",  "HIGH"),
    "beacon":          ("NETWORK_SEND",  "HIGH"),
    "sha256_block":    ("CRYPTO_HASH",   "MEDIUM"),
    "keccak256":       ("CRYPTO_HASH",   "MEDIUM"),
    "randomx_hash":    ("CRYPTO_HASH",   "HIGH"),
}

# Dangerous source → sink combinations
DANGEROUS_FLOWS: List[Tuple[str, str, str, str]] = [
    # (source_type, sink_type, threat_name, severity)
    ("NETWORK_RECV",  "FILE_WRITE",   "NETWORK_TO_DISK",     "HIGH"),
    ("NETWORK_RECV",  "EXECUTION",    "NETWORK_TO_EXEC",     "CRITICAL"),
    ("ENVIRONMENT",   "NETWORK_SEND", "ENV_EXFILTRATION",    "CRITICAL"),
    ("ENVIRONMENT",   "FILE_WRITE",   "ENV_TO_DISK",         "HIGH"),
    ("FILE_READ",     "NETWORK_SEND", "FILE_EXFILTRATION",   "CRITICAL"),
    ("RANDOMNESS",    "FILE_WRITE",   "RANDOM_TO_DISK",      "HIGH"),
    ("RANDOMNESS",    "CRYPTO_HASH",  "KEY_GENERATION",      "MEDIUM"),
    ("BROWSER_COOKIE","NETWORK_SEND", "COOKIE_THEFT",        "CRITICAL"),
    ("BROWSER_STORAGE","NETWORK_SEND","STORAGE_EXFILTRATION","CRITICAL"),
    ("NETWORK_XHR",   "CODE_EVAL",   "XHR_CODE_INJECTION",  "CRITICAL"),
    ("NETWORK_RECV",  "CRYPTO_HASH",  "REMOTE_KEY_MATERIAL", "HIGH"),
    ("ENVIRONMENT",   "CRYPTO_HASH",  "ENV_KEY_DERIVATION",  "HIGH"),
    ("STDIN",         "EXECUTION",    "STDIN_INJECTION",     "CRITICAL"),
    ("FILE_READ",     "EXECUTION",    "FILE_TO_EXEC",        "CRITICAL"),
    ("TIMING",        "NETWORK_SEND", "TIMING_EXFIL",        "MEDIUM"),
    ("FILE_READ",     "FILE_WRITE",   "FILE_ENCRYPT_PATTERN","HIGH"),
    ("NETWORK_RECV",  "FILE_RENAME",  "RANSOM_PATTERN",      "CRITICAL"),
    ("RANDOMNESS",    "FILE_RENAME",  "RANSOM_KEY_RENAME",   "CRITICAL"),
]



#  DATA STRUCTURES

@dataclass
class TaintSource:
    import_index: int
    import_name:  str
    source_type:  str


@dataclass
class TaintSink:
    import_index: int
    import_name:  str
    sink_type:    str
    severity:     str


@dataclass
class TaintChain:
    source:       TaintSource
    sink:         TaintSink
    call_path:    List[int]   # function indices from source to sink
    path_depth:   int
    threat_name:  str
    severity:     str
    description:  str


@dataclass
class DataFlowResult:
    sources:      List[TaintSource]
    sinks:        List[TaintSink]
    chains:       List[TaintChain]
    reachability: Dict[int, Set[int]]  # func -> set of reachable import indices
    summary:      str



#  INTER-PROCEDURAL DATA FLOW ENGINE

class InterProceduralDataFlow:

    # Builds a call graph from WASMShark function analysis results, then performs forward taint propagation to find source→sink chains.


    def analyze(self, report) -> DataFlowResult:
        # Build index maps
        import_map: Dict[int, object] = {
            i.index: i for i in report.imports if i.kind == "func"
        }
        import_count = len(import_map)

        # Identify sources and sinks in imports
        sources: List[TaintSource] = []
        sinks:   List[TaintSink]   = []

        for imp in report.imports:
            if imp.kind != "func": continue
            nl = imp.name.lower()
            for pattern, src_type in TAINT_SOURCES.items():
                if pattern.lower() in nl:
                    sources.append(TaintSource(
                        import_index = imp.index,
                        import_name  = f"{imp.module}.{imp.name}",
                        source_type  = src_type))
                    break
            for pattern, (sink_type, sev) in TAINT_SINKS.items():
                if pattern.lower() in nl:
                    sinks.append(TaintSink(
                        import_index = imp.index,
                        import_name  = f"{imp.module}.{imp.name}",
                        sink_type    = sink_type,
                        severity     = sev))
                    break

        if not sources or not sinks:
            return DataFlowResult(
                sources=sources, sinks=sinks,
                chains=[], reachability={},
                summary=f"No flow: {len(sources)} sources, {len(sinks)} sinks")

        # Build call graph: func_index -> set of called indices
        call_graph: Dict[int, Set[int]] = defaultdict(set)
        for fn in report.functions:
            for target in fn.call_targets:
                call_graph[fn.index].add(target)

        # Forward reachability: for each function, which imports can it reach?
        reachability: Dict[int, Set[int]] = {}
        sink_indices = {s.import_index for s in sinks}

        for fn in report.functions:
            reachable = set()
            visited   = set()
            queue     = deque([fn.index])
            while queue:
                curr = queue.popleft()
                if curr in visited: continue
                visited.add(curr)
                # If this is an import index, record it
                if curr < import_count:
                    reachable.add(curr)
                # Continue traversal
                for child in call_graph.get(curr, set()):
                    if child not in visited:
                        queue.append(child)
            reachability[fn.index] = reachable

        # Find source→sink chains
        chains: List[TaintChain] = []

        for src in sources:
            # Find all functions that call this source
            src_callers = {fn.index for fn in report.functions
                           if src.import_index in fn.call_targets}

            for caller_idx in src_callers:
                # BFS from caller to any sink
                for sink in sinks:
                    if sink.import_index == src.import_index:
                        continue  # Same import, skip
                    # Check reachability
                    if sink.import_index in reachability.get(caller_idx, set()):
                        # Reconstruct path (simplified)
                        path = self._find_path(
                            caller_idx, sink.import_index,
                            call_graph, max_depth=8)

                        if path is None:
                            path = [caller_idx, sink.import_index]

                        # Check if this is a known dangerous flow
                        threat_name = "DATA_FLOW"
                        severity    = "MEDIUM"
                        description = (f"Data from {src.source_type} reaches "
                                       f"{sink.sink_type}")

                        for s_type, k_type, t_name, t_sev in DANGEROUS_FLOWS:
                            if (s_type == src.source_type and
                                k_type == sink.sink_type):
                                threat_name = t_name
                                severity    = t_sev
                                description = (
                                    f"{src.source_type} → {sink.sink_type}: "
                                    f"{t_name.replace('_',' ')}")
                                break

                        # Avoid duplicates
                        key = f"{src.import_index}:{sink.import_index}"
                        if not any(f"{c.source.import_index}:{c.sink.import_index}"
                                   == key for c in chains):
                            chains.append(TaintChain(
                                source     = src,
                                sink       = sink,
                                call_path  = path,
                                path_depth = len(path),
                                threat_name = threat_name,
                                severity    = severity,
                                description = description))

        # Sort by severity
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        chains.sort(key=lambda c: sev_order.get(c.severity, 9))

        critical = sum(1 for c in chains if c.severity == "CRITICAL")
        summary  = (f"{len(chains)} data flow chains: "
                    f"{critical} CRITICAL, {len(sources)} sources, {len(sinks)} sinks")

        return DataFlowResult(
            sources      = sources,
            sinks        = sinks,
            chains       = chains[:20],  # Top 20
            reachability = reachability,
            summary      = summary)

    def _find_path(self, start: int, target: int,
                   graph: Dict[int, Set[int]],
                   max_depth: int = 8) -> Optional[List[int]]:

        # BFS path from start to target in call graph
        queue    = deque([(start, [start])])
        visited  = set()
        while queue:
            curr, path = queue.popleft()
            if curr in visited or len(path) > max_depth: continue
            visited.add(curr)
            if curr == target:
                return path
            for child in graph.get(curr, set()):
                if child not in visited:
                    queue.append((child, path + [child]))
        return None



#  REPORT FORMATTER

def format_dataflow_terminal(result: DataFlowResult) -> str:
    if not result.chains:
        return f"  No inter-procedural taint chains found ({result.summary})\n"

    lines = [f"\n  {result.summary}"]
    sev_colors = {
        "CRITICAL": "\033[91m\033[1m",
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[96m"
    }
    R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"

    for i, chain in enumerate(result.chains[:10]):
        col = sev_colors.get(chain.severity, "")
        path_str = " → ".join(
            f"func[{p}]" if p >= 10 else f"import[{p}]"
            for p in chain.call_path[:6])
        lines.append(
            f"\n  {col}[{chain.severity}] {chain.threat_name}{R}")
        lines.append(
            f"    {B}{chain.description}{R}")
        lines.append(
            f"    Source : {DIM}{chain.source.import_name} ({chain.source.source_type}){R}")
        lines.append(
            f"    Sink   : {DIM}{chain.sink.import_name} ({chain.sink.sink_type}){R}")
        lines.append(
            f"    Path   : {DIM}{path_str}{R}  (depth={chain.path_depth})")

    return "\n".join(lines)


def format_dataflow_html(result: DataFlowResult) -> str:
    if not result.chains:
        return f"<p style='color:#888'>{result.summary}</p>"

    sev_col = {"CRITICAL":"#ff3333","HIGH":"#ff6600","MEDIUM":"#ffaa00","LOW":"#44aaff"}
    rows = ""
    for chain in result.chains[:15]:
        col   = sev_col.get(chain.severity, "#aaa")
        path  = " → ".join(
            f"func[{p}]" if p >= 10 else f"import[{p}]"
            for p in chain.call_path[:5])
        rows += (
            f'<tr>'
            f'<td style="color:{col}">{chain.severity}</td>'
            f'<td><strong>{chain.threat_name}</strong></td>'
            f'<td>{chain.description}</td>'
            f'<td><code>{chain.source.import_name}</code></td>'
            f'<td><code>{chain.sink.import_name}</code></td>'
            f'<td style="font-size:0.85em;color:#888">{path}</td>'
            f'</tr>')

    return (
        f'<p><strong>Total chains: {len(result.chains)}</strong> — {result.summary}</p>'
        f'<table>'
        f'<tr><th>Severity</th><th>Threat</th><th>Description</th>'
        f'<th>Source</th><th>Sink</th><th>Call Path</th></tr>'
        f'{rows}</table>')
