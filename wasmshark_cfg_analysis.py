#!/usr/bin/env python3

# WASMShark CFG Analysis Engine


import math, hashlib
from collections import defaultdict, deque
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field



#  DATA STRUCTURES

@dataclass
class DomTree:
    # Dominator tree for a CFG

    idom:       Dict[int,int]        # immediate dominator: node -> idom
    dominates:  Dict[int,Set[int]]   # node -> set of nodes it dominates
    dom_depth:  Dict[int,int]        # depth in dominator tree
    entry:      int = 0


@dataclass
class NaturalLoop:
    # A natural loop identified by a back edge

    header:      int           # Loop header block id
    back_edge_from: int        # Block that has back edge to header
    body:        Set[int]      # All blocks in the loop body
    nesting_depth: int = 0     # How deeply nested this loop is
    is_inner:    bool = False   # True if no other loops inside this one


@dataclass
class SCC:
    # A Strongly Connected Component

    nodes:       Set[int]
    is_trivial:  bool = False   # SCC of size 1 with no self-loop


@dataclass
class CFGAnalysisResult:
    # Complete structural analysis result for one function
    func_index:         int
    block_count:        int
    edge_count:         int
    cyclomatic:         int

    # Dominance
    dom_tree:           Optional[DomTree]
    dom_tree_depth:     int    # Max depth of dominator tree

    # Loops
    natural_loops:      List[NaturalLoop]
    loop_nesting_max:   int    # Maximum loop nesting depth
    has_irreducible:    bool   # True if CFG has non-natural loops
    irreducible_nodes:  Set[int]

    # SCCs
    sccs:               List[SCC]
    scc_count:          int
    non_trivial_sccs:   int    # SCCs with >1 node (real loops/cycles)

    # Path analysis
    path_count_estimate: float  # Estimated execution paths (capped)
    path_count_exact:    bool   # True if exact, False if capped

    # Structural fingerprint
    cfg_fingerprint:    str     # Hash of CFG shape (topology only)

    # Anomaly scores
    structural_score:   float
    anomalies:          List[Dict]



#  TARJAN'S SCC ALGORITHM

def compute_sccs(adj: Dict[int,List[int]], nodes: List[int]) -> List[SCC]:
    
    # Tarjan's strongly connected components algorithm.
    #   Returns list of SCCs in reverse topological order.

    index_counter = [0]
    stack         = []
    lowlink       = {}
    index         = {}
    on_stack      = {}
    sccs          = []

    def strongconnect(v):
        index[v]   = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack[v] = True

        for w in adj.get(v, []):
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink.get(w, lowlink[v]))
            elif on_stack.get(w):
                lowlink[v] = min(lowlink[v], index[w])

        if lowlink[v] == index[v]:
            scc_nodes = set()
            while True:
                w = stack.pop()
                on_stack[w] = False
                scc_nodes.add(w)
                if w == v: break
            has_self_loop = any(v in adj.get(n,[]) for n in scc_nodes
                                if n == v) if len(scc_nodes)==1 else False
            sccs.append(SCC(
                nodes     = scc_nodes,
                is_trivial = len(scc_nodes)==1 and not has_self_loop))

    # Iterative version to avoid Python recursion limit
    for v in nodes:
        if v not in index:
            # Iterative Tarjan
            call_stack = [(v, iter(adj.get(v, [])))]
            index[v]   = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True

            while call_stack:
                node, children = call_stack[-1]
                try:
                    w = next(children)
                    if w not in index:
                        index[w]   = index_counter[0]
                        lowlink[w] = index_counter[0]
                        index_counter[0] += 1
                        stack.append(w)
                        on_stack[w] = True
                        call_stack.append((w, iter(adj.get(w, []))))
                    elif on_stack.get(w):
                        lowlink[node] = min(lowlink[node], index[w])
                except StopIteration:
                    call_stack.pop()
                    if call_stack:
                        parent = call_stack[-1][0]
                        lowlink[parent] = min(lowlink[parent], lowlink[node])
                    if lowlink[node] == index[node]:
                        scc_nodes = set()
                        while True:
                            w = stack.pop()
                            on_stack[w] = False
                            scc_nodes.add(w)
                            if w == node: break
                        has_self = node in adj.get(node,[])
                        sccs.append(SCC(
                            nodes=scc_nodes,
                            is_trivial=(len(scc_nodes)==1 and not has_self)))

    return sccs



#  DOMINANCE TREE (simplified Cooper et al. algorithm)

def compute_dom_tree(adj: Dict[int,List[int]],
                     pred: Dict[int,List[int]],
                     nodes: List[int],
                     entry: int) -> DomTree:
    
    # Compute immediate dominators using Cooper et al's simple iterative algorithm.

    if not nodes:
        return DomTree(idom={}, dominates={}, dom_depth={}, entry=entry)

    # BFS order for post-order numbering
    bfs_order = []
    visited   = set()
    queue     = deque([entry])
    while queue:
        n = queue.popleft()
        if n in visited: continue
        visited.add(n); bfs_order.append(n)
        for s in adj.get(n, []):
            if s not in visited: queue.append(s)

    post_order = {n: i for i, n in enumerate(reversed(bfs_order))}
    rpo        = list(reversed(bfs_order))

    idom: Dict[int,int] = {entry: entry}

    def intersect(b1, b2):
        while b1 != b2:
            while post_order.get(b1,0) < post_order.get(b2,0):
                b1 = idom.get(b1, b1)
            while post_order.get(b2,0) < post_order.get(b1,0):
                b2 = idom.get(b2, b2)
        return b1

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry: continue
            preds = [p for p in pred.get(b,[]) if p in idom]
            if not preds: continue
            new_idom = preds[0]
            for p in preds[1:]:
                if p in idom:
                    new_idom = intersect(new_idom, p)
            if idom.get(b) != new_idom:
                idom[b] = new_idom
                changed  = True

    # Build dominates map
    dominates: Dict[int,Set[int]] = defaultdict(set)
    for n, d in idom.items():
        if n != d:
            dominates[d].add(n)

    # Compute depths
    dom_depth: Dict[int,int] = {entry: 0}
    queue = deque([entry])
    while queue:
        n = queue.popleft()
        for child in dominates.get(n, set()):
            dom_depth[child] = dom_depth.get(n, 0) + 1
            queue.append(child)

    return DomTree(idom=idom, dominates=dominates,
                   dom_depth=dom_depth, entry=entry)



#  NATURAL LOOP DETECTION

def find_natural_loops(adj: Dict[int,List[int]],
                       dom_tree: DomTree,
                       nodes: List[int]) -> List[NaturalLoop]:
   
    # Find natural loops by identifying back edges. A back edge n→h exists when h dominates n in the dom tree.
    # The natural loop body is all nodes that can reach n without going through h (plus h itself).

    loops = []

    # Find back edges: edges n->h where h dom n
    def dominates(a, b) -> bool:

        curr = b
        seen = set()
        while curr not in seen:
            if curr == a: return True
            seen.add(curr)
            curr = dom_tree.idom.get(curr, curr)
            if curr == dom_tree.entry and a != dom_tree.entry:
                return a == dom_tree.entry
        return False

    back_edges = []
    for n in nodes:
        for h in adj.get(n, []):
            if h in dom_tree.idom and dominates(h, n):
                back_edges.append((n, h))

    # For each back edge, find loop body
    for (tail, header) in back_edges:
        body: Set[int] = {header}
        work_list = [tail]
        while work_list:
            d = work_list.pop()
            if d not in body:
                body.add(d)
                # Add predecessors (reverse graph traversal)
                for n2 in nodes:
                    if d in adj.get(n2, []) and n2 not in body:
                        work_list.append(n2)

        loop = NaturalLoop(
            header       = header,
            back_edge_from = tail,
            body         = body)
        loops.append(loop)

    # Compute nesting depths
    for i, loop_a in enumerate(loops):
        depth = 0
        for j, loop_b in enumerate(loops):
            if i != j and loop_b.body < loop_a.body:
                depth += 1
        loop_a.nesting_depth = depth
        loop_a.is_inner = not any(
            loop_a.body < loop_b.body for jj, loop_b in enumerate(loops) if jj != i
        )

    return loops



#  IRREDUCIBLE CFG DETECTION

def find_irreducible_nodes(sccs: List[SCC],
                           adj: Dict[int,List[int]],
                           dom_tree: DomTree) -> Set[int]:

    """
    A CFG is irreducible if it contains a non-natural loop. This happens when a non-trivial SCC has 
    multiple entry points (nodes reachable from outside the SCC through different paths).

    Irreducible CFGs cannot result from normal structured programming - they indicate obfuscated control flow.
    """

    irreducible = set()
    for scc in sccs:
        if scc.is_trivial or len(scc.nodes) <= 1:
            continue
        # Find SCC entry points: nodes in SCC reachable from outside
        entry_points = set()
        for node in scc.nodes:
            # Check if any predecessor is outside this SCC
            is_entry = False
            for other_scc in sccs:
                if other_scc is scc: continue
                for n in other_scc.nodes:
                    if node in adj.get(n, []):
                        is_entry = True
                        break
            if is_entry:
                entry_points.add(node)
        # If more than one entry point, the SCC is irreducible
        if len(entry_points) > 1:
            irreducible.update(scc.nodes)
    return irreducible



#  PATH COUNT ESTIMATION

def estimate_path_count(adj: Dict[int,List[int]],
                        nodes: List[int],
                        entry: int,
                        max_count: float = 1e9) -> Tuple[float, bool]:

    # Estimate number of distinct execution paths from entry to exits.
    # Uses dynamic programming on DAG (ignoring back edges). Returns (count, is_exact).
    
    if not nodes:
        return 1.0, True

    # Topological sort (ignore back edges detected by DFS)
    visited = set(); topo = []; in_stack = set()
    back_edge_targets = set()

    def dfs_topo(v):
        if v in in_stack:
            back_edge_targets.add(v)
            return
        if v in visited: return
        visited.add(v); in_stack.add(v)
        for w in adj.get(v, []):
            dfs_topo(w)
        in_stack.discard(v)
        topo.append(v)

    for n in nodes:
        if n not in visited:
            dfs_topo(n)
    topo.reverse()

    # DP: paths[v] = number of paths from entry to v
    paths: Dict[int,float] = {entry: 1.0}
    exact = True

    for v in topo:
        if v not in paths: continue
        for w in adj.get(v, []):
            if w in back_edge_targets: continue  # Skip back edges
            paths[w] = paths.get(w, 0.0) + paths[v]
            if paths[w] > max_count:
                paths[w] = max_count
                exact = False

    total = sum(p for n, p in paths.items()
                if not adj.get(n, []) or n in back_edge_targets)
    return min(total, max_count), exact



#  CFG FINGERPRINTING

def compute_cfg_fingerprint(adj: Dict[int,List[int]],
                             nodes: List[int]) -> str:
    
    """
    Compute a structural fingerprint (hash) of the CFG topology.
    2 CFGs with the same shape (isomorphic) get the same fingerprint.

    Approach: canonical BFS traversal encoding the degree sequence
    and edge structure, then MD5 of the canonical string.
    """

    if not nodes:
        return "empty"

    # Encode as sorted degree sequence + edge count pattern
    degree_seq = sorted(
        (len(adj.get(n,[])), sum(1 for m in nodes if n in adj.get(m,[])))
        for n in nodes)
    canonical = f"N{len(nodes)}E{sum(len(adj.get(n,[])) for n in nodes)}"
    canonical += "|" + ",".join(f"{o}-{i}" for o,i in degree_seq)

    return hashlib.md5(canonical.encode()).hexdigest()[:12]



#  MAIN ANALYZER

def analyze_cfg_advanced(cfg, func_index: int) -> Optional[CFGAnalysisResult]:

    # Run full advanced CFG analysis on a single function's CFG. Returns None if CFG is empty or too small to analyze.

    if not cfg or not cfg.blocks or len(cfg.blocks) < 2:
        return None

    blocks = cfg.blocks
    nodes  = [b.id for b in blocks]
    entry  = blocks[0].id

    # Build adjacency and predecessor maps
    adj  = {b.id: list(b.successors) for b in blocks}
    pred = defaultdict(list)
    for b in blocks:
        for s in b.successors:
            pred[s].append(b.id)

    edge_count = sum(len(v) for v in adj.values())

    sccs     = compute_sccs(adj, nodes)
    non_triv = [s for s in sccs if not s.is_trivial]

    # Dominance tree
    try:
        dom_tree  = compute_dom_tree(adj, dict(pred), nodes, entry)
        dom_depth = max(dom_tree.dom_depth.values()) if dom_tree.dom_depth else 0
    except Exception:
        dom_tree  = None
        dom_depth = 0

    # Natural loops
    nat_loops    = []
    max_nesting  = 0
    if dom_tree:
        try:
            nat_loops   = find_natural_loops(adj, dom_tree, nodes)
            max_nesting = max((l.nesting_depth for l in nat_loops), default=0)
        except Exception:
            pass

    # Irreducible nodes
    irreducible = set()
    if dom_tree:
        try:
            irreducible = find_irreducible_nodes(sccs, adj, dom_tree)
        except Exception:
            pass

    # Path count
    try:
        path_count, path_exact = estimate_path_count(adj, nodes, entry)
    except Exception:
        path_count  = 1.0
        path_exact  = False

    # CFG fingerprint
    fingerprint = compute_cfg_fingerprint(adj, nodes)

    # Anomaly scoring
    anomalies = []
    score     = 0.0

    # Irreducible control flow
    if irreducible:
        score += 35
        anomalies.append({
            "type":        "IRREDUCIBLE_CFG",
            "severity":    "HIGH",
            "description": (f"{len(irreducible)} nodes in irreducible CFG regions — "
                           f"non-structured control flow, strong obfuscation indicator"),
            "evidence":    f"nodes={sorted(irreducible)[:5]}"
        })

    # High nesting depth
    if max_nesting >= 4:
        score += 20
        anomalies.append({
            "type":        "DEEP_LOOP_NESTING",
            "severity":    "HIGH",
            "description": f"Loop nesting depth {max_nesting} — abnormally deep for legitimate code",
            "evidence":    f"max_nesting={max_nesting} loops={len(nat_loops)}"
        })
    elif max_nesting == 3:
        score += 10
        anomalies.append({
            "type":        "ELEVATED_LOOP_NESTING",
            "severity":    "MEDIUM",
            "description": f"Loop nesting depth {max_nesting}",
            "evidence":    f"max_nesting={max_nesting}"
        })

    # High path count (exponential path explosion)
    if path_count >= 1e6:
        score += 25
        anomalies.append({
            "type":        "PATH_EXPLOSION",
            "severity":    "HIGH",
            "description": (f"Estimated {path_count:.2e} execution paths — "
                           f"exponential path complexity, typical of obfuscated code"),
            "evidence":    f"paths≥{path_count:.2e} exact={path_exact}"
        })
    elif path_count >= 1000:
        score += 10
        anomalies.append({
            "type":        "HIGH_PATH_COUNT",
            "severity":    "MEDIUM",
            "description": f"~{path_count:.0f} distinct execution paths",
            "evidence":    f"paths={path_count:.0f}"
        })

    # Large non-trivial SCCs (complex cyclic subgraphs)
    for scc in non_triv:
        if len(scc.nodes) > 5:
            score += 15
            anomalies.append({
                "type":        "LARGE_SCC",
                "severity":    "HIGH",
                "description": (f"Strongly connected component with {len(scc.nodes)} nodes — "
                               f"complex cyclic control flow"),
                "evidence":    f"nodes={sorted(scc.nodes)[:6]}"
            })

    # High dominator tree depth
    if dom_depth > 8:
        score += 15
        anomalies.append({
            "type":        "DEEP_DOM_TREE",
            "severity":    "MEDIUM",
            "description": f"Dominator tree depth {dom_depth} — deeply nested control structure",
            "evidence":    f"dom_depth={dom_depth}"
        })

    # Many loops relative to block count
    loop_ratio = len(nat_loops) / max(1, len(nodes))
    if loop_ratio > 0.3 and len(nat_loops) > 3:
        score += 10
        anomalies.append({
            "type":        "HIGH_LOOP_DENSITY",
            "severity":    "MEDIUM",
            "description": f"{len(nat_loops)} loops in {len(nodes)} blocks ({loop_ratio*100:.0f}% loop density)",
            "evidence":    f"loops={len(nat_loops)} blocks={len(nodes)}"
        })

    return CFGAnalysisResult(
        func_index          = func_index,
        block_count         = len(nodes),
        edge_count          = edge_count,
        cyclomatic          = cfg.cyclomatic_complexity,
        dom_tree            = dom_tree,
        dom_tree_depth      = dom_depth,
        natural_loops       = nat_loops,
        loop_nesting_max    = max_nesting,
        has_irreducible     = bool(irreducible),
        irreducible_nodes   = irreducible,
        sccs                = sccs,
        scc_count           = len(sccs),
        non_trivial_sccs    = len(non_triv),
        path_count_estimate = path_count,
        path_count_exact    = path_exact,
        cfg_fingerprint     = fingerprint,
        structural_score    = min(100.0, score),
        anomalies           = anomalies,
    )



#  MODULE-LEVEL ANALYSIS


def analyze_module_cfgs(report) -> Dict:
    # Run advanced CFG analysis on all functions and return summary
    results      = []
    all_anomalies = []
    fingerprints  = {}

    for fn in report.functions:
        if not fn.cfg or not fn.cfg.blocks:
            continue
        result = analyze_cfg_advanced(fn.cfg, fn.index)
        if result is None:
            continue
        results.append(result)
        all_anomalies.extend(result.anomalies)
        fingerprints[fn.index] = result.cfg_fingerprint

    if not results:
        return {"summary": "No CFGs available for advanced analysis"}

    # Find CFG clones (same fingerprint = structurally identical functions)
    fp_groups: Dict[str, List[int]] = defaultdict(list)
    for fn_idx, fp in fingerprints.items():
        fp_groups[fp].append(fn_idx)
    clones = {fp: idxs for fp, idxs in fp_groups.items() if len(idxs) > 1}

    # Module-wide stats
    irreducible_fns = [r for r in results if r.has_irreducible]
    max_paths       = max(r.path_count_estimate for r in results)
    max_nesting     = max(r.loop_nesting_max    for r in results)
    max_cyc         = max(r.cyclomatic          for r in results)
    avg_cyc         = sum(r.cyclomatic          for r in results) / len(results)

    # Severity counts
    sev = {"HIGH":0,"MEDIUM":0,"LOW":0}
    for a in all_anomalies:
        sev[a.get("severity","LOW")] = sev.get(a.get("severity","LOW"),0)+1

    # Clone anomaly (many identical CFG shapes = obfuscation padding)
    clone_anomalies = []
    for fp, idxs in clones.items():
        if len(idxs) > 4:
            clone_anomalies.append({
                "type":        "CFG_CLONE_CLUSTER",
                "severity":    "MEDIUM",
                "description": f"{len(idxs)} functions share identical CFG shape (fingerprint={fp})",
                "evidence":    f"func_indices={idxs[:8]}"
            })
    all_anomalies.extend(clone_anomalies)

    top_results = sorted(results, key=lambda r: r.structural_score, reverse=True)[:10]

    return {
        "functions_analyzed":    len(results),
        "total_anomalies":       len(all_anomalies),
        "severity_counts":       sev,
        "irreducible_functions": len(irreducible_fns),
        "max_path_count":        max_paths,
        "max_loop_nesting":      max_nesting,
        "max_cyclomatic":        max_cyc,
        "avg_cyclomatic":        round(avg_cyc, 2),
        "cfg_clone_groups":      len(clones),
        "top_anomalous": [{
            "func_index":     r.func_index,
            "structural_score": r.structural_score,
            "cyclomatic":     r.cyclomatic,
            "dom_depth":      r.dom_tree_depth,
            "loops":          len(r.natural_loops),
            "loop_nesting":   r.loop_nesting_max,
            "irreducible":    r.has_irreducible,
            "path_count":     r.path_count_estimate,
            "scc_count":      r.non_trivial_sccs,
            "fingerprint":    r.cfg_fingerprint,
            "anomalies":      r.anomalies,
        } for r in top_results],
        "clone_groups":   {fp: idxs for fp, idxs in clones.items()},
        "all_anomalies":  sorted(all_anomalies,
                                  key=lambda a: {"HIGH":0,"MEDIUM":1,"LOW":2}.get(
                                      a.get("severity","LOW"),3))[:20],
        "summary": (f"{len(all_anomalies)} CFG anomalies across {len(results)} functions — "
                   f"{len(irreducible_fns)} irreducible, max_cyc={max_cyc}, "
                   f"max_nesting={max_nesting}, max_paths≈{max_paths:.2e}")
    }


"""
Structural analysis of WASM function control flow graphs.

Algorithms implemented:
  - Lengauer-Tarjan dominance tree (O(n log n))
  - Natural loop detection via back-edge analysis
  - Irreducible CFG detection (non-natural loops)
  - Approximate path count (execution path complexity)
  - CFG structural fingerprinting (hash of graph shape)
  - Loop nesting depth and loop body size
  - Strongly Connected Component (SCC) analysis via Tarjan's algorithm
  - Single-entry single-exit (SESE) region detection

All purely structural — no attack technique content.
"""