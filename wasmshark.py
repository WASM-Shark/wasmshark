#!/usr/bin/env python3

# WASMShark CLI 
# Static + Runtime Analysis of WebAssembly binaries


import sys, os, json, time, argparse, csv, hashlib
from pathlib import Path
from datetime import datetime
from wasmshark_core import (
    WASMParser, ScoringEngine, RuleEngine, PluginManager,
    CFGExporter, generate_html_report, to_json_report, to_sarif,
    AnalysisReport, FunctionAnalysis, Finding
)


R="\033[0m";B="\033[1m";RED="\033[91m";YEL="\033[93m";GRN="\033[92m"
CYN="\033[96m";BLU="\033[94m";MAG="\033[95m";DIM="\033[2m";WHT="\033[97m"
def sc(s): return {"CRITICAL":RED+B,"HIGH":RED,"MEDIUM":YEL,"LOW":CYN,"INFO":DIM+WHT}.get(s,R)
def vc(v): return {"MALICIOUS":RED+B,"SUSPICIOUS":YEL+B,"POTENTIALLY_UNWANTED":YEL,"CLEAN":GRN+B}.get(v,R)

def bar(score, w=22):
    f=int(score/100*w); c=RED if score>60 else (YEL if score>30 else GRN)
    return f"{c}[{'█'*f+'░'*(w-f)}]{R}"

# Banner 

def banner():
    print(f"""
{RED}{B}
 ██╗    ██╗ █████╗ ███████╗███╗   ███╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗
 ██║    ██║██╔══██╗██╔════╝████╗ ████║██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝
 ██║ █╗ ██║███████║███████╗██╔████╔██║███████╗███████║███████║██████╔╝█████╔╝
 ██║███╗██║██╔══██║╚════██║██║╚██╔╝██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗
 ╚███╔███╔╝██║  ██║███████║██║ ╚═╝ ██║███████║██║  ██║██║  ██║██║  ██║██║  ██╗
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
{R}{DIM}  WebAssembly Malware Analyzer
  Static · CFG · eBPF Runtime · Rules · Plugins {R}
""")

# Terminal Report 

def print_report(report: AnalysisReport, verbose: bool = False):
    V = vc(report.verdict)
    print(f"\n{CYN}{'═'*72}{R}")
    print(f"{B}  STATIC ANALYSIS REPORT{R}")
    print(f"{CYN}{'═'*72}{R}")
    print(f"  File       : {WHT}{report.filename}{R}")
    print(f"  Size       : {report.file_size:,} bytes")
    print(f"  SHA-256    : {DIM}{report.sha256}{R}")
    print(f"  SHA-1      : {DIM}{report.sha1}{R}")
    print(f"  MD5        : {DIM}{report.md5}{R}")
    print(f"  WASM Ver   : {report.wasm_version}  |  Valid: {'✓' if report.is_valid else '✗'}")
    print(f"  Entropy    : {report.file_entropy:.4f}/8.0  Chi²={report.chi2_score:.1f}")
    print(f"  Functions  : {len(report.functions)}  Imports: {len(report.imports)}  Exports: {len(report.exports)}")
    print(f"  Data segs  : {report.data_segments}  Globals: {len(report.globals)}")
    print(f"  Imphash    : {DIM}{report.imphash}{R}  {DIM}(cluster similar samples){R}")
    if report.dead_functions:
        print(f"  Dead funcs : {YEL}{len(report.dead_functions)} unreachable{R}  {DIM}{report.dead_functions[:8]}{R}")
    if report.has_start:
        print(f"  {YEL}⚡ Start func: func[{report.start_idx}] — auto-executes on load{R}")

    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  VERDICT  &  SCORES{R}")
    print(f"{CYN}{'─'*72}{R}")
    print(f"  {V}▶  {report.verdict}{R}")
    print(f"  Malice Score      : {bar(report.malice_score)}  {report.malice_score:.1f}/100")
    print(f"  Obfuscation Score : {bar(report.obfuscation_score)}  {report.obfuscation_score:.1f}/100")
    print(f"  Complexity Score  : {bar(report.complexity_score)}  {report.complexity_score:.1f}/100")
    print(f"  Confidence        : {bar(report.confidence)}  {report.confidence:.0f}%")

    if report.matched_rules:
        print(f"\n{RED}{B}  ◉ RULE MATCHES ({len(report.matched_rules)}){R}")
        for rule in report.matched_rules:
            sev = rule.get('severity','HIGH')
            tags = ",".join(rule.get('tags',[]))
            print(f"    {sc(sev)}▸ {rule['name']}{R}  {DIM}[{tags}]{R}")
            print(f"      {rule['description']}")

    if report.mitre_tags:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  MITRE ATT&CK TAGS{R}")
        print(f"{CYN}{'─'*72}{R}")
        for t in report.mitre_tags:
            print(f"  {MAG}▸{R} {t}")

    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  SECTIONS ({len(report.sections)}){R}")
    print(f"{CYN}{'─'*72}{R}")
    for s in report.sections:
        ef = f" {RED}⚠ HIGH-ENT{R}" if s.entropy > 7.0 else ""
        print(f"  {s.name:<14} off={s.offset:#08x}  sz={s.size:>9,}  ent={s.entropy:.3f}  χ²={s.chi2:.0f}{ef}")

    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  IMPORTS ({len(report.imports)}){R}")
    print(f"{CYN}{'─'*72}{R}")
    from wasmshark_core import SUSPICIOUS_IMPORTS
    for imp in report.imports:
        flag = ""
        nl   = imp.name.lower()
        for cat, info in SUSPICIOUS_IMPORTS.items():
            if any(p.lower() in nl for p in info["patterns"]):
                col = sc(info["severity"])
                flag = f" {col}[{cat.upper()}]{R}"; break
        print(f"  {imp.module:<28} {imp.name:<32} {DIM}{imp.kind}{R}{flag}")

    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  EXPORTS ({len(report.exports)}){R}")
    print(f"{CYN}{'─'*72}{R}")
    for e in report.exports:
        print(f"  [{e.index:>4}] {e.name:<40} {DIM}{e.kind}{R}")

    if report.crypto_hits:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  CRYPTO CONSTANTS DETECTED ({len(report.crypto_hits)}){R}")
        print(f"{CYN}{'─'*72}{R}")
        for c in report.crypto_hits:
            print(f"  {RED}{c['value']:<14}{R}  {c['name']:<35}  func[{c['func_index']}]  off={c['file_offset']}")

    if report.iocs:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  INDICATORS OF COMPROMISE ({len(report.iocs)}){R}")
        print(f"{CYN}{'─'*72}{R}")
        for ioc_str, ioc_type in report.iocs[:25]:
            print(f"  {YEL}[{ioc_type:<22}]{R}  {ioc_str[:80]}")

    if verbose and report.functions:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  FUNCTION ANALYSIS (top 12 by suspicion){R}")
        print(f"{CYN}{'─'*72}{R}")
        top = sorted(report.functions, key=lambda f: f.suspicious_score, reverse=True)[:12]
        print(f"  {'idx':>5}  {'sz':>7}  {'ins':>7}  {'xor':>5}  {'rot':>5}  {'mr':>5}  {'mw':>5}  "
              f"{'ind':>5}  {'cyc':>5}  {'nop':>6}  {'flags':<30}  {'score':>7}")
        for fn in top:
            tc = RED if fn.suspicious_score > 20 else (YEL if fn.suspicious_score > 5 else GRN)
            ind = f"{RED}{fn.indirect_calls}{R}" if fn.indirect_calls else "0"
            flags_str = ",".join(fn.flags[:3])
            taint_flag = f" {MAG}[TAINT]{R}" if fn.taint else ""
            print(f"  {fn.index:>5}  {fn.size:>7,}  {fn.instruction_count:>7,}  "
                  f"{fn.xor_ops:>5}  {fn.rot_ops:>5}  {fn.memory_reads:>5}  {fn.memory_writes:>5}  "
                  f"{ind:>5}  {fn.cyclomatic:>5}  {fn.nop_max_run:>6}  "
                  f"{flags_str:<30}  {tc}{fn.suspicious_score:>7.1f}{R}{taint_flag}")

    if report.strings:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  EXTRACTED STRINGS ({len(report.strings)}){R}")
        print(f"{CYN}{'─'*72}{R}")
        for s in report.strings[:30]:
            print(f"  {DIM}{s[:100]}{R}")
        if len(report.strings)>30: print(f"  {DIM}... +{len(report.strings)-30} more{R}")

    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  FINDINGS ({len(report.findings)}){R}")
    print(f"{CYN}{'─'*72}{R}")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        fi = [f for f in report.findings if f.severity==sev]
        if not fi: continue
        col = sc(sev)
        print(f"\n  {col}[{sev}] — {len(fi)}{R}")
        for f in fi:
            loc = f" func[{f.func_index}]" if f.func_index >= 0 else ""
            print(f"    {col}▸{R} {B}{f.title}{R}{DIM}{loc}{R}")
            print(f"      {DIM}{f.description}{R}")
            if verbose and f.evidence:
                print(f"      {MAG}{f.evidence}{R}")

    if report.plugin_results:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  PLUGIN RESULTS{R}")
        print(f"{CYN}{'─'*72}{R}")
        for pname, presult in report.plugin_results.items():
            print(f"  {MAG}[{pname}]{R}")
            if isinstance(presult, dict):
                for k,v in presult.items():
                    print(f"    {k}: {v}")

    print(f"\n{CYN}{'═'*72}{R}\n")


# Full analysis pipeline

def analyze(path: str, args) -> AnalysisReport:
    t0 = time.monotonic()
    with open(path,'rb') as f: data = f.read()

    # 1. Parse
    parser = WASMParser(data)
    report = parser.parse()
    report.filename = os.path.basename(path)

    # 2. Score
    report = ScoringEngine().score(report)

    # 2b. Advanced engines
    try:
        from wasmshark_advanced import (
            WASICapabilityAnalyzer, LoopCharacterizer,
            ObfuscationClassifier, FunctionClusterer,
            compute_entropy_timeline, score_string,
            compute_api_abuse_score, detect_section_anomalies,
            ScanHistory
        )
        # WASI capability analysis
        wasi = WASICapabilityAnalyzer().analyze(report.imports)
        import dataclasses
        report.wasi_analysis = dataclasses.asdict(wasi)
        for combo in wasi.dangerous_combos:
            report.findings.append(Finding(
                severity=combo["severity"], category="WASI_CAPABILITY",
                title=f"Dangerous WASI combination: {combo['name']}",
                description=combo["description"],
                evidence=f"capabilities={combo['capabilities_matched']}"))

        # Per-function loop + obfuscation analysis
        loop_char = LoopCharacterizer()
        obf_class  = ObfuscationClassifier()
        for fn in report.functions:
            lp  = loop_char.characterize(fn.disassembly)
            obr = obf_class.classify(fn.disassembly)
            import dataclasses
            report.loop_profiles.append({
                "func_index": fn.index, **dataclasses.asdict(lp)})
            if obr.techniques:
                report.obfuscation_detail.append({
                    "func_index": fn.index,
                    "techniques": obr.techniques,
                    "score":      obr.score,
                    "dominant":   obr.dominant})
                for tech in obr.techniques:
                    if tech.get("severity") in ("HIGH","CRITICAL"):
                        report.findings.append(Finding(
                            severity=tech["severity"], category="OBFUSCATION_DETAIL",
                            title=f"Obfuscation: {tech['technique']} in func[{fn.index}]",
                            description=tech["description"],
                            evidence=tech.get("evidence",""),
                            func_index=fn.index))
            if lp.has_mining_loop:
                report.findings.append(Finding(
                    severity="HIGH", category="LOOP_ANALYSIS",
                    title=f"Mining loop pattern in func[{fn.index}]",
                    description="High XOR + rotate density loop — characteristic of hash-based mining",
                    func_index=fn.index))
            elif lp.has_decode_loop:
                report.findings.append(Finding(
                    severity="MEDIUM", category="LOOP_ANALYSIS",
                    title=f"Decode loop in func[{fn.index}]",
                    description="XOR + load + store loop — string/data decryption routine",
                    func_index=fn.index))

        # Function clustering
        clusters = FunctionClusterer().cluster(report.functions)
        report.function_clusters = clusters
        if len(clusters) > 0 and clusters[0]["size"] > 5:
            report.findings.append(Finding(
                severity="MEDIUM", category="CLUSTERING",
                title=f"{clusters[0]['size']} near-identical functions detected",
                description="Large function cluster — code duplication or obfuscated copies",
                evidence=f"func_indices={clusters[0]['func_indices'][:8]}"))

        # API abuse scoring
        report.api_abuse_score, report.api_abuse_detail =             compute_api_abuse_score(report.imports)

        # Section anomalies
        anomalies = detect_section_anomalies(report.sections, report.file_size)
        report.section_anomalies = [dataclasses.asdict(a) for a in anomalies]
        for anom in anomalies:
            if anom.severity in ("HIGH","CRITICAL"):
                report.findings.append(Finding(
                    severity=anom.severity, category="SECTION_ANOMALY",
                    title=f"Section anomaly: {anom.anomaly_type}",
                    description=anom.description,
                    evidence=anom.evidence))

        # String scoring
        report.string_scores = [
            {"string": s[:80], "score": sc, "reason": reason}
            for s in report.strings
            for sc, reason in [score_string(s)]
            if sc > 30
        ][:20]

        # Entropy timeline
        with open(path, "rb") as f:
            raw = f.read()
        etl = compute_entropy_timeline(raw, block_size=256)
        report.entropy_timeline = etl.blocks[:50]  # First 50 blocks

        # Scan history
        if not getattr(args, 'no_history', False):
            try:
                hist = ScanHistory()
                delta = hist.record(report)
                if delta.get("verdict_changed"):
                    print(f"{YEL}  ⚡ Verdict changed from previous scan!{R}")
                if delta.get("imphash_changed"):
                    print(f"{YEL}  ⚡ Import fingerprint changed — binary modified{R}")
                if delta.get("new_rules"):
                    print(f"{YEL}  ⚡ New rules triggered: {delta['new_rules']}{R}")
            except: pass

        # Re-score with new findings
        report = ScoringEngine().score(report)

    except ImportError:
        pass  # Advanced module not available — continue without it
    except Exception as e:
        import sys
        print(f"  [advanced] {e}", file=sys.stderr)

    # 2c. Threat family classification
    try:
        from wasmshark_classify import ThreatClassifier
        clf_result = ThreatClassifier().classify(report)
        report.plugin_results["threat_classification"] = {
            "family":           clf_result.family,
            "confidence":       clf_result.confidence,
            "evidence":         clf_result.evidence,
            "mitre_techniques": clf_result.mitre_techniques,
            "response_actions": clf_result.response_actions,
            "runner_up":        clf_result.runner_up,
            "runner_up_conf":   clf_result.runner_up_conf,
            "all_scores":       clf_result.all_scores,
        }
    except Exception:
        pass

    # 3. Built-in rules
    re_engine = RuleEngine()
    matched   = re_engine.evaluate(report, RuleEngine.BUILTIN_RULES)

    # 4. External .wsr rules
    if args.rules_dir:
        ext_rules = re_engine.load_rules(args.rules_dir)
        matched  += re_engine.evaluate(report, ext_rules)

    report.matched_rules = matched
    for rule in matched:
        report.findings.append(Finding(
            severity=rule.get("severity","HIGH"), category="RULE_MATCH",
            title=f"Rule: {rule['name']}", description=rule["description"],
            rule_name=rule["name"]))

    # 5. Plugins
    if args.plugins_dir:
        pm = PluginManager(args.plugins_dir)
        pm.load()
        report.plugin_results = pm.run_all(report)

    elapsed = time.monotonic() - t0
    if not args.quiet:
        print(f"{DIM}  Analyzed in {elapsed*1000:.0f}ms{R}")

    return report


# Output writers

def write_outputs(report: AnalysisReport, args):
    stem = Path(report.filename).stem

    if args.json or args.output_json:
        outpath = args.output_json or f"{stem}_wasmshark.json"
        with open(outpath,'w') as f: json.dump(to_json_report(report), f, indent=2)
        print(f"{GRN}[+] JSON report  → {outpath}{R}")

    if args.html or args.output_html:
        outpath = args.output_html or f"{stem}_wasmshark.html"
        with open(outpath,'w') as f: f.write(generate_html_report(report))
        print(f"{GRN}[+] HTML report  → {outpath}{R}")

    if args.sarif or args.output_sarif:
        outpath = args.output_sarif or f"{stem}_wasmshark.sarif"
        with open(outpath,'w') as f: json.dump(to_sarif(report), f, indent=2)
        print(f"{GRN}[+] SARIF report → {outpath}{R}")

    if args.cfg_dir:
        export_cfgs(report, args.cfg_dir)

    if getattr(args, 'wasabi', False):
        try:
            from wasmshark_wasabi import WasabiRunner, correlate_static_dynamic, print_wasabi_report
            print(f"\n{CYN}[*] Running Wasabi dynamic instrumentation...{R}")
            runner  = WasabiRunner(timeout=30)
            wok, nok = runner.check_dependencies()
            if not wok:
                print(f"  {YEL}wasabi not found. Install:{R}")
                print(f"  {DIM}  git clone https://github.com/danleh/wasabi.git{R}")
                print(f"  {DIM}  cd wasabi && cargo install --path .{R}")
            elif not nok:
                print(f"  {YEL}node not found: sudo apt install nodejs{R}")
            else:
                wasabi_result = runner.run(args.file, report)
                correlations  = correlate_static_dynamic(report, wasabi_result)
                print_wasabi_report(wasabi_result, correlations)

                # Dynamic state machine + CFG analysis
                try:
                    from wasmshark_dynamic import (
                        extract_state_machine, reconstruct_dynamic_cfg,
                        analyze_divergence, print_dynamic_analysis,
                        dynamic_cfg_to_dot)
                    if wasabi_result.success and wasabi_result.call_sequence:
                        sm   = extract_state_machine(
                            wasabi_result.call_sequence,
                            wasabi_result.func_call_counts)
                        dcfg = reconstruct_dynamic_cfg(wasabi_result, report)
                        div  = analyze_divergence(report, dcfg, sm)
                        print_dynamic_analysis(sm, dcfg, div)
                        # Export dynamic CFG dot file
                        dot_path = f"{Path(args.file).stem}_dynamic_cfg.dot"
                        dot = dynamic_cfg_to_dot(dcfg, div, report, wasabi_result)
                        with open(dot_path, 'w') as df:
                            df.write(dot)
                        print(f"{GRN}[+] Dynamic CFG → {dot_path}{R}")
                        # Add to JSON report
                        if args.json or args.output_json:
                            outpath = args.output_json or f"{Path(report.filename).stem}_wasmshark.json"
                            if os.path.exists(outpath):
                                with open(outpath) as jf:
                                    jdata = json.load(jf)
                                jdata["dynamic_cfg"] = {
                                    "observed_funcs":    sorted(dcfg.observed_funcs),
                                    "observed_edges":    [list(e) for e in dcfg.observed_edges],
                                    "hot_edges":         dcfg.hot_edges,
                                    "dead_code":         div.dead_code_confirmed,
                                    "hidden_paths":      div.hidden_paths,
                                    "coverage_pct":      div.coverage,
                                    "findings":          div.findings,
                                    "hot_paths":         sm.hot_paths,
                                }
                                with open(outpath, 'w') as jf:
                                    json.dump(jdata, jf, indent=2)
                        # Add divergence findings to report
                        for f in div.findings:
                            report.findings.append(Finding(
                                severity    = f["severity"],
                                category    = f"DYNAMIC_{f['type']}",
                                title       = f["title"],
                                description = f["description"],
                                evidence    = f.get("evidence", "")))
                except ImportError:
                    print(f"  {DIM}wasmshark_dynamic.py not found — skipping state machine analysis{R}")
                except Exception as e:
                    print(f"  {YEL}Dynamic analysis error: {e}{R}")
                if args.json or args.output_json:
                    # Add wasabi results to JSON output
                    import dataclasses
                    from wasmshark_wasabi import WasabiResult
                    wasabi_dict = dataclasses.asdict(wasabi_result)
                    corr_dicts  = correlations
                    outpath = args.output_json or f"{Path(report.filename).stem}_wasmshark.json"
                    if os.path.exists(outpath):
                        with open(outpath) as jf:
                            jdata = json.load(jf)
                        jdata["dynamic_analysis"] = wasabi_dict
                        jdata["correlations"]     = corr_dicts
                        with open(outpath, 'w') as jf:
                            json.dump(jdata, jf, indent=2)
                        print(f"{GRN}[+] Dynamic results added to JSON report{R}")
        except ImportError as e:
            print(f"  {YEL}wasabi module error: {e}{R}")
        except Exception as e:
            print(f"  {YEL}Wasabi error: {e}{R}")

    if getattr(args, "cfg_anomaly", False) or getattr(args, "cfg_overview", None):
        try:
            from plugins.plugin_cfg_anomaly import analyze_module_cfg
            from wasmshark_cfg_viz import export_anomaly_cfgs, export_module_overview
            cfg_results = analyze_module_cfg(report)
            if cfg_results.get("total_findings", 0) > 0:
                print(f"\n{CYN}CFG Anomaly Analysis:{R} {cfg_results['summary']}")
                for f in cfg_results.get("top_findings", [])[:8]:
                    col = sc(f.get("severity","LOW"))
                    print(f"  {col}[{f['severity']}]{R} {f['type']} — func[{f['func_index']}]")
                    print(f"    {DIM}{f['description']}{R}")
            out_dir = getattr(args, "cfg_overview", None) or "./cfgs/"
            written = export_anomaly_cfgs(report, cfg_results, out_dir)
            export_module_overview(report, cfg_results,
                os.path.join(out_dir, "module_overview.dot"))
            print(f"{GRN}[+] CFG anomaly exports → {out_dir}/ ({len(written)} files){R}")
        except Exception as e:
            print(f"{YEL}[CFG anomaly] {e}{R}")


def export_cfgs(report: AnalysisReport, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    exp   = CFGExporter()
    count = 0
    # Export top 20 most suspicious functions
    top = sorted(report.functions, key=lambda f: f.suspicious_score, reverse=True)[:20]
    for fn in top:
        if fn.cfg:
            dot = exp.to_dot(fn)
            dot_path = os.path.join(out_dir, f"func_{fn.index}.dot")
            with open(dot_path,'w') as f: f.write(dot)
            count += 1
            # Try to render if graphviz available
            try:
                import subprocess
                svg_path = dot_path.replace('.dot','.svg')
                subprocess.run(["dot","-Tsvg",dot_path,"-o",svg_path],
                               capture_output=True, timeout=5)
            except: pass
    print(f"{GRN}[+] CFG exports  → {out_dir}/ ({count} functions){R}")


# Directory scan

def scan_dir(directory: str, args) -> list:
    files = [str(p) for p in Path(directory).rglob("*.wasm")]
    if not files:
        print(f"{YEL}No .wasm files in {directory}{R}"); return []

    print(f"{CYN}Scanning {len(files)} WASM files...{R}\n")
    results = []
    for fp in files:
        print(f"  {DIM}→ {fp}{R}")
        try:
            r = analyze(fp, args)
            V = vc(r.verdict)
            print(f"    {V}{r.verdict:<25}{R}  "
                  f"malice={r.malice_score:>5.1f}  "
                  f"obfusc={r.obfuscation_score:>5.1f}  "
                  f"rules={len(r.matched_rules)}  "
                  f"findings={len(r.findings)}")
            results.append(r)
            if args.json:
                write_outputs(r, args)
        except Exception as e:
            print(f"    {RED}ERROR: {e}{R}")
    print(f"\n{CYN}{'═'*60}{R}  SCAN SUMMARY")
    for v in ("MALICIOUS","SUSPICIOUS","POTENTIALLY_UNWANTED","CLEAN"):
        cnt = sum(1 for r in results if r.verdict==v)
        if cnt: print(f"  {vc(v)}{v:<25}{R}: {cnt}")
    return results


# Command Line

def diff_wasm(path_a: str, path_b: str, args):
    
    # Compare two WASM files and report what changed
    print(f"\n{CYN}{'═'*72}{R}")
    print(f"{B}  WASM DIFF: {os.path.basename(path_a)}  vs  {os.path.basename(path_b)}{R}")
    print(f"{CYN}{'═'*72}{R}")

    ra = analyze(path_a, args)
    rb = analyze(path_b, args)

    # Import diff
    imps_a = {f"{i.module}.{i.name}" for i in ra.imports}
    imps_b = {f"{i.module}.{i.name}" for i in rb.imports}
    added   = imps_b - imps_a
    removed = imps_a - imps_b
    print(f"\n{B}  IMPORTS{R}")
    for i in sorted(added):   print(f"  {GRN}+ {i}{R}  {DIM}(new){R}")
    for i in sorted(removed): print(f"  {RED}- {i}{R}  {DIM}(removed){R}")
    if not added and not removed: print(f"  {DIM}No import changes{R}")

    # Export diff
    exps_a = {f"{e.name}({e.kind})" for e in ra.exports}
    exps_b = {f"{e.name}({e.kind})" for e in rb.exports}
    added_e = exps_b - exps_a; removed_e = exps_a - exps_b
    print(f"\n{B}  EXPORTS{R}")
    for e in sorted(added_e):   print(f"  {GRN}+ {e}{R}")
    for e in sorted(removed_e): print(f"  {RED}- {e}{R}")
    if not added_e and not removed_e: print(f"  {DIM}No export changes{R}")

    # Score diff
    print(f"\n{B}  SCORES{R}")
    dm = rb.malice_score - ra.malice_score
    do_ = rb.obfuscation_score - ra.obfuscation_score
    dm_col  = RED if dm  > 0 else (GRN if dm  < 0 else DIM)
    do_col  = RED if do_ > 0 else (GRN if do_ < 0 else DIM)
    print(f"  Malice      : {ra.malice_score:.1f}  →  {rb.malice_score:.1f}  {dm_col}({dm:+.1f}){R}")
    print(f"  Obfuscation : {ra.obfuscation_score:.1f}  →  {rb.obfuscation_score:.1f}  {do_col}({do_:+.1f}){R}")
    print(f"  Verdict     : {vc(ra.verdict)}{ra.verdict}{R}  →  {vc(rb.verdict)}{rb.verdict}{R}")

    # Entropy diff
    de = rb.file_entropy - ra.file_entropy
    de_col = RED if de > 0.3 else (GRN if de < -0.3 else DIM)
    print(f"  Entropy     : {ra.file_entropy:.4f}  →  {rb.file_entropy:.4f}  {de_col}({de:+.4f}){R}")

    # Imphash
    same_imp = ra.imphash == rb.imphash
    print(f"\n{B}  IMPORT FINGERPRINT{R}")
    print(f"  A: {DIM}{ra.imphash}{R}")
    print(f"  B: {DIM}{rb.imphash}{R}")
    print(f"  Match: {GRN}YES — same import profile{R}" if same_imp else f"  Match: {RED}NO — different import profile{R}")

    # Size diff
    ds = rb.file_size - ra.file_size
    print(f"\n{B}  SIZE{R}")
    print(f"  {ra.file_size:,} bytes  →  {rb.file_size:,} bytes  ({ds:+,} bytes)")

    # New rules matched
    rules_a = {r["name"] for r in ra.matched_rules}
    rules_b = {r["name"] for r in rb.matched_rules}
    new_rules = rules_b - rules_a; gone_rules = rules_a - rules_b
    print(f"\n{B}  RULE CHANGES{R}")
    for r in sorted(new_rules):  print(f"  {RED}+ {r}{R}  {DIM}(newly triggered){R}")
    for r in sorted(gone_rules): print(f"  {GRN}- {r}{R}  {DIM}(no longer triggered){R}")
    if not new_rules and not gone_rules: print(f"  {DIM}Same rules matched{R}")

    # Dead code diff
    dead_a = set(ra.dead_functions); dead_b = set(rb.dead_functions)
    new_dead = dead_b - dead_a
    if new_dead:
        print(f"\n{B}  NEW DEAD CODE{R}")
        print(f"  {YEL}{len(new_dead)} new unreachable functions: {sorted(new_dead)[:10]}{R}")

    print(f"\n{CYN}{'═'*72}{R}\n")


def csv_scan(directory: str, args, out_csv: str):
    """Scan all .wasm files in directory and write summary CSV."""
    import csv as csv_mod
    files = [str(p) for p in Path(directory).rglob("*.wasm")]
    if not files:
        print(f"{YEL}No .wasm files in {directory}{R}"); return

    print(f"{CYN}CSV batch scan: {len(files)} files → {out_csv}{R}\n")
    rows = []
    for fp in files:
        print(f"  {DIM}→ {fp}{R}", end="", flush=True)
        try:
            r = analyze(fp, args)
            rows.append({
                "filename":          os.path.basename(fp),
                "path":              fp,
                "verdict":           r.verdict,
                "malice_score":      r.malice_score,
                "obfuscation_score": r.obfuscation_score,
                "complexity_score":  r.complexity_score,
                "confidence":        r.confidence,
                "file_size":         r.file_size,
                "entropy":           r.file_entropy,
                "sha256":            r.sha256,
                "md5":               r.md5,
                "imphash":           r.imphash,
                "imports":           len(r.imports),
                "exports":           len(r.exports),
                "functions":         len(r.functions),
                "dead_functions":    len(r.dead_functions),
                "iocs":              len(r.iocs),
                "crypto_hits":       len(r.crypto_hits),
                "rules_matched":     len(r.matched_rules),
                "rule_names":        "|".join(x["name"] for x in r.matched_rules),
                "findings":          len(r.findings),
                "has_start_func":    r.has_start,
                "data_segments":     r.data_segments,
                "mitre_tags":        "|".join(r.mitre_tags),
            })
            V = vc(r.verdict)
            print(f"  {V}{r.verdict:<22}{R} malice={r.malice_score:.0f}")
        except Exception as e:
            print(f"  {RED}ERROR: {e}{R}")
            rows.append({"filename": os.path.basename(fp), "verdict": "ERROR",
                         "malice_score": -1, "path": fp})

    # Write CSV
    if rows:
        fieldnames = list(rows[0].keys())
        with open(out_csv, 'w', newline='') as f:
            w = csv_mod.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            w.writeheader()
            w.writerows(rows)
        print(f"\n{GRN}[+] CSV report → {out_csv}  ({len(rows)} rows){R}")

        # Summary
        verdicts = [r.get("verdict","?") for r in rows]
        print(f"\n{CYN}{'─'*50}{R}  SUMMARY")
        for v in ("MALICIOUS","SUSPICIOUS","POTENTIALLY_UNWANTED","CLEAN","ERROR"):
            cnt = verdicts.count(v)
            if cnt: print(f"  {vc(v)}{v:<25}{R}: {cnt}")


def main():
    banner()
    ap = argparse.ArgumentParser(
        description="WASMShark v2.0 — WebAssembly Malware Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  Static analysis    : wasmshark.py sample.wasm
  Verbose + CFG      : wasmshark.py sample.wasm -v --cfg-dir ./cfgs/
  All outputs        : wasmshark.py sample.wasm --json --html --sarif
  Directory scan     : wasmshark.py -d ./samples/ --json
  With custom rules  : wasmshark.py sample.wasm --rules ./rules/
  With plugins       : wasmshark.py sample.wasm --plugins ./plugins/
  eBPF runtime (sudo): python3 wasmshark_ebpf.py --exec "wasmtime run sample.wasm"
        """)
    ap.add_argument("file",         nargs="?",              help="WASM file to analyze")
    ap.add_argument("--verbose","-v",action="store_true",   help="Extended output (functions, evidence)")
    ap.add_argument("--quiet",  "-q",action="store_true",   help="Verdict only")
    ap.add_argument("--json",   "-j",action="store_true",   help="Write JSON report")
    ap.add_argument("--html",        action="store_true",   help="Write HTML report")
    ap.add_argument("--sarif",       action="store_true",   help="Write SARIF 2.1 report")
    ap.add_argument("--output-json", metavar="FILE",        help="JSON output path")
    ap.add_argument("--output-html", metavar="FILE",        help="HTML output path")
    ap.add_argument("--output-sarif",metavar="FILE",        help="SARIF output path")
    ap.add_argument("--cfg-dir",     metavar="DIR",         help="Export CFGs as DOT/SVG to DIR")
    ap.add_argument("--rules-dir",   metavar="DIR",         help="Load .wsr rule files from DIR")
    ap.add_argument("--plugins-dir", metavar="DIR",         help="Load Python plugins from DIR")
    ap.add_argument("--scan-dir","-d",metavar="DIR",        help="Scan directory for .wasm files")
    ap.add_argument("--diff",        metavar="FILE_B",      help="Diff FILE against FILE_B  (e.g. --diff b.wasm)")
    ap.add_argument("--classify",    action="store_true",   help="Show threat family classification")
    ap.add_argument("--baseline",    metavar="FILE",        help="Score against baseline JSON")
    ap.add_argument("--yara",        metavar="PATH",        help="Scan with YARA rules (file or dir)")
    ap.add_argument("--yara-builtin",action="store_true",   help="Use built-in WASM YARA rules")
    ap.add_argument("--csv",         metavar="OUT.CSV",     help="Batch scan --scan-dir and write CSV  (use with -d)")
    ap.add_argument("--cfg-anomaly", action="store_true",   help="Run CFG anomaly detection on all functions")
    ap.add_argument("--cfg-overview",metavar="DIR",         help="Export module-level CFG overview DOT to DIR")
    ap.add_argument("--wasabi",       action="store_true",   help="Run Wasabi dynamic instrumentation (needs wasabi + node)")
    ap.add_argument("--disasm",      action="store_true",   help="Show disassembly of top functions")
    ap.add_argument("--func",        type=int, default=-1,  help="Show CFG for specific function index")
    args = ap.parse_args()

    if args.scan_dir and args.csv:
        csv_scan(args.scan_dir, args, args.csv)
        sys.exit(0)

    if args.scan_dir:
        results = scan_dir(args.scan_dir, args)
        sys.exit(1 if any(r.verdict in ("MALICIOUS","SUSPICIOUS") for r in results) else 0)

    if args.diff and args.file:
        if not os.path.exists(args.diff):
            print(f"{RED}Error: diff target not found: {args.diff}{R}"); sys.exit(1)
        diff_wasm(args.file, args.diff, args)
        sys.exit(0)

    if not args.file:
        ap.print_help(); sys.exit(0)

    if not os.path.exists(args.file):
        print(f"{RED}Error: {args.file} not found{R}"); sys.exit(1)

    report = analyze(args.file, args)

    if args.quiet:
        V = vc(report.verdict)
        print(f"\n  {V}{report.verdict}{R}  "
              f"malice={report.malice_score:.1f}  "
              f"obfusc={report.obfuscation_score:.1f}  "
              f"confidence={report.confidence:.0f}%")
    else:
        print_report(report, verbose=args.verbose)

    if args.disasm:
        _print_disassembly(report)

    if args.func >= 0:
        _print_function_cfg(report, args.func)

    write_outputs(report, args)

    # Threat family classification
    if args.classify or not args.quiet:
        tc = report.plugin_results.get("threat_classification")
        if tc:
            try:
                from wasmshark_classify import ClassificationResult, print_classification
                cr = ClassificationResult(**tc)
                print_classification(cr, report.filename)
            except Exception: pass

    # Baseline anomaly scoring
    if getattr(args, 'baseline', None):
        try:
            from wasmshark_baseline import BaselineProfile, BaselineAnomalyScorer
            bp = BaselineProfile.load(args.baseline)
            result = BaselineAnomalyScorer().score(report, bp)
            BaselineAnomalyScorer().print_result(result, report.filename)
        except Exception as e:
            print(f"{YEL}[baseline] {e}{R}")

    # YARA scanning
    if getattr(args, 'yara', None) or getattr(args, 'yara_builtin', False):
        try:
            from wasmshark_yara import YARAScanner, write_builtin_rules
            rules_path = args.yara
            if args.yara_builtin:
                rules_path = write_builtin_rules()
            if rules_path:
                scanner = YARAScanner(rules_path)
                yara_result = scanner.scan_file(args.file)
                scanner.print_result(yara_result)
        except Exception as e:
            print(f"{YEL}[yara] {e}{R}")

    sys.exit(1 if report.verdict in ("MALICIOUS","SUSPICIOUS") else 0)


def _print_disassembly(report: AnalysisReport):
    top = sorted(report.functions, key=lambda f: f.suspicious_score, reverse=True)[:3]
    for fn in top:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  DISASSEMBLY: func[{fn.index}]  score={fn.suspicious_score:.1f}  flags={fn.flags}{R}")
        print(f"{CYN}{'─'*72}{R}")
        for ins in fn.disassembly[:60]:
            taint = f" {MAG}[T]{R}" if ins.tainted else ""
            ops   = " ".join(str(o) for o in ins.operands[:3])
            print(f"  {DIM}{ins.offset:#010x}{R}  {ins.mnemonic:<20} {ops}{taint}")
        if len(fn.disassembly)>60:
            print(f"  {DIM}... +{len(fn.disassembly)-60} more instructions{R}")


def _print_function_cfg(report: AnalysisReport, func_idx: int):
    fn = next((f for f in report.functions if f.index==func_idx), None)
    if not fn:
        print(f"{RED}func[{func_idx}] not found{R}"); return
    exp = CFGExporter()
    dot = exp.to_dot(fn)
    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  CFG DOT: func[{func_idx}]{R}")
    print(f"{CYN}{'─'*72}{R}")
    print(dot)


if __name__ == "__main__":
    main()
