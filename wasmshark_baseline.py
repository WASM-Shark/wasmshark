#!/usr/bin/env python3

# WASMShark Baseline Profiler

import os, sys, json, argparse, math, hashlib
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field

R="\033[0m"; B="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; DIM="\033[2m"; WHT="\033[97m"



#  FEATURE EXTRACTOR

def extract_features(report) -> Dict[str, float]:
    
    #  Extract a fixed-length numeric feature vector from an AnalysisReport.
    #  All values are normalized to comparable scales.
    
    fns = report.functions
    imps = report.imports

    # Safe division helper
    def safediv(a, b): return a / b if b else 0.0

    # Function stats
    fn_sizes    = [fn.size for fn in fns] or [0]
    fn_xors     = [fn.xor_ops for fn in fns] or [0]
    fn_nops     = [fn.nop_max_run for fn in fns] or [0]
    fn_cyc      = [fn.cyclomatic for fn in fns] or [0]
    fn_instrs   = [fn.instruction_count for fn in fns] or [0]
    fn_indirect = [fn.indirect_calls for fn in fns] or [0]

    # Import categories
    crypto_imps  = sum(1 for i in imps if any(k in i.name.lower() for k in
                       ("sha","keccak","aes","hash","crypt","cipher")))
    network_imps = sum(1 for i in imps if any(k in i.name.lower() for k in
                       ("socket","connect","recv","send","fetch","http")))
    wasi_imps    = sum(1 for i in imps if i.module.startswith("wasi"))
    exec_imps    = sum(1 for i in imps if any(k in i.name.lower() for k in
                       ("exec","system","spawn","fork","shell")))

    # Section entropies
    code_ent = next((s.entropy for s in report.sections if s.name == "CODE"), 0)
    data_ent = next((s.entropy for s in report.sections if s.name == "DATA"), 0)

    features = {
        # Scale / size features
        "file_size_log":      math.log1p(report.file_size),
        "import_count":       len(imps),
        "export_count":       len(report.exports),
        "function_count":     len(fns),
        "data_seg_count":     report.data_segments,
        "custom_sec_count":   len(report.custom_secs),
        "string_count":       len(report.strings),
        "ioc_count":          len(report.iocs),

        # Entropy features
        "file_entropy":       report.file_entropy,
        "code_entropy":       code_ent,
        "data_entropy":       data_ent,
        "chi2_score_log":     math.log1p(report.chi2_score),

        # Function distribution
        "fn_size_mean":       safediv(sum(fn_sizes), len(fn_sizes)),
        "fn_size_max":        max(fn_sizes),
        "fn_xor_mean":        safediv(sum(fn_xors), len(fn_xors)),
        "fn_xor_max":         max(fn_xors),
        "fn_nop_mean":        safediv(sum(fn_nops), len(fn_nops)),
        "fn_nop_max":         max(fn_nops),
        "fn_cyclomatic_mean": safediv(sum(fn_cyc), len(fn_cyc)),
        "fn_instr_mean":      safediv(sum(fn_instrs), len(fn_instrs)),
        "fn_indirect_total":  sum(fn_indirect),

        # Import composition
        "crypto_imp_ratio":   safediv(crypto_imps, max(1, len(imps))),
        "network_imp_ratio":  safediv(network_imps, max(1, len(imps))),
        "wasi_imp_ratio":     safediv(wasi_imps, max(1, len(imps))),
        "exec_imp_ratio":     safediv(exec_imps, max(1, len(imps))),

        # Binary flags
        "has_start_func":     1.0 if report.has_start else 0.0,
        "has_dead_code":      1.0 if report.dead_functions else 0.0,
        "has_crypto_consts":  1.0 if report.crypto_hits else 0.0,
        "has_iocs":           1.0 if report.iocs else 0.0,
        "has_custom_secs":    1.0 if report.custom_secs else 0.0,
    }
    return features



#  BASELINE STATISTICS

@dataclass
class FeatureStats:
    # Per-feature statistics computed from clean corpus
    name:   str
    mean:   float
    std:    float
    min_v:  float
    max_v:  float
    p25:    float
    p75:    float
    count:  int


class BaselineProfile:

    # Statistical profile of known-clean WASM binaries
    # Stores mean + std per feature for z-score anomaly detection

    def __init__(self):
        self.stats: Dict[str, FeatureStats] = {}
        self.sample_count = 0
        self.sample_hashes: List[str] = []
        self._raw: Dict[str, List[float]] = defaultdict(list)

    def add_sample(self, report):
        # Add a clean sample to the baseline
        feats = extract_features(report)
        for name, val in feats.items():
            self._raw[name].append(val)
        self.sample_hashes.append(report.sha256[:8])
        self.sample_count += 1

    def compute(self):
        for name, values in self._raw.items():
            if not values: continue
            n    = len(values)
            mean = sum(values) / n
            std  = math.sqrt(sum((v-mean)**2 for v in values) / max(1,n-1))
            sv   = sorted(values)
            p25  = sv[int(n*0.25)]
            p75  = sv[int(n*0.75)]
            self.stats[name] = FeatureStats(
                name=name, mean=mean, std=std,
                min_v=min(values), max_v=max(values),
                p25=p25, p75=p75, count=n)

    def save(self, path: str):
        data = {
            "sample_count":  self.sample_count,
            "sample_hashes": self.sample_hashes[:20],
            "stats": {
                k: {"mean":v.mean,"std":v.std,"min":v.min_v,"max":v.max_v,
                    "p25":v.p25,"p75":v.p75,"count":v.count}
                for k, v in self.stats.items()
            }
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{GRN}[+] Baseline saved → {path}  ({self.sample_count} samples){R}")

    @classmethod
    def load(cls, path: str) -> 'BaselineProfile':
        with open(path) as f:
            data = json.load(f)
        bp = cls()
        bp.sample_count  = data.get("sample_count", 0)
        bp.sample_hashes = data.get("sample_hashes", [])
        for name, s in data.get("stats", {}).items():
            bp.stats[name] = FeatureStats(
                name=name, mean=s["mean"], std=s["std"],
                min_v=s["min"], max_v=s["max"],
                p25=s["p25"], p75=s["p75"], count=s["count"])
        return bp



#  ANOMALY SCORER

@dataclass
class AnomalyResult:
    anomaly_score:    float           # 0-100
    verdict:          str             # ANOMALOUS / SUSPICIOUS / NORMAL
    top_deviations:   List[Dict]      # features that deviated most
    z_scores:         Dict[str,float] # full z-score breakdown


class BaselineAnomalyScorer:

    # Score a sample against a baseline using z-scores.
    # Features that deviate >2 std from baseline mean are flagged.

    def score(self, report, baseline: BaselineProfile) -> AnomalyResult:
        if not baseline.stats:
            return AnomalyResult(0.0, "NO_BASELINE", [], {})

        feats   = extract_features(report)
        z_scores: Dict[str, float] = {}
        deviations: List[Dict]     = []

        for name, val in feats.items():
            stat = baseline.stats.get(name)
            if not stat: continue
            # Z-score: how many standard deviations from mean
            if stat.std < 0.001:
                # Zero variance in baseline : flag any non-zero value
                z = abs(val - stat.mean) * 10 if abs(val - stat.mean) > 0.1 else 0.0
            else:
                z = abs(val - stat.mean) / stat.std
            z_scores[name] = round(z, 2)
            if z > 1.5:
                deviations.append({
                    "feature":    name,
                    "value":      round(val, 3),
                    "baseline":   round(stat.mean, 3),
                    "z_score":    round(z, 2),
                    "direction":  "ABOVE" if val > stat.mean else "BELOW",
                })

        # Sort by z-score in descending order
        deviations.sort(key=lambda x: x["z_score"], reverse=True)

        # Anomaly score = weighted sum of z-scores above threshold
        HIGH_WEIGHT_FEATURES = {
            "file_entropy", "fn_xor_max", "fn_nop_max", "fn_indirect_total",
            "crypto_imp_ratio", "network_imp_ratio", "exec_imp_ratio",
            "has_iocs", "has_crypto_consts", "ioc_count",
        }
        score = 0.0
        for dev in deviations:
            weight = 2.0 if dev["feature"] in HIGH_WEIGHT_FEATURES else 1.0
            score += min(dev["z_score"] - 1.5, 10.0) * weight

        # Normalize to 0-100
        anomaly_score = min(100.0, round(score * 4, 1))

        if   anomaly_score >= 60: verdict = "ANOMALOUS"
        elif anomaly_score >= 30: verdict = "SUSPICIOUS"
        else:                     verdict = "NORMAL"

        return AnomalyResult(
            anomaly_score  = anomaly_score,
            verdict        = verdict,
            top_deviations = deviations[:10],
            z_scores       = z_scores,
        )

    def print_result(self, result: AnomalyResult, filename: str = ""):
        vc = {"ANOMALOUS":RED+B,"SUSPICIOUS":YEL+B,"NORMAL":GRN+B,"NO_BASELINE":DIM}.get(result.verdict,R)
        print(f"\n{CYN}{'═'*70}{R}")
        print(f"{B}  BASELINE ANOMALY ANALYSIS{' — '+filename if filename else ''}{R}")
        print(f"{CYN}{'═'*70}{R}")
        print(f"  Anomaly Score : {result.anomaly_score:.1f}/100")
        print(f"  Verdict       : {vc}{result.verdict}{R}")

        if result.top_deviations:
            print(f"\n{CYN}{'─'*70}{R}")
            print(f"{B}  TOP DEVIATIONS FROM BASELINE{R}")
            print(f"{CYN}{'─'*70}{R}")
            for dev in result.top_deviations[:8]:
                z    = dev["z_score"]
                col  = RED if z > 4 else (YEL if z > 2 else DIM)
                dirn = "▲" if dev["direction"] == "ABOVE" else "▼"
                print(f"  {col}{dirn} {dev['feature']:<28}{R}"
                      f"  val={dev['value']:<10}  baseline={dev['baseline']:<10}"
                      f"  z={z:.1f}σ")
        print(f"{CYN}{'═'*70}{R}\n")



#  LEARNER

def learn_baseline(clean_dir: str, save_path: str):
    # Scan a directory of known-clean WASM files and build a baseline
    try:
        from wasmshark_core import WASMParser, ScoringEngine
    except ImportError:
        print(f"{RED}[!] wasmshark_core not found in path{R}"); return

    files = list(Path(clean_dir).rglob("*.wasm"))
    if not files:
        print(f"{YEL}No .wasm files in {clean_dir}{R}"); return

    print(f"{CYN}Learning baseline from {len(files)} files...{R}")
    bp = BaselineProfile()
    ok = skip = 0

    for fp in files:
        try:
            with open(fp, 'rb') as f: data = f.read()
            parser = WASMParser(data)
            report = parser.parse()
            report.filename = fp.name
            report = ScoringEngine().score(report)
            # Only include actually clean files
            if report.malice_score < 20 and report.verdict == "CLEAN":
                bp.add_sample(report)
                ok += 1
                print(f"  {GRN}✓{R} {fp.name}")
            else:
                skip += 1
                print(f"  {YEL}skip{R} {fp.name}  (malice={report.malice_score:.0f})")
        except Exception as e:
            skip += 1
            print(f"  {RED}err{R}  {fp.name}  ({e})")

    if bp.sample_count < 2:
        print(f"{RED}[!] Need at least 2 clean samples to build baseline{R}")
        return

    bp.compute()
    bp.save(save_path)
    print(f"\n{GRN}Baseline built: {ok} samples, {skip} skipped{R}")



#  Command Line

def main():
    ap = argparse.ArgumentParser(
        description="WASMShark Baseline Profiler — anomaly detection against clean baseline")
    ap.add_argument("file",          nargs="?",        help="WASM file to score")
    ap.add_argument("--learn",       metavar="DIR",    help="Learn baseline from clean WASM directory")
    ap.add_argument("--save",        metavar="FILE",   help="Save baseline to JSON file")
    ap.add_argument("--baseline","-b",metavar="FILE",  help="Load baseline JSON for scoring")
    ap.add_argument("--scan-dir","-d",metavar="DIR",   help="Score all .wasm files in directory")
    ap.add_argument("--threshold",   type=float, default=40.0,
                                                       help="Anomaly score threshold (default 40)")
    args = ap.parse_args()

    if args.learn:
        save = args.save or "wasmshark_baseline.json"
        learn_baseline(args.learn, save)
        return

    if not args.baseline:
        print(f"{RED}[!] Specify --baseline FILE or --learn DIR{R}")
        ap.print_help(); sys.exit(1)

    try:
        bp = BaselineProfile.load(args.baseline)
        print(f"{CYN}[*] Baseline loaded: {bp.sample_count} samples, "
              f"{len(bp.stats)} features{R}")
    except Exception as e:
        print(f"{RED}[!] Could not load baseline: {e}{R}"); sys.exit(1)

    try:
        from wasmshark_core import WASMParser, ScoringEngine
    except ImportError:
        print(f"{RED}[!] wasmshark_core not found{R}"); sys.exit(1)

    scorer = BaselineAnomalyScorer()

    def score_file(filepath):
        with open(filepath,'rb') as f: data = f.read()
        parser = WASMParser(data)
        report = parser.parse()
        report.filename = os.path.basename(filepath)
        report = ScoringEngine().score(report)
        result = scorer.score(report, bp)
        return report, result

    if args.scan_dir:
        files = list(Path(args.scan_dir).rglob("*.wasm"))
        print(f"{CYN}Scoring {len(files)} files against baseline...{R}\n")
        for fp in files:
            try:
                report, result = score_file(str(fp))
                vc = {"ANOMALOUS":RED+B,"SUSPICIOUS":YEL+B,"NORMAL":GRN+B}.get(result.verdict,R)
                print(f"  {vc}{result.verdict:<12}{R}  score={result.anomaly_score:>5.1f}  "
                      f"malice={report.malice_score:>5.1f}  {fp.name}")
            except Exception as e:
                print(f"  {RED}ERROR{R}  {fp.name}  {e}")

    elif args.file:
        if not os.path.exists(args.file):
            print(f"{RED}File not found: {args.file}{R}"); sys.exit(1)
        report, result = score_file(args.file)
        scorer.print_result(result, args.file)
        sys.exit(1 if result.verdict in ("ANOMALOUS","SUSPICIOUS") else 0)

    else:
        ap.print_help()


if __name__ == "__main__":
    main()





"""
Learn a statistical baseline from known-clean WASM binaries,
then score new samples against that baseline to detect anomalies.

This catches malware that static signatures miss — if a binary
deviates significantly from how legitimate WASM looks, it gets flagged
even if no specific indicator matches.

Usage:
    # Build baseline from clean WASM directory
    python3 wasmshark_baseline.py --learn ./clean_wasm/ --save baseline.json

    # Score a new sample against baseline
    python3 wasmshark_baseline.py --baseline baseline.json sample.wasm

    # Score a directory
    python3 wasmshark_baseline.py --baseline baseline.json -d ./samples/

Baseline features captured:
    - Import count distribution
    - Export count distribution
    - Function count and size distributions
    - Entropy distribution per section type
    - Opcode frequency distributions
    - XOR density distribution
    - NOP density distribution
    - Data segment count and size distributions
    - Custom section presence rate
    - Import category frequency (crypto, network, wasi, etc.)
"""