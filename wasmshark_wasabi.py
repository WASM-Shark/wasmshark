#!/usr/bin/env python3

# WASMShark Wasabi Integration

# Integrates Wasabi dynamic instrumentation with WASMShark static analysis.

import os, sys, json, subprocess, tempfile, hashlib
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field



#  WASABI ANALYSIS SCRIPT

WASABI_ANALYSIS_JS = r"""
// WASMShark Dynamic Analysis via Wasabi - Enhanced v2.0
// Collects rich runtime behavioral data for security analysis

const WASMSharkAnalysis = {
    instrCounts:    {},
    callGraph:      {},
    callSequence:   [],   // Order functions were called
    indirectCalls:  [],
    memReads:       [],
    memWrites:      [],
    memGrows:       [],
    globalReads:    {},   // global index -> read count
    globalWrites:   {},   // global index -> write count
    constValues:    [],   // Interesting constant values seen
    branches:       { taken: 0, notTaken: 0 },
    xorCount:       0,
    rotCount:       0,
    shiftCount:     0,
    andCount:       0,
    funcCallCounts: {},
    funcExecOrder:  [],   // First execution order of each func
    seenFuncs:      new Set(),
    startFunc:      null,
    errors:         [],
    suspiciousConsts: [],  // Known crypto/magic constants seen at runtime

    // Known suspicious constant values
    SUSPICIOUS_CONSTS: new Set([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,  // SHA-256 IVs
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  // ChaCha20 sigma
        0xdeadbeef, 0xcafebabe, 0x13371337, 0xdeadc0de,  // Magic markers
        0xEDB88320,  // CRC32
        0x9E3779B9,  // XTEA delta
    ]),

    _loc(location) {
        return `${location.func}:${location.instr}`;
    },

    _trackFunc(funcIdx) {
        if (!this.seenFuncs.has(funcIdx)) {
            this.seenFuncs.add(funcIdx);
            this.funcExecOrder.push(funcIdx);
        }
    },

    start(location) {
        this.startFunc = location.func;
        this._trackFunc(location.func);
    },

    // Globals tracking
    global_get(location, globalIndex, value) {
        this.globalReads[globalIndex] = (this.globalReads[globalIndex] || 0) + 1;
    },

    global_set(location, globalIndex, value) {
        this.globalWrites[globalIndex] = (this.globalWrites[globalIndex] || 0) + 1;
    },

    // Constants — check for suspicious values
    const_(location, op, val) {
        this.instrCounts[op] = (this.instrCounts[op] || 0) + 1;
        const numVal = Number(val);
        if (this.SUSPICIOUS_CONSTS.has(numVal >>> 0)) {
            this.suspiciousConsts.push({
                value: (numVal >>> 0).toString(16),
                op, location: this._loc(location)
            });
        }
    },

    if_(location, condition) {
        if (condition) this.branches.taken++;
        else           this.branches.notTaken++;
    },

    br_if(location, condition, target) {
        if (condition) this.branches.taken++;
        else           this.branches.notTaken++;
    },

    load(location, op, memArg, value) {
        this.instrCounts[op] = (this.instrCounts[op] || 0) + 1;
        if (this.memReads.length < 1000) {
            this.memReads.push({ op, offset: memArg.offset });
        }
    },

    store(location, op, memArg, value) {
        this.instrCounts[op] = (this.instrCounts[op] || 0) + 1;
        if (this.memWrites.length < 1000) {
            this.memWrites.push({ op, offset: memArg.offset });
        }
    },

    memory_size(location, currentSize) {
        this.instrCounts['memory.size'] = (this.instrCounts['memory.size'] || 0) + 1;
    },

    memory_grow(location, pages, result) {
        this.instrCounts['memory.grow'] = (this.instrCounts['memory.grow'] || 0) + 1;
        this.memGrows.push({ pages: Number(pages), result: Number(result) });
    },

    binop(location, op, left, right, result) {
        this.instrCounts[op] = (this.instrCounts[op] || 0) + 1;
        if (op === 'i32.xor' || op === 'i64.xor') this.xorCount++;
        if (op === 'i32.rotl' || op === 'i32.rotr' ||
            op === 'i64.rotl' || op === 'i64.rotr') this.rotCount++;
        if (op === 'i32.shl' || op === 'i32.shr_s' || op === 'i32.shr_u' ||
            op === 'i64.shl' || op === 'i64.shr_s' || op === 'i64.shr_u')
            this.shiftCount++;
        if (op === 'i32.and' || op === 'i64.and') this.andCount++;
    },

    unop(location, op, input, result) {
        this.instrCounts[op] = (this.instrCounts[op] || 0) + 1;
    },

    call_pre(location, targetFunc, args, indirectTableIdx) {
        const caller = location.func;
        this._trackFunc(caller);

        if (!this.callGraph[caller]) this.callGraph[caller] = new Set();
        this.callGraph[caller].add(targetFunc);
        this.funcCallCounts[targetFunc] = (this.funcCallCounts[targetFunc] || 0) + 1;

        // Record call sequence (first 200)
        if (this.callSequence.length < 200) {
            this.callSequence.push({ caller, target: targetFunc, indirect: indirectTableIdx !== undefined });
        }

        if (indirectTableIdx !== undefined) {
            this.indirectCalls.push({
                caller, tableIdx: indirectTableIdx,
                location: this._loc(location)
            });
        }
    },

    call_post(location, vals) {
        this._trackFunc(location.func);
    },

    return_(location, vals) {
        this.instrCounts['return'] = (this.instrCounts['return'] || 0) + 1;
    },

    drop(location) {
        this.instrCounts['drop'] = (this.instrCounts['drop'] || 0) + 1;
    },

    nop(location) {
        this.instrCounts['nop'] = (this.instrCounts['nop'] || 0) + 1;
    },

    unreachable(location) {
        this.instrCounts['unreachable'] = (this.instrCounts['unreachable'] || 0) + 1;
        this.errors.push({ type: 'unreachable', location: this._loc(location) });
    },

    end() {
        const cgSerialized = {};
        for (const [k, v] of Object.entries(this.callGraph)) {
            cgSerialized[k] = Array.from(v);
        }

        // Detect sequential memory writes (encryption pattern)
        let seqWrites = 0;
        for (let i = 1; i < this.memWrites.length; i++) {
            if (this.memWrites[i].offset === this.memWrites[i-1].offset + 4 ||
                this.memWrites[i].offset === this.memWrites[i-1].offset + 1) {
                seqWrites++;
            }
        }

        // Compute opcode entropy
        const totalInstrs = Object.values(this.instrCounts).reduce((a,b)=>a+b, 0);
        let opcodeEntropy = 0;
        for (const count of Object.values(this.instrCounts)) {
            const p = count / totalInstrs;
            if (p > 0) opcodeEntropy -= p * Math.log2(p);
        }

        const report = {
            instrCounts:       this.instrCounts,
            callGraph:         cgSerialized,
            callSequence:      this.callSequence,
            funcCallCounts:    this.funcCallCounts,
            funcExecOrder:     this.funcExecOrder,
            indirectCalls:     this.indirectCalls,
            globalReads:       this.globalReads,
            globalWrites:      this.globalWrites,
            suspiciousConsts:  this.suspiciousConsts,
            memReads:          this.memReads.length,
            memWrites:         this.memWrites.length,
            memGrows:          this.memGrows,
            sequentialWrites:  seqWrites,
            branches:          this.branches,
            xorCount:          this.xorCount,
            rotCount:          this.rotCount,
            shiftCount:        this.shiftCount,
            andCount:          this.andCount,
            startFunc:         this.startFunc,
            errors:            this.errors,
            totalInstrs:       totalInstrs,
            opcodeEntropy:     opcodeEntropy,
            uniqueFuncsRun:    this.seenFuncs.size,
        };

        process.stdout.write('WASMSHARK_REPORT_START\n');
        process.stdout.write(JSON.stringify(report, null, 2));
        process.stdout.write('\nWASMSHARK_REPORT_END\n');
    }
};

Wasabi.analysis = WASMSharkAnalysis;
"""


#  NODE.JS RUNNER TEMPLATE

NODE_RUNNER_JS = r"""
'use strict';
const fs   = require('fs');
const path = require('path');

const wasabiJsPath   = process.argv[2];
const analysisJsPath = process.argv[3];
const wasmPath       = process.argv[4];
const importsJson    = process.argv[5] ? JSON.parse(process.argv[5]) : {};

// Change to wasabi dir so ./long.js resolves (same as manual test)
const wasabiDir = path.dirname(path.resolve(wasabiJsPath));
process.chdir(wasabiDir);

// Load Wasabi via require — matches the working manual approach
const Wasabi = require(path.resolve(wasabiJsPath));

// Set analysis hooks BEFORE instantiating WASM
const analysisCode = fs.readFileSync(path.resolve(analysisJsPath), 'utf8');
eval(analysisCode);

// Build import stubs from provided JSON
const finalImports = {};
for (const [mod, funcs] of Object.entries(importsJson)) {
    finalImports[mod] = {};
    for (const [fname, sig] of Object.entries(funcs)) {
        finalImports[mod][fname] = function(...args) { return sig.returns ? 0 : undefined; };
    }
}
// Always provide memory
if (!finalImports.memory) {
    finalImports.memory = { memory: new WebAssembly.Memory({initial: 16}) };
}
// Always provide WASI stubs
if (!finalImports.wasi_snapshot_preview1) {
    finalImports.wasi_snapshot_preview1 = new Proxy({}, {
        get: (_, name) => (...args) => 0
    });
}
// Stub any other missing modules
for (const [mod, funcs] of Object.entries(importsJson)) {
    if (!finalImports[mod]) {
        finalImports[mod] = new Proxy({}, { get: (_, name) => (...args) => 0 });
    }
}

// Load and instantiate
const wasmBytes = fs.readFileSync(wasmPath);
WebAssembly.instantiate(wasmBytes, finalImports)
    .then(({instance, module}) => {
        // Call exports if no start function ran
        const exports = instance.exports;
        if (exports.main)    try { exports.main(); }    catch(e) {}
        if (exports._start)  try { exports._start(); }  catch(e) {}
        if (exports.mine)    try { exports.mine(); }     catch(e) {}
        if (exports.run)     try { exports.run(); }      catch(e) {}
        // Trigger end hook
        if (Wasabi.analysis && Wasabi.analysis.end) {
            Wasabi.analysis.end();
        }
    })
    .catch(err => {
        process.stderr.write('WASM_ERROR: ' + err.message + '\n');
        // Still try to get partial report
        if (Wasabi.analysis && Wasabi.analysis.end) {
            Wasabi.analysis.end();
        }
    });
"""


#  DATA STRUCTURES

@dataclass
class WasabiResult:

    # Results from Wasabi dynamic instrumentation
    success:         bool
    error:           str = ""

    # Instruction profile
    total_instrs:    int = 0
    instr_counts:    Dict[str,int] = field(default_factory=dict)
    xor_count:       int = 0
    rot_count:       int = 0
    nop_count:       int = 0

    # Memory
    mem_reads:       int = 0
    mem_writes:      int = 0
    mem_grows:       List[Dict] = field(default_factory=list)

    # Control flow
    branches_taken:  int = 0
    branches_not:    int = 0
    indirect_calls:  List[Dict] = field(default_factory=list)
    call_sequence:   List[Dict] = field(default_factory=list)

    # Call graph
    call_graph:      Dict[str,List[str]] = field(default_factory=dict)
    func_call_counts: Dict[str,int] = field(default_factory=dict)

    # Other
    start_func:      Optional[int] = None
    errors:          List[Dict] = field(default_factory=list)

    # Derived findings
    findings:        List[Dict] = field(default_factory=list)



#  WASABI RUNNER

class WasabiRunner:

    # Instruments and executes a WASM binary via Wasabi + Node.js, returning a WasabiResult with runtime behavioral data

    def __init__(self, timeout: int = 30):
        self.timeout    = timeout
        self._wasabi_ok = None
        self._node_ok   = None

    def check_dependencies(self) -> tuple:
        """Returns (wasabi_available, node_available)."""
        if self._wasabi_ok is None:
            try:
                r = subprocess.run(["wasabi", "--help"],
                                   capture_output=True, timeout=5)
                self._wasabi_ok = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._wasabi_ok = False

        if self._node_ok is None:
            try:
                r = subprocess.run(["node", "--version"],
                                   capture_output=True, timeout=5)
                self._node_ok = r.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._node_ok = False

        return self._wasabi_ok, self._node_ok

    def _build_import_stubs(self, report) -> Dict:
    
        # Build a JSON description of imports so Node.js can stub them

        stubs = {}
        for imp in report.imports:
            if imp.kind != "func":
                continue
            mod = imp.module
            if mod not in stubs:
                stubs[mod] = {}
            # Determine if function returns a value
            tidx = imp.type_idx
            has_return = False
            if tidx < len(report.types):
                has_return = len(report.types[tidx].returns) > 0
            stubs[mod][imp.name] = {"returns": has_return}
        return stubs

    def run(self, wasm_path: str, report) -> WasabiResult:
    
        # Instrument wasm_path with Wasabi and run under Node.js.
        #  Returns WasabiResult with runtime observations.
    
        wasabi_ok, node_ok = self.check_dependencies()

        if not wasabi_ok:
            return WasabiResult(success=False,
                                error="wasabi not found. Install: cargo install --path <wasabi_repo>")
        if not node_ok:
            return WasabiResult(success=False,
                                error="node not found. Install: sudo apt install nodejs")

        import os as _os, shutil as _shutil

        # Find long.js before entering temp dir
        project_dir  = _os.path.dirname(_os.path.abspath(wasm_path))
        long_js_path = _os.path.join(project_dir, "node_modules", "long", "index.js")
        if not _os.path.exists(long_js_path):
            try:
                npm_global   = subprocess.run(["npm","root","-g"],
                    capture_output=True,text=True).stdout.strip()
                long_js_path = _os.path.join(npm_global, "long", "index.js")
            except: pass
        if not _os.path.exists(long_js_path):
            return WasabiResult(success=False,
                error="long.js not found. Run: npm install long")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # 1. Instrument with Wasabi - output to tmpdir
            try:
                result = subprocess.run(
                    ["wasabi", "--node", "-o", str(tmpdir), wasm_path],
                    capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    return WasabiResult(success=False,
                        error=f"Wasabi failed: {result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                return WasabiResult(success=False, error="Wasabi timed out")
            except Exception as e:
                return WasabiResult(success=False, error=str(e))

            # 2. Copy long.js into tmpdir right next to wasabi.js
            _shutil.copy2(long_js_path, str(tmpdir / "long.js"))

            # Find output files
            wasm_name = Path(wasm_path).stem
            instr_wasm = tmpdir / f"{wasm_name}.wasm"
            wasabi_js  = tmpdir / f"{wasm_name}.wasabi.js"
            instr_dir  = tmpdir

            # Copy long.js into tmpdir (Wasabi requires ./long.js)
            import os as _os, shutil as _shutil
            project_dir = _os.path.dirname(_os.path.abspath(wasm_path))

            # Search all candidate locations
            long_candidates = []
            # Walk up from project dir looking for node_modules/long/index.js
            search = project_dir
            for _ in range(5):
                cand = _os.path.join(search, "node_modules", "long", "index.js")
                long_candidates.append(cand)
                search = _os.path.dirname(search)
            # npm global
            try:
                npm_global = subprocess.run(
                    ["npm", "root", "-g"],
                    capture_output=True, text=True).stdout.strip()
                if npm_global:
                    long_candidates.append(_os.path.join(npm_global, "long", "index.js"))
            except: pass

            long_copied = False
            for long_src in long_candidates:
                if _os.path.exists(long_src):
                    _shutil.copy2(long_src, str(tmpdir / "long.js"))
                    long_copied = True
                    break

            if not long_copied:
                return WasabiResult(success=False,
                    error="long.js not found. Run: npm install long")

            if not instr_wasm.exists() or not wasabi_js.exists():
                # Try finding any .wasm file in output
                wasm_files = list(instr_dir.glob("*.wasm"))
                js_files   = list(instr_dir.glob("*.wasabi.js"))
                if not wasm_files or not js_files:
                    return WasabiResult(success=False,
                                        error="Wasabi output files not found")
                instr_wasm = wasm_files[0]
                wasabi_js  = js_files[0]

            # 2. Write analysis script
            analysis_path = tmpdir / "wasmshark_analysis.js"
            analysis_path.write_text(WASABI_ANALYSIS_JS)

            # 3. Write Node.js runner
            runner_path = tmpdir / "runner.js"
            runner_path.write_text(NODE_RUNNER_JS)

            # 4. Build import stubs
            stubs = self._build_import_stubs(report)
            stubs_json = json.dumps(stubs)

            # 5. Copy node_modules into temp dir so relative requires work
            import os as _os, shutil as _shutil
            project_dir = _os.path.dirname(_os.path.abspath(wasm_path))
            src_nm = _os.path.join(project_dir, "node_modules")
            dst_nm = str(tmpdir / "node_modules")
            if _os.path.exists(src_nm) and not _os.path.exists(dst_nm):
                _shutil.copytree(src_nm, dst_nm, symlinks=True)
            # Also check global npm modules
            try:
                global_nm = subprocess.run(
                    ["npm", "root", "-g"],
                    capture_output=True, text=True).stdout.strip()
                if global_nm and _os.path.exists(global_nm):
                    for pkg in _os.listdir(global_nm):
                        dst_pkg = str(tmpdir / "node_modules" / pkg)
                        src_pkg = _os.path.join(global_nm, pkg)
                        if not _os.path.exists(dst_pkg):
                            try: _shutil.copytree(src_pkg, dst_pkg, symlinks=True)
                            except: pass
            except: pass

            # 6. Run under Node.js from temp dir
            try:
                env = _os.environ.copy()
                env["NODE_PATH"] = str(tmpdir / "node_modules")
                node_result = subprocess.run(
                    ["node", str(runner_path),
                     str(wasabi_js), str(analysis_path),
                     str(instr_wasm), stubs_json],
                    capture_output=True, text=True,
                    timeout=self.timeout,
                    env=env,
                    cwd=str(tmpdir))
            except subprocess.TimeoutExpired:
                return WasabiResult(success=False,
                                    error=f"Node.js timed out after {self.timeout}s")
            except Exception as e:
                return WasabiResult(success=False, error=str(e))

            # 6. Parse output
            return self._parse_output(node_result.stdout, node_result.stderr)

    def _parse_output(self, stdout: str, stderr: str) -> WasabiResult:

        # Extract WASMShark report JSON from Node.js output
        if "WASMSHARK_REPORT_START" not in stdout:
            err = stderr[:200] if stderr else "No report generated"
            return WasabiResult(success=False, error=err)

        try:
            start = stdout.index("WASMSHARK_REPORT_START\n") + len("WASMSHARK_REPORT_START\n")
            end   = stdout.index("\nWASMSHARK_REPORT_END")
            json_str = stdout[start:end]
            data = json.loads(json_str)
        except (ValueError, json.JSONDecodeError) as e:
            return WasabiResult(success=False, error=f"JSON parse error: {e}")

        result = WasabiResult(
            success          = True,
            total_instrs     = data.get("totalInstrs", 0),
            instr_counts     = data.get("instrCounts", {}),
            xor_count        = data.get("xorCount", 0),
            rot_count        = data.get("rotCount", 0),
            nop_count        = data.get("instrCounts", {}).get("nop", 0),
            mem_reads        = data.get("memReads", 0),
            mem_writes       = data.get("memWrites", 0),
            mem_grows        = data.get("memGrows", []),
            branches_taken   = data.get("branches", {}).get("taken", 0),
            branches_not     = data.get("branches", {}).get("notTaken", 0),
            indirect_calls   = data.get("indirectCalls", []),
            call_graph       = data.get("callGraph", {}),
            call_sequence    = data.get("callSequence", []),
            func_call_counts = data.get("funcCallCounts", {}),
            start_func       = data.get("startFunc"),
            errors           = data.get("errors", []),
        )

        # Generate findings from runtime data
        result.findings = self._generate_findings(result)
        return result

    def _generate_findings(self, r: WasabiResult) -> List[Dict]:
        """Generate security findings from runtime behavior."""
        findings = []

        # High XOR at runtime confirms decryption
        if r.xor_count > 100:
            findings.append({
                "severity":    "HIGH",
                "category":    "RUNTIME_XOR",
                "title":       f"High XOR density at runtime: {r.xor_count} XOR ops executed",
                "description": "Confirmed decryption/encryption routine executing at runtime",
                "evidence":    f"xor_count={r.xor_count}"
            })

        # Memory growth at runtime
        if len(r.mem_grows) > 5:
            total_pages = sum(g.get("pages", 0) for g in r.mem_grows)
            findings.append({
                "severity":    "HIGH",
                "category":    "RUNTIME_MEMORY",
                "title":       f"memory.grow called {len(r.mem_grows)}× at runtime ({total_pages} pages)",
                "description": "Confirmed runtime memory expansion",
                "evidence":    f"grows={len(r.mem_grows)} total_pages={total_pages}"
            })

        # Indirect calls at runtime
        if r.indirect_calls:
            findings.append({
                "severity":    "MEDIUM",
                "category":    "RUNTIME_INDIRECT",
                "title":       f"{len(r.indirect_calls)} indirect calls executed at runtime",
                "description": "Confirmed obfuscated dispatch executing",
                "evidence":    f"count={len(r.indirect_calls)}"
            })

        # Runtime unreachable reached
        if r.errors:
            findings.append({
                "severity":    "MEDIUM",
                "category":    "RUNTIME_UNREACHABLE",
                "title":       f"Unreachable instruction executed: {len(r.errors)} times",
                "description": "Unexpected control flow — possible runtime exploit attempt",
                "evidence":    str(r.errors[:3])
            })

        # Very high instruction count
        if r.total_instrs > 1_000_000:
            findings.append({
                "severity":    "MEDIUM",
                "category":    "RUNTIME_VOLUME",
                "title":       f"High runtime instruction volume: {r.total_instrs:,} instructions",
                "description": "Long-running computation — consistent with mining loop",
                "evidence":    f"total_instrs={r.total_instrs:,}"
            })

        # Start function confirmed running
        if r.start_func is not None:
            findings.append({
                "severity":    "MEDIUM",
                "category":    "RUNTIME_AUTORUN",
                "title":       f"Start function confirmed executing at runtime: func[{r.start_func}]",
                "description": "Auto-execution confirmed by dynamic instrumentation",
                "evidence":    f"start_func={r.start_func}"
            })

        return findings



#  STATIC + DYNAMIC CORRELATOR

def correlate_static_dynamic(static_report, wasabi_result: WasabiResult) -> List[Dict]:

    # Correlate static analysis predictions with Wasabi runtime observations.
    #  Returns list of correlation findings.

    correlations = []

    if not wasabi_result.success:
        return correlations

    # Static predicted XOR-heavy — runtime confirms
    static_xor = sum(fn.xor_ops for fn in static_report.functions)
    if static_xor > 20 and wasabi_result.xor_count > 50:
        correlations.append({
            "type":        "CONFIRMED_XOR",
            "confidence":  "HIGH",
            "description": f"Static predicted {static_xor} XOR ops — runtime confirms {wasabi_result.xor_count} executed",
        })

    # Static predicted indirect calls — runtime confirms
    static_indirect = sum(fn.indirect_calls for fn in static_report.functions)
    if static_indirect > 0 and wasabi_result.indirect_calls:
        correlations.append({
            "type":        "CONFIRMED_INDIRECT_CALLS",
            "confidence":  "HIGH",
            "description": f"Static found {static_indirect} call_indirect — runtime confirms {len(wasabi_result.indirect_calls)} executed",
        })

    # Static predicted start function — runtime confirms
    if static_report.has_start and wasabi_result.start_func is not None:
        correlations.append({
            "type":        "CONFIRMED_AUTORUN",
            "confidence":  "HIGH",
            "description": f"Static predicted auto-exec func[{static_report.start_idx}] — runtime confirms it ran",
        })

    # Static rules matched — runtime evidence supports
    rule_names = [r.get("name","") for r in static_report.matched_rules]
    if any("CRYPTOMINER" in r for r in rule_names) and wasabi_result.xor_count > 30:
        correlations.append({
            "type":        "MINING_BEHAVIOR_CONFIRMED",
            "confidence":  "HIGH",
            "description": "CRYPTOMINER rule + high runtime XOR = mining algorithm executing",
        })

    if any("OBFUSC" in r for r in rule_names) and wasabi_result.indirect_calls:
        correlations.append({
            "type":        "OBFUSCATION_CONFIRMED",
            "confidence":  "HIGH",
            "description": "Obfuscation rule + runtime indirect calls = dispatcher confirmed active",
        })

    # Memory grows at runtime with ransomware static signature
    if any("RANSOM" in r for r in rule_names) and wasabi_result.mem_grows:
        correlations.append({
            "type":        "RANSOMWARE_MEMORY_CONFIRMED",
            "confidence":  "HIGH",
            "description": f"Ransomware rule + {len(wasabi_result.mem_grows)} runtime memory expansions",
        })

    return correlations



#  TERMINAL REPORT

R="\033[0m"; B="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; MAG="\033[95m"; DIM="\033[2m"

def print_wasabi_report(result: WasabiResult, correlations: List[Dict]):
    print(f"\n{CYN}{'─'*72}{R}")
    print(f"{B}  WASABI DYNAMIC ANALYSIS{R}")
    print(f"{CYN}{'─'*72}{R}")

    if not result.success:
        print(f"  {YEL}Not available: {result.error}{R}")
        return

    print(f"  Total instructions executed : {result.total_instrs:>12,}")
    print(f"  XOR ops at runtime          : {result.xor_count:>12,}")
    print(f"  Rotate ops at runtime       : {result.rot_count:>12,}")
    print(f"  NOP ops at runtime          : {result.nop_count:>12,}")
    print(f"  Memory reads                : {result.mem_reads:>12,}")
    print(f"  Memory writes               : {result.mem_writes:>12,}")
    print(f"  memory.grow calls           : {len(result.mem_grows):>12,}")
    print(f"  Branches taken/not          : {result.branches_taken:>6,} / {result.branches_not:,}")
    print(f"  Indirect calls executed     : {len(result.indirect_calls):>12,}")
    print(f"  Start func ran              : {result.start_func if result.start_func is not None else 'No':>12}")

    if result.func_call_counts:
        top = sorted(result.func_call_counts.items(),
                     key=lambda x: x[1], reverse=True)[:5]
        print(f"\n  Top called functions:")
        for func, count in top:
            print(f"    func[{func}]: {count:,} calls")

    if result.call_graph:
        print(f"\n  Runtime call graph ({len(result.call_graph)} callers):")
        for caller, callees in list(result.call_graph.items())[:5]:
            print(f"    func[{caller}] → {[f'func[{c}]' for c in callees[:4]]}")

    if result.findings:
        print(f"\n  Runtime findings ({len(result.findings)}):")
        for f in result.findings:
            col = RED if f["severity"]=="HIGH" else YEL
            print(f"    {col}[{f['severity']}]{R} {f['title']}")
            print(f"           {DIM}{f['description']}{R}")

    if correlations:
        print(f"\n{CYN}{'─'*72}{R}")
        print(f"{B}  STATIC ↔ DYNAMIC CORRELATIONS{R}")
        print(f"{CYN}{'─'*72}{R}")
        for c in correlations:
            col = GRN if c["confidence"] == "HIGH" else YEL
            print(f"  {col}✓ [{c['confidence']}]{R} {c['type']}")
            print(f"    {DIM}{c['description']}{R}")

