#!/usr/bin/env python3

# WASMShark Core Engine


import sys, os, re, json, math, struct, hashlib, argparse, importlib.util
from collections  import Counter, defaultdict, deque
from dataclasses  import dataclass, field, asdict
from typing       import List, Dict, Optional, Tuple, Set, Any, Iterator
from enum         import Enum
from pathlib      import Path


#  WASM CONSTANTS

WASM_MAGIC   = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'

class SecID(Enum):
    CUSTOM=0;TYPE=1;IMPORT=2;FUNCTION=3;TABLE=4;MEMORY=5
    GLOBAL=6;EXPORT=7;START=8;ELEMENT=9;CODE=10;DATA=11;DATACOUNT=12

VALTYPE = {0x7F:"i32",0x7E:"i64",0x7D:"f32",0x7C:"f64",0x70:"funcref",0x6F:"externref"}

# Full opcode table
OPCODE_TABLE: Dict[int,str] = {
    0x00:"unreachable",0x01:"nop",0x02:"block",0x03:"loop",0x04:"if",0x05:"else",
    0x0B:"end",0x0C:"br",0x0D:"br_if",0x0E:"br_table",0x0F:"return",
    0x10:"call",0x11:"call_indirect",0x1A:"drop",0x1B:"select",
    0x20:"local.get",0x21:"local.set",0x22:"local.tee",
    0x23:"global.get",0x24:"global.set",
    0x25:"table.get",0x26:"table.set",
    0x28:"i32.load",0x29:"i64.load",0x2A:"f32.load",0x2B:"f64.load",
    0x2C:"i32.load8_s",0x2D:"i32.load8_u",0x2E:"i32.load16_s",0x2F:"i32.load16_u",
    0x30:"i64.load8_s",0x31:"i64.load8_u",0x32:"i64.load16_s",0x33:"i64.load16_u",
    0x34:"i64.load32_s",0x35:"i64.load32_u",
    0x36:"i32.store",0x37:"i64.store",0x38:"f32.store",0x39:"f64.store",
    0x3A:"i32.store8",0x3B:"i32.store16",0x3C:"i64.store8",0x3D:"i64.store16",0x3E:"i64.store32",
    0x3F:"memory.size",0x40:"memory.grow",
    0x41:"i32.const",0x42:"i64.const",0x43:"f32.const",0x44:"f64.const",
    0x45:"i32.eqz",0x46:"i32.eq",0x47:"i32.ne",0x48:"i32.lt_s",0x49:"i32.lt_u",
    0x4A:"i32.gt_s",0x4B:"i32.gt_u",0x4C:"i32.le_s",0x4D:"i32.le_u",
    0x4E:"i32.ge_s",0x4F:"i32.ge_u",
    0x50:"i64.eqz",0x51:"i64.eq",0x52:"i64.ne",0x53:"i64.lt_s",0x54:"i64.lt_u",
    0x60:"f32.eq",0x61:"f32.ne",0x65:"f64.eq",0x66:"f64.ne",
    0x67:"i32.clz",0x68:"i32.ctz",0x69:"i32.popcnt",
    0x6A:"i32.add",0x6B:"i32.sub",0x6C:"i32.mul",0x6D:"i32.div_s",0x6E:"i32.div_u",
    0x6F:"i32.rem_s",0x70:"i32.rem_u",
    0x71:"i32.and",0x72:"i32.or",0x73:"i32.xor",
    0x74:"i32.shl",0x75:"i32.shr_s",0x76:"i32.shr_u",0x77:"i32.rotl",0x78:"i32.rotr",
    0x79:"i64.clz",0x7A:"i64.ctz",0x7B:"i64.popcnt",
    0x7C:"i64.add",0x7D:"i64.sub",0x7E:"i64.mul",0x7F:"i64.div_s",
    0x80:"i64.div_u",0x81:"i64.rem_s",0x82:"i64.rem_u",
    0x83:"i64.and",0x84:"i64.or",0x85:"i64.xor",
    0x86:"i64.shl",0x87:"i64.shr_s",0x88:"i64.shr_u",0x89:"i64.rotl",0x8A:"i64.rotr",
    0xA7:"i32.wrap_i64",0xAC:"i32.trunc_f32_s",0xAD:"i32.trunc_f32_u",
    0xAE:"i32.trunc_f64_s",0xAF:"i32.trunc_f64_u",
    0xFC:"misc_prefix",
}

# Opcodes that change control flow depth
BLOCK_OPS   = {0x02,0x03,0x04}
END_OPS     = {0x0B}
BRANCH_OPS  = {0x0C,0x0D,0x0E,0x0F}
CALL_OPS    = {0x10,0x11}
MEM_LOAD    = set(range(0x28,0x36))
MEM_STORE   = set(range(0x36,0x3F))
XOR_OPS     = {0x73,0x85}
AND_OPS     = {0x71,0x83}
OR_OPS      = {0x72,0x84}
ROT_OPS     = {0x77,0x78,0x89,0x8A}
ARITH_OPS   = {0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,
               0x7C,0x7D,0x7E,0x7F,0x80,0x81,0x82}


#  THREAT INTELLIGENCE DATABASES

SUSPICIOUS_IMPORTS: Dict[str, Dict] = {
    "exec": {
        "severity":"CRITICAL",
        "patterns":["exec","system","popen","spawn","shell","cmd","eval",
                    "execve","execvp","fork","CreateProcess","WinExec",
                    "ShellExecute","system32","runtime.exec"],
        "description":"Shell/process execution — direct code execution capability"
    },
    "network": {
        "severity":"HIGH",
        "patterns":["socket","connect","recv","send","fetch","xhr","websocket",
                    "XMLHttpRequest","beacon","curl","wget","http_request",
                    "tcp_connect","dns","bind","listen","accept","getaddrinfo"],
        "description":"Network I/O — C2 communication or data exfiltration"
    },
    "crypto": {
        "severity":"HIGH",
        "patterns":["sha256","sha3","sha1","keccak","scrypt","argon2","randomx",
                    "cryptonight","equihash","hashrate","nonce","difficulty",
                    "md5","hmac","pbkdf2","aes","chacha","salsa","blake2",
                    "whirlpool","ripemd"],
        "description":"Cryptographic operations — mining, ransomware, or payload encryption"
    },
    "memory": {
        "severity":"MEDIUM",
        "patterns":["memcpy","memmove","malloc","realloc","VirtualAlloc",
                    "mmap","brk","sbrk","HeapAlloc","mprotect","munmap",
                    "VirtualProtect","RtlAllocateHeap"],
        "description":"Memory manipulation — payload staging or injection"
    },
    "evasion": {
        "severity":"HIGH",
        "patterns":["sleep","usleep","nanosleep","delay","setTimeout",
                    "performance.now","Date.now","debugger","anti_debug",
                    "is_debugger","timing","rdtsc","cpuid","ptrace"],
        "description":"Anti-analysis / evasion techniques"
    },
    "exfil": {
        "severity":"HIGH",
        "patterns":["localStorage","sessionStorage","indexedDB","cookie",
                    "document.cookie","clipboard","geolocation","navigator",
                    "screen","battery","usb","bluetooth","camera","microphone"],
        "description":"Data exfiltration or device fingerprinting"
    },
    "wasi": {
        "severity":"MEDIUM",
        "patterns":["fd_write","fd_read","fd_seek","fd_close","path_open",
                    "path_rename","path_unlink","proc_exit","environ_get",
                    "args_get","sock_recv","sock_send","sock_accept","sock_bind",
                    "poll_oneoff","clock_time_get","random_get"],
        "description":"WASI system interface — host filesystem/network/process access"
    },
    "ransomware": {
        "severity":"CRITICAL",
        "patterns":["encrypt","decrypt","ransom","lockfile","readme.txt",
                    "how_to_decrypt","your_files","bitcoin_address","tor_browser"],
        "description":"Ransomware behavioral indicators"
    },
}

CRYPTO_CONSTANTS: List[Tuple] = [
    # SHA-256
    (0x6a09e667,"SHA-256 H0"),(0xbb67ae85,"SHA-256 H1"),
    (0x3c6ef372,"SHA-256 H2"),(0xa54ff53a,"SHA-256 H3"),
    (0x510e527f,"SHA-256 H4"),(0x9b05688c,"SHA-256 H5"),
    (0x1f83d9ab,"SHA-256 H6"),(0x5be0cd19,"SHA-256 H7"),
    # SHA-256 round constants (first few)
    (0x428a2f98,"SHA-256 K[0]"),(0x71374491,"SHA-256 K[1]"),
    (0xb5c0fbcf,"SHA-256 K[2]"),(0xe9b5dba5,"SHA-256 K[3]"),
    # AES
    (0x637c777c,"AES S-box marker"),(0x63636363,"AES constant"),
    (0x01010101,"AES GF multiplier"),(0x1b000000,"AES rcon"),
    # ChaCha20
    (0x61707865,"ChaCha20 'expa'"),(0x3320646e,"ChaCha20 'nd 3'"),
    (0x79622d32,"ChaCha20 '2-by'"),(0x6b206574,"ChaCha20 'te k'"),
    # RC4
    (0x0f0e0d0c,"RC4-like XOR pattern"),
    # CRC32
    (0xEDB88320,"CRC32 polynomial"),(0x04C11DB7,"CRC32 poly (reflect)"),
    # TEA/XTEA
    (0x61C88647,"XTEA delta"),(0x9E3779B9,"TEA/Knuth hash delta"),
    # Keccak / SHA-3
    (0xD7C5A5B9,"Keccak-f theta"),
    # Suspicious
    (0xdeadbeef,"Magic: DEADBEEF"),(0xcafebabe,"Magic: CAFEBABE"),
    (0x13371337,"Leet constant"),(0xbadc0de,"Magic: BADC0DE"),
    (0x0badf00d,"Magic: 0BADF00D"),(0xfeedface,"Magic: FEEDFACE"),
    # Common XOR keys in malware
    (0x41414141,"Repeated 'AAAA' (debug marker)"),(0x90909090,"NOP sled x4"),
]

IOC_STRINGS = [
    ("http://",   "HTTP URL"),       ("https://",  "HTTPS URL"),
    (".onion",    "Tor hidden svc"), ("bitcoin:",   "Bitcoin URI"),
    ("monero:",   "Monero URI"),     ("wallet",     "Crypto wallet ref"),
    ("ransom",    "Ransomware kw"),  ("decrypt",    "Decrypt kw"),
    ("cmd.exe",   "Windows shell"),  ("/bin/sh",    "Unix shell"),
    ("/bin/bash", "Bash shell"),     ("powershell", "PowerShell"),
    ("base64",    "Base64 codec"),   ("eval(",      "Dynamic eval"),
    ("exec(",     "Dynamic exec"),   ("shellcode",  "Shellcode ref"),
    ("meterpreter","MSF payload"),   ("cobalt",     "CobaltStrike ref"),
    ("beacon",    "CS beacon"),      ("c2",         "C2 reference"),
    ("exfil",     "Exfil keyword"),  ("bypass",     "Security bypass"),
    ("inject",    "Injection kw"),   ("reflective", "Reflective load"),
    ("mimikatz",  "Mimikatz ref"),   ("lsass",      "LSASS ref"),
    ("ntdll",     "NTDLL ref"),      ("kernel32",   "Kernel32 ref"),
    ("/etc/passwd","Linux cred"),    ("/etc/shadow","Linux shadow"),
    ("id_rsa",    "SSH key"),        ("authorized_keys","SSH auth"),
    ("AWS_",      "AWS credential"), ("AKIA",       "AWS access key"),
]


#  DATA STRUCTURES

@dataclass
class Finding:
    severity:    str
    category:    str
    title:       str
    description: str
    evidence:    str = ""
    offset:      int = -1
    func_index:  int = -1
    rule_name:   str = ""

@dataclass
class Instruction:
    offset:   int
    opcode:   int
    mnemonic: str
    operands: List[Any] = field(default_factory=list)
    tainted:  bool = False

@dataclass
class BasicBlock:
    id:           int
    start_offset: int
    end_offset:   int
    instructions: List[Instruction] = field(default_factory=list)
    successors:   List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_entry:     bool = False
    is_exit:      bool = False

@dataclass
class CFG:
    func_index: int
    blocks:     List[BasicBlock] = field(default_factory=list)
    entry_block: int = 0
    cyclomatic_complexity: int = 0

@dataclass
class ImportEntry:
    module:   str
    name:     str
    kind:     str
    type_idx: int = 0
    index:    int = 0

@dataclass
class ExportEntry:
    name:  str
    kind:  str
    index: int

@dataclass
class TypeEntry:
    params:  List[str]
    returns: List[str]

@dataclass
class GlobalEntry:
    valtype:  str
    mutable:  bool
    init_val: Any = None

@dataclass
class TaintNode:
    # Tracks tainted data flow from suspicious import calls
    source_import: str
    tainted_locals: Set[int] = field(default_factory=set)
    tainted_globals: Set[int] = field(default_factory=set)
    propagation_depth: int = 0

@dataclass
class FunctionAnalysis:
    index:             int
    size:              int
    type_idx:          int
    local_count:       int
    instruction_count: int
    unique_opcodes:    int
    max_stack_depth:   int
    max_cfg_depth:     int
    cyclomatic:        int
    call_targets:      List[int] = field(default_factory=list)
    indirect_calls:    int = 0
    memory_reads:      int = 0
    memory_writes:     int = 0
    xor_ops:           int = 0
    rot_ops:           int = 0
    nop_max_run:       int = 0
    disassembly:       List[Instruction] = field(default_factory=list)
    cfg:               Optional[CFG] = None
    taint:             Optional[TaintNode] = None
    suspicious_score:  float = 0.0
    complexity_score:  float = 0.0
    flags:             List[str] = field(default_factory=list)

@dataclass
class SectionInfo:
    name:    str
    id:      int
    offset:  int
    size:    int
    entropy: float
    chi2:    float

@dataclass
class AnalysisReport:
    # Metadata
    filename:    str
    file_size:   int
    sha256:      str
    sha1:        str
    md5:         str
    ssdeep:      str = ""   # fuzzy hash placeholder
    is_valid:    bool = False
    wasm_version: int = 1

    # Parsed data
    sections:      List[SectionInfo] = field(default_factory=list)
    types:         List[TypeEntry] = field(default_factory=list)
    imports:       List[ImportEntry] = field(default_factory=list)
    exports:       List[ExportEntry] = field(default_factory=list)
    globals:       List[GlobalEntry] = field(default_factory=list)
    functions:     List[FunctionAnalysis] = field(default_factory=list)
    custom_secs:   List[Dict] = field(default_factory=list)

    # Strings & IoCs
    strings:       List[str] = field(default_factory=list)
    iocs:          List[Tuple[str,str]] = field(default_factory=list)

    # Crypto
    crypto_hits:   List[Dict] = field(default_factory=list)

    # Memory layout
    memory_pages:  Dict[str,Dict] = field(default_factory=dict)
    data_segments: int = 0
    data_entropy:  List[float] = field(default_factory=list)

    # Entry point
    has_start:     bool = False
    start_idx:     int = -1

    # Overall entropy
    file_entropy:  float = 0.0
    chi2_score:    float = 0.0

    # Scoring
    malice_score:       float = 0.0
    obfuscation_score:  float = 0.0
    complexity_score:   float = 0.0
    verdict:            str = "CLEAN"
    confidence:         float = 0.0

    # Findings
    findings:      List[Finding] = field(default_factory=list)
    matched_rules: List[Dict]    = field(default_factory=list)

    # Tags (MITRE ATT&CK for containers/WASM)
    mitre_tags:    List[str] = field(default_factory=list)

    # Import fingerprint (imphash) for clustering related samples
    imphash:        str = ""

    # Dead code: functions never exported or called
    dead_functions: List[int] = field(default_factory=list)

    # Advanced analysis results
    wasi_analysis:      Dict[str,Any] = field(default_factory=dict)
    obfuscation_detail: List[Dict]    = field(default_factory=list)
    loop_profiles:      List[Dict]    = field(default_factory=list)
    function_clusters:  List[Dict]    = field(default_factory=list)
    section_anomalies:  List[Dict]    = field(default_factory=list)
    entropy_timeline:   List[Dict]    = field(default_factory=list)
    api_abuse_score:    float         = 0.0
    api_abuse_detail:   List[Dict]    = field(default_factory=list)
    string_scores:      List[Dict]    = field(default_factory=list)

    # Plugin output
    plugin_results: Dict[str,Any] = field(default_factory=dict)



#  BINARY READER

class BinaryReader:
    __slots__ = ('data','pos','size')
    def __init__(self, data: bytes):
        self.data = data; self.pos = 0; self.size = len(data)

    def remaining(self): return self.size - self.pos
    def tell(self):      return self.pos
    def seek(self, p):   self.pos = p

    def read(self, n):
        if self.pos+n > self.size: raise EOFError(f"Read {n}B at {self.pos:#x}")
        v = self.data[self.pos:self.pos+n]; self.pos += n; return v

    def read_u8(self):    return self.read(1)[0]
    def read_u16_le(self): return struct.unpack('<H',self.read(2))[0]
    def read_u32_le(self): return struct.unpack('<I',self.read(4))[0]
    def read_u64_le(self): return struct.unpack('<Q',self.read(8))[0]
    def read_f32(self):   return struct.unpack('<f',self.read(4))[0]
    def read_f64(self):   return struct.unpack('<d',self.read(8))[0]

    def read_leb128_u(self):
        r=s=0
        while True:
            b=self.read_u8(); r|=(b&0x7F)<<s; s+=7
            if not(b&0x80): break
            if s>63: raise ValueError("LEB128u overflow")
        return r

    def read_leb128_s(self):
        r=s=0
        while True:
            b=self.read_u8(); r|=(b&0x7F)<<s; s+=7
            if not(b&0x80):
                if s<64 and (b&0x40): r|=-(1<<s)
                break
        return r

    def read_string(self):
        n=self.read_leb128_u(); return self.read(n).decode('utf-8',errors='replace')

    def slice(self, start, length):
        return BinaryReader(self.data[start:start+length])

    def peek(self, n=1): return self.data[self.pos:self.pos+n]


#  ENTROPY / STATISTICS

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    c=Counter(data); n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values() if v)

def chi_square(data: bytes) -> float:
    if len(data)<256: return 0.0
    c=Counter(data); exp=len(data)/256
    return sum((c.get(i,0)-exp)**2/exp for i in range(256))

def entropy_blocks(data: bytes, block_size=256) -> List[float]:
    return [shannon_entropy(data[i:i+block_size])
            for i in range(0,len(data),block_size)]

def byte_histogram(data: bytes) -> Dict[int,int]:
    return dict(Counter(data))


#  DISASSEMBLER

class WASMDisassembler:
    # Disassemble a function body into a list of Instructions

    def disassemble(self, data: bytes, base_offset: int = 0) -> List[Instruction]:
        br = BinaryReader(data)
        instrs: List[Instruction] = []
        while br.remaining() > 0:
            off = base_offset + br.tell()
            op  = br.read_u8()
            mn  = OPCODE_TABLE.get(op, f"0x{op:02x}")
            ops = []
            try:
                ops = self._read_operands(br, op)
            except EOFError:
                pass
            instrs.append(Instruction(offset=off, opcode=op, mnemonic=mn, operands=ops))
        return instrs

    def _read_operands(self, br: BinaryReader, op: int) -> List[Any]:
        if op in BLOCK_OPS:
            bt = br.read_u8()
            return [VALTYPE.get(bt,"void") if bt != 0x40 else "void"]
        elif op in (0x0C,0x0D):   return [br.read_leb128_u()]
        elif op == 0x0E:
            n=br.read_leb128_u(); tgts=[br.read_leb128_u() for _ in range(n+1)]; return tgts
        elif op == 0x10:          return [br.read_leb128_u()]   # call
        elif op == 0x11:
            t=br.read_leb128_u(); br.read_u8(); return [t]      # call_indirect
        elif op in (0x20,0x21,0x22,0x23,0x24,0x25,0x26): return [br.read_leb128_u()]
        elif 0x28<=op<=0x3E:
            a=br.read_leb128_u(); o=br.read_leb128_u(); return [a,o]  # align, offset
        elif op in (0x3F,0x40):   br.read_u8(); return []
        elif op == 0x41:          return [br.read_leb128_s()]
        elif op == 0x42:          return [br.read_leb128_s()]
        elif op == 0x43:          return [br.read_f32()]
        elif op == 0x44:          return [br.read_f64()]
        elif op == 0xFC:
            sub=br.read_leb128_u()
            if sub in (8,9,10,11): br.read_u8(); br.read_u8()
            elif sub in (12,14):   br.read_leb128_u(); br.read_leb128_u()
            return [sub]
        return []


#  CONTROL FLOW GRAPH BUILDER

class _OldCFGBuilder_REPLACED:
    """
    Build a basic-block CFG from a list of Instructions.

    WASM uses structured control flow (block/loop/if/end) rather than
    arbitrary jumps. This builder tracks the scope stack to correctly
    resolve branch targets (br depth N = jump to the Nth enclosing scope).

    Scope types:
        block: br exits the block (target = instruction after matching end)
        loop:  br re-enters the loop (target = loop header)
        if:    br exits the if (target = instruction after matching end)
    """

    def build(self, instrs: List[Instruction], func_idx: int) -> CFG:
        if not instrs: return CFG(func_index=func_idx)
        n = len(instrs)

        # Pass 1: Resolve structured scope targets
        # scope_stack: list of (scope_type, entry_instr_idx)
        scope_stack: List[Tuple[str,int]] = []
        # scope_exit[entry_idx] = exit_instr_idx (instruction after end)
        scope_exit: Dict[int,int] = {}
        # loop_entry[entry_idx] = entry_instr_idx (loop back-target)
        loop_entry: Dict[int,int] = {}

        depth_open = []   # Stack of (scope_type, instr_idx)
        for i, ins in enumerate(instrs):
            if ins.opcode in (0x02, 0x04):   # block / if
                depth_open.append(("block", i))
            elif ins.opcode == 0x03:          # loop
                depth_open.append(("loop", i))
                loop_entry[i] = i
            elif ins.opcode == 0x05:          # else
                pass  # treat as block separator
            elif ins.opcode == 0x0B:          # end
                if depth_open:
                    stype, sidx = depth_open.pop()
                    scope_exit[sidx] = i + 1   # instruction after end
                    if stype == "loop":
                        loop_entry[sidx] = sidx

        # Pass 2: Identify leader instructions
        leaders: Set[int] = {0}

        for i, ins in enumerate(instrs):
            op = ins.opcode
            # Instructions after any branch/block/end are leaders
            if op in (0x0B, 0x0F, 0x0C, 0x0D, 0x0E,  # end/return/br/br_if/br_table
                      0x02, 0x03, 0x04, 0x05):          # block/loop/if/else
                if i + 1 < n:
                    leaders.add(i + 1)

        sorted_leaders = sorted(leaders)
        # Map instruction index → block id
        instr_to_block: Dict[int,int] = {}
        for li, start in enumerate(sorted_leaders):
            end = sorted_leaders[li+1] if li+1 < len(sorted_leaders) else n
            for j in range(start, end):
                instr_to_block[j] = li

        # Pass 3: Build basic blocks
        blocks: List[BasicBlock] = []
        for li, start in enumerate(sorted_leaders):
            end = sorted_leaders[li+1] if li+1 < len(sorted_leaders) else n
            bb  = BasicBlock(
                id           = li,
                start_offset = instrs[start].offset,
                end_offset   = instrs[end-1].offset,
                instructions = instrs[start:end],
                is_entry     = (li == 0))
            last_op = instrs[end-1].opcode
            if last_op in (0x0B, 0x0F):
                bb.is_exit = True
            blocks.append(bb)

        id_map = {b.id: b for b in blocks}

        # Pass 4: Wire edges
        # Rebuild scope stack per-block for accurate br depth resolution
        # We walk the flat instruction list and maintain scope context
        open_scopes: List[Tuple[str,int]] = []  # (type, entry_instr_idx)

        def _add_edge(from_bid: int, to_bid: int):
            if (from_bid in id_map and to_bid in id_map and
                to_bid not in id_map[from_bid].successors):
                id_map[from_bid].successors.append(to_bid)
                if from_bid not in id_map[to_bid].predecessors:
                    id_map[to_bid].predecessors.append(from_bid)

        for i, ins in enumerate(instrs):
            op      = ins.opcode
            curr_bid = instr_to_block.get(i, -1)
            if curr_bid < 0: continue

            # Track scope stack
            if op in (0x02, 0x04): open_scopes.append(("block", i))
            elif op == 0x03:       open_scopes.append(("loop",  i))
            elif op == 0x05:       pass  # else
            elif op == 0x0B:
                if open_scopes:    open_scopes.pop()

            # br depth N: resolve target
            elif op in (0x0C, 0x0D):
                depth = ins.operands[0] if ins.operands else 0
                if depth < len(open_scopes):
                    stype, sidx = open_scopes[-(depth+1)]
                    if stype == "loop":
                        # br to loop header
                        target_instr = sidx
                    else:
                        # br exits block — target is after matching end
                        target_instr = scope_exit.get(sidx, i+1)
                    target_bid = instr_to_block.get(target_instr, -1)
                    if target_bid >= 0:
                        _add_edge(curr_bid, target_bid)
                # br_if also falls through
                if op == 0x0D and i+1 < n:
                    fall_bid = instr_to_block.get(i+1, -1)
                    if fall_bid >= 0:
                        _add_edge(curr_bid, fall_bid)

            # br_table: multiple targets
            elif op == 0x0E:
                targets = ins.operands if ins.operands else []
                for depth in targets:
                    if isinstance(depth, int) and depth < len(open_scopes):
                        stype, sidx = open_scopes[-(depth+1)]
                        target_instr = (sidx if stype == "loop"
                                        else scope_exit.get(sidx, i+1))
                        target_bid = instr_to_block.get(target_instr, -1)
                        if target_bid >= 0:
                            _add_edge(curr_bid, target_bid)

            # Fall-through edges (all non-terminating instructions)
            elif op not in (0x0F,):  # not return
                if i+1 < n:
                    next_bid = instr_to_block.get(i+1, -1)
                    if next_bid >= 0 and next_bid != curr_bid:
                        _add_edge(curr_bid, next_bid)

        # Pass 5: Compute cyclomatic complexity
        cfg = CFG(func_index=func_idx, blocks=blocks)
        E   = sum(len(b.successors) for b in blocks)
        N   = len(blocks)
        cfg.cyclomatic_complexity = max(1, E - N + 2)
        return cfg


#  TAINT ANALYSIS ENGINE

class CFGBuilder:
    
    # Build a basic-block CFG from WASM instructions.
    # Uses scope-stack tracking to resolve structured branch targets.

    def build(self, instrs: List[Instruction], func_idx: int) -> CFG:
        if not instrs: return CFG(func_index=func_idx)
        n = len(instrs)

        # Step 1: Find matching end for each block/loop/if
        # end_of[i] = instruction index just after the 'end' that closes scope at i
        end_of: Dict[int,int] = {}
        stack: List[int] = []
        for i, ins in enumerate(instrs):
            if ins.opcode in (0x02, 0x03, 0x04):  # block / loop / if
                stack.append(i)
            elif ins.opcode == 0x0B:               # end
                if stack:
                    opener = stack.pop()
                    end_of[opener] = i + 1         # index after end

        # Step 2: Identify leaders
        leaders: Set[int] = {0}
        for i, ins in enumerate(instrs):
            op = ins.opcode
            if op in (0x0B, 0x0F, 0x0C, 0x0D, 0x0E,
                      0x02, 0x03, 0x04, 0x05):
                if i + 1 < n:
                    leaders.add(i + 1)

        sorted_leaders = sorted(leaders)
        instr_to_block: Dict[int,int] = {}
        for li, start in enumerate(sorted_leaders):
            end = sorted_leaders[li+1] if li+1 < len(sorted_leaders) else n
            for j in range(start, end):
                instr_to_block[j] = li

        # Step 3: Build blocks
        blocks: List[BasicBlock] = []
        for li, start in enumerate(sorted_leaders):
            end = sorted_leaders[li+1] if li+1 < len(sorted_leaders) else n
            last_op = instrs[end-1].opcode
            bb = BasicBlock(
                id=li, start_offset=instrs[start].offset,
                end_offset=instrs[end-1].offset,
                instructions=instrs[start:end],
                is_entry=(li==0),
                is_exit=(last_op in (0x0B, 0x0F)))
            blocks.append(bb)

        id_map = {b.id: b for b in blocks}

        def add_edge(f: int, t: int):
            if f in id_map and t in id_map and t not in id_map[f].successors:
                id_map[f].successors.append(t)
                if f not in id_map[t].predecessors:
                    id_map[t].predecessors.append(f)

        # Step 4: Wire edges with scope tracking
        # scope_stack: list of (opcode, instr_idx)
        scope_stack: List[Tuple[int,int]] = []

        for i, ins in enumerate(instrs):
            op      = ins.opcode
            curr_bid = instr_to_block.get(i, -1)
            if curr_bid < 0: continue

            if op in (0x02, 0x03, 0x04):   # block / loop / if
                scope_stack.append((op, i))
                # Fall through into body
                if i+1 < n:
                    add_edge(curr_bid, instr_to_block.get(i+1, curr_bid))

            elif op == 0x05:               # else
                pass

            elif op == 0x0B:               # end
                if scope_stack: scope_stack.pop()
                # Fall through after end
                if i+1 < n:
                    add_edge(curr_bid, instr_to_block.get(i+1, curr_bid))

            elif op == 0x0F:               # return — no edge
                pass

            elif op in (0x0C, 0x0D):       # br / br_if
                depth = ins.operands[0] if ins.operands else 0
                if depth < len(scope_stack):
                    scope_op, scope_idx = scope_stack[-(depth+1)]
                    if scope_op == 0x03:   # loop — branch back to header
                        target_instr = scope_idx
                    else:                   # block/if — branch to after end
                        target_instr = end_of.get(scope_idx, i+1)
                    target_bid = instr_to_block.get(target_instr, -1)
                    if target_bid >= 0:
                        add_edge(curr_bid, target_bid)
                # br_if falls through too
                if op == 0x0D and i+1 < n:
                    add_edge(curr_bid, instr_to_block.get(i+1, curr_bid))

            elif op == 0x0E:               # br_table
                for depth in (ins.operands or []):
                    if isinstance(depth, int) and depth < len(scope_stack):
                        scope_op, scope_idx = scope_stack[-(depth+1)]
                        target_instr = (scope_idx if scope_op == 0x03
                                        else end_of.get(scope_idx, i+1))
                        target_bid = instr_to_block.get(target_instr, -1)
                        if target_bid >= 0:
                            add_edge(curr_bid, target_bid)

            else:
                # Normal instruction — fall through to next block if at boundary
                if i+1 < n:
                    next_bid = instr_to_block.get(i+1, curr_bid)
                    if next_bid != curr_bid:
                        add_edge(curr_bid, next_bid)

        # Step 5: Cyclomatic complexity
        cfg = CFG(func_index=func_idx, blocks=blocks)
        E = sum(len(b.successors) for b in blocks)
        N = len(blocks)
        cfg.cyclomatic_complexity = max(1, E - N + 2)
        return cfg


class TaintAnalyzer:
    
    # Intra-procedural taint analysis. Marks locals/globals as tainted if they receive data from
    # suspicious import calls (network recv, crypto output, etc.)


    TAINT_SOURCES = {"recv","read","fread","fd_read","sock_recv",
                     "random_get","getrandom","rand","srand"}

    def analyze(self, instrs: List[Instruction],
                imports: List[ImportEntry]) -> Optional[TaintNode]:
        import_map = {i.index: i for i in imports if i.kind == "func"}
        tainted_locals: Set[int] = set()
        tainted_globals: Set[int] = set()
        propagation = 0

        for i, ins in enumerate(instrs):
            # Taint source: call to suspicious import
            if ins.opcode == 0x10 and ins.operands:
                target = ins.operands[0]
                if target in import_map:
                    imp = import_map[target]
                    if any(p in imp.name.lower() for p in self.TAINT_SOURCES):
                        # Next local.set receives tainted data
                        for j in range(i+1, min(i+5, len(instrs))):
                            if instrs[j].opcode in (0x21,0x22) and instrs[j].operands:
                                tainted_locals.add(instrs[j].operands[0])
                                propagation += 1
                                break

            # Taint propagation: if a tainted local is used, taint result
            if ins.opcode == 0x20 and ins.operands:
                local_idx = ins.operands[0]
                if local_idx in tainted_locals:
                    # Propagate to next local.set
                    for j in range(i+1, min(i+8, len(instrs))):
                        if instrs[j].opcode in (0x21,0x22) and instrs[j].operands:
                            tainted_locals.add(instrs[j].operands[0])
                            propagation += 1
                            break
                        # Propagate to global.set
                        if instrs[j].opcode == 0x24 and instrs[j].operands:
                            tainted_globals.add(instrs[j].operands[0])
                            propagation += 1
                            break

        if tainted_locals or tainted_globals:
            # Find source name
            source = "unknown"
            for imp in imports:
                if any(p in imp.name.lower() for p in self.TAINT_SOURCES):
                    source = f"{imp.module}.{imp.name}"; break
            return TaintNode(source_import=source,
                             tainted_locals=tainted_locals,
                             tainted_globals=tainted_globals,
                             propagation_depth=propagation)
        return None


#  WASM PARSER

class WASMParser:
    def __init__(self, data: bytes):
        self.raw  = data
        self.br   = BinaryReader(data)
        self.dis  = WASMDisassembler()
        self.cfg  = CFGBuilder()
        self.taint= TaintAnalyzer()
        self.report = AnalysisReport(
            filename="", file_size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            is_valid=False)
        self._types: List[TypeEntry] = []
        self._func_type_map: List[int] = []
        self._import_func_count = 0

    def parse(self) -> AnalysisReport:
        self._check_header()
        if not self.report.is_valid: return self.report
        self._parse_sections()
        self.report.file_entropy = round(shannon_entropy(self.raw), 4)
        self.report.chi2_score   = round(chi_square(self.raw), 2)
        self._compute_imphash()
        self._detect_dead_code()
        return self.report

    def _compute_imphash(self):
        # Import hash - MD5 of sorted module.name pairs. Clusters similar samples
        imp_list = sorted(f"{i.module}.{i.name}" for i in self.report.imports if i.kind == "func")
        raw = ",".join(imp_list).encode()
        self.report.imphash = hashlib.md5(raw).hexdigest() if imp_list else "d41d8cd98f00b204e9800998ecf8427e"

    def _detect_dead_code(self):
        # Find functions that are never exported or called by any other function

        if not self.report.functions: return
        import_func_count = self._import_func_count
        # Collect all call targets across all functions
        called: set = set()

        for fn in self.report.functions:
            for t in fn.call_targets:
                called.add(t)
        # Collect exported function indices
        exported: set = {e.index for e in self.report.exports if e.kind == "func"}
        # Start function
        if self.report.has_start:
            exported.add(self.report.start_idx)

        # Dead means not exported and never called
        for fn in self.report.functions:
            if fn.index not in exported and fn.index not in called:
                self.report.dead_functions.append(fn.index)
        if self.report.dead_functions:
            self._add("LOW", "DEAD_CODE",
                      f"{len(self.report.dead_functions)} unreachable function(s) detected",
                      "Functions never exported or called — may be dead code or obfuscation padding",
                      evidence=f"func indices: {self.report.dead_functions[:10]}")

    # Header

    def _check_header(self):
        if self.br.remaining() < 8:
            self._add("CRITICAL","FORMAT","File too small","< 8 bytes"); return
        magic = self.br.read(4)
        if magic != WASM_MAGIC:
            self._add("CRITICAL","FORMAT","Bad magic bytes",f"Got {magic.hex()}"); return
        ver_bytes = self.br.read(4)
        ver = struct.unpack('<I',ver_bytes)[0]
        self.report.wasm_version = ver
        self.report.is_valid     = True
        if ver != 1:
            self._add("HIGH","FORMAT",f"Non-standard WASM version {ver}",
                      "Custom VM or obfuscated binary")

    # Sections

    def _parse_sections(self):
        while self.br.remaining() >= 2:
            s_off = self.br.tell()
            try:
                sid   = self.br.read_u8()
                ssz   = self.br.read_leb128_u()
                sd_start = self.br.tell()
                sdata = self.raw[sd_start:sd_start+ssz]
                ent   = shannon_entropy(sdata)
                chi2  = chi_square(sdata)
                try:   sname = SecID(sid).name
                except: sname = f"UNKNOWN_{sid}"

                si = SectionInfo(name=sname, id=sid, offset=s_off,
                                 size=ssz, entropy=round(ent,4),
                                 chi2=round(chi2,2))
                self.report.sections.append(si)

                if ent > 7.2 and sname not in ("CUSTOM",):
                    self._add("HIGH","ENTROPY",
                              f"High entropy in {sname} ({ent:.3f})",
                              "Entropy >7.2 suggests encrypted/compressed payload",
                              evidence=f"off={s_off:#x} sz={ssz}",offset=s_off)

                sr = self.br.slice(sd_start, ssz)
                {SecID.TYPE.value:     lambda r: self._sec_type(r),
                 SecID.IMPORT.value:   lambda r: self._sec_import(r),
                 SecID.FUNCTION.value: lambda r: self._sec_function(r),
                 SecID.TABLE.value:    lambda r: self._sec_table(r),
                 SecID.MEMORY.value:   lambda r: self._sec_memory(r),
                 SecID.GLOBAL.value:   lambda r: self._sec_global(r),
                 SecID.EXPORT.value:   lambda r: self._sec_export(r),
                 SecID.START.value:    lambda r: self._sec_start(r),
                 SecID.ELEMENT.value:  lambda r: self._sec_element(r),
                 SecID.CODE.value:     lambda r: self._sec_code(r, sd_start),
                 SecID.DATA.value:     lambda r: self._sec_data(r),
                 SecID.CUSTOM.value:   lambda r: self._sec_custom(r, ssz),
                }.get(sid, lambda r: None)(sr)

                self.br.seek(sd_start + ssz)
            except Exception as e:
                self._add("MEDIUM","PARSE_ERROR",f"Section error at {s_off:#x}",str(e),offset=s_off)
                break

    # Type Section

    def _sec_type(self, sr):
        n = sr.read_leb128_u()
        for _ in range(n):
            sr.read_u8()  # 0x60
            pc = sr.read_leb128_u()
            params  = [VALTYPE.get(sr.read_u8(),"?") for _ in range(pc)]
            rc = sr.read_leb128_u()
            returns = [VALTYPE.get(sr.read_u8(),"?") for _ in range(rc)]
            self._types.append(TypeEntry(params=params,returns=returns))
        self.report.types = self._types

    # Import Section

    def _sec_import(self, sr):
        n = sr.read_leb128_u()
        idx = 0
        for _ in range(n):
            mod  = sr.read_string()
            name = sr.read_string()
            kind = sr.read_u8()
            kn   = {0:"func",1:"table",2:"memory",3:"global"}.get(kind,"unk")
            tidx = 0
            if kind == 0:
                tidx = sr.read_leb128_u()
                self._import_func_count += 1
            elif kind == 1:
                sr.read_u8(); flags=sr.read_leb128_u(); sr.read_leb128_u()
                if flags&1: sr.read_leb128_u()
            elif kind == 2:
                flags=sr.read_leb128_u(); sr.read_leb128_u()
                if flags&1: sr.read_leb128_u()
            elif kind == 3:
                sr.read_u8(); sr.read_u8()
            imp = ImportEntry(module=mod,name=name,kind=kn,type_idx=tidx,
                              index=idx if kind==0 else -1)
            self.report.imports.append(imp)
            self._triage_import(imp)
            idx += (1 if kind==0 else 0)

    def _triage_import(self, imp: ImportEntry):
        nl = imp.name.lower(); fl = f"{imp.module}.{imp.name}".lower()
        for cat, info in SUSPICIOUS_IMPORTS.items():
            for p in info["patterns"]:
                if p.lower() in nl or p.lower() in fl:
                    self._add(info["severity"], cat.upper(),
                              f"Suspicious import: {imp.module}.{imp.name}",
                              info["description"],
                              evidence=f"pattern='{p}' kind={imp.kind}")
                    return  # one finding per import

    # Function Section

    def _sec_function(self, sr):
        n = sr.read_leb128_u()
        for _ in range(n): self._func_type_map.append(sr.read_leb128_u())

    # Table Section

    def _sec_table(self, sr):
        n = sr.read_leb128_u()
        if n > 0:
            self._add("INFO","TABLE",f"{n} table(s) defined",
                      "Tables enable call_indirect — possible obfuscated dispatch")
        for _ in range(n):
            sr.read_u8()  # reftype
            flags=sr.read_leb128_u(); sr.read_leb128_u()
            if flags&1: sr.read_leb128_u()

    # Memory Section

    def _sec_memory(self, sr):
        n = sr.read_leb128_u()
        for i in range(n):
            flags=sr.read_leb128_u(); mn=sr.read_leb128_u(); mx=mn
            if flags&1: mx=sr.read_leb128_u()
            mb = mn*64/1024
            self.report.memory_pages[f"mem_{i}"] = {"min":mn,"max":mx,"min_mb":round(mb,2)}
            if mn > 256:
                self._add("MEDIUM","MEMORY",f"Large initial memory: {mn}p ({mb:.1f}MB)",
                          "Excessive allocation may indicate payload staging")
            if mx > 65536:
                self._add("HIGH","MEMORY",f"Max memory limit: {mx} pages ({mx*64/1024:.0f}MB)",
                          "Unbounded memory growth")

    # Global Section

    def _sec_global(self, sr):
        n = sr.read_leb128_u()
        for _ in range(n):
            vt=sr.read_u8(); mut=sr.read_u8()
            # Parse init expression
            init_op=sr.read_u8(); init_val=None
            if init_op==0x41:   init_val=sr.read_leb128_s()
            elif init_op==0x42: init_val=sr.read_leb128_s()
            elif init_op==0x43: init_val=sr.read_f32()
            elif init_op==0x44: init_val=sr.read_f64()
            sr.read_u8()  # end
            self.report.globals.append(GlobalEntry(
                valtype=VALTYPE.get(vt,"?"),mutable=bool(mut),init_val=init_val))

    # Export Section

    def _sec_export(self, sr):
        n = sr.read_leb128_u()
        kn={0:"func",1:"table",2:"memory",3:"global"}
        for _ in range(n):
            name=sr.read_string(); kind=sr.read_u8(); idx=sr.read_leb128_u()
            self.report.exports.append(ExportEntry(name=name,kind=kn.get(kind,"unk"),index=idx))

        # Suspicious export names
        sus=["main","_start","run","execute","init","decode","decrypt",
             "payload","stage","shellcode","loader","drop","inject","patch"]
        for e in self.report.exports:
            for s in sus:
                if s in e.name.lower():
                    self._add("MEDIUM","EXPORT",f"Suspicious export: '{e.name}'",
                              "Export name suggests executable payload/loader")
                    break

    # Start Section

    def _sec_start(self, sr):
        idx = sr.read_leb128_u()
        self.report.has_start = True; self.report.start_idx = idx
        self._add("MEDIUM","START",f"Start function: func[{idx}]",
                  "Executes automatically on instantiation — common malware entry",
                  evidence=f"func_index={idx}")

    # Element Section

    def _sec_element(self, sr):
        n = sr.read_leb128_u()
        if n > 20:
            self._add("MEDIUM","ELEMENT",f"Large element section: {n} entries",
                      "Large dispatch tables may indicate obfuscated indirect call routing")
        # Just consume (Will be added in future)

    # Code Section

    def _sec_code(self, sr, base_off):
        n = sr.read_leb128_u()
        for fi in range(n):
            fsz   = sr.read_leb128_u()
            fstart= sr.tell()
            fdata = sr.data[fstart:fstart+fsz]
            fsr   = sr.slice(fstart, fsz)
            global_idx = self._import_func_count + fi
            tidx = self._func_type_map[fi] if fi < len(self._func_type_map) else 0
            fa = self._analyze_function(fsr, fdata, global_idx, fsz, tidx, base_off+fstart)
            self.report.functions.append(fa)
            self._scan_crypto_constants(fdata, global_idx, base_off+fstart)
            sr.seek(fstart + fsz)

    def _analyze_function(self, fsr, fdata, idx, size, tidx, base_off) -> FunctionAnalysis:
        fa = FunctionAnalysis(index=idx, size=size, type_idx=tidx,
                              local_count=0, instruction_count=0,
                              unique_opcodes=0, max_stack_depth=0,
                              max_cfg_depth=0, cyclomatic=1)
        # Parse locals
        try:
            nlg = fsr.read_leb128_u()
            for _ in range(nlg):
                cnt=fsr.read_leb128_u(); fsr.read_u8(); fa.local_count+=cnt
        except: pass

        func_body_data = fsr.data[fsr.tell():]

        # Disassemble
        try:
            fa.disassembly = self.dis.disassemble(func_body_data, base_off)
        except: fa.disassembly = []

        # Build CFG
        try:
            c = self.cfg.build(fa.disassembly, idx)
            fa.cfg = c
            fa.cyclomatic = c.cyclomatic_complexity
        except: pass

        # Taint analysis
        try:
            fa.taint = self.taint.analyze(fa.disassembly, self.report.imports)
        except: pass

        # Behavioral profiling
        opcodes_seen = set()
        depth = max_depth = nop_run = max_nop = 0
        xors = rots = mreads = mwrites = 0
        calls = []; indirect = 0; stack_depth = 0; max_stack = 0
        prev3 = []

        for ins in fa.disassembly:
            op = ins.opcode; opcodes_seen.add(op)

            if op in BLOCK_OPS:   depth+=1; max_depth=max(max_depth,depth)
            elif op == 0x0B:      depth=max(0,depth-1)

            if op == 0x01:        nop_run+=1; max_nop=max(max_nop,nop_run)
            else:                 nop_run=0

            if op in XOR_OPS:  xors+=1
            if op in ROT_OPS:  rots+=1
            if op in MEM_LOAD: mreads+=1
            if op in MEM_STORE: mwrites+=1

            if op == 0x10 and ins.operands:   calls.append(ins.operands[0])
            if op == 0x11: indirect+=1

            # Stack depth simulation (rough)
            if op in (0x41,0x42,0x43,0x44,0x20,0x23): stack_depth+=1
            elif op in (0x1A,0x21,0x22,0x24,0x36,0x37): stack_depth=max(0,stack_depth-1)
            max_stack=max(max_stack,stack_depth)

            prev3.append(op)
            if len(prev3)>3: prev3.pop(0)

        fa.instruction_count = len(fa.disassembly)
        fa.unique_opcodes    = len(opcodes_seen)
        fa.max_cfg_depth     = max_depth
        fa.max_stack_depth   = max_stack
        fa.call_targets      = list(set(calls))
        fa.indirect_calls    = indirect
        fa.memory_reads      = mreads
        fa.memory_writes     = mwrites
        fa.xor_ops           = xors
        fa.rot_ops           = rots
        fa.nop_max_run       = max_nop

        # Scoring + flags
        score = 0.0
        if max_nop > 50:
            score+=20; fa.flags.append("NOP_SLED")
            self._add("HIGH","OBFUSCATION",f"NOP sled func[{idx}] ({max_nop} NOPs)",
                      "NOP sleds obfuscate code or align shellcode",offset=idx,func_index=idx)
        if xors > 25:
            score+=15; fa.flags.append("XOR_HEAVY")
            self._add("MEDIUM","OBFUSCATION",f"XOR-heavy func[{idx}] ({xors} XORs)",
                      "Excessive XOR = encryption/decryption routine",func_index=idx)
        if rots > 10:
            score+=10; fa.flags.append("ROTATE_HEAVY")
        if indirect > 0:
            score+=10; fa.flags.append("INDIRECT_CALL")
            self._add("MEDIUM","OBFUSCATION",f"Indirect call in func[{idx}]",
                      "call_indirect = obfuscated dispatch",func_index=idx)
        if size > 65536:
            score+=30; fa.flags.append("HUGE_FUNCTION")
            self._add("HIGH","STRUCTURE",f"Huge function func[{idx}] ({size:,}B)",
                      "Oversized functions may contain packed payloads",func_index=idx)
        elif size > 10000:
            score+=10; fa.flags.append("LARGE_FUNCTION")
        if fa.cyclomatic > 50:
            score+=15; fa.flags.append("HIGH_CYCLOMATIC")
        if fa.taint:
            score+=20; fa.flags.append("TAINT_FLOW")
            self._add("HIGH","TAINT",
                      f"Taint flow in func[{idx}]: {fa.taint.source_import}",
                      f"Data from '{fa.taint.source_import}' flows to "
                      f"{len(fa.taint.tainted_locals)} locals, "
                      f"{len(fa.taint.tainted_globals)} globals",
                      func_index=idx)
        fa.suspicious_score = score
        fa.complexity_score = (fa.cyclomatic * 0.5 + fa.instruction_count * 0.001 +
                               max_depth * 2 + len(opcodes_seen) * 0.1)
        return fa

    # Data Section

    def _sec_data(self, sr):
        n = sr.read_leb128_u(); self.report.data_segments = n
        for si in range(n):
            try:
                flags=sr.read_leb128_u()
                if flags==0:
                    op=sr.read_u8()
                    if op==0x41: sr.read_leb128_s()
                    elif op==0x42: sr.read_leb128_s()
                    sr.read_u8()
                elif flags==2:
                    sr.read_leb128_u()
                    op=sr.read_u8()
                    if op==0x41: sr.read_leb128_s()
                    sr.read_u8()
                dsz=sr.read_leb128_u(); seg=sr.read(dsz)
                ent=shannon_entropy(seg)
                self.report.data_entropy.append(round(ent,4))
                self._extract_strings(seg, si)
                if ent>7.0 and dsz>256:
                    self._add("HIGH","ENTROPY",
                              f"High-entropy data seg[{si}] ({ent:.3f})",
                              "Encrypted/compressed embedded payload",
                              evidence=f"size={dsz}")
            except: break

    def _extract_strings(self, data: bytes, seg: int):
        for m in re.findall(rb'[ -~]{6,}', data):
            s = m.decode('ascii','ignore')
            if s not in self.report.strings:
                self.report.strings.append(s)
            sl = s.lower()
            # IoC matching
            for ioc_pat, ioc_name in IOC_STRINGS:
                if ioc_pat.lower() in sl:
                    self.report.iocs.append((s[:120], ioc_name))
                    self._add("HIGH","IOC",
                              f"IoC in data[{seg}]: [{ioc_name}]",
                              f"String matches '{ioc_pat}'",
                              evidence=s[:200])
                    break
            # High-entropy string detection (base64/encoded payloads)
            if len(s) >= 20:
                s_ent = shannon_entropy(s.encode())
                if s_ent > 5.0 and re.match(r'^[A-Za-z0-9+/=]+$', s) and len(s) % 4 == 0:
                    self._add("MEDIUM", "ENCODED_STRING",
                              f"Possible base64 string in data[{seg}] (entropy={s_ent:.2f})",
                              "High-entropy printable string — may be encoded payload",
                              evidence=s[:80])

    # Custom Section

    def _sec_custom(self, sr, sec_size):
        try:
            name    = sr.read_string()
            payload = sr.read(sr.remaining())
            ent     = shannon_entropy(payload)
            entry   = {"name":name,"size":sec_size,"entropy":round(ent,4),
                       "preview":payload[:64].hex()}
            self.report.custom_secs.append(entry)

            known = {"name","producers","target_features","sourceMappingURL",
                     "dylink","dylink.0","linking","reloc.CODE","reloc.DATA"}
            if name == "name":
                self._add("INFO","DEBUG","Name section present",
                          "Symbols not stripped — aids analysis")
            elif name not in known:
                self._add("MEDIUM","CUSTOM_SECTION",
                          f"Unknown custom section: '{name}'",
                          "Non-standard sections may contain hidden payloads",
                          evidence=f"preview={payload[:32].hex()}")
            if ent > 7.0 and len(payload) > 64:
                self._add("HIGH","ENTROPY",
                          f"High-entropy custom '{name}' ({ent:.3f})",
                          "Possible encrypted payload",
                          evidence=f"size={len(payload)}")
        except: pass

    # Crypto Scanner

    def _scan_crypto_constants(self, data: bytes, func_idx: int, base_off: int):
        for val, name in CRYPTO_CONSTANTS:
            packed = struct.pack('<I', val & 0xFFFFFFFF)
            # Collect all positions
            positions = []
            off = 0
            while True:
                pos = data.find(packed, off)
                if pos == -1: break
                positions.append(base_off + pos)
                off = pos + 1
            if not positions: continue
            # Deduplicate: ONE entry per (constant name × function) pair
            key = f"{name}||func{func_idx}"
            if any(h.get("_dedup_key") == key for h in self.report.crypto_hits):
                continue
            entry = {"value": hex(val), "name": name,
                     "func_index": func_idx,
                     "file_offset": f"{positions[0]:#x}",
                     "hit_count": len(positions),
                     "_dedup_key": key}
            self.report.crypto_hits.append(entry)
            cnt = f" \xd7{len(positions)}" if len(positions) > 1 else ""
            self._add("HIGH", "CRYPTO",
                      f"Crypto constant: {name}{cnt}",
                      f"{val:#010x} found {len(positions)}\xd7 in func[{func_idx}]",
                      evidence=f"first_offset={positions[0]:#x}  count={len(positions)}",
                      offset=positions[0], func_index=func_idx)

    # Helper

    def _add(self, severity, category, title, description,
             evidence="", offset=-1, func_index=-1, rule_name=""):
        self.report.findings.append(Finding(
            severity=severity, category=category,
            title=title, description=description,
            evidence=evidence, offset=offset,
            func_index=func_index, rule_name=rule_name))



#  SCORING ENGINE

class ScoringEngine:
    SEV_W = {"CRITICAL":30,"HIGH":18,"MEDIUM":10,"LOW":4,"INFO":0}
    OBFUSC_CATS = {"OBFUSCATION","ENTROPY","CUSTOM_SECTION","STRUCTURE"}
    MALICE_CATS = {"CRYPTO","NETWORK","EXEC","EXFIL","IOC","STRINGS",
                   "START","TAINT","RANSOMWARE"}

    MITRE_MAP = {
        "EXEC":    "T1059 - Command and Scripting Interpreter",
        "NETWORK": "T1071 - Application Layer Protocol",
        "CRYPTO":  "T1496 - Resource Hijacking (Cryptomining)",
        "EXFIL":   "T1041 - Exfiltration Over C2 Channel",
        "EVASION": "T1027 - Obfuscated Files/Information",
        "OBFUSCATION":"T1027 - Obfuscated Files/Information",
        "TAINT":   "T1055 - Process Injection (data flow)",
        "RANSOMWARE":"T1486 - Data Encrypted for Impact",
        "IOC":     "T1071 - Application Layer Protocol",
    }

    def score(self, report: AnalysisReport) -> AnalysisReport:
        malice = obfusc = complexity = 0.0
        seen_mitre: Set[str] = set()

        for f in report.findings:
            w = self.SEV_W.get(f.severity, 0)
            if f.category in self.OBFUSC_CATS: obfusc  += w
            if f.category in self.MALICE_CATS: malice  += w * 1.5
            if f.severity in ("CRITICAL","HIGH"): malice += w * 0.5
            tag = self.MITRE_MAP.get(f.category,"")
            if tag: seen_mitre.add(tag)

        for fn in report.functions:
            malice     += fn.suspicious_score * 0.4
            obfusc     += (fn.nop_max_run / 10) + (fn.indirect_calls * 5)
            complexity += fn.complexity_score * 0.01

        # High file entropy contribution
        if report.file_entropy > 7.0: obfusc  += 20
        if report.file_entropy > 7.5: malice  += 10

        report.malice_score      = min(100.0, round(malice, 1))
        report.obfuscation_score = min(100.0, round(obfusc, 1))
        report.complexity_score  = min(100.0, round(complexity, 1))
        report.mitre_tags        = sorted(seen_mitre)

        if   report.malice_score >= 75:                                     report.verdict = "MALICIOUS"
        elif report.malice_score >= 45 or report.obfuscation_score >= 65:  report.verdict = "SUSPICIOUS"
        elif report.malice_score >= 20:                                    report.verdict = "POTENTIALLY_UNWANTED"
        else:                                                               report.verdict = "CLEAN"

        # Confidence = how many independent signals agree
        signals = sum([
            report.malice_score > 40,
            report.obfuscation_score > 40,
            len(report.crypto_hits) > 0,
            len(report.iocs) > 0,
            bool(report.matched_rules),
            any(fn.taint for fn in report.functions),
        ])
        report.confidence = round(min(100, signals * 18), 1)
        return report



#  RULE ENGINE  (.wsr files)

@dataclass
class WSRRule:
    name:        str
    description: str
    author:      str = ""
    severity:    str = "HIGH"
    tags:        List[str] = field(default_factory=list)
    conditions:  List[str] = field(default_factory=list)
    raw:         str = ""

class RuleEngine:
    """
    Load and evaluate WASMShark Rule (.wsr) files.

    Syntax:
        rule RULE_NAME {
            meta:
                description = "..."
                author = "..."
                severity = HIGH
            condition:
                imports contains "eval"
                strings contains "bitcoin"
                entropy > 7.0
                crypto_constant "SHA-256 H0"
                has_start_func
                malice_score > 50
                xor_ops > 20
                function_count > 10
        }
    """

    def load_rules(self, rules_dir: str) -> List[WSRRule]:
        rules = []
        p = Path(rules_dir)
        if not p.exists(): return rules
        for f in p.glob("*.wsr"):
            try:
                text = f.read_text()
                rules.extend(self._parse_file(text))
            except Exception as e:
                print(f"[!] Rule parse error {f}: {e}", file=sys.stderr)
        return rules

    def _parse_file(self, text: str) -> List[WSRRule]:
        rules = []
        for block in re.finditer(r'rule\s+(\w+)\s*\{(.*?)\}', text, re.DOTALL):
            name = block.group(1); body = block.group(2)
            # Provide defaults so WSRRule never throws missing-arg errors
            rule = WSRRule(name=name, description=f"Rule: {name}", raw=block.group(0))
            in_condition = False
            for line in body.splitlines():
                line = line.strip()
                if line.startswith("condition:"): in_condition = True; continue
                if line.startswith("meta:"):      in_condition = False; continue
                if not line or line.startswith("#"): continue
                if not in_condition:
                    if   line.startswith("description"): rule.description = line.split("=",1)[-1].strip().strip('"')
                    elif line.startswith("author"):      rule.author      = line.split("=",1)[-1].strip().strip('"')
                    elif line.startswith("severity"):    rule.severity    = line.split("=",1)[-1].strip()
                    elif line.startswith("tags"):        rule.tags        = [t.strip() for t in line.split("=",1)[-1].split(",")]
                else:
                    rule.conditions.append(line)
            rules.append(rule)
        return rules

    def evaluate(self, report: AnalysisReport, rules: List[WSRRule]) -> List[Dict]:
        matched = []
        for rule in rules:
            try:
                if self._eval_rule(rule, report):
                    matched.append({"name":rule.name,"description":rule.description,
                                    "severity":rule.severity,"tags":rule.tags,
                                    "author":rule.author})
            except Exception as e:
                pass
        return matched

    def _eval_rule(self, rule: WSRRule, r: AnalysisReport) -> bool:
        if not rule.conditions: return False
        all_imports = [f"{i.module}.{i.name}".lower() for i in r.imports]
        all_strings = [s.lower() for s in r.strings]
        all_crypto  = [h["name"].lower() for h in r.crypto_hits]
        total_xors  = sum(fn.xor_ops for fn in r.functions)

        for cond in rule.conditions:
            cond = cond.strip()
            if not cond or cond.startswith("#"): continue
            match = False
            if   re.match(r'imports contains "(.*)"', cond):
                pat = re.search(r'"(.*)"', cond).group(1).lower()
                match = any(pat in i for i in all_imports)
            elif re.match(r'strings contains "(.*)"', cond):
                pat = re.search(r'"(.*)"', cond).group(1).lower()
                match = any(pat in s for s in all_strings)
            elif re.match(r'ioc contains "(.*)"', cond):
                pat = re.search(r'"(.*)"', cond).group(1).lower()
                match = any(pat in ioc.lower() for ioc,_ in r.iocs)
            elif re.match(r'crypto_constant "(.*)"', cond):
                pat = re.search(r'"(.*)"', cond).group(1).lower()
                match = any(pat in c for c in all_crypto)
            elif re.match(r'entropy\s*([><=!]+)\s*([\d.]+)', cond):
                m = re.match(r'entropy\s*([><=!]+)\s*([\d.]+)', cond)
                match = self._compare(r.file_entropy, m.group(1), float(m.group(2)))
            elif re.match(r'malice_score\s*([><=!]+)\s*([\d.]+)', cond):
                m = re.match(r'malice_score\s*([><=!]+)\s*([\d.]+)', cond)
                match = self._compare(r.malice_score, m.group(1), float(m.group(2)))
            elif re.match(r'obfusc_score\s*([><=!]+)\s*([\d.]+)', cond):
                m = re.match(r'obfusc_score\s*([><=!]+)\s*([\d.]+)', cond)
                match = self._compare(r.obfuscation_score, m.group(1), float(m.group(2)))
            elif re.match(r'xor_ops\s*([><=!]+)\s*(\d+)', cond):
                m = re.match(r'xor_ops\s*([><=!]+)\s*(\d+)', cond)
                match = self._compare(total_xors, m.group(1), int(m.group(2)))
            elif re.match(r'function_count\s*([><=!]+)\s*(\d+)', cond):
                m = re.match(r'function_count\s*([><=!]+)\s*(\d+)', cond)
                match = self._compare(len(r.functions), m.group(1), int(m.group(2)))
            elif cond == "has_start_func":      match = r.has_start
            elif cond == "has_indirect_calls":  match = any(fn.indirect_calls>0 for fn in r.functions)
            elif cond == "has_taint":           match = any(fn.taint for fn in r.functions)
            elif cond == "has_custom_sections": match = bool(r.custom_secs)
            elif cond == "is_wasi":             match = any(i.module.startswith("wasi") for i in r.imports)
            elif re.match(r'import_count\s*([><=!]+)\s*(\d+)', cond):
                m = re.match(r'import_count\s*([><=!]+)\s*(\d+)', cond)
                match = self._compare(len(r.imports), m.group(1), int(m.group(2)))
            else:
                continue
            if not match: return False
        return True

    def _compare(self, a, op, b) -> bool:
        return {">":a>b,">=":a>=b,"<":a<b,"<=":a<=b,"==":a==b,"!=":a!=b}.get(op, False)

    # Built-in rules (no files needed)
    BUILTIN_RULES: List[WSRRule] = []  # populated below

# Add built-in rules programmatically
_builtin = [
    WSRRule("CRYPTOMINER_WASM","WebAssembly cryptominer","WASMShark","CRITICAL",
            ["mining","crypto"],
            ['imports contains "sha256"','imports contains "randomx"',
             'malice_score > 30']),
    WSRRule("WASI_DROPPER","WASI-based file dropper","WASMShark","CRITICAL",
            ["dropper","wasi"],
            ['is_wasi','imports contains "fd_write"','strings contains "powershell"']),
    WSRRule("WASI_DROPPER_v2","WASI dropper alt variant","WASMShark","HIGH",
            ["dropper","wasi"],
            ['is_wasi','imports contains "path_open"','import_count > 3']),
    WSRRule("OBFUSCATED_PAYLOAD","Heavily obfuscated payload","WASMShark","HIGH",
            ["obfuscation"],
            ['obfusc_score > 50','entropy > 6.5','has_indirect_calls']),
    WSRRule("AUTORUN_MALWARE","Auto-executing malicious start","WASMShark","HIGH",
            ["autorun"],
            ['has_start_func','malice_score > 30']),
    WSRRule("NETWORK_BEACON","C2 beacon / network malware","WASMShark","CRITICAL",
            ["c2","network"],
            ['imports contains "socket"','ioc contains "http"']),
    WSRRule("NETWORK_BEACON_v2","Network + onion IoC","WASMShark","CRITICAL",
            ["c2","tor"],
            ['ioc contains ".onion"']),
    WSRRule("PACKED_BINARY","Packed or compressed binary","WASMShark","HIGH",
            ["packing"],
            ['entropy > 7.3','import_count < 3']),
    WSRRule("XOR_DECRYPTOR","XOR decryption routine","WASMShark","MEDIUM",
            ["crypto","xor"],
            ['xor_ops > 50']),
    WSRRule("INDIRECT_DISPATCHER","Obfuscated call dispatcher","WASMShark","MEDIUM",
            ["obfuscation"],
            ['has_indirect_calls','obfusc_score > 30']),
    WSRRule("TAINT_DATA_FLOW","Suspicious data flow from imports","WASMShark","HIGH",
            ["taint"],
            ['has_taint']),
    WSRRule("RANSOMWARE_KW","Ransomware keyword indicators","WASMShark","CRITICAL",
            ["ransomware"],
            ['strings contains "ransom"']),
    WSRRule("RANSOMWARE_KW_v2","Ransomware encrypt+decrypt","WASMShark","CRITICAL",
            ["ransomware"],
            ['strings contains "decrypt"','strings contains "encrypt"']),
    WSRRule("SHA256_IMPL","SHA-256 implementation detected","WASMShark","HIGH",
            ["crypto"],
            ['crypto_constant "SHA-256 H0"','crypto_constant "SHA-256 H1"']),
    WSRRule("CHACHA20_IMPL","ChaCha20 implementation","WASMShark","HIGH",
            ["crypto"],
            ['crypto_constant "ChaCha20 \'expa\'"']),
    WSRRule("LARGE_COMPLEX","Suspiciously large/complex module","WASMShark","MEDIUM",
            ["complexity"],
            ['function_count > 200','complexity_score > 60']),
]
RuleEngine.BUILTIN_RULES = _builtin



#  PLUGIN SYSTEM

class PluginManager:
    # Load Python plugins from plugins/ directory

    def __init__(self, plugins_dir: str):
        self.plugins_dir = plugins_dir
        self.plugins: List[Any] = []

    def load(self):
        p = Path(self.plugins_dir)
        if not p.exists(): return
        for f in p.glob("plugin_*.py"):
            try:
                spec = importlib.util.spec_from_file_location(f.stem, f)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, 'WASMPlugin'):
                    self.plugins.append(mod.WASMPlugin())
            except Exception as e:
                print(f"[!] Plugin load error {f}: {e}", file=sys.stderr)

    def run_all(self, report: AnalysisReport) -> Dict[str,Any]:
        results = {}
        for plugin in self.plugins:
            try:
                name   = getattr(plugin,'name','unnamed')
                result = plugin.analyze(report)
                results[name] = result
            except Exception as e:
                results[getattr(plugin,'name','err')] = {"error":str(e)}
        return results



#  CFG DOT EXPORTER

class CFGExporter:
    # Export a function's CFG to Graphviz DOT format

    def to_dot(self, fa: FunctionAnalysis) -> str:
        if not fa.cfg or not fa.cfg.blocks:
            return f'digraph func_{fa.index} {{ label="func[{fa.index}]: empty CFG" }}'

        lines = [f'digraph func_{fa.index} {{']
        lines.append(f'  label="func[{fa.index}] — {fa.instruction_count} instrs, '
                     f'cyclomatic={fa.cyclomatic}";')
        lines.append('  node [fontname="Courier" shape=box style=filled];')

        for bb in fa.cfg.blocks:
            color = "#ff4444" if bb.is_entry else ("#44ff44" if bb.is_exit else "#ffffff")
            label_lines = [f"BB{bb.id} off={bb.start_offset:#x}"]
            for ins in bb.instructions[:8]:  # first 8 instrs
                ops_str = " ".join(str(o) for o in ins.operands[:2])
                taint_marker = " [T]" if ins.tainted else ""
                label_lines.append(f"  {ins.mnemonic} {ops_str}{taint_marker}")
            if len(bb.instructions) > 8:
                label_lines.append(f"  ... +{len(bb.instructions)-8} more")
            label = "\\n".join(label_lines)
            lines.append(f'  bb{bb.id} [label="{label}" fillcolor="{color}"];')

        for bb in fa.cfg.blocks:
            for succ_id in bb.successors:
                lines.append(f'  bb{bb.id} -> bb{succ_id};')

        lines.append('}')
        return '\n'.join(lines)



#  REPORT FORMATTERS

# SARIF 2.1 output
def to_sarif(report: AnalysisReport) -> Dict:
    results = []
    for f in report.findings:
        results.append({
            "ruleId": f"WASMSHARK/{f.category}/{f.severity}",
            "level": {"CRITICAL":"error","HIGH":"error",
                      "MEDIUM":"warning","LOW":"note","INFO":"none"}.get(f.severity,"warning"),
            "message": {"text": f"{f.title} — {f.description}"},
            "locations": [{"logicalLocations":[
                {"name": report.filename,
                 "decoratedName": f"func[{f.func_index}]" if f.func_index>=0 else ""}
            ]}],
            "properties": {"evidence":f.evidence,"offset":f.offset}
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver":{
                "name":"WASMShark","version":"2.0","informationUri":"https://github.com/WASM-Shark/wasmshark",
                "rules": [{"id":"WASMSHARK","name":"WASMShark Analyzer"}]
            }},
            "artifacts": [{"location":{"uri":report.filename},
                           "hashes":{"sha-256":report.sha256,"md5":report.md5}}],
            "results": results,
            "properties": {
                "verdict":report.verdict,"malice_score":report.malice_score,
                "obfuscation_score":report.obfuscation_score,"entropy":report.file_entropy
            }
        }]
    }


def to_json_report(report: AnalysisReport) -> Dict:
    return {
        "metadata": {
            "tool":"WASMShark v2.0","filename":report.filename,
            "file_size":report.file_size,"sha256":report.sha256,
            "sha1":report.sha1,"md5":report.md5,
            "is_valid_wasm":report.is_valid,"wasm_version":report.wasm_version
        },
        "scores": {
            "malice":report.malice_score,"obfuscation":report.obfuscation_score,
            "complexity":report.complexity_score,"confidence":report.confidence
        },
        "verdict": report.verdict,
        "mitre_tags": report.mitre_tags,
        "entropy": {"file":report.file_entropy,"chi2":report.chi2_score,
                    "sections":{s.name:s.entropy for s in report.sections}},
        "sections": [asdict(s) for s in report.sections],
        "imports":  [asdict(i) for i in report.imports],
        "exports":  [asdict(e) for e in report.exports],
        "memory_pages": report.memory_pages,
        "data_segments": report.data_segments,
        "has_start_func": report.has_start,
        "start_func_idx": report.start_idx,
        "custom_sections": report.custom_secs,
        "crypto_constants": report.crypto_hits,
        "iocs": [{"string":ioc,"type":typ} for ioc,typ in report.iocs],
        "strings": report.strings[:150],
        "functions": [{
            "index":fn.index,"size":fn.size,"instructions":fn.instruction_count,
            "unique_opcodes":fn.unique_opcodes,"xor_ops":fn.xor_ops,
            "rot_ops":fn.rot_ops,"memory_reads":fn.memory_reads,
            "memory_writes":fn.memory_writes,"indirect_calls":fn.indirect_calls,
            "cyclomatic":fn.cyclomatic,"nop_max_run":fn.nop_max_run,
            "flags":fn.flags,"suspicious_score":fn.suspicious_score,
            "taint": asdict(fn.taint) if fn.taint else None,
        } for fn in report.functions],
        "findings":      [asdict(f) for f in report.findings],
        "matched_rules": report.matched_rules,
        "plugin_results": report.plugin_results,
        "imphash":        report.imphash,
        "dead_functions": report.dead_functions,
    }


def _wasi_html(report) -> str:
    wa = report.wasi_analysis
    if not wa: return ""
    caps = ", ".join(wa.get("claimed_capabilities", [])) or "none"
    combos = wa.get("dangerous_combos", [])
    combo_html = "".join(
        f'<div class="finding"><strong style="color:#ff6b6b">{c["name"]}</strong> — {c["description"]}<br>'
        f'<code>caps: {", ".join(c.get("capabilities_matched",[]))}</code></div>'
        for c in combos)
    risk = wa.get("risk_label","CLEAN")
    rc = {"CRITICAL":"#ff3333","HIGH":"#ff6600","MEDIUM":"#ffaa00","LOW":"#44aaff","CLEAN":"#33cc66"}.get(risk,"#aaa")
    return (f'<p><strong>Risk Level:</strong> <span style="color:{rc}">{risk}</span></p>'
            f'<p><strong>Claimed Capabilities:</strong> <code>{caps}</code></p>'
            f'<p><strong>WASI Imports:</strong> {wa.get("wasi_import_count",0)}</p>'
            + (combo_html or "<p style=\'color:#888\'>No dangerous combinations detected</p>"))

def _loop_html(report) -> str:
    rows = ""
    for lp in report.loop_profiles[:20]:
        flags = []
        if lp.get("has_mining_loop"):  flags.append('<span style="color:#ff6600">MINING</span>')
        if lp.get("has_crypto_loop"):  flags.append('<span style="color:#ff9900">CRYPTO</span>')
        if lp.get("has_decode_loop"):  flags.append('<span style="color:#ffcc00">DECODE</span>')
        if lp.get("has_memcpy_loop"):  flags.append('<span style="color:#aaaaff">MEMCPY</span>')
        if not flags: continue
        rows += (f'<tr><td>func[{lp["func_index"]}]</td>'
                 f'<td>{lp.get("loop_count",0)}</td>'
                 f'<td>{lp.get("dominant_type","")}</td>'
                 f'<td>{lp.get("xor_density",0):.3f}</td>'
                 f'<td>{lp.get("rotate_density",0):.3f}</td>'
                 f'<td>{" ".join(flags)}</td></tr>')
    if not rows: return "<p style=\'color:#888\'>No notable loops detected</p>"
    return (f'<table><tr><th>Function</th><th>Loops</th><th>Type</th>'
            f'<th>XOR Density</th><th>Rotate Density</th><th>Flags</th></tr>{rows}</table>')

def _obf_html(report) -> str:
    if not report.obfuscation_detail:
        return "<p style=\'color:#888\'>No advanced obfuscation patterns detected</p>"
    html = ""
    for item in report.obfuscation_detail[:10]:
        html += f'<div class="finding"><strong>func[{item["func_index"]}]</strong> — {item["dominant"]} (score={item["score"]:.0f})<br>'
        for tech in item["techniques"][:3]:
            col = {"HIGH":"#ff6600","CRITICAL":"#ff3333","MEDIUM":"#ffaa00"}.get(tech.get("severity","LOW"),"#aaa")
            html += f'<span style="color:{col}">▸ {tech["technique"]}</span> — {tech["description"]}<br>'
        html += "</div>"
    return html

def _api_html(report) -> str:
    score_col = "#ff3333" if report.api_abuse_score > 60 else ("#ff9900" if report.api_abuse_score > 30 else "#33cc66")
    rows = "".join(
        f'<tr><td><code>{d.get("api") or d.get("combo","")}</code></td>'
        f'<td style="color:#ff9900">{d["score"]}</td>'
        f'<td>{d["reason"]}</td></tr>'
        for d in report.api_abuse_detail[:15])
    return (f'<p><strong>API Abuse Score: <span style="color:{score_col}">{report.api_abuse_score:.1f}/100</span></strong></p>'
            f'<table><tr><th>API / Combination</th><th>Score</th><th>Reason</th></tr>{rows}</table>')

def _sec_anom_html(report) -> str:
    if not report.section_anomalies:
        return "<p style=\'color:#888\'>No section anomalies detected</p>"
    rows = "".join(
        f'<tr><td style="color:#ff9900">{a["anomaly_type"]}</td>'
        f'<td>{a["severity"]}</td><td>{a["description"]}</td>'
        f'<td><code>{a["evidence"]}</code></td></tr>'
        for a in report.section_anomalies)
    return f'<table><tr><th>Type</th><th>Severity</th><th>Description</th><th>Evidence</th></tr>{rows}</table>'

def _entropy_timeline_html(report) -> str:
    if not report.entropy_timeline: return ""
    # SVG bar chart of entropy blocks
    blocks = report.entropy_timeline[:50]
    w = 8; h = 80; gap = 1; total_w = len(blocks) * (w + gap) + 20
    bars = ""
    for i, b in enumerate(blocks):
        ent = b["entropy"]; bh = int(ent / 8.0 * h)
        col = ("#ff3333" if ent > 7.5 else "#ff9900" if ent > 7.0
               else "#ffcc00" if ent > 6.0 else "#44aaff" if ent > 3.0 else "#444444")
        x = 10 + i * (w + gap); y = h - bh + 10
        bars += f'<rect x="{x}" y="{y}" width="{w}" height="{bh}" fill="{col}" opacity="0.85"/>'
    svg = (f'<svg viewBox="0 0 {total_w} {h+30}" xmlns="http://www.w3.org/2000/svg" '
           f'style="width:100%;max-width:900px;background:#161b22;border-radius:6px">'
           f'<text x="10" y="105" fill="#888" font-size="9">0</text>'
           f'<text x="10" y="15" fill="#888" font-size="9">8.0</text>'
           f'<text x="{total_w//2}" y="120" fill="#888" font-size="9" text-anchor="middle">File offset →</text>'
           f'{bars}</svg>')
    anomalous = sum(1 for b in blocks if b["entropy"] > 7.0)
    return (f'<p>Block size: 256 bytes | <span style="color:#ff3333">■</span> >7.5 encrypted '
            f'<span style="color:#ff9900">■</span> >7.0 compressed '
            f'<span style="color:#44aaff">■</span> normal | '
            f'{anomalous} anomalous blocks</p>{svg}')

def _string_scores_html(report) -> str:
    if not report.string_scores: return "<p style=\'color:#888\'>No suspicious strings above threshold</p>"
    rows = "".join(
        f'<tr><td><code style="color:#f0883e">{s["string"][:80]}</code></td>'
        f'<td style="color:#ff9900">{s["score"]:.0f}</td>'
        f'<td style="color:#888">{s["reason"]}</td></tr>'
        for s in report.string_scores[:15])
    return f'<table><tr><th>String</th><th>Score</th><th>Reason</th></tr>{rows}</table>'


def generate_html_report(report: AnalysisReport) -> str:
    vc = {"MALICIOUS":"#ff3333","SUSPICIOUS":"#ff9900",
          "POTENTIALLY_UNWANTED":"#ffcc00","CLEAN":"#33cc33"}.get(report.verdict,"#aaa")
    sev_col = {"CRITICAL":"#ff2222","HIGH":"#ff6600","MEDIUM":"#ffaa00",
               "LOW":"#44aaff","INFO":"#888888"}

    findings_html = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        fi = [f for f in report.findings if f.severity==sev]
        if not fi: continue
        col = sev_col.get(sev,"#aaa")
        findings_html += f'<div class="sev-group"><h3 style="color:{col}">[{sev}] — {len(fi)} finding(s)</h3>'
        for f in fi:
            findings_html += f'''<div class="finding">
  <strong>{f.title}</strong><br>
  <span class="desc">{f.description}</span>
  {"<br><code>"+f.evidence+"</code>" if f.evidence else ""}
</div>'''
        findings_html += '</div>'

    imports_html = "".join(
        f'<tr><td>{i.module}</td><td>{i.name}</td><td>{i.kind}</td></tr>'
        for i in report.imports)
    exports_html = "".join(
        f'<tr><td>{e.index}</td><td>{e.name}</td><td>{e.kind}</td></tr>'
        for e in report.exports)
    rules_html   = "".join(
        f'<div class="rule-match"><strong>{r["name"]}</strong> — {r["description"]}</div>'
        for r in report.matched_rules)
    iocs_html    = "".join(
        f'<tr><td>{i[1]}</td><td><code>{i[0][:80]}</code></td></tr>'
        for i in report.iocs)
    crypto_html  = "".join(
        f'<tr><td><code>{c["value"]}</code></td><td>{c["name"]}</td><td>func[{c["func_index"]}]</td></tr>'
        for c in report.crypto_hits)
    mitre_html   = "".join(f'<li>{t}</li>' for t in report.mitre_tags)

    def score_bar(score, width=200):
        color = "#ff3333" if score>60 else ("#ff9900" if score>30 else "#33cc66")
        filled = int(score/100*width)
        return (f'<div style="background:#333;width:{width}px;height:14px;border-radius:4px;display:inline-block">'
                f'<div style="background:{color};width:{filled}px;height:14px;border-radius:4px"></div></div>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WASMShark Report — {report.filename}</title>
<style>
  :root {{ --bg:#0d1117; --surface:#161b22; --border:#30363d;
           --text:#c9d1d9; --accent:#58a6ff; --red:#ff6b6b; }}
  body {{ background:var(--bg);color:var(--text);font-family:'Courier New',monospace;margin:0;padding:20px }}
  h1 {{ color:#58a6ff;border-bottom:1px solid var(--border);padding-bottom:12px }}
  h2 {{ color:#79c0ff;margin-top:30px }}
  h3 {{ margin:10px 0 5px }}
  .card {{ background:var(--surface);border:1px solid var(--border);border-radius:8px;
           padding:20px;margin:16px 0 }}
  .verdict {{ font-size:2em;font-weight:bold;color:{vc} }}
  table {{ width:100%;border-collapse:collapse;margin:10px 0 }}
  th {{ background:#21262d;text-align:left;padding:8px;color:#79c0ff;border-bottom:1px solid var(--border) }}
  td {{ padding:6px 8px;border-bottom:1px solid #21262d;font-size:0.9em }}
  .finding {{ background:#21262d;border-left:3px solid #ff6600;padding:10px;margin:8px 0;border-radius:4px }}
  .desc {{ color:#8b949e;font-size:0.9em }}
  .rule-match {{ background:#21262d;border-left:3px solid #ff3333;padding:8px;margin:6px 0;border-radius:4px }}
  code {{ background:#21262d;padding:2px 6px;border-radius:3px;font-size:0.85em;color:#f0883e }}
  .badge {{ display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;
            font-weight:bold;margin:2px }}
  .score-row {{ display:flex;align-items:center;gap:12px;margin:8px 0 }}
  ul {{ padding-left:20px }}
  .sev-group {{ margin:16px 0 }}
  .mono {{ font-family:'Courier New',monospace;font-size:0.85em;color:#8b949e }}
</style>
</head>
<body>
<h1> WASMShark Analysis Report</h1>

<div class="card">
  <div class="verdict">{report.verdict}</div>
  <div class="score-row"><span>Malice Score</span>{score_bar(report.malice_score)}<strong>{report.malice_score:.1f}/100</strong></div>
  <div class="score-row"><span>Obfuscation </span>{score_bar(report.obfuscation_score)}<strong>{report.obfuscation_score:.1f}/100</strong></div>
  <div class="score-row"><span>Complexity  </span>{score_bar(report.complexity_score)}<strong>{report.complexity_score:.1f}/100</strong></div>
  <div class="score-row"><span>Confidence  </span>{score_bar(report.confidence)}<strong>{report.confidence:.1f}%</strong></div>
</div>

<div class="card">
  <h2>📁 File Metadata</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Filename</td><td>{report.filename}</td></tr>
    <tr><td>File Size</td><td>{report.file_size:,} bytes</td></tr>
    <tr><td>SHA-256</td><td><code>{report.sha256}</code></td></tr>
    <tr><td>SHA-1</td><td><code>{report.sha1}</code></td></tr>
    <tr><td>MD5</td><td><code>{report.md5}</code></td></tr>
    <tr><td>WASM Version</td><td>{report.wasm_version}</td></tr>
    <tr><td>File Entropy</td><td>{report.file_entropy:.4f} / 8.0</td></tr>
    <tr><td>Chi-Square</td><td>{report.chi2_score:.2f}</td></tr>
    <tr><td>Functions</td><td>{len(report.functions)}</td></tr>
    <tr><td>Imports</td><td>{len(report.imports)}</td></tr>
    <tr><td>Data Segments</td><td>{report.data_segments}</td></tr>
    <tr><td>Has Start Func</td><td>{"YES ⚡ (func["+str(report.start_idx)+"])" if report.has_start else "No"}</td></tr>
    <tr><td>Imphash</td><td><code>{report.imphash}</code></td></tr>
    <tr><td>Dead Functions</td><td>{len(report.dead_functions)} unreachable ({report.dead_functions[:5]})</td></tr>
  </table>
</div>

{"<div class='card'><h2>⚠️ Matched Rules ("+str(len(report.matched_rules))+")</h2>"+rules_html+"</div>" if report.matched_rules else ""}

{"<div class='card'><h2>🎯 MITRE ATT&CK Tags</h2><ul>"+mitre_html+"</ul></div>" if report.mitre_tags else ""}

{"<div class='card'><h2>🔑 Crypto Constants ("+str(len(report.crypto_hits))+")</h2><table><tr><th>Value</th><th>Name</th><th>Location</th></tr>"+crypto_html+"</table></div>" if report.crypto_hits else ""}

{"<div class='card'><h2>🌐 IoC Strings ("+str(len(report.iocs))+")</h2><table><tr><th>Type</th><th>String</th></tr>"+iocs_html+"</table></div>" if report.iocs else ""}

<div class="card">
  <h2>📥 Imports ({len(report.imports)})</h2>
  <table><tr><th>Module</th><th>Name</th><th>Kind</th></tr>{imports_html}</table>
</div>

<div class="card">
  <h2>📤 Exports ({len(report.exports)})</h2>
  <table><tr><th>Index</th><th>Name</th><th>Kind</th></tr>{exports_html}</table>
</div>

<div class="card">
  <h2>🔍 Findings ({len(report.findings)})</h2>
  {findings_html}
</div>

<div class="card mono">
  <h2>🧵 Extracted Strings ({len(report.strings)})</h2>
  {"<br>".join(s[:120] for s in report.strings[:60])}
  {"<br>... +"+str(len(report.strings)-60)+" more" if len(report.strings)>60 else ""}
</div>

{"<div class='card'><h2>🔬 WASI Capability Analysis</h2>" + _wasi_html(report) + "</div>" if report.wasi_analysis else ""}

{"<div class='card'><h2>🔁 Loop Analysis</h2>" + _loop_html(report) + "</div>" if report.loop_profiles else ""}

{"<div class='card'><h2>🧩 Obfuscation Detail</h2>" + _obf_html(report) + "</div>" if report.obfuscation_detail else ""}

{"<div class='card'><h2>📊 API Abuse Score</h2>" + _api_html(report) + "</div>" if report.api_abuse_detail else ""}

{"<div class='card'><h2>⚠️ Section Anomalies</h2>" + _sec_anom_html(report) + "</div>" if report.section_anomalies else ""}

{"<div class='card'><h2>📈 Entropy Timeline</h2>" + _entropy_timeline_html(report) + "</div>" if report.entropy_timeline else ""}

{"<div class='card'><h2>🔤 Suspicious Strings</h2>" + _string_scores_html(report) + "</div>" if report.string_scores else ""}

<footer style="color:#444;margin-top:40px;text-align:center">
  WebAssembly Malware Analyzer
</footer>
</body>
</html>"""
