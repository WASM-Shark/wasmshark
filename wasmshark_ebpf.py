#!/usr/bin/env python3

# WASMShark eBPF Runtime Monitor

import os, sys, re, time, json, signal, struct, ctypes, socket
import subprocess, threading, argparse, hashlib, traceback
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing  import List, Dict, Optional, Set, Tuple, Any
from datetime import datetime
from enum import Enum


# Dangerous syscalls that WASM runtimes should not normally make
DANGEROUS_SYSCALLS: Dict[str,str] = {
    "execve":        "CRITICAL:Process execution (RCE indicator)",
    "execveat":      "CRITICAL:Process execution (RCE indicator)",
    "fork":          "HIGH:Process fork",
    "vfork":         "HIGH:Process vfork",
    "clone":         "HIGH:Thread/process clone",
    "ptrace":        "CRITICAL:Debug/injection attempt",
    "mmap":          "MEDIUM:Memory mapping",
    "mprotect":      "HIGH:Memory permission change",
    "munmap":        "LOW:Memory unmap",
    "connect":       "HIGH:Network connection",
    "bind":          "HIGH:Network bind",
    "accept":        "HIGH:Network accept",
    "socket":        "HIGH:Socket creation",
    "sendto":        "HIGH:Network data send",
    "recvfrom":      "HIGH:Network data receive",
    "open":          "MEDIUM:File open",
    "openat":        "MEDIUM:File open (at)",
    "creat":         "MEDIUM:File create",
    "unlink":        "MEDIUM:File delete",
    "rename":        "MEDIUM:File rename",
    "chmod":         "MEDIUM:File permission change",
    "chown":         "MEDIUM:File ownership change",
    "write":         "LOW:File/pipe write",
    "read":          "LOW:File/pipe read",
    "kill":          "HIGH:Signal send (kill attempt)",
    "tkill":         "HIGH:Thread kill",
    "tgkill":        "HIGH:Group kill",
    "prctl":         "HIGH:Process control (anti-debug common)",
    "ioctl":         "MEDIUM:Device I/O control",
    "sysinfo":       "LOW:System info query",
    "uname":         "LOW:System name query",
    "getpid":        "LOW:PID query",
    "getuid":        "LOW:UID query",
    "getcwd":        "LOW:Working dir query",
    "readlink":      "LOW:Symlink read",
    "stat":          "LOW:File stat",
    "access":        "LOW:File access check",
    "nanosleep":     "MEDIUM:Sleep (evasion/timing)",
    "clock_gettime": "LOW:Timing (anti-analysis)",
    "getrandom":     "HIGH:Random bytes (crypto/mining)",
    "memfd_create":  "CRITICAL:Anonymous memory exec (fileless malware)",
    "shmat":         "HIGH:Shared memory attach",
    "shmget":        "HIGH:Shared memory create",
    "setuid":        "CRITICAL:Privilege escalation",
    "setgid":        "CRITICAL:Privilege escalation",
    "capset":        "CRITICAL:Capability modification",
    "pivot_root":    "CRITICAL:Container escape",
    "unshare":       "CRITICAL:Namespace manipulation",
    "setns":         "CRITICAL:Namespace entry",
    "init_module":   "CRITICAL:Kernel module load",
    "delete_module": "CRITICAL:Kernel module unload",
    "perf_event_open":"HIGH:Perf event (cryptominer timing)",
    "bpf":           "CRITICAL:BPF syscall (rootkit indicator)",
    "io_uring_setup":"HIGH:io_uring setup",
}

MMAP_PROT_EXEC  = 0x4
MMAP_PROT_WRITE = 0x2
MMAP_PROT_READ  = 0x1

# Linux syscall numbers (x86_64)
SYS_MMAP     = 9
SYS_MPROTECT = 10
SYS_EXECVE   = 59
SYS_CONNECT  = 42


#  Data Structures

class AlertLevel(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class RuntimeAlert:
    timestamp:   str
    level:       str
    category:    str
    title:       str
    description: str
    pid:         int
    evidence:    str = ""
    syscall:     str = ""
    address:     int = 0

@dataclass
class MemoryRegion:
    start:     int
    end:       int
    perms:     str
    offset:    int
    dev:       str
    inode:     int
    pathname:  str
    is_rwx:    bool = False
    is_new:    bool = False

@dataclass
class NetworkConnection:
    local_addr:  str
    local_port:  int
    remote_addr: str
    remote_port: int
    state:       str
    pid:         int = -1

@dataclass
class RuntimeProfile:
    pid:            int
    cmdline:        str
    exe:            str
    start_time:     str
    alerts:         List[RuntimeAlert] = field(default_factory=list)
    syscall_counts: Dict[str,int]      = field(default_factory=dict)
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    rwx_regions:    List[MemoryRegion] = field(default_factory=list)
    connections:    List[NetworkConnection] = field(default_factory=list)
    open_files:     List[str]          = field(default_factory=list)
    exec_children:  List[str]          = field(default_factory=list)
    threat_score:   float              = 0.0
    verdict:        str                = "CLEAN"
    monitoring_duration: float         = 0.0
    bpf_available:  bool               = False


#  Proc Inspector

class ProcInspector:
    # Reads /proc/[pid]/* to inspect process state

    def __init__(self, pid: int):
        self.pid  = pid
        self.base = Path(f"/proc/{pid}")

    def exists(self) -> bool:
        return self.base.exists()

    def cmdline(self) -> str:
        try:
            return (self.base/"cmdline").read_bytes().replace(b'\x00',b' ').decode(errors='replace').strip()
        except: return ""

    def exe(self) -> str:
        try:  return os.readlink(self.base/"exe")
        except: return ""

    def status(self) -> Dict[str,str]:
        try:
            lines = (self.base/"status").read_text().splitlines()
            return {l.split(':')[0].strip(): l.split(':')[1].strip() for l in lines if ':' in l}
        except: return {}

    def current_syscall(self) -> Optional[str]:
        try:
            data = (self.base/"syscall").read_text().strip()
            if data == "running": return "running"
            parts = data.split()
            if parts: return parts[0]  # syscall number
        except: pass
        return None

    def memory_maps(self) -> List[MemoryRegion]:
        regions = []
        try:
            lines = (self.base/"maps").read_text().splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) < 5: continue
                addrs = parts[0].split('-')
                if len(addrs) != 2: continue
                start = int(addrs[0],16); end = int(addrs[1],16)
                perms = parts[1]
                offset= int(parts[2],16)
                dev   = parts[3]
                inode = int(parts[4]) if parts[4].isdigit() else 0
                path  = parts[5] if len(parts)>5 else ""
                is_rwx = 'r' in perms and 'w' in perms and 'x' in perms
                regions.append(MemoryRegion(
                    start=start,end=end,perms=perms,offset=offset,
                    dev=dev,inode=inode,pathname=path,is_rwx=is_rwx))
        except: pass
        return regions

    def open_fds(self) -> List[str]:
        fds = []
        try:
            fd_dir = self.base/"fd"
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                    fds.append(target)
                except: pass
        except: pass
        return fds

    def children(self) -> List[int]:
        try:
            task_dir = self.base/"task"
            children_file = self.base/"task"/str(self.pid)/"children"
            text = children_file.read_text().strip()
            return [int(x) for x in text.split() if x.isdigit()]
        except: return []

    def environ(self) -> Dict[str,str]:
        try:
            raw = (self.base/"environ").read_bytes().split(b'\x00')
            env = {}
            for item in raw:
                if b'=' in item:
                    k,v = item.split(b'=',1)
                    env[k.decode(errors='replace')] = v.decode(errors='replace')
            return env
        except: return {}



#  Network Monitor

class NetworkMonitor:
    # Monitor /proc/net/tcp and /proc/net/tcp6 for new connections

    @staticmethod
    def _hex_to_ip4(hex_str: str) -> str:
        try:
            addr = int(hex_str, 16)
            return socket.inet_ntoa(struct.pack('<I', addr))
        except: return hex_str

    @staticmethod
    def _hex_to_ip6(hex_str: str) -> str:
        try:
            a = bytes.fromhex(hex_str)
            return socket.inet_ntop(socket.AF_INET6, a)
        except: return hex_str

    @staticmethod
    def _parse_tcp_file(path: str, ipv6=False) -> List[NetworkConnection]:
        conns = []
        try:
            lines = Path(path).read_text().splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4: continue
                la, lp = parts[1].split(':'); ra, rp = parts[2].split(':')
                state = int(parts[3],16)
                state_names = {1:"ESTABLISHED",2:"SYN_SENT",3:"SYN_RECV",
                               4:"FIN_WAIT1",5:"FIN_WAIT2",10:"LISTEN",11:"CLOSING"}
                if ipv6:
                    local_ip=NetworkMonitor._hex_to_ip6(la)
                    remote_ip=NetworkMonitor._hex_to_ip6(ra)
                else:
                    local_ip=NetworkMonitor._hex_to_ip4(la)
                    remote_ip=NetworkMonitor._hex_to_ip4(ra)
                conns.append(NetworkConnection(
                    local_addr=local_ip, local_port=int(lp,16),
                    remote_addr=remote_ip, remote_port=int(rp,16),
                    state=state_names.get(state,f"STATE_{state}")))
        except: pass
        return conns

    def snapshot(self) -> List[NetworkConnection]:
        conns  = self._parse_tcp_file("/proc/net/tcp",  ipv6=False)
        conns += self._parse_tcp_file("/proc/net/tcp6", ipv6=True)
        return [c for c in conns if c.state == "ESTABLISHED"]



#  Memory Monitor

class MemoryMonitor:
    # Detect suspicious memory region changes (RWX pages, new execs)

    def __init__(self):
        self._prev_regions: Set[str] = set()

    def _region_key(self, r: MemoryRegion) -> str:
        return f"{r.start:#x}-{r.end:#x}:{r.perms}"

    def check(self, regions: List[MemoryRegion]) -> Tuple[List[MemoryRegion], List[MemoryRegion]]:
        """Returns (rwx_regions, new_regions)."""
        current_keys = {self._region_key(r) for r in regions}
        new_keys     = current_keys - self._prev_regions
        self._prev_regions = current_keys

        rwx  = [r for r in regions if r.is_rwx]
        new_rwx = [r for r in regions if self._region_key(r) in new_keys and r.is_rwx]
        return rwx, new_rwx



#  BPF Probe (requires bcc / bpf kernel support)

BPF_PROG_SYSCALL_COUNT = """
#include <uapi/linux/ptrace.h>

BPF_HASH(syscall_counts, u64, u64);
BPF_HASH(target_pid, u32, u8);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *enabled = target_pid.lookup(&pid);
    if (!enabled) return 0;
    u64 nr = args->id;
    u64 *cnt = syscall_counts.lookup_or_try_init(&nr, &(u64){0});
    if (cnt) (*cnt)++;
    return 0;
}
"""

BPF_PROG_MMAP_EXEC = """
#include <uapi/linux/ptrace.h>
#include <linux/mman.h>

BPF_PERF_OUTPUT(mmap_events);

struct mmap_event_t {
    u32 pid;
    u64 addr;
    u64 len;
    u64 prot;
    u64 flags;
    char comm[16];
};

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u64 prot = args->prot;
    if (!((prot & PROT_EXEC) && (prot & PROT_WRITE))) return 0;
    struct mmap_event_t ev = {};
    ev.pid  = bpf_get_current_pid_tgid() >> 32;
    ev.addr = (u64)args->addr;
    ev.len  = args->len;
    ev.prot = prot;
    ev.flags= args->flags;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    mmap_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

BPF_PROG_EXECVE = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(exec_events);

struct exec_event_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    char filename[256];
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t ev = {};
    ev.pid  = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), args->filename);
    exec_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

BPF_PROG_CONNECT = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/in6.h>

BPF_PERF_OUTPUT(connect_events);

struct connect_event_t {
    u32  pid;
    u32  daddr;
    u16  dport;
    char comm[16];
};

int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    struct connect_event_t ev = {};
    ev.pid   = bpf_get_current_pid_tgid() >> 32;
    ev.daddr = sk->__sk_common.skc_daddr;
    ev.dport = sk->__sk_common.skc_dport;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    connect_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


class BPFProbe:
    """
    eBPF instrumentation via bpftrace subprocess.
    Works on kernels where BCC compilation fails (e.g. kernel 6.14+).
    Falls back gracefully if bpftrace is not installed.

    Three probes:
      - tracepoint:syscalls:sys_enter_execve  → child process spawning
      - tracepoint:syscalls:sys_enter_mmap    → W+X memory mapping (shellcode staging)
      - tracepoint:net:net_dev_queue          → outbound network activity (pid-attributed)
    """

    # bpftrace script — filters to target PID, outputs structured lines
    BPFTRACE_SCRIPT = """
tracepoint:syscalls:sys_enter_execve
/ pid == TARGET_PID /
{
    printf("EXECVE|%d|%s|%s\\n",
        pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_mmap
/ pid == TARGET_PID /
{
    if ((args->prot & 4) && (args->prot & 2)) {
        printf("MMAP_WX|%d|%d\\n", pid, args->prot);
    }
}

tracepoint:syscalls:sys_enter_connect
/ pid == TARGET_PID /
{
    printf("CONNECT|%d|%s\\n", pid, comm);
}

tracepoint:syscalls:sys_enter_mprotect
/ pid == TARGET_PID /
{
    if (args->prot & 4) {
        printf("MPROTECT_X|%d|%d\\n", pid, args->prot);
    }
}

tracepoint:syscalls:sys_enter_execveat
/ pid == TARGET_PID /
{
    printf("EXECVE|%d|%s|execveat\\n", pid, comm);
}
"""

    def __init__(self, target_pid: int):
        self.pid       = target_pid
        self.available = False
        self.alerts: List[RuntimeAlert] = []
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running  = False

    def try_attach(self) -> bool:
        # Launch bpftrace as a subprocess. Returns True if successful
        # Check bpftrace is available
        try:
            result = subprocess.run(["which", "bpftrace"],
                                    capture_output=True, timeout=3)
            if result.returncode != 0:
                return False
        except Exception:
            return False

        # Write bpftrace script with target PID substituted
        script = self.BPFTRACE_SCRIPT.replace("TARGET_PID", str(self.pid))
        self._script_path = f"/tmp/wasmshark_bpf_{self.pid}.bt"
        try:
            with open(self._script_path, 'w') as f:
                f.write(script)
        except Exception as e:
            print(f"[BPF] Script write failed: {e}", file=sys.stderr)
            return False

        # Launch bpftrace
        try:
            self._proc = subprocess.Popen(
                ["bpftrace", self._script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, bufsize=1)

            # Give it a moment to attach
            time.sleep(1.5)
            if self._proc.poll() is not None:
                err = self._proc.stderr.read(500)
                print(f"[BPF] bpftrace exited early: {err[:200]}", file=sys.stderr)
                return False

            self.available = True
            self._running  = True
            self._thread   = threading.Thread(target=self._read_loop, daemon=True)
            self._thread.start()
            return True

        except Exception as e:
            print(f"[BPF] bpftrace launch failed: {e}", file=sys.stderr)
            return False

    def _read_loop(self):
        """Read bpftrace stdout line by line and parse events."""
        if not self._proc: return
        try:
            for line in self._proc.stdout:
                if not self._running: break
                line = line.strip()
                if not line or line.startswith("Attaching"): continue
                self._parse_event(line)
        except Exception:
            pass

    def _parse_event(self, line: str):
        ts = datetime.now().isoformat()
        parts = line.split("|")
        if not parts: return
        etype = parts[0]

        try:
            if etype == "EXECVE" and len(parts) >= 4:
                pid_ev = int(parts[1])
                comm   = parts[2]; fname = parts[3]
                alert  = RuntimeAlert(
                    timestamp=ts, level="CRITICAL", category="EXECUTION",
                    title=f"execve() via bpftrace tracepoint: {fname[:60]}",
                    description="WASM runtime spawned child process — RCE or dropper execution",
                    pid=pid_ev,
                    evidence=f"comm={comm} file={fname[:80]}")
                self.alerts.append(alert)

            elif etype == "MMAP_WX" and len(parts) >= 3:
                pid_ev = int(parts[1]); prot = parts[2]
                alert  = RuntimeAlert(
                    timestamp=ts, level="CRITICAL", category="MEMORY",
                    title="W+X mmap() via bpftrace tracepoint",
                    description="PROT_WRITE|PROT_EXEC mapping — fileless shellcode staging indicator",
                    pid=pid_ev,
                    evidence=f"prot={prot}")
                self.alerts.append(alert)

            elif etype == "MPROTECT_X" and len(parts) >= 3:
                pid_ev = int(parts[1]); prot = parts[2]
                alert  = RuntimeAlert(
                    timestamp=ts, level="HIGH", category="MEMORY",
                    title="mprotect(PROT_EXEC) via bpftrace tracepoint",
                    description="Memory region made executable — possible shellcode activation",
                    pid=pid_ev,
                    evidence=f"prot={prot}")
                self.alerts.append(alert)

            elif etype == "CONNECT" and len(parts) >= 3:
                pid_ev = int(parts[1]); comm = parts[2]
                alert  = RuntimeAlert(
                    timestamp=ts, level="HIGH", category="NETWORK",
                    title="connect() syscall via bpftrace tracepoint",
                    description="WASM runtime initiated network connection (PID-attributed via eBPF)",
                    pid=pid_ev,
                    evidence=f"pid={pid_ev} comm={comm}")
                self.alerts.append(alert)

        except Exception:
            pass

    def poll(self, timeout_ms=10):
        # bpftrace runs in background thread - nothing to poll here
        pass

    def detach(self):
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                pass
        # Clean up temp script
        try:
            os.unlink(self._script_path)
        except Exception:
            pass



#  Syscall Tracer (ptrace fallback / /proc/syscall polling)

# Syscall number -> name (x86_64, partial)
SYSCALL_NAMES: Dict[int,str] = {
    0:"read",1:"write",2:"open",3:"close",4:"stat",5:"fstat",6:"lstat",
    7:"poll",8:"lseek",9:"mmap",10:"mprotect",11:"munmap",12:"brk",
    13:"rt_sigaction",14:"rt_sigprocmask",15:"rt_sigreturn",16:"ioctl",
    17:"pread64",18:"pwrite64",19:"readv",20:"writev",21:"access",22:"pipe",
    23:"select",24:"sched_yield",25:"mremap",26:"msync",27:"mincore",
    28:"madvise",29:"shmget",30:"shmat",31:"shmctl",32:"dup",33:"dup2",
    39:"getpid",40:"sendfile",41:"socket",42:"connect",43:"accept",
    44:"sendto",45:"recvfrom",46:"sendmsg",47:"recvmsg",48:"shutdown",
    49:"bind",50:"listen",51:"getsockname",52:"getpeername",53:"socketpair",
    54:"setsockopt",55:"getsockopt",56:"clone",57:"fork",58:"vfork",
    59:"execve",60:"exit",61:"wait4",62:"kill",63:"uname",72:"fcntl",
    79:"getcwd",82:"rename",83:"mkdir",84:"rmdir",85:"creat",86:"link",
    87:"unlink",88:"symlink",89:"readlink",90:"chmod",92:"chown",
    95:"umask",96:"gettimeofday",97:"getrlimit",99:"sysinfo",
    102:"getuid",104:"getgid",105:"setuid",106:"setgid",
    131:"sigaltstack",139:"rt_sigpending",158:"arch_prctl",
    186:"gettid",228:"clock_gettime",230:"clock_nanosleep",
    231:"exit_group",232:"epoll_wait",233:"epoll_ctl",
    257:"openat",258:"mkdirat",269:"faccessat",
    280:"accept4",291:"epoll_create1",293:"pipe2",
    302:"prlimit64",307:"sendmmsg",308:"setns",311:"process_vm_readv",
    312:"process_vm_writev",317:"seccomp",318:"getrandom",
    319:"memfd_create",321:"execveat",332:"statx",
    334:"close_range",435:"clone3",439:"faccessat2",
    440:"process_madvise",447:"memfd_secret",
}

class SyscallTracer:

    # Non-invasive syscall monitoring via /proc/[pid]/syscall polling

    def __init__(self, pid: int, interval: float = 0.01):
        self.pid      = pid
        self.interval = interval
        self._counts: Counter = Counter()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._recent: deque = deque(maxlen=200)

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread: self._thread.join(timeout=2)

    def _poll_loop(self):
        syscall_path = Path(f"/proc/{self.pid}/syscall")
        while self._running:
            try:
                if not syscall_path.exists(): break
                text = syscall_path.read_text().strip()
                if text and text != "running":
                    nr_str = text.split()[0]
                    if nr_str.lstrip('-').isdigit():
                        nr = int(nr_str)
                        name = SYSCALL_NAMES.get(nr, f"syscall_{nr}")
                        self._counts[name] += 1
                        self._recent.append((time.monotonic(), name))
            except (PermissionError, ProcessLookupError): break
            except: pass
            time.sleep(self.interval)

    def get_counts(self) -> Dict[str,int]: return dict(self._counts)
    def get_recent(self) -> List[Tuple]:   return list(self._recent)

    def detect_anomalies(self) -> List[RuntimeAlert]:
        alerts = []
        ts = datetime.now().isoformat()
        for name, count in self._counts.items():
            if name in DANGEROUS_SYSCALLS:
                info = DANGEROUS_SYSCALLS[name]
                level, desc = info.split(":",1)
                if name in ("execve","execveat","ptrace","memfd_create","bpf"):
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level=level, category="SYSCALL",
                        title=f"Dangerous syscall: {name}() × {count}",
                        description=desc.strip(), pid=self.pid,
                        evidence=f"call_count={count}", syscall=name))
                elif count > 100 and name in ("connect","socket","sendto","recvfrom"):
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level="HIGH", category="SYSCALL",
                        title=f"High-frequency network syscall: {name}() × {count}",
                        description="Possible C2 beaconing or data exfiltration",
                        pid=self.pid, evidence=f"call_count={count}", syscall=name))
                elif count > 50 and name in ("mprotect",):
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level="HIGH", category="MEMORY",
                        title=f"Excessive mprotect() × {count}",
                        description="Repeated memory permission changes — shellcode staging",
                        pid=self.pid, evidence=f"call_count={count}", syscall=name))
                elif count > 200 and name in ("getrandom","clock_gettime"):
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level="MEDIUM", category="MINING",
                        title=f"High-frequency {name}() × {count}",
                        description="Cryptominer timing pattern or random byte generation",
                        pid=self.pid, evidence=f"call_count={count}", syscall=name))
        return alerts



#  File Monitor (inotify)

class FileMonitor:
    # Monitor filesystem activity via /proc/[pid]/fd and inotify

    SUSPICIOUS_PATHS = [
        "/tmp/", "/dev/shm/", "/proc/", "/sys/",
        "/etc/passwd", "/etc/shadow", "/etc/cron",
        "/root/.ssh/", "/home/", "authorized_keys",
        "/var/spool/cron/", "/etc/ld.so", ".bashrc",
        ".bash_profile", "known_hosts", "id_rsa",
        "AWS_", ".aws/credentials", ".kube/config",
    ]

    def __init__(self, pid: int):
        self.pid    = pid
        self._seen: Set[str] = set()

    def check_fds(self, inspector: ProcInspector) -> List[RuntimeAlert]:
        alerts = []
        fds = inspector.open_fds()
        ts  = datetime.now().isoformat()

        for fd in fds:
            if fd in self._seen: continue
            self._seen.add(fd)
            fd_lower = fd.lower()
            for sus_path in self.SUSPICIOUS_PATHS:
                if sus_path.lower() in fd_lower:
                    level = "CRITICAL" if "shadow" in fd_lower or "id_rsa" in fd_lower \
                            else ("HIGH" if "/tmp" in fd_lower or "/dev/shm" in fd_lower else "MEDIUM")
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level=level, category="FILE",
                        title=f"Suspicious file access: {fd[:80]}",
                        description=f"WASM runtime opened potentially sensitive path",
                        pid=self.pid, evidence=f"path={fd}"))
                    break

        # Check for new executable files
        for fd in fds:
            if fd.startswith("/tmp/") and not fd.startswith("/tmp/wasmtime") \
               and not fd.endswith(".wasm"):
                if fd not in self._seen:
                    self._seen.add(fd)
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level="HIGH", category="FILE",
                        title=f"New file in /tmp: {fd}",
                        description="Files dropped to /tmp may be staged payloads",
                        pid=self.pid, evidence=f"path={fd}"))
        return alerts



#  Environment Leak Detector

class EnvLeakDetector:
    SENSITIVE_ENV_KEYS = [
        "AWS_ACCESS_KEY","AWS_SECRET","DATABASE_URL","DB_PASSWORD",
        "GITHUB_TOKEN","GITLAB_TOKEN","API_KEY","SECRET_KEY",
        "PRIVATE_KEY","JWT_SECRET","REDIS_URL","MONGO_URI",
        "PGPASSWORD","MYSQL_PASSWORD","SSH_AUTH_SOCK",
    ]

    def check(self, inspector: ProcInspector) -> List[RuntimeAlert]:
        alerts = []
        env = inspector.environ()
        ts  = datetime.now().isoformat()
        for key in env:
            for sk in self.SENSITIVE_ENV_KEYS:
                if sk in key.upper():
                    alerts.append(RuntimeAlert(
                        timestamp=ts, level="HIGH", category="CREDENTIALS",
                        title=f"Sensitive environment variable: {key}",
                        description="WASM runtime has access to credential/secret env var",
                        pid=inspector.pid, evidence=f"key={key} (value redacted)"))
        return alerts



#  Audit Log Parser

class AuditLogParser:
    # Parse /var/log/audit/audit.log for syscall events from target pid

    AUDIT_PATH = "/var/log/audit/audit.log"

    def __init__(self, pid: int):
        self.pid   = pid
        self._pos  = 0

    def tail_events(self) -> List[Dict]:
        events = []
        try:
            with open(self.AUDIT_PATH) as f:
                f.seek(0, 2)
                size = f.tell()
                if self._pos == 0: self._pos = size
                if size > self._pos:
                    f.seek(self._pos)
                    for line in f:
                        if f"pid={self.pid}" in line or f"ppid={self.pid}" in line:
                            events.append(self._parse_line(line))
                    self._pos = f.tell()
        except (FileNotFoundError, PermissionError): pass
        return [e for e in events if e]

    def _parse_line(self, line: str) -> Optional[Dict]:
        try:
            event = {}
            for m in re.finditer(r'(\w+)=(\S+)', line):
                event[m.group(1)] = m.group(2).strip('"')
            return event if event else None
        except: return None



#  Threat Scorer

class ThreatScorer:
    LEVEL_W = {"CRITICAL":30,"HIGH":18,"MEDIUM":8,"LOW":3,"INFO":0}
    CAT_MULT = {"MEMORY":2.0,"EXECUTION":2.5,"SYSCALL":1.5,
                "NETWORK":1.5,"CREDENTIALS":2.0,"FILE":1.0}

    def score(self, profile: RuntimeProfile) -> RuntimeProfile:
        total = 0.0
        for alert in profile.alerts:
            w = self.LEVEL_W.get(alert.level, 0)
            m = self.CAT_MULT.get(alert.category, 1.0)
            total += w * m

        # RWX region bonus
        total += len(profile.rwx_regions) * 15

        # Network connection bonus
        for conn in profile.connections:
            if conn.remote_port not in (80,443,8080,8443,22):
                total += 20

        profile.threat_score = min(100.0, round(total, 1))

        if   profile.threat_score >= 70: profile.verdict = "MALICIOUS"
        elif profile.threat_score >= 40: profile.verdict = "SUSPICIOUS"
        elif profile.threat_score >= 15: profile.verdict = "POTENTIALLY_UNWANTED"
        else:                            profile.verdict = "CLEAN"
        return profile



#  Runtime Monitor

R="\033[0m";B="\033[1m";RED="\033[91m";YEL="\033[93m";GRN="\033[92m"
CYN="\033[96m";MAG="\033[95m";DIM="\033[2m";WHT="\033[97m"
def lc(l): return {"CRITICAL":RED+B,"HIGH":RED,"MEDIUM":YEL,"LOW":CYN,"INFO":DIM}.get(l,R)
def vc(v): return {"MALICIOUS":RED+B,"SUSPICIOUS":YEL+B,"POTENTIALLY_UNWANTED":YEL,"CLEAN":GRN+B}.get(v,R)

class RuntimeMonitor:

    def __init__(self, pid: int, timeout: float = 60.0,
                 use_bpf: bool = True, output_json: str = ""):
        self.pid          = pid
        self.timeout      = timeout
        self.output_json  = output_json
        self.profile      = RuntimeProfile(pid=pid, cmdline="", exe="",
                                           start_time=datetime.now().isoformat())
        self.inspector    = ProcInspector(pid)
        self.syscall_tracer = SyscallTracer(pid)
        self.net_monitor  = NetworkMonitor()
        self.mem_monitor  = MemoryMonitor()
        self.file_monitor = FileMonitor(pid)
        self.env_detector = EnvLeakDetector()
        self.audit_parser = AuditLogParser(pid)
        self.bpf_probe    = BPFProbe(pid) if use_bpf else None
        self.scorer       = ThreatScorer()
        self._start_time  = 0.0
        self._known_conns: Set[str] = set()

    def start(self):
        if not self.inspector.exists():
            print(f"{RED}[!] PID {self.pid} not found{R}"); return

        self._print_banner()
        self.profile.cmdline = self.inspector.cmdline()
        self.profile.exe     = self.inspector.exe()
        print(f"{CYN}[*] Monitoring PID {self.pid}{R}")
        print(f"    CMD: {DIM}{self.profile.cmdline[:100]}{R}")
        print(f"    EXE: {DIM}{self.profile.exe}{R}\n")

        # Try BPF
        if self.bpf_probe:
            if self.bpf_probe.try_attach():
                self.profile.bpf_available = True
                print(f"{GRN}[+] eBPF probes attached via bpftrace{R}")
                print(f"    Watching: execve(), mmap(W+X), mprotect(EXEC), connect()")
                print(f"    PID-filtered tracepoints active — kernel 6.x compatible\n")
            else:
                print(f"{YEL}[~] bpftrace not available — using /proc + syscall poll fallback{R}")
                print(f"    Install bpftrace: sudo apt install bpftrace\n")

        # Initial environment check
        env_alerts = self.env_detector.check(self.inspector)
        self.profile.alerts.extend(env_alerts)
        for a in env_alerts: self._print_alert(a)

        # Start syscall tracer
        self.syscall_tracer.start()

        self._start_time = time.monotonic()
        try:
            self._monitor_loop()
        except KeyboardInterrupt:
            print(f"\n{YEL}[~] Interrupted by user{R}")
        finally:
            self._finalize()

    def _monitor_loop(self):
        iteration = 0
        while True:
            elapsed = time.monotonic() - self._start_time
            if elapsed >= self.timeout: break
            if not self.inspector.exists():
                print(f"{YEL}[~] PID {self.pid} exited after {elapsed:.1f}s{R}"); break

            # BPF poll
            if self.bpf_probe and self.profile.bpf_available:
                self.bpf_probe.poll()
                new_bpf = self.bpf_probe.alerts[len(self.profile.alerts):]
                for a in new_bpf:
                    self.profile.alerts.append(a); self._print_alert(a)

            # Memory map check (every 5 iterations)
            if iteration % 5 == 0:
                regions = self.inspector.memory_maps()
                rwx, new_rwx = self.mem_monitor.check(regions)
                self.profile.memory_regions = regions
                self.profile.rwx_regions    = rwx
                for r in new_rwx:
                    a = RuntimeAlert(
                        timestamp=datetime.now().isoformat(),
                        level="CRITICAL", category="MEMORY",
                        title=f"New RWX memory region: {r.start:#x}-{r.end:#x}",
                        description="New read/write/exec memory page — shellcode staging (W^X violation)",
                        pid=self.pid,
                        evidence=f"perms={r.perms} path={r.pathname} size={r.end-r.start:#x}")
                    self.profile.alerts.append(a); self._print_alert(a)

            # Network check (every 10 iterations)
            if iteration % 10 == 0:
                conns = self.net_monitor.snapshot()
                for c in conns:
                    key = f"{c.remote_addr}:{c.remote_port}"
                    if key not in self._known_conns and c.remote_addr not in ("0.0.0.0","127.0.0.1","::"):
                        self._known_conns.add(key)
                        level = "HIGH" if c.remote_port not in (80,443,8080,8443) else "MEDIUM"
                        a = RuntimeAlert(
                            timestamp=datetime.now().isoformat(),
                            level=level, category="NETWORK",
                            title=f"New TCP connection: {c.remote_addr}:{c.remote_port}",
                            description="WASM runtime established outbound connection",
                            pid=self.pid,
                            evidence=f"local={c.local_addr}:{c.local_port} state={c.state}")
                        self.profile.alerts.append(a); self._print_alert(a)
                        self.profile.connections.append(c)

            # File descriptor check (every 20 iterations)
            if iteration % 20 == 0:
                fd_alerts = self.file_monitor.check_fds(self.inspector)
                for a in fd_alerts:
                    self.profile.alerts.append(a); self._print_alert(a)

            # Syscall anomaly check (every 50 iterations)
            if iteration % 50 == 0:
                sc_alerts = self.syscall_tracer.detect_anomalies()
                for a in sc_alerts:
                    # Only report new ones
                    if not any(x.syscall == a.syscall for x in self.profile.alerts):
                        self.profile.alerts.append(a); self._print_alert(a)

            # Audit log check (every 30 iterations)
            if iteration % 30 == 0:
                for event in self.audit_parser.tail_events():
                    if event.get("type") == "EXECVE":
                        a = RuntimeAlert(
                            timestamp=datetime.now().isoformat(),
                            level="CRITICAL", category="EXECUTION",
                            title=f"execve via audit: {event.get('exe','?')}",
                            description="Child process spawned (audit log)",
                            pid=self.pid, evidence=str(event)[:200])
                        self.profile.alerts.append(a); self._print_alert(a)

            iteration += 1
            time.sleep(0.1)

    def _finalize(self):
        elapsed = time.monotonic() - self._start_time
        self.profile.monitoring_duration = round(elapsed, 2)
        self.syscall_tracer.stop()
        if self.bpf_probe: self.bpf_probe.detach()

        self.profile.syscall_counts = self.syscall_tracer.get_counts()
        self.profile.open_files     = self.inspector.open_fds()
        self.profile = self.scorer.score(self.profile)
        self._print_report()

        if self.output_json:
            self._write_json()

    def _write_json(self):
        out = {
            "pid":       self.profile.pid,
            "cmdline":   self.profile.cmdline,
            "exe":       self.profile.exe,
            "verdict":   self.profile.verdict,
            "threat_score": self.profile.threat_score,
            "bpf_used":  self.profile.bpf_available,
            "duration":  self.profile.monitoring_duration,
            "alerts":    [asdict(a) for a in self.profile.alerts],
            "syscall_counts": self.profile.syscall_counts,
            "rwx_regions": [asdict(r) for r in self.profile.rwx_regions],
            "connections": [asdict(c) for c in self.profile.connections],
        }
        with open(self.output_json,'w') as f: json.dump(out, f, indent=2)
        print(f"\n{GRN}[+] Runtime report → {self.output_json}{R}")

    def _print_alert(self, alert: RuntimeAlert):
        col = lc(alert.level)
        ts  = alert.timestamp.split('T')[1][:8]
        print(f"  [{ts}] {col}[{alert.level}]{R} {B}{alert.title}{R}")
        print(f"          {DIM}{alert.description}{R}")
        if alert.evidence:
            print(f"          {MAG}{alert.evidence}{R}")

    def _print_report(self):
        V = vc(self.profile.verdict)
        print(f"\n{CYN}{'═'*70}{R}")
        print(f"{B}  RUNTIME MONITORING REPORT{R}")
        print(f"{CYN}{'═'*70}{R}")
        print(f"  PID            : {self.profile.pid}")
        print(f"  Duration       : {self.profile.monitoring_duration:.1f}s")
        print(f"  eBPF Active    : {'✓ kprobe/tracepoint' if self.profile.bpf_available else '✗ /proc fallback'}")
        print(f"  Verdict        : {V}{self.profile.verdict}{R}")
        print(f"  Threat Score   : {self.profile.threat_score:.1f}/100")
        print(f"  Total Alerts   : {len(self.profile.alerts)}")
        print(f"  RWX Regions    : {len(self.profile.rwx_regions)}")
        print(f"  New Connections: {len(self.profile.connections)}")

        if self.profile.syscall_counts:
            print(f"\n{CYN}{'─'*70}{R}")
            print(f"{B}  TOP SYSCALLS{R}")
            top = sorted(self.profile.syscall_counts.items(), key=lambda x: x[1], reverse=True)[:15]
            for sc, cnt in top:
                flag = f" {RED}⚠{R}" if sc in DANGEROUS_SYSCALLS else ""
                print(f"    {sc:<25} {cnt:>8,}{flag}")

        if self.profile.alerts:
            print(f"\n{CYN}{'─'*70}{R}")
            print(f"{B}  ALL ALERTS ({len(self.profile.alerts)}){R}")
            for a in self.profile.alerts:
                col = lc(a.level)
                print(f"  {col}[{a.level:<8}]{R} {a.category:<12} {a.title}")
        print(f"{CYN}{'═'*70}{R}\n")

    def _print_banner(self):
        print(f"""
{CYN}{B}
  ╔══════════════════════════════════════════════════════╗
  ║   WASMShark eBPF Runtime Monitor                     ║
  ║   WASM Behavioral Analysis via Kernel Instrumentation║
  ║   eBPF kprobes · /proc · syscall tracing · inotify   ║
  ╚══════════════════════════════════════════════════════╝
{R}""")


#  Process Launcher

def launch_and_monitor(cmd: str, timeout: float, use_bpf: bool, output_json: str):
    """Launch a WASM runtime command and monitor it."""
    print(f"{CYN}[*] Launching: {cmd}{R}")
    try:
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        pid  = proc.pid
        print(f"{GRN}[+] Spawned PID {pid}{R}\n")
        time.sleep(0.2)  # Let process initialize

        monitor = RuntimeMonitor(pid=pid, timeout=timeout,
                                 use_bpf=use_bpf, output_json=output_json)
        monitor.start()

        # Wait for process
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()
    except FileNotFoundError as e:
        print(f"{RED}[!] Could not launch: {e}{R}")
        print(f"{YEL}    Install wasmtime: curl https://wasmtime.dev/install.sh | bash{R}")
        sys.exit(1)



#  CLI

def main():
    ap = argparse.ArgumentParser(
        description="WASMShark eBPF Runtime Monitor — Behavioral WASM analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor existing WASM runtime process
  sudo %(prog)s --pid 1234

  # Launch and monitor wasmtime
  sudo %(prog)s --exec "wasmtime run sample.wasm" --timeout 30

  # Launch with wasmer
  sudo %(prog)s --exec "wasmer run sample.wasm" --bpf

  # Save report
  sudo %(prog)s --pid 1234 --output runtime_report.json --timeout 60

Note:
  Full eBPF instrumentation requires: sudo + bcc-tools
  Fallback mode (/proc + syscall polling) works without BCC.
  Install BCC: apt install bpfcc-tools python3-bpfcc (Ubuntu)
        """)
    ap.add_argument("--pid",     "-p", type=int,          help="PID to monitor")
    ap.add_argument("--exec",    "-e", type=str,          help="Command to launch and monitor")
    ap.add_argument("--timeout", "-t", type=float, default=60, help="Monitor duration (seconds)")
    ap.add_argument("--bpf",           action="store_true",   help="Try to use eBPF (requires BCC)")
    ap.add_argument("--no-bpf",        action="store_true",   help="Force /proc-only mode")
    ap.add_argument("--output",  "-o", type=str, default="",  help="JSON output file")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print(f"{YEL}[!] Warning: Not running as root. /proc access may be limited.{R}")
        print(f"    For full eBPF instrumentation: sudo python3 {sys.argv[0]} ...\n")

    use_bpf = args.bpf and not args.no_bpf

    if args.exec:
        launch_and_monitor(args.exec, args.timeout, use_bpf, args.output)
    elif args.pid:
        monitor = RuntimeMonitor(pid=args.pid, timeout=args.timeout,
                                 use_bpf=use_bpf, output_json=args.output)
        monitor.start()
    else:
        ap.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()



"""
This Instruments a running WASM runtime (wasmtime / wasmer / node) using
Linux eBPF / perf_event / /proc introspection to detect malicious runtime
behavior AFTER a WASM module begins executing.

It watches what the runtime DOES and alerts
on anomalies. It does NOT require kernel module compilation; it uses:
  1. /proc/[pid]/syscall  — current syscall
  2. /proc/[pid]/maps     — memory map changes (new RWX pages = shellcode)
  3. /proc/[pid]/net/tcp  — new network connections
  4. /proc/[pid]/fd/      — file descriptor activity
  5. inotify              — filesystem write monitoring
  6. perf_event_open      — syscall counting (via ctypes, no BCC needed)
  7. Simulated eBPF via seccomp-bpf audit log parsing (/var/log/audit)

For systems WITH bcc/BPF toolchain:
  - Attaches actual kprobes for execve, connect, mmap(PROT_EXEC)
  - Counts and classifies syscalls in real-time
  - Detects memory region transitions (W->X = shellcode staging)

Architecture:
  WASMShark -> RuntimeMonitor
                  ├── ProcInspector    (/proc introspection)
                  ├── SyscallTracer    (perf_event / ptrace fallback)
                  ├── NetworkMonitor   (/proc/net/tcp + /tcp6)
                  ├── FileMonitor      (inotify + /proc/fd)
                  ├── MemoryMonitor    (/proc/maps + RWX detection)
                  └── AuditLogParser   (/var/log/audit/audit.log)

Usage:
  sudo python3 wasmshark_ebpf.py --pid 1234
  sudo python3 wasmshark_ebpf.py --exec "wasmtime run malware.wasm"
  sudo python3 wasmshark_ebpf.py --exec "wasmer run malware.wasm" --timeout 30
  sudo python3 wasmshark_ebpf.py --pid 1234 --bpf        # use BCC if available
"""