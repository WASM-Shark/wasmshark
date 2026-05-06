#!/usr/bin/env python3

# WASMShark Threat Classifier


from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field



#  MITRE ATT&CK MAPPINGS

MITRE_TECHNIQUES = {
    "CRYPTOMINER":        ["T1496 - Resource Hijacking"],
    "RANSOMWARE":         ["T1486 - Data Encrypted for Impact",
                           "T1489 - Service Stop",
                           "T1490 - Inhibit System Recovery"],
    "DROPPER":            ["T1105 - Ingress Tool Transfer",
                           "T1059 - Command and Scripting Interpreter"],
    "BACKDOOR":           ["T1071 - Application Layer Protocol",
                           "T1543 - Create or Modify System Process"],
    "INFOSTEALER":        ["T1552 - Unsecured Credentials",
                           "T1041 - Exfiltration Over C2 Channel"],
    "CRYPTOJACKER":       ["T1496 - Resource Hijacking",
                           "T1185 - Browser Session Hijacking"],
    "WIPER":              ["T1485 - Data Destruction",
                           "T1490 - Inhibit System Recovery"],
    "ADWARE":             ["T1185 - Browser Session Hijacking"],
    "BOTNET_NODE":        ["T1498 - Network Denial of Service",
                           "T1071 - Application Layer Protocol"],
    "OBFUSCATED_LOADER":  ["T1027 - Obfuscated Files/Information",
                           "T1055 - Process Injection"],
    "POTENTIALLY_UNWANTED": [],
    "CLEAN":              [],
}

# Recommended analyst actions per family
RESPONSE_ACTIONS = {
    "CRYPTOMINER": [
        "Block all outbound connections to mining pool domains/IPs",
        "Check CPU usage on hosts running this module",
        "Search for other WASM files with same imphash",
        "Review browser extension permissions if browser-delivered",
    ],
    "RANSOMWARE": [
        "ISOLATE affected systems immediately",
        "Do not pay ransom — check for decryptors at nomoreransom.org",
        "Preserve memory dump before remediation",
        "Check WASI filesystem permissions — restrict path_rename, path_unlink",
        "Review backup integrity",
    ],
    "DROPPER": [
        "Inspect network traffic for stage-2 download URLs",
        "Check for newly written files on affected hosts",
        "Block C2 URLs extracted from strings section",
        "Scan dropped files with additional AV/EDR",
    ],
    "BACKDOOR": [
        "Review all outbound connections from WASM runtime process",
        "Check for persistence mechanisms (cron, systemd, registry)",
        "Rotate all credentials accessible from affected environment",
        "Block C2 infrastructure",
    ],
    "INFOSTEALER": [
        "Rotate all credentials immediately (AWS, SSH, API keys)",
        "Review environment variables exposed to WASM runtime",
        "Check outbound network connections for exfiltration",
        "Audit file access logs for sensitive path access",
    ],
    "CRYPTOJACKER": [
        "Remove or block the WASM file from web server",
        "Check CSP headers — add worker-src and script-src restrictions",
        "Audit all WASM served from CDN or third-party sources",
        "Monitor browser CPU usage",
    ],
    "WIPER": [
        "ISOLATE immediately — do not allow further execution",
        "Check for backup availability before remediation",
        "Preserve forensic image of affected system",
        "Review WASI capabilities — restrict path_unlink",
    ],
    "OBFUSCATED_LOADER": [
        "Submit to sandbox for dynamic analysis",
        "Extract and analyze embedded payloads from data sections",
        "Monitor runtime behavior with eBPF monitor",
        "Deobfuscate and re-analyze stage-2 payload",
    ],
    "ADWARE":            ["Block domain in web filter", "Audit browser extension installs"],
    "BOTNET_NODE":       ["Block C2 IP ranges", "Check for other infected hosts"],
    "POTENTIALLY_UNWANTED": ["Monitor for additional indicators", "Review in sandbox"],
    "CLEAN":             ["No action required"],
}


#  CLASSIFICATION RESULT

@dataclass
class ClassificationResult:
    family:          str
    confidence:      float           # 0-100
    evidence:        List[str]       # signals that contributed
    mitre_techniques: List[str]
    response_actions: List[str]
    runner_up:       Optional[str]   # second-best classification
    runner_up_conf:  float
    all_scores:      Dict[str,float] # full score breakdown



#  CLASSIFIER

class ThreatClassifier:
    
    # Decision-tree classifier that maps WASMShark analysis signals to specific threat family labels.

    # Uses a scoring approach: each family has a set of indicator checks. The family with the highest weighted score wins.


    def classify(self, report) -> ClassificationResult:
        scores: Dict[str,float] = {
            "CRYPTOMINER":        self._score_cryptominer(report),
            "RANSOMWARE":         self._score_ransomware(report),
            "DROPPER":            self._score_dropper(report),
            "BACKDOOR":           self._score_backdoor(report),
            "INFOSTEALER":        self._score_infostealer(report),
            "CRYPTOJACKER":       self._score_cryptojacker(report),
            "WIPER":              self._score_wiper(report),
            "ADWARE":             self._score_adware(report),
            "BOTNET_NODE":        self._score_botnet(report),
            "OBFUSCATED_LOADER":  self._score_obfuscated_loader(report),
        }

        # If malice score is too low, return CLEAN or PUP
        if report.malice_score < 15:
            return ClassificationResult(
                family="CLEAN", confidence=100.0 - report.malice_score,
                evidence=["Malice score below threshold"],
                mitre_techniques=[], response_actions=RESPONSE_ACTIONS["CLEAN"],
                runner_up=None, runner_up_conf=0.0, all_scores=scores)

        if report.malice_score < 30 and max(scores.values()) < 20:
            return ClassificationResult(
                family="POTENTIALLY_UNWANTED",
                confidence=50.0,
                evidence=["Low malice score with weak indicators"],
                mitre_techniques=[], response_actions=RESPONSE_ACTIONS["POTENTIALLY_UNWANTED"],
                runner_up=None, runner_up_conf=0.0, all_scores=scores)

        # Sort families by score
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_family, top_score = ranked[0]
        runner_up_family, runner_up_score = ranked[1] if len(ranked) > 1 else (None, 0)

        # Confidence = top score normalized, boosted by gap to runner-up
        gap        = top_score - runner_up_score
        confidence = min(100.0, round(top_score * 0.8 + gap * 0.5, 1))

        # If top score is very low, fall back to OBFUSCATED_LOADER
        if top_score < 10:
            top_family = "OBFUSCATED_LOADER"
            confidence = 40.0

        evidence = self._build_evidence(top_family, report)

        return ClassificationResult(
            family           = top_family,
            confidence       = confidence,
            evidence         = evidence,
            mitre_techniques = MITRE_TECHNIQUES.get(top_family, []),
            response_actions = RESPONSE_ACTIONS.get(top_family, []),
            runner_up        = runner_up_family if runner_up_score > 5 else None,
            runner_up_conf   = round(runner_up_score * 0.6, 1),
            all_scores       = {k: round(v, 1) for k,v in scores.items()},
        )

    # Scorer methods 

    def _imports(self, report) -> List[str]:
        return [f"{i.module}.{i.name}".lower() for i in report.imports]

    def _strings(self, report) -> List[str]:
        return [s.lower() for s in report.strings]

    def _iocs(self, report) -> List[str]:
        return [ioc.lower() for ioc, _ in report.iocs]

    def _has_import(self, report, *patterns) -> bool:
        imps = self._imports(report)
        return any(p in i for p in patterns for i in imps)

    def _has_string(self, report, *patterns) -> bool:
        strs = self._strings(report)
        return any(p in s for p in patterns for s in strs)

    def _has_ioc(self, report, *patterns) -> bool:
        iocs = self._iocs(report)
        return any(p in i for p in patterns for i in iocs)

    def _has_rule(self, report, *names) -> bool:
        matched = {r["name"] for r in report.matched_rules}
        return any(n in matched for n in names)

    def _score_cryptominer(self, report) -> float:
        score = 0.0
        if self._has_import(report, "sha256","randomx","keccak","cryptonight","hashrate"):
            score += 40
        if self._has_string(report, "stratum+tcp","stratum+ssl","moneroocean",
                            "supportxmr","nanopool","xmrig","hashrate","difficulty","nonce"):
            score += 35
        if self._has_ioc(report, "monero:", "xmr", "mining", "pool"):
            score += 20
        if any("CRYPTO" in f.category for f in report.findings): score += 10
        if report.crypto_hits: score += 15
        if self._has_rule(report, "CRYPTOMINER_WASM","SHA256_IMPL","RANDOMX_MONERO_MINER"):
            score += 25
        return score

    def _score_ransomware(self, report) -> float:
        score = 0.0
        if self._has_import(report, "random_get","getrandom"): score += 15
        if self._has_import(report, "path_rename"): score += 30
        if self._has_import(report, "path_unlink"): score += 20
        if self._has_import(report, "fd_write"):    score += 15
        if self._has_string(report, "ransom","your files","encrypted","decrypt",
                            "bitcoin","btc","payment","deadline"):
            score += 40
        if self._has_string(report, "vssadmin","shadow","bcdedit","wbadmin"):
            score += 35
        if self._has_rule(report, "RANSOMWARE_KW","RANSOMWARE_KW_v2",
                          "RANSOMWARE_DROPPER","WASI_RANSOM_TRIAD",
                          "RANSOMWARE_ENCRYPT_WASI","CHACHA20_RANSOMWARE"):
            score += 40
        wasi = getattr(report, 'wasi_analysis', {})
        for combo in wasi.get("dangerous_combos", []):
            if "RANSOMWARE" in combo.get("name",""):
                score += 30
        return score

    def _score_dropper(self, report) -> float:
        score = 0.0
        if self._has_import(report, "fd_write","path_open"): score += 20
        if self._has_import(report, "sock_recv","fetch","wget","curl"): score += 25
        if self._has_string(report, "powershell","cmd.exe","/bin/bash","wget",
                            "curl","stage2","stage_2","dropper","loader"):
            score += 35
        if self._has_ioc(report, "powershell","wget","curl","bash"): score += 25
        if report.has_start: score += 10
        if self._has_rule(report, "WASI_DROPPER","WASI_DROPPER_v2",
                          "POWERSHELL_DROPPER","BASH_DROPPER","WGET_CURL_STAGE2"):
            score += 35
        return score

    def _score_backdoor(self, report) -> float:
        score = 0.0
        if self._has_import(report, "sock_accept","sock_bind","accept","bind"):
            score += 40
        if self._has_import(report, "sock_recv","sock_send","connect"): score += 20
        if self._has_import(report, "environ_get"): score += 15
        if self._has_ioc(report, ".onion","c2","beacon","cobalt","meterpreter"):
            score += 30
        if self._has_rule(report, "TOR_C2_BEACON","COBALT_STRIKE_WASM",
                          "HTTP_BEACON","NETWORK_BEACON","WASI_FULL_CAPABILITY",
                          "BACKDOOR_CAPABILITY"):
            score += 40
        return score

    def _score_infostealer(self, report) -> float:
        score = 0.0
        if self._has_import(report, "environ_get"): score += 30
        if self._has_import(report, "sock_send","send","fetch"): score += 20
        if self._has_string(report, "id_rsa","authorized_keys","known_hosts",
                            ".aws","credentials","ssh","password","passwd",
                            "shadow","api_key","secret","token"):
            score += 40
        if self._has_ioc(report, "id_rsa","/etc/shadow","aws_","akia",
                         "ghp_","credential"):
            score += 35
        if self._has_rule(report, "AWS_CREDENTIAL_THEFT","SSH_KEY_THEFT",
                          "LINUX_SHADOW_READ","AWS_KEY_THEFT","GITHUB_TOKEN_THEFT",
                          "CREDENTIAL_EXFILTRATION"):
            score += 40
        return score

    def _score_cryptojacker(self, report) -> float:
        score = 0.0
        # Browser-specific APIs distinguish cryptojacker from server miner
        if self._has_import(report, "XMLHttpRequest","WebSocket","fetch",
                            "performance.now","Date.now"): score += 30
        if self._has_import(report, "localStorage","sessionStorage","cookie"): score += 20
        if self._has_import(report, "sha256","keccak","randomx","cryptonight"):
            score += 30
        if self._has_string(report, "coinhive","cryptoloot","deepminer",
                            "coin-hive","jsecoin","webminer"): score += 40
        if self._has_rule(report, "BROWSER_FINGERPRINT","BROWSER_FINGERPRINT_ADVANCED"):
            score += 15
        return score

    def _score_wiper(self, report) -> float:
        score = 0.0
        if self._has_import(report, "path_unlink","path_remove","unlink","remove"):
            score += 40
        if self._has_import(report, "fd_write"): score += 15
        if self._has_string(report, "vssadmin delete","wbadmin delete",
                            "bcdedit","recoveryenabled","delete shadows"):
            score += 50
        if self._has_rule(report, "DESTRUCTIVE_WIPER"): score += 40
        wasi = getattr(report, 'wasi_analysis', {})
        for combo in wasi.get("dangerous_combos",[]):
            if "WIPER" in combo.get("name","") or "DESTRUCTIVE" in combo.get("name",""):
                score += 30
        return score

    def _score_adware(self, report) -> float:
        score = 0.0
        if self._has_import(report, "localStorage","sessionStorage","cookie",
                            "document.cookie","navigator","clipboard"): score += 25
        if self._has_import(report, "geolocation","battery","usb"): score += 20
        if self._has_string(report, "advertisement","tracking","analytics",
                            "fingerprint","impression","click","ad_network"): score += 30
        # Low malice but has browser tracking imports
        if report.malice_score < 50: score += 10
        return score

    def _score_botnet(self, report) -> float:
        score = 0.0
        if self._has_import(report, "sock_send","sock_recv","connect"): score += 25
        if self._has_import(report, "sock_accept","bind"): score += 20
        if self._has_string(report, "bot","zombie","ddos","flood","amplif",
                            "reflec","c&c","command and control"): score += 35
        if self._has_ioc(report, "c2","beacon"): score += 15
        # Botnet nodes often have moderate malice with network focus
        net_findings = sum(1 for f in report.findings if f.category == "NETWORK")
        score += net_findings * 5
        return score

    def _score_obfuscated_loader(self, report) -> float:
        score = 0.0
        if report.obfuscation_score > 60: score += 40
        if report.file_entropy > 7.0:     score += 25
        if any(fn.nop_max_run > 50 for fn in report.functions): score += 20
        if any(fn.indirect_calls > 0 for fn in report.functions): score += 15
        if report.custom_secs:            score += 20
        obf_findings = sum(1 for f in report.findings if f.category == "OBFUSCATION")
        score += obf_findings * 3
        if self._has_rule(report, "OBFUSCATED_PAYLOAD","MULTI_LAYER_OBFUSC",
                          "HEAVILY_OBFUSCATED_LARGE","PACKED_BINARY"):
            score += 30
        return score

    def _build_evidence(self, family: str, report) -> List[str]:
        ev = []
        imp_names = [i.name.lower() for i in report.imports]
        str_lower  = [s.lower() for s in report.strings[:20]]

        # Generic evidence from signals
        if report.malice_score >= 70:
            ev.append(f"Malice score: {report.malice_score}/100")
        if report.obfuscation_score >= 50:
            ev.append(f"Obfuscation score: {report.obfuscation_score}/100")
        if report.crypto_hits:
            names = list({h['name'] for h in report.crypto_hits})[:3]
            ev.append(f"Crypto constants: {', '.join(names)}")
        if report.iocs:
            ev.append(f"IoCs detected: {len(report.iocs)}")
        if report.matched_rules:
            ev.append(f"Rules matched: {', '.join(r['name'] for r in report.matched_rules[:4])}")
        if report.has_start:
            ev.append("Auto-executing start function")
        if any(fn.indirect_calls > 0 for fn in report.functions):
            ev.append("Indirect call dispatch (obfuscation)")

        # Family-specific evidence
        if family == "CRYPTOMINER":
            mining_imps = [n for n in imp_names if any(k in n for k in
                           ("sha256","randomx","keccak","hash"))]
            if mining_imps: ev.append(f"Mining imports: {mining_imps[:3]}")
        elif family == "RANSOMWARE":
            ransom_str = [s for s in str_lower if any(k in s for k in
                          ("ransom","your files","decrypt","bitcoin"))]
            if ransom_str: ev.append(f"Ransom strings: {ransom_str[0][:50]}")
            if any("path_rename" in n for n in imp_names):
                ev.append("WASI path_rename import (file renaming)")
        elif family == "INFOSTEALER":
            cred_str = [s for s in str_lower if any(k in s for k in
                        ("id_rsa","shadow","credentials","aws","token"))]
            if cred_str: ev.append(f"Credential paths: {cred_str[0][:50]}")
        elif family == "DROPPER":
            drop_str = [s for s in str_lower if any(k in s for k in
                        ("powershell","wget","curl","/bin/bash"))]
            if drop_str: ev.append(f"Dropper strings: {drop_str[0][:50]}")

        return ev[:8]  # Cap at 8 evidence items



#  TERMINAL OUTPUT

R="\033[0m"; B="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; MAG="\033[95m"; DIM="\033[2m"

FAMILY_COLORS = {
    "CRYPTOMINER":        YEL+B,
    "RANSOMWARE":         RED+B,
    "DROPPER":            RED+B,
    "BACKDOOR":           RED+B,
    "INFOSTEALER":        RED+B,
    "CRYPTOJACKER":       YEL+B,
    "WIPER":              RED+B,
    "ADWARE":             YEL,
    "BOTNET_NODE":        RED,
    "OBFUSCATED_LOADER":  YEL+B,
    "POTENTIALLY_UNWANTED": YEL,
    "CLEAN":              GRN+B,
}

FAMILY_ICONS = {
    "CRYPTOMINER":        "⛏ ",
    "RANSOMWARE":         "🔒",
    "DROPPER":            "💉",
    "BACKDOOR":           "🚪",
    "INFOSTEALER":        "🕵️ ",
    "CRYPTOJACKER":       "⛏ ",
    "WIPER":              "🔥",
    "ADWARE":             "📢",
    "BOTNET_NODE":        "🤖",
    "OBFUSCATED_LOADER":  "📦",
    "POTENTIALLY_UNWANTED":"⚠️ ",
    "CLEAN":              "✅",
}

def print_classification(result: ClassificationResult, filename: str = ""):
    col  = FAMILY_COLORS.get(result.family, R)
    icon = FAMILY_ICONS.get(result.family, "  ")

    print(f"\n{CYN}{'═'*70}{R}")
    print(f"{B}  THREAT CLASSIFICATION{' — '+filename if filename else ''}{R}")
    print(f"{CYN}{'═'*70}{R}")
    print(f"  Family      : {col}{icon} {result.family}{R}")
    print(f"  Confidence  : {result.confidence:.0f}%")

    if result.runner_up:
        print(f"  Runner-up   : {DIM}{result.runner_up} ({result.runner_up_conf:.0f}%){R}")

    print(f"\n{CYN}{'─'*70}{R}")
    print(f"{B}  EVIDENCE{R}")
    for ev in result.evidence:
        print(f"  {MAG}▸{R} {ev}")

    print(f"\n{CYN}{'─'*70}{R}")
    print(f"{B}  MITRE ATT&CK{R}")
    if result.mitre_techniques:
        for t in result.mitre_techniques:
            print(f"  {DIM}▸{R} {t}")
    else:
        print(f"  {DIM}None mapped{R}")

    print(f"\n{CYN}{'─'*70}{R}")
    print(f"{B}  RECOMMENDED ACTIONS{R}")
    for i, action in enumerate(result.response_actions[:5], 1):
        print(f"  {i}. {action}")

    print(f"\n{CYN}{'─'*70}{R}")
    print(f"{B}  ALL FAMILY SCORES{R}")
    ranked = sorted(result.all_scores.items(), key=lambda x: x[1], reverse=True)
    for fam, sc in ranked:
        if sc == 0: continue
        bar_w = int(sc / max(1, max(result.all_scores.values())) * 30)
        bar   = "█" * bar_w + "░" * (30 - bar_w)
        fc    = FAMILY_COLORS.get(fam, R)
        print(f"  {fc}{fam:<22}{R} {DIM}[{bar}]{R} {sc:.0f}")
    print(f"{CYN}{'═'*70}{R}\n")



"""
Threat family classifier using decision-tree logic
derived from scoring signals, import patterns, and IoC matches.

Outputs a specific threat family label rather than just MALICIOUS/CLEAN:

  CRYPTOMINER       - Browser or server-side cryptocurrency mining
  RANSOMWARE        - File encryption + ransom demand
  DROPPER           - Delivers and executes a secondary payload
  BACKDOOR          - Persistent remote access
  INFOSTEALER       - Credential/data harvesting
  CRYPTOJACKER      - Browser-based hidden mining
  WIPER             - Destructive file deletion/corruption
  ADWARE            - Unwanted ad injection / tracking
  BOTNET_NODE       - Participates in a botnet/DDoS network
  OBFUSCATED_LOADER - Packed/obfuscated payload loader
  POTENTIALLY_UNWANTED - Low-confidence suspicious
  CLEAN             - No threat indicators

Each label comes with:
    Confidence score (0-100)
    Evidence list (which signals contributed)
    MITRE ATT&CK technique IDs
    Recommended response actions
"""
