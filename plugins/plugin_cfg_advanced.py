#!/usr/bin/env python3

# Plugin: Advanced CFG Analysis
#   Runs the full advanced CFG analysis engine on all functions.

from wasmshark_core import AnalysisReport
from wasmshark_cfg_analysis import analyze_module_cfgs


class WASMPlugin:
    name        = "cfg_advanced"
    description = "Advanced CFG analysis: dominance tree, natural loops, irreducibility, path complexity, fingerprinting"
    version     = "2.0"

    def analyze(self, report: AnalysisReport) -> dict:
        return analyze_module_cfgs(report)
