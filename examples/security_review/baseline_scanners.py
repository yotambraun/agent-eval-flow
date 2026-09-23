"""Deterministic scanner baseline on the same fixtures and ground truth; no agents.

python -m examples.security_review.baseline_scanners --data DIR --output OUT

Runs Bandit and Semgrep (registry rule packs, metrics off) on every pinned
snapshot. A scanner detects an advisory with the same rule as the AI reviewer:
any result in a fixed file within ``window`` lines of the fixed region. Results
elsewhere are counted as unverified, never as correct or false.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from .evaluators import hits

SEMGREP_CONFIGS = ("p/python", "p/security-audit")


def bandit(root):
    exe = shutil.which("bandit") or str(Path(sys.executable).with_name("bandit"))
    proc = subprocess.run([exe, "-r", str(root), "-f", "json", "-q"], capture_output=True, text=True)
    data = json.loads(proc.stdout or "{}")
    return [{"file": str(Path(r["filename"]).relative_to(root)), "line": r["line_number"],
             "rule": r["test_id"], "severity": r["issue_severity"]} for r in data.get("results", [])]


def semgrep(root):
    exe = shutil.which("semgrep") or str(Path(sys.executable).with_name("semgrep"))
    args = [exe, "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check"]
    for config in SEMGREP_CONFIGS:
        args += ["--config", config]
    proc = subprocess.run([*args, str(root)], capture_output=True, text=True)
    data = json.loads(proc.stdout or "{}")
    return [{"file": str(Path(r["path"]).resolve().relative_to(root.resolve())), "line": r["start"]["line"],
             "rule": r["check_id"], "severity": r["extra"].get("severity")} for r in data.get("results", [])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()
    dataset = json.loads((args.data / "dataset.json").read_text(encoding="utf-8"))
    rows = []
    for row in dataset["truth"]:
        truth, root = row["truth"], args.data / "fixtures" / row["task_id"] / "files"
        for name, scan in (("bandit", bandit), ("semgrep", semgrep)):
            results = scan(root)
            matched = [r for r in results if hits(r, truth, args.window)]
            rows.append({"scanner": name, "advisory": truth["advisory"], "project": truth["project"],
                         "category": truth["category"], "variant": truth["variant"], "results": len(results),
                         "hit": bool(matched), "matched": matched})
            print(name, truth["project"], truth["variant"], len(results), bool(matched), file=sys.stderr)
    summary = {}
    for name in ("bandit", "semgrep"):
        mine = [r for r in rows if r["scanner"] == name]
        vuln = [r for r in mine if r["variant"] == "vulnerable"]
        patched = [r for r in mine if r["variant"] == "patched"]
        summary[name] = {"detected": sum(r["hit"] for r in vuln), "advisories": len(vuln),
                         "reflagged_after_fix": sum(r["hit"] for r in patched),
                         "results_total": sum(r["results"] for r in mine),
                         "detected_advisories": sorted(r["advisory"] for r in vuln if r["hit"])}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "scanner_baseline.json").write_text(
        json.dumps({"configs": {"semgrep": SEMGREP_CONFIGS}, "summary": summary, "rows": rows}, indent=2) + "\n",
        encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
