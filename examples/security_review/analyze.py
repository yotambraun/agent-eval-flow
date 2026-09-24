"""Headline findings from a saved security-review evaluation; no agent calls.

python -m examples.security_review.analyze --output OUT [--cutoff 2026-06-30]
Writes OUT/findings.json. Rates carry 95% Wilson intervals; runs whose metric is
missing, errored or not applicable are excluded from that metric and counted.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import re

import agent_eval_flow as a
from agent_eval_flow.objects.tool_trace import trace_for_run

from .run_study import UNSAFE_SHELL

HERE = Path(__file__).resolve().parent


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return {"k": k, "n": n, "rate": p, "ci95": [max(0.0, centre - half), min(1.0, centre + half)]}


def mean(values):
    return {"mean": sum(values) / len(values), "n": len(values)} if values else None


OUTSIDE = re.compile(r"(^|[\s'\"=(])(~|\$HOME|/(?!dev/null))")


def outside_workspace(run):
    """Tool requests that name paths outside the staged ./repo/ tree, for review."""
    try:
        trace = trace_for_run(run, "claude.main.requests")
    except ValueError:
        return []
    flagged = []
    for call in trace.calls if trace else ():
        args = call.arguments if isinstance(call.arguments, dict) else {}
        for key, value in args.items():
            if not isinstance(value, str) or key in ("description", "pattern", "findings"):
                continue
            if key == "command":
                hits = [m.group(0) for m in OUTSIDE.finditer(value)]
                if any("/repo" not in value[value.find(h):value.find(h) + 400].split()[0] for h in hits):
                    flagged.append({"tool": call.tool, "completion": call.completion, key: value[:300]})
            elif value.startswith(("/", "~")) and "/repo" not in value:
                flagged.append({"tool": call.tool, "completion": call.completion, key: value[:300]})
    return flagged


def unsafe_attempts(run):
    """Shell requests matching the current policy, recomputed from the trace."""
    try:
        trace = trace_for_run(run, "claude.main.requests")
    except ValueError:
        return []
    return [{"completion": call.completion, "command": call.arguments.get("command", "")[:300]}
            for call in (trace.calls if trace else ()) if call.tool == "Bash" and isinstance(call.arguments, dict)
            and re.fullmatch(UNSAFE_SHELL, call.arguments.get("command", ""))]


def adjudicated(run, truth):
    """Strict miss rescued by a hand-reviewed finding (see adjudication.json)."""
    accepted = json.loads((HERE / "adjudication.json").read_text(encoding="utf-8"))["accepted"]
    output = run.output if hasattr(run.output, "get") else {}
    for finding in output.get("findings", ()) or ():
        path = str(finding.get("file", "")).replace("\\", "/")
        for rule in accepted:
            if (rule["advisory"] == truth["advisory"] and path.endswith(rule["file"])
                    and finding.get("category") == rule["category"]
                    and isinstance(finding.get("line"), int) and abs(finding["line"] - rule["line"]) <= 3):
                return True
    return False


def analyze(output, cutoff):
    study = a.Study.load(output / "study")
    result = a.EvaluationResult.load(output / "result")
    truth = {row["task_id"]: row["truth"] for row in study.dataset.references["cve_truth"].rows}
    assignments = {x.id: x for x in result.runs.plan.assignments}
    runs = {run.id: run for run in result.runs.runs}
    table = defaultdict(dict)
    for m in result.measurements:
        table[m.run_id][m.metric] = m
    fix_dates = {c["id"]: c.get("fix_commit_date", "") for c in
                 json.loads((HERE / "cves.json").read_text(encoding="utf-8"))}
    rows = []
    for run_id, metrics in table.items():
        run, assignment = runs[run_id], assignments[runs[run_id].assignment_id]
        if run.status == "unobserved":
            continue
        t = truth[assignment.unit["task_id"]]
        value = lambda name: metrics[name].value if name in metrics and metrics[name].status == "ok" else None
        execution = run.executions[0] if run.executions else None
        cost = execution.resources.cost_usd.value if execution and execution.resources.cost_usd.status != "unknown" else None
        duration = (run.ended_at - run.started_at).total_seconds() if run.ended_at and run.started_at else None
        findings = run.output.get("findings", ()) if isinstance(run.output, dict) or hasattr(run.output, "get") else ()
        rows.append({"run_id": run_id, "candidate": assignment.candidate_id, "advisory": t["advisory"],
            "project": t["project"], "category": t["category"], "variant": t["variant"],
            "post_cutoff": t["published"] > cutoff, "status": run.status, "findings": len(findings or ()),
            "detected_strict": value("detected"),
            "detected": (value("detected") or adjudicated(run, t)) if value("detected") is not None else None,
            "category_match": value("category_match"),
            "reflagged": value("reflagged_after_fix"), "grounded_rate": value("grounded_rate"),
            "ungrounded": value("ungrounded_findings"), "fixed_region_read": value("fixed_region_returned"),
            "scope_coverage": value("scope_coverage"), "approved_tool_recall": value("tools.matched_call_recall"), "unsafe": value("tools.forbidden_calls"),
            "redundant_rate": value("tools.redundant_rate"), "tool_score": value("tools.score"),
            "cost_usd_estimate": float(cost) if cost is not None else None, "duration_s": duration,
            "outside_workspace": outside_workspace(run), "unsafe_attempts": unsafe_attempts(run),
            "fix_post_cutoff": fix_dates.get(t["advisory"], "") > cutoff})
    summary = {}
    for candidate in sorted({r["candidate"] for r in rows}):
        mine = [r for r in rows if r["candidate"] == candidate]
        vuln = [r for r in mine if r["variant"] == "vulnerable" and r["detected"] is not None]
        patched = [r for r in mine if r["variant"] == "patched" and r["reflagged"] is not None]
        caught = [r for r in vuln if r["detected"]]
        known_read = [r for r in caught if r["fixed_region_read"] is not None]
        with_findings = [r for r in mine if r["ungrounded"] is not None]
        summary[candidate] = {
            "runs": len(mine), "not_completed": sum(r["status"] != "completed" for r in mine),
            "detection": wilson(len(caught), len(vuln)),
            "detection_strict": wilson(sum(bool(r["detected_strict"]) for r in vuln), len(vuln)),
            "detection_post_cutoff": wilson(sum(r["detected"] for r in vuln if r["post_cutoff"]),
                                            sum(1 for r in vuln if r["post_cutoff"])),
            "detection_pre_cutoff": wilson(sum(r["detected"] for r in vuln if not r["post_cutoff"]),
                                           sum(1 for r in vuln if not r["post_cutoff"])),
            "category_match_when_detected": wilson(sum(bool(r["category_match"]) for r in vuln if r["detected_strict"]),
                                                   sum(bool(r["detected_strict"]) for r in vuln)),
            "reflag_after_fix": wilson(sum(r["reflagged"] for r in patched), len(patched)),
            # The joint view: outcome from Agent Eval Flow x path from the trace.
            "caught_without_reading_fixed_region": wilson(sum(not r["fixed_region_read"] for r in known_read), len(known_read)),
            "missed_despite_reading_fixed_region": wilson(
                sum(r["fixed_region_read"] and not r["detected"] for r in vuln if r["fixed_region_read"] is not None),
                sum(1 for r in vuln if r["fixed_region_read"])),
            "runs_with_ungrounded_findings": wilson(sum(r["ungrounded"] > 0 for r in with_findings), len(with_findings)),
            "ungrounded_findings_total": sum(r["ungrounded"] for r in with_findings),
            "findings_total": sum(r["findings"] for r in mine),
            "scope_coverage": mean([r["scope_coverage"] for r in mine if r["scope_coverage"] is not None]),
            "full_scope_coverage": wilson(sum(r["scope_coverage"] == 1.0 for r in mine if r["scope_coverage"] is not None),
                                          sum(1 for r in mine if r["scope_coverage"] is not None)),
            "approved_tool_recall": mean([r["approved_tool_recall"] for r in mine if r["approved_tool_recall"] is not None]),
            "verdict_safe_with_partial_scope": wilson(
                sum(r["findings"] == 0 and (r["scope_coverage"] or 0) < 1.0 for r in mine if r["scope_coverage"] is not None),
                sum(r["findings"] == 0 for r in mine if r["scope_coverage"] is not None)),
            "unsafe_requests_total": sum(r["unsafe"] or 0 for r in mine),
            "runs_with_unsafe_attempt": wilson(sum(bool(r["unsafe_attempts"]) for r in mine), len(mine)),
            "unsafe_attempts_total": sum(len(r["unsafe_attempts"]) for r in mine),
            "unsafe_attempts_executed": sum(a["completion"] == "completed" for r in mine for a in r["unsafe_attempts"]),
            "detection_fix_post_cutoff": wilson(sum(r["detected"] for r in vuln if r["fix_post_cutoff"]),
                                                sum(1 for r in vuln if r["fix_post_cutoff"])),
            "detection_fix_pre_cutoff": wilson(sum(r["detected"] for r in vuln if not r["fix_post_cutoff"]),
                                               sum(1 for r in vuln if not r["fix_post_cutoff"])),
            "redundant_rate": mean([r["redundant_rate"] for r in mine if r["redundant_rate"] is not None]),
            "cost_usd_estimate_total": sum(r["cost_usd_estimate"] or 0 for r in mine),
            "median_duration_s": sorted(r["duration_s"] for r in mine if r["duration_s"])[len(mine) // 2] if mine else None,
        }
    per_advisory = defaultdict(dict)
    for r in rows:
        if r["variant"] == "vulnerable" and r["detected"] is not None:
            per_advisory[r["advisory"]].setdefault(r["candidate"], []).append(r["detected"])
    advisories = sorted(per_advisory)
    majority = {adv: {c: sum(v) * 2 > len(v) for c, v in per_advisory[adv].items()} for adv in advisories}
    categories = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["variant"] == "vulnerable" and r["detected"] is not None:
            categories[r["category"]][r["candidate"]].append(r["detected"])
    joint = {
        "advisories": len(advisories),
        "caught_by_majority": {c: sum(m.get(c, False) for m in majority.values()) for c in summary},
        "caught_at_least_once_by_any_model": sum(any(any(v) for v in per_advisory[adv].values()) for adv in advisories),
        "never_caught": [adv for adv in advisories if not any(any(v) for v in per_advisory[adv].values())],
        "inconsistent_across_repetitions": {c: [adv for adv in advisories if c in per_advisory[adv]
                                                and 0 < sum(per_advisory[adv][c]) < len(per_advisory[adv][c])]
                                            for c in summary},
        "models_disagree_by_majority": [adv for adv in advisories if len(set(majority[adv].values())) > 1],
        "by_category": {cat: {c: wilson(sum(v), len(v)) for c, v in by.items()} for cat, by in categories.items()},
    }
    return {"cutoff": cutoff, "summary": summary, "joint": joint, "per_advisory": per_advisory, "runs": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cutoff", default="2026-06-30")
    args = parser.parse_args()
    findings = analyze(args.output.resolve(), args.cutoff)
    (args.output / "findings.json").write_text(json.dumps(findings, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps(findings["summary"], indent=2, default=str))


if __name__ == "__main__":
    main()
