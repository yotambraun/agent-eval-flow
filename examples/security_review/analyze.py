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

import agent_eval_flow as a


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return {"k": k, "n": n, "rate": p, "ci95": [max(0.0, centre - half), min(1.0, centre + half)]}


def mean(values):
    return {"mean": sum(values) / len(values), "n": len(values)} if values else None


def analyze(output, cutoff):
    study = a.Study.load(output / "study")
    result = a.EvaluationResult.load(output / "result")
    truth = {row["task_id"]: row["truth"] for row in study.dataset.references["cve_truth"].rows}
    assignments = {x.id: x for x in result.runs.plan.assignments}
    runs = {run.id: run for run in result.runs.runs}
    table = defaultdict(dict)
    for m in result.measurements:
        table[m.run_id][m.metric] = m
    rows = []
    for run_id, metrics in table.items():
        run, assignment = runs[run_id], assignments[runs[run_id].assignment_id]
        t = truth[assignment.unit["task_id"]]
        value = lambda name: metrics[name].value if name in metrics and metrics[name].status == "ok" else None
        execution = run.executions[0] if run.executions else None
        cost = execution.resources.cost_usd.value if execution and execution.resources.cost_usd.status != "unknown" else None
        duration = (run.ended_at - run.started_at).total_seconds() if run.ended_at and run.started_at else None
        findings = run.output.get("findings", ()) if isinstance(run.output, dict) or hasattr(run.output, "get") else ()
        rows.append({"run_id": run_id, "candidate": assignment.candidate_id, "advisory": t["advisory"],
            "project": t["project"], "category": t["category"], "variant": t["variant"],
            "post_cutoff": t["published"] > cutoff, "status": run.status, "findings": len(findings or ()),
            "detected": value("detected"), "category_match": value("category_match"),
            "reflagged": value("reflagged_after_fix"), "grounded_rate": value("grounded_rate"),
            "ungrounded": value("ungrounded_findings"), "fixed_region_read": value("fixed_region_read"),
            "scope_recall": value("tools.matched_call_recall"), "unsafe": value("tools.forbidden_calls"),
            "redundant_rate": value("tools.redundant_rate"), "tool_score": value("tools.score"),
            "cost_usd_estimate": float(cost) if cost is not None else None, "duration_s": duration})
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
            "detection_post_cutoff": wilson(sum(r["detected"] for r in vuln if r["post_cutoff"]),
                                            sum(1 for r in vuln if r["post_cutoff"])),
            "detection_pre_cutoff": wilson(sum(r["detected"] for r in vuln if not r["post_cutoff"]),
                                           sum(1 for r in vuln if not r["post_cutoff"])),
            "category_match_when_detected": wilson(sum(bool(r["category_match"]) for r in caught), len(caught)),
            "reflag_after_fix": wilson(sum(r["reflagged"] for r in patched), len(patched)),
            # The joint view: outcome from Agent Eval Flow x path from the trace.
            "caught_without_reading_fixed_region": wilson(sum(not r["fixed_region_read"] for r in known_read), len(known_read)),
            "missed_despite_reading_fixed_region": wilson(
                sum(r["fixed_region_read"] and not r["detected"] for r in vuln if r["fixed_region_read"] is not None),
                sum(1 for r in vuln if r["fixed_region_read"])),
            "runs_with_ungrounded_findings": wilson(sum(r["ungrounded"] > 0 for r in with_findings), len(with_findings)),
            "ungrounded_findings_total": sum(r["ungrounded"] for r in with_findings),
            "findings_total": sum(r["findings"] for r in mine),
            "scope_read_recall": mean([r["scope_recall"] for r in mine if r["scope_recall"] is not None]),
            "full_scope_read": wilson(sum(r["scope_recall"] == 1.0 for r in mine if r["scope_recall"] is not None),
                                      sum(1 for r in mine if r["scope_recall"] is not None)),
            "unsafe_requests_total": sum(r["unsafe"] or 0 for r in mine),
            "redundant_rate": mean([r["redundant_rate"] for r in mine if r["redundant_rate"] is not None]),
            "cost_usd_estimate_total": sum(r["cost_usd_estimate"] or 0 for r in mine),
            "median_duration_s": sorted(r["duration_s"] for r in mine if r["duration_s"])[len(mine) // 2] if mine else None,
        }
    per_advisory = defaultdict(dict)
    for r in rows:
        if r["variant"] == "vulnerable" and r["detected"] is not None:
            per_advisory[r["advisory"]].setdefault(r["candidate"], []).append(r["detected"])
    return {"cutoff": cutoff, "summary": summary, "per_advisory": per_advisory, "runs": rows}


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
