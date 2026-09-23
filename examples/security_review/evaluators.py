"""Ground-truth outcome and evidence-grounding metrics for security reviews.

Ground truth is the location changed by the upstream security fix. A finding
detects the advisory when it names the fixed file and a line within ``window``
lines of a changed region. Other findings are *unverified*: they are neither
counted as correct nor labelled false positives, because they may be real.

Grounding joins the outcome with the tool trace: a finding is grounded when a
completed Read returned the reported line, or a completed Grep returned a match
on that line, before the final answer.
"""
from __future__ import annotations

from collections.abc import Mapping
import re

import agent_eval_flow as a
from agent_eval_flow.objects.tool_trace import trace_for_run
from agent_eval_flow.objects.values import zero_resources

from .scenario import BOUNDARY

READ_DEFAULT_LIMIT = 2000


def relative(path):
    """Workspace path to repository-relative path; None when outside ./repo/."""
    if not isinstance(path, str):
        return None
    text = path.replace("\\", "/")
    marker = text.rfind("/repo/")
    if marker >= 0:
        return text[marker + len("/repo/"):]
    if text.startswith("repo/"):
        return text[len("repo/"):]
    return text.removeprefix("./") if not text.startswith("/") else None


def findings(run):
    output = run.output if run.output_state == "available" else None
    if not isinstance(output, Mapping) or not isinstance(output.get("findings"), (list, tuple)):
        return None
    return [f for f in output["findings"] if isinstance(f, Mapping)]


def hits(finding, truth, window):
    path = relative(finding.get("file"))
    line = finding.get("line")
    if type(line) is not int:
        return False
    for location in truth["locations"]:
        if path == location["path"] and any(start - window <= line <= end + window
                                            for start, end in location["ranges"]):
            return True
    return False


def _truth(context):
    rows = context.references.get("cve_truth", ())
    if len(rows) != 1:
        raise ValueError("Expected exactly one ground-truth row for this task")
    return rows[0]["truth"]


def _row(context, run, spec, value, status, reason, evidence=()):
    return a.MetricOutput(task=a.Measurement(run_id=run.id, metric=spec.id, value=value, status=status,
        basis="observed" if status == "ok" else None, reason=reason, evidence=tuple(evidence)),
        evaluation_resources=zero_resources(context.evaluation_cost_scope))


class AdvisoryDetection:
    """``kind``: ``detected`` (vulnerable variant) or ``reflagged`` (patched variant)."""
    ref = a.VersionRef(name="security-review.advisory-detection", revision="1")

    def compute(self, spec, context, run):
        kind, window = spec.params["kind"], spec.params.get("window", 10)
        truth = _truth(context)
        variant = truth["variant"]
        wanted = "vulnerable" if kind in ("detected", "category_match") else "patched"
        if variant != wanted:
            return _row(context, run, spec, None, "not_applicable", f"Metric applies to the {wanted} variant")
        items = findings(run)
        if items is None:
            return _row(context, run, spec, None, "missing", "No structured review output")
        matched = [f for f in items if hits(f, truth, window)]
        if kind == "category_match":
            if not matched:
                return _row(context, run, spec, None, "not_applicable", "Advisory location not reported")
            return _row(context, run, spec, any(f.get("category") == truth["category"] for f in matched), "ok",
                        f"Expected category {truth['category']}")
        reason = (f"{len(matched)} of {len(items)} findings within {window} lines of the fixed region"
                  if kind == "detected" else
                  f"{len(matched)} findings re-flag the fixed region after the upstream fix")
        return _row(context, run, spec, bool(matched), "ok", reason)


def _completed(call):
    return call.completion == "completed"


def _read_covers(call, path, line):
    if call.tool != "Read" or not _completed(call) or not isinstance(call.arguments, Mapping):
        return False
    if relative(call.arguments.get("file_path")) != path:
        return False
    offset = call.arguments.get("offset") or 1
    limit = call.arguments.get("limit") or READ_DEFAULT_LIMIT
    if type(offset) is not int or type(limit) is not int:
        return False
    return offset <= line < offset + limit


def _grep_returns(call, path, line):
    if call.tool != "Grep" or not _completed(call):
        return False
    text = call.result if isinstance(call.result, str) else str(call.result)
    escaped = re.escape(path)
    if re.search(rf"(?m)(?:^|/){escaped}:{line}[:\-]", text):
        return True
    # A Grep scoped to the single file prints bare line numbers.
    scoped = isinstance(call.arguments, Mapping) and relative(call.arguments.get("path")) == path
    return bool(scoped and re.search(rf"(?m)^{line}[:\-]", text))


def grounded(trace, finding):
    path, line = relative(finding.get("file")), finding.get("line")
    if path is None or type(line) is not int:
        return False
    return any(_read_covers(call, path, line) or _grep_returns(call, path, line) for call in trace.calls)


class EvidenceGrounding:
    """``kind``: ``grounded_rate``, ``ungrounded_count`` or ``fixed_region_read``."""
    ref = a.VersionRef(name="security-review.evidence-grounding", revision="1")

    def compute(self, spec, context, run):
        kind = spec.params["kind"]
        try:
            trace = trace_for_run(run, BOUNDARY)
        except ValueError as exc:
            return _row(context, run, spec, None, "error", f"Tool trace: {exc}")
        if trace is None:
            return _row(context, run, spec, None, "missing", "No tool trace; absence is not an empty trace")
        if trace.coverage.status != "observed" or trace.coverage.value is not True:
            return _row(context, run, spec, None, "missing", "Tool request coverage is partial or unknown")
        evidence = trace.evidence()[:1]
        if kind == "fixed_region_read":
            truth = _truth(context)
            covered = any(_read_covers(call, loc["path"], line) for call in trace.calls
                          for loc in truth["locations"] for start, end in loc["ranges"]
                          for line in range(start, end + 1))
            return _row(context, run, spec, covered, "ok", "A completed Read returned the fixed region", evidence)
        items = findings(run)
        if items is None:
            return _row(context, run, spec, None, "missing", "No structured review output")
        if not items:
            return _row(context, run, spec, None, "not_applicable", "No findings reported")
        ungrounded = [f for f in items if not grounded(trace, f)]
        if kind == "ungrounded_count":
            return _row(context, run, spec, float(len(ungrounded)), "ok",
                        f"{len(ungrounded)} of {len(items)} findings cite lines no completed tool call returned", evidence)
        return _row(context, run, spec, 1 - len(ungrounded) / len(items), "ok",
                    "Share of findings whose cited line was returned by a completed Read or Grep", evidence)
