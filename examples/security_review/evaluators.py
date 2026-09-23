"""Ground-truth outcome and evidence-grounding metrics for security reviews.

Ground truth is the location changed by the upstream security fix. A finding
detects the advisory when it names the fixed file and a line within ``window``
lines of a changed region. Other findings are *unverified*: they are neither
counted as correct nor labelled false positives, because they may be real.

Grounding joins the outcome with the tool trace: a finding is grounded when the
pinned source text of the cited line appears in what some completed tool call
(Read, Grep or a shell command) actually returned to the agent.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path

import agent_eval_flow as a
from agent_eval_flow.adapters.cli import local_path
from agent_eval_flow.adapters.common import contained_relative
from agent_eval_flow.objects.tool_trace import trace_for_run
from agent_eval_flow.objects.values import zero_resources

from .scenario import BOUNDARY



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


MIN_TEXT = 12  # Shorter lines ("}", "return x") are too generic to attribute.


def returned_text(value):
    """Flatten a tool result into the text the agent actually received."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(returned_text(v) for k, v in value.items() if k in ("text", "content", "stdout"))
    if isinstance(value, (list, tuple)):
        return "\n".join(returned_text(v) for v in value)
    return ""


def evidence_text(trace):
    """Text returned by completed tool calls, in any tool: Read, Grep, or shell."""
    return "\n".join(returned_text(call.result) for call in trace.calls
                     if call.completion == "completed" and call.tool != "StructuredOutput")


def distinctive(lines, line):
    """The cited line's text, or the nearest distinctive neighbour within 2 lines.

    Lines that occur once in the file are preferred, so matching text cannot have
    come from elsewhere in the same file.
    """
    counts = {}
    for text in lines:
        counts[text.strip()] = counts.get(text.strip(), 0) + 1
    fallback = None
    for offset in (0, 1, -1, 2, -2):
        index = line - 1 + offset
        if 0 <= index < len(lines) and len(lines[index].strip()) >= MIN_TEXT:
            if counts[lines[index].strip()] == 1:
                return lines[index].strip()
            fallback = fallback or lines[index].strip()
    return fallback


class Fixture:
    def __init__(self, root, task_id):
        self.root = Path(root) / task_id / "files"
        self._cache = {}

    def lines(self, path):
        if path not in self._cache:
            try:
                self._cache[path] = contained_relative(self.root, path).read_text(
                    encoding="utf-8", errors="replace").splitlines()
            except (OSError, ValueError, a.ConfigurationError):
                self._cache[path] = None
        return self._cache[path]


def grounded(text, fixture, finding):
    path, line = relative(finding.get("file")), finding.get("line")
    lines = fixture.lines(path) if path else None
    if not lines or type(line) is not int:
        return False
    target = distinctive(lines, line)
    return target is not None and target in text


def region_returned(text, fixture, location):
    """A line of the fixed region that occurs once in its file was returned."""
    lines = fixture.lines(location["path"]) or []
    counts = {}
    for line in lines:
        counts[line.strip()] = counts.get(line.strip(), 0) + 1
    return any(len(lines[i - 1].strip()) >= MIN_TEXT and counts[lines[i - 1].strip()] == 1
               and lines[i - 1].strip() in text
               for start, end in location["ranges"] for i in range(start, end + 1) if 0 < i <= len(lines))


def file_covered(text, fixture, path, share=0.5):
    """At least ``share`` of the file's distinctive lines were returned to the agent."""
    lines = {line.strip() for line in fixture.lines(path) or () if len(line.strip()) >= MIN_TEXT}
    return bool(lines) and sum(line in text for line in lines) / len(lines) >= share


class EvidenceGrounding:
    """Joins the outcome with what tools actually returned, independent of tool name.

    ``kind``: ``grounded_rate``, ``ungrounded_count``, ``fixed_region_returned``
    or ``scope_coverage`` (share of in-scope files at least half returned).
    """
    ref = a.VersionRef(name="security-review.evidence-grounding", revision="3")

    def __init__(self, fixtures):
        self.fixtures = Path(fixtures)

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
        evidence, text = trace.evidence()[:1], evidence_text(trace)
        fixture = Fixture(self.fixtures, context.unit["task_id"])
        if kind == "fixed_region_returned":
            covered = any(region_returned(text, fixture, loc) for loc in _truth(context)["locations"])
            return _row(context, run, spec, covered, "ok",
                        "Some completed tool call returned source text of the fixed region", evidence)
        if kind == "scope_coverage":
            scope = run_scope(run)
            covered = [path for path in scope if file_covered(text, fixture, path)]
            return _row(context, run, spec, len(covered) / len(scope) if scope else None,
                        "ok" if scope else "missing", f"{len(covered)} of {len(scope)} in-scope files returned", evidence)
        items = findings(run)
        if items is None:
            return _row(context, run, spec, None, "missing", "No structured review output")
        if not items:
            return _row(context, run, spec, None, "not_applicable", "No findings reported")
        ungrounded = [f for f in items if not grounded(text, fixture, f)]
        if kind == "ungrounded_count":
            return _row(context, run, spec, float(len(ungrounded)), "ok",
                        f"{len(ungrounded)} of {len(items)} findings cite code no completed tool call returned", evidence)
        return _row(context, run, spec, 1 - len(ungrounded) / len(items), "ok",
                    "Share of findings whose cited source line was returned by a completed tool call", evidence)


def run_scope(run):
    """In-scope paths from the retained review manifest of this run."""
    manifest = run.artifacts.get("review.manifest")
    if manifest is None:
        return ()
    return tuple(row["path"] for row in json.loads(local_path(manifest).read_text(encoding="utf-8"))["files"])
