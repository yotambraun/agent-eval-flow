"""Stage pinned source snapshots for a read-only security review; attach tool traces.

The agent sees only the source files of one review scope, at one pinned commit,
under ``repo/``. It never sees version-control history, advisory text, which
variant it received, or the expected answer. After capture, the retained Claude
stream is projected into a versioned tool trace for Toolscore.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import agent_eval_flow as a
from agent_eval_flow.adapters.cli import local_path
from agent_eval_flow.adapters.common import contained_relative
from agent_eval_flow.adapters.tool_trace import claude_stream_tool_trace
from agent_eval_flow.objects.values import observed, unknown

BOUNDARY = "claude.main.requests"
HERE = Path(__file__).resolve().parent

# Adapted from the three-phase methodology of anthropics/claude-code-security-review
# (context research, comparative analysis, vulnerability assessment), applied to a
# fixed file scope instead of a pull-request diff. Exploit write-ups are not requested.
MISSION = """You are a senior application security engineer performing a read-only
security review of the source files listed in the public task input. The files are
under ./repo/ in your working directory, at their repository-relative paths.

Method:
1. Context research: search the code to understand frameworks, trust boundaries,
   and existing validation or sanitization patterns.
2. Comparative analysis: look for places that deviate from the project's own safe
   patterns or introduce new attack surface.
3. Vulnerability assessment: examine every in-scope file. Trace data from external
   input (requests, files, user-supplied configuration) to sensitive operations
   (filesystem paths, network requests, queries, commands, deserialization,
   templates, authorization decisions).

Report only concrete, high-confidence vulnerabilities (confidence >= 0.8). Do not
report denial of service, resource exhaustion, rate limiting, secrets on disk, or
missing hardening without a concrete security impact. It is acceptable and expected
to report no findings when the code is safe.

For each finding give the repository-relative file path and the line number of the
vulnerable operation. Base every finding on code you have actually read in this
review. Do not modify files, execute project code, install packages, or access the
network. Return your result in the required JSON structure."""

CATEGORIES = ("path_traversal", "ssrf", "sql_injection", "command_injection", "code_injection",
              "deserialization", "auth_bypass", "template_injection", "open_redirect", "xss", "other")

RESPONSE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["findings", "analysis_summary"],
    "properties": {
        "findings": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["file", "line", "severity", "category", "description", "recommendation", "confidence"],
            "properties": {
                "file": {"type": "string"}, "line": {"type": "integer", "minimum": 1},
                "severity": {"enum": ["HIGH", "MEDIUM", "LOW"]}, "category": {"enum": list(CATEGORIES)},
                "description": {"type": "string"}, "recommendation": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1}}}},
        "analysis_summary": {"type": "object", "additionalProperties": False,
            "required": ["files_reviewed", "review_completed"],
            "properties": {"files_reviewed": {"type": "integer", "minimum": 0},
                           "review_completed": {"type": "boolean"}}}},
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class SecurityReviewScenario:
    """Stage one pinned, hash-verified review scope per run."""
    accepted_settings = frozenset({"runtime_revision", "executable"})

    def __init__(self, fixtures: Path):
        self.fixtures = Path(fixtures).resolve()

    def prepare(self, request, workspace, cache):
        unit = request.input.tables["units"][0]
        fixture = contained_relative(self.fixtures, unit["task_id"])
        manifest_bytes = (fixture / "MANIFEST.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        repo = workspace / "repo"
        for row in manifest["files"]:
            data = contained_relative(fixture / "files", row["path"]).read_bytes()
            if _sha(data) != row["sha256"]:
                raise a.ConfigurationError(f"Fixture bytes changed: {unit['task_id']}/{row['path']}")
            if row["path"] not in unit["scope"]:
                raise a.ConfigurationError("Fixture file outside the declared public scope")
            target = contained_relative(repo, row["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return {"mission": "Files in scope are staged under ./repo/.",
                "artifacts": {"review.manifest": cache.write_bytes("review.manifest", manifest_bytes, "application/json")}}

    def finish(self, request, prepared, run, cache):
        """Project the retained stream; claim completeness only with evidence."""
        stream = run.artifacts.get("native.trace")
        receipt = run.artifacts.get("native.receipt")
        if stream is None or receipt is None:
            return run
        argv = json.loads(local_path(receipt).read_text(encoding="utf-8"))["argv"]
        tools = argv[argv.index("--tools") + 1].split(",") if "--tools" in argv else None
        evidence = (a.EvidenceRef(artifact=receipt, description="Invocation argv: tool set and isolation"),)
        if run.status != "completed":
            coverage = unknown(f"Run ended with {run.status}; trailing requests may be missing")
        elif tools is None or "Task" in tools or "Agent" in tools:
            coverage = unknown("Subagent tools were available; nested requests are outside this stream")
        else:
            coverage = observed(True, "Terminal result retained and no subagent tool available "
                                f"(tools={','.join(tools)}); every request is in the main stream", evidence)
        execution_id = run.id + "/native"
        try:
            trace = claude_stream_tool_trace(local_path(stream).read_bytes(), artifact=stream,
                execution_id=execution_id, boundary=BOUNDARY, coverage=coverage)
        except (ValueError, KeyError, TypeError) as exc:
            note = cache.write_bytes("trace.projection-error", str(exc).encode("utf-8"), "text/plain")
            return replace(run, artifacts={**run.artifacts, "trace.projection_error": note})
        event = trace.to_event(id=run.id + "/tool-trace", execution_id=execution_id)
        return replace(run, events=(*run.events, event))
