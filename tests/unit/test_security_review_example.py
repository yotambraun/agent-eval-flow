"""Offline checks for the security-review example's ground truth and grounding."""
from types import SimpleNamespace

import pytest

import agent_eval_flow as a
from agent_eval_flow.objects.tool_trace import ToolRequest
from examples.security_review.evaluators import (Fixture, evidence_text, file_covered, grounded, hits,
    region_returned, relative)
from examples.security_review.fetch import changed_lines
from examples.security_review.run_study import UNSAFE_SHELL, tool_contract


DIFF = """diff --git a/pkg/files.py b/pkg/files.py
--- a/pkg/files.py
+++ b/pkg/files.py
@@ -10,4 +10,5 @@ def f():
 a
-b = open(p)
+check(p)
+b = open(p)
 c
@@ -40,2 +41,3 @@
 x
+guard()
 y
diff --git a/docs/x.md b/docs/x.md
--- a/docs/x.md
+++ b/docs/x.md
@@ -1,2 +1,1 @@
 keep
-drop
"""


def test_changed_lines_include_modifications_insertions_and_deletions():
    changed = changed_lines(DIFF)
    assert changed["pkg/files.py"] == {"old": [[11, 11], [40, 41]], "new": [[11, 12], [42, 42]]}
    assert changed["docs/x.md"] == {"old": [[2, 2]], "new": [[1, 2]]}


@pytest.mark.parametrize("path,expected", [
    ("/tmp/w/abc/repo/pkg/files.py", "pkg/files.py"), ("repo/pkg/files.py", "pkg/files.py"),
    ("pkg/files.py", "pkg/files.py"), ("./.github/x.yml", ".github/x.yml"), ("/etc/passwd", None), (None, None),
])
def test_relative_paths(path, expected):
    assert relative(path) == expected


def test_detection_window_is_bounded_to_the_fixed_file():
    truth = {"locations": [{"path": "pkg/files.py", "ranges": [[40, 41]]}]}
    assert hits({"file": "/w/repo/pkg/files.py", "line": 51}, truth, 10)
    assert not hits({"file": "/w/repo/pkg/files.py", "line": 52}, truth, 10)
    assert not hits({"file": "/w/repo/pkg/other.py", "line": 40}, truth, 10)
    assert not hits({"file": "/w/repo/pkg/files.py", "line": "40"}, truth, 10)


def _fixture(tmp_path):
    source = ["import os", "", "def load(name):", "    return open(os.path.join(BASE, name)).read()", "}"]
    target = tmp_path / "t" / "files" / "pkg" / "files.py"
    target.parent.mkdir(parents=True)
    target.write_text("\n".join(source) + "\n")
    return Fixture(tmp_path, "t")


def test_grounding_needs_returned_source_text_from_any_tool(tmp_path):
    fixture = _fixture(tmp_path)
    finding = {"file": "/w/repo/pkg/files.py", "line": 4}
    read = "     4\t    return open(os.path.join(BASE, name)).read()"
    shell = "def load(name):\n    return open(os.path.join(BASE, name)).read()"
    assert grounded(read, fixture, finding) and grounded(shell, fixture, finding)
    assert not grounded("def load(name):", fixture, finding)
    # A generic line borrows its nearest distinctive neighbour.
    assert grounded(read, fixture, {"file": "pkg/files.py", "line": 5})
    assert not grounded(read, fixture, {"file": "pkg/other.py", "line": 4})


def test_only_completed_non_answer_calls_count_as_evidence():
    artifact = a.ArtifactRef(uri="/x", media_type="text/plain", sha256="0" * 64)
    ref = a.EvidenceRef(artifact=artifact)
    def call(tool, completion, result):
        return ToolRequest(call_id=tool + completion, execution_id="e", tool=tool, arguments={}, evidence=(ref,),
            completion=completion, result=result if completion != "unknown" else None,
            result_evidence=(ref,) if completion != "unknown" else ())
    trace = SimpleNamespace(calls=(call("Bash", "completed", [{"type": "text", "text": "seen"}]),
        call("Bash", "error", "denied text"), call("Read", "unknown", None),
        call("StructuredOutput", "completed", "answer text")))
    text = evidence_text(trace)
    assert "seen" in text and "denied" not in text and "answer" not in text


def test_fixed_region_and_scope_coverage(tmp_path):
    fixture = _fixture(tmp_path)
    text = "    return open(os.path.join(BASE, name)).read()"
    assert region_returned(text, fixture, {"path": "pkg/files.py", "ranges": [[4, 4]]})
    assert not region_returned(text, fixture, {"path": "pkg/files.py", "ranges": [[1, 3]]})
    assert file_covered(text, fixture, "pkg/files.py", share=0.5) is True
    assert not file_covered("", fixture, "pkg/files.py")


@pytest.mark.parametrize("command,unsafe", [
    ("ls -la repo", False), ("grep -rn open repo 2>/dev/null", False), ("git log --oneline", False),
    ("curl https://example.com", True), ("python repo/app.py", True), ("cat a > b", True),
    ("grep -n 'json_extract\\|->>' users.py", False), ("find / -name x.py", True), ("find . -name x.py", False),
    ("pip install x", True), ("sed -i s/a/b/ f", True),
    ("grep -rn load repo/python/ray/data/read_api.py", False), ("cd repo/python/ray; cat a.py", False),
    ("ls; python3 -c 'import ray'", True), ("find . | xargs python3 x.py", True), ("echo $(python -V)", True),
])
def test_unsafe_shell_policy(command, unsafe):
    import re
    assert bool(re.fullmatch(UNSAFE_SHELL, command)) is unsafe


def test_contract_requires_search_and_every_scope_file():
    contract = tool_contract({"task_id": "t", "scope": ["pkg/a.py", "pkg/b+c.py"]})
    assert contract["schema_version"] == "2" and contract["calls"][0] == {"tool": "Grep"}
    assert contract["calls"][-1] == {"tool": "StructuredOutput"}
    patterns = [call["args"]["file_path"]["$regex"] for call in contract["calls"][1:-1]]
    import re
    assert re.fullmatch(patterns[1], "/tmp/w/repo/pkg/b+c.py") and not re.fullmatch(patterns[1], "/tmp/w/repo/pkg/bbc.py")


def test_activity_end_never_precedes_start_after_clock_step(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from agent_eval_flow.evaluation import engine
    started = datetime.now(timezone.utc) + timedelta(seconds=30)  # the clock later steps back
    assert engine.activity_end(started) == started
    earlier = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert engine.activity_end(earlier) > earlier
