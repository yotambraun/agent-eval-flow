"""Offline checks for the security-review example's ground truth and grounding."""
from types import SimpleNamespace

import pytest

import agent_eval_flow as a
from agent_eval_flow.objects.tool_trace import ToolRequest
from examples.security_review.evaluators import grounded, hits, relative
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


def _call(tool, arguments, result="", completion="completed"):
    artifact = a.ArtifactRef(uri="/x", media_type="text/plain", sha256="0" * 64)
    ref = a.EvidenceRef(artifact=artifact)
    return ToolRequest(call_id=tool + str(id(arguments)), execution_id="e", tool=tool, arguments=arguments,
        evidence=(ref,), completion=completion, result=result if completion != "unknown" else None,
        result_evidence=(ref,) if completion != "unknown" else ())


def test_grounding_requires_a_completed_call_that_returned_the_line():
    finding = {"file": "pkg/files.py", "line": 120}
    read_head = _call("Read", {"file_path": "/w/repo/pkg/files.py", "limit": 100})
    assert not grounded(SimpleNamespace(calls=(read_head,)), finding)
    read_window = _call("Read", {"file_path": "/w/repo/pkg/files.py", "offset": 100, "limit": 50})
    assert grounded(SimpleNamespace(calls=(read_window,)), finding)
    unfinished = _call("Read", {"file_path": "/w/repo/pkg/files.py"}, completion="unknown")
    assert not grounded(SimpleNamespace(calls=(unfinished,)), finding)
    grep = _call("Grep", {"pattern": "open"}, result="repo/pkg/files.py:120:    return open(p)")
    assert grounded(SimpleNamespace(calls=(grep,)), finding)
    scoped = _call("Grep", {"pattern": "open", "path": "/w/repo/pkg/files.py"}, result="120:    return open(p)")
    assert grounded(SimpleNamespace(calls=(scoped,)), finding)
    other = _call("Grep", {"pattern": "open"}, result="repo/pkg/files.py:1200:    x")
    assert not grounded(SimpleNamespace(calls=(other,)), finding)


@pytest.mark.parametrize("command,unsafe", [
    ("ls -la repo", False), ("grep -rn open repo 2>/dev/null", False), ("git log --oneline", False),
    ("curl https://example.com", True), ("python repo/app.py", True), ("cat a > b", True),
    ("pip install x", True), ("sed -i s/a/b/ f", True),
])
def test_unsafe_shell_policy(command, unsafe):
    import re
    assert bool(re.fullmatch(UNSAFE_SHELL, command)) is unsafe


def test_contract_requires_search_and_every_scope_file():
    contract = tool_contract({"task_id": "t", "scope": ["pkg/a.py", "pkg/b+c.py"]})
    assert contract["schema_version"] == "2" and contract["calls"][0] == {"tool": "Grep"}
    patterns = [call["args"]["file_path"]["$regex"] for call in contract["calls"][1:]]
    import re
    assert re.fullmatch(patterns[1], "/tmp/w/repo/pkg/b+c.py") and not re.fullmatch(patterns[1], "/tmp/w/repo/pkg/bbc.py")
