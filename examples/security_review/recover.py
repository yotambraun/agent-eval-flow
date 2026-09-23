"""Rebuild a captured RunSet from retained, hashed evidence; never re-executes agents.

Use when capture finished but the process died before saving (the pipeline
captures and grades in one call). Each run is rebuilt with the library's own
code: backend.prepare() recreates the request artifacts (no agent is started),
map_capture() and the scenario's finish() project the retained native stream.

Every link is checked, and anything unproven is excluded rather than guessed:
- receipt -> stream: sha256(run_id)[:16] names the run workspace recorded as the
  stream's init cwd, and the stream session id equals the receipt's native id;
- stream -> task: the advisory is identified from the in-scope paths the agent
  touched, and the variant from source lines that exist in only one variant
  and that tools actually returned; ties are unresolved;
- request -> receipt: the prepared argv must equal the retained argv exactly;
- each candidate x task cell must hold exactly ``repetitions`` runs.
Timing is approximate (stream file mtime and the native duration_ms) and is
declared in a per-run recovery note.

python -m examples.security_review.recover --data DIR --output OUT
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

import agent_eval_flow as a
from agent_eval_flow.adapters.process import NativeProcessCapture, StopEvidence
from agent_eval_flow.execution.capture import missing_run
from agent_eval_flow.execution.runner import allocate
from agent_eval_flow.objects.values import observed
from agent_eval_flow.pipeline.bindings import snapshot
from agent_eval_flow.pipeline.preflight import prepare_evaluation
from agent_eval_flow.storage.artifacts import ArtifactCache

from .evaluators import MIN_TEXT, returned_text
from .run_study import build_study, evaluators, make_backend


def stream_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def tool_results(rows):
    return "\n".join(returned_text(block.get("content")) for row in rows if row.get("type") == "user"
                     and isinstance(row.get("message"), dict) and isinstance(row["message"].get("content"), list)
                     for block in row["message"]["content"] if isinstance(block, dict) and block.get("type") == "tool_result")


NUMBERED = re.compile(r"(?m)^(?:[^\n:]*?:)?\s*(\d+)(?:\t|\u2192|:|-)(.*)$")


def numbered_lines(text):
    """(line number, stripped text) pairs from Read, grep -n and cat -n output."""
    return {(int(n), body.strip()) for n, body in NUMBERED.findall(text) if len(body.strip()) >= MIN_TEXT}


def fixture_numbered(data, task_id, scope):
    pairs = set()
    for path in scope:
        file = data / "fixtures" / task_id / "files" / path
        if file.is_file():
            pairs |= {(i, l.strip()) for i, l in enumerate(
                file.read_text(encoding="utf-8", errors="replace").splitlines(), 1) if len(l.strip()) >= MIN_TEXT}
    return pairs


def fixture_lines(data, task_id, scope):
    lines = set()
    for path in scope:
        file = data / "fixtures" / task_id / "files" / path
        if file.is_file():
            lines |= {l.strip() for l in file.read_text(encoding="utf-8", errors="replace").splitlines()
                      if len(l.strip()) >= MIN_TEXT}
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data, output = args.data.resolve(), args.output.resolve()
    saved = a.Study.load(output / "study")
    evidence = output / "evidence"
    cache = ArtifactCache(evidence)

    # Index streams by workspace hash and receipts by run id.
    streams, receipts = {}, {}
    for file in evidence.iterdir():
        head = file.open("rb").read(64)
        if head.startswith(b'{"type":"system","subtype":"init"'):
            init = json.loads(file.open(encoding="utf-8").readline())
            streams[Path(init["cwd"]).name.split("-")[0]] = (file, init)
        elif head.startswith(b"{") and b'"projection_issues"' in file.read_bytes()[:20000]:
            receipt = json.loads(file.read_text(encoding="utf-8"))
            receipts[receipt["run_id"]] = receipt

    dataset = json.loads((data / "dataset.json").read_text(encoding="utf-8"))
    truth = {row["task_id"]: row["truth"] for row in dataset["truth"]}
    scope = {u["task_id"]: u["scope"] for u in dataset["units"]}
    by_advisory = defaultdict(list)
    for task_id, t in truth.items():
        by_advisory[t["advisory"]].append(task_id)
    unique, unique_numbered = {}, {}
    for advisory, (first, second) in by_advisory.items():
        la, lb = fixture_lines(data, first, scope[first]), fixture_lines(data, second, scope[second])
        unique[first], unique[second] = la - lb, lb - la
        na, nb = fixture_numbered(data, first, scope[first]), fixture_numbered(data, second, scope[second])
        unique_numbered[first], unique_numbered[second] = na - nb, nb - na

    identified, problems = defaultdict(list), []
    for run_id, receipt in receipts.items():
        key = hashlib.sha256(run_id.encode()).hexdigest()[:16]
        if key not in streams:
            problems.append({"run_id": run_id, "problem": "no stream with this workspace"})
            continue
        file, init = streams[key]
        if init.get("session_id") != receipt.get("native_id"):
            problems.append({"run_id": run_id, "problem": "session id differs from receipt"})
            continue
        raw = file.read_text(encoding="utf-8")
        rows = stream_rows(file)
        # In-scope paths or their directories, however the agent addressed them
        # (absolute Read paths, or "cd repo/<dir>; cat file" in a shell).
        mentions = {adv: sum(raw.count(p) + raw.count(p.rsplit("/", 1)[0] + "/") + raw.count(p.rsplit("/", 1)[0] + ";")
                             + raw.count(p.rsplit("/", 1)[0] + " ") for p in scope[ids[0]] if "/" in p)
                    for adv, ids in by_advisory.items()}
        advisory = max(mentions, key=mentions.get)
        if sorted(mentions.values())[-1] == sorted(mentions.values())[-2]:
            problems.append({"run_id": run_id, "problem": "advisory ambiguous", "mentions": mentions})
            continue
        text = tool_results(rows)
        pairs = numbered_lines(text)
        scores = {task_id: sum(line in text for line in unique[task_id]) + len(pairs & unique_numbered[task_id])
                  for task_id in by_advisory[advisory]}
        (best, best_score), (_, other) = sorted(scores.items(), key=lambda kv: -kv[1])
        if best_score == other:
            problems.append({"run_id": run_id, "problem": "variant unresolved", "advisory": advisory, "scores": scores})
            continue
        candidate = next(c.id for c in saved.candidates.values() if c.settings["model"]["id"] == receipt["model"]["id"])
        identified[(candidate, best)].append((run_id, receipt, file, rows, scores))

    # Rebuild requests exactly as the executor would, then bind retained run ids.
    runtime = next(iter(receipts.values()))["runtime_revision"].split()[0]
    executable = next(iter(receipts.values()))["argv"][0]
    study, ref = build_study(data, [c.settings["model"]["id"] for c in saved.candidates.values()],
                             saved.execution.repetitions, runtime, executable)
    if study.fingerprint() != saved.fingerprint():
        raise SystemExit("Rebuilt study differs from the saved study; refusing to recover")
    backend = make_backend(ref, runtime, executable, output, data / "fixtures")
    bindings = snapshot({ref.name: backend}, None, evaluators(output, data / "fixtures"), None, None)
    execution = prepare_evaluation(saved, bindings, None).source
    allocated = allocate(execution)
    cells = defaultdict(list)
    for request in allocated.requests.values():
        cells[(request.candidate.id, request.assignment.unit["task_id"])].append(request)

    runs, notes, excluded = {}, [], []
    for cell, requests in cells.items():
        found = identified.get(cell, [])
        if len(found) > len(requests):
            problems.append({"cell": list(cell), "problem": f"{len(found)} runs identified for {len(requests)} assignments"})
            continue
        requests = sorted(requests, key=lambda r: r.assignment.id)
        for request in requests[len(found):]:
            # Captured, but which task it answered cannot be proven: not graded.
            runs[request.assignment.id] = missing_run(request.assignment, run_id=request.run_id,
                cost_scope=request.policy.cost_scope, reason="Recovered capture: a retained run could not be "
                "linked to this task from evidence alone; see recovery_report.json")
            excluded.append({"cell": list(cell), "assignment": request.assignment.id})
        for request, (run_id, receipt, file, rows, scores) in zip(requests, sorted(found, key=lambda f: f[0])):
            request = replace(request, run_id=run_id)
            prepared = backend.prepare(request)
            shutil.rmtree(prepared.launch.workspace, ignore_errors=True)
            if list(prepared.launch.argv) != list(receipt["argv"]):
                problems.append({"run_id": run_id, "problem": "prepared argv differs from retained argv"})
                continue
            stdout = cache.write_bytes("stdout", file.read_bytes(), "application/octet-stream")
            stderr = cache.write_bytes("stderr", b"", "application/octet-stream")
            result = next((r for r in rows if r.get("type") == "result"), {})
            ended = datetime.fromtimestamp(os.path.getmtime(file), timezone.utc)
            started = ended - timedelta(milliseconds=result.get("duration_ms") or 0)
            stop = StopEvidence(**{k: receipt["stop"][k] for k in ("requested", "confirmed", "reason")})
            capture = NativeProcessCapture(stdout=stdout, stderr=stderr, exit_code=receipt["exit_code"],
                started_at=started, ended_at=ended, stop=stop,
                output_complete=observed(True, "Recovered: retained stream ends with a terminal result")
                if result else observed(False, "Recovered: no terminal result in the retained stream"))
            native = backend.dialect.parse(capture)
            run = backend.map_capture(request, capture, native, prepared)
            if run.artifacts["native.receipt"].sha256 != hashlib.sha256(
                    json.dumps(receipt, ensure_ascii=False, allow_nan=False, indent=2).encode() + b"\n").hexdigest():
                notes.append({"run_id": run_id, "note": "receipt re-serialization differs; original retained below"})
            note = {"method": "examples.security_review.recover", "stream_sha256": stdout.sha256,
                    "variant_scores": scores, "timing": "approximate: stream mtime and native duration_ms",
                    "stderr": "not retained by link; recorded as empty"}
            recovery = cache.write_bytes("recovery.note", json.dumps(note, indent=2).encode(), "application/json")
            run = replace(run, artifacts={**run.artifacts, "recovery.note": recovery})
            run = backend.scenario.finish(request, prepared, run, cache)
            runs[request.assignment.id] = run
    unidentified = [p for p in problems if p.get("problem") in ("advisory ambiguous", "variant unresolved")]
    problems = [p for p in problems if p not in unidentified]
    report = {"receipts": len(receipts), "streams": len(streams),
              "recovered": len(runs) - len(excluded), "unobserved_assignments": excluded,
              "unidentified_runs": unidentified, "problems": problems, "notes": notes}
    (output / "recovery_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v if k != "problems" else v[:20] for k, v in report.items() if k != "notes"}, indent=2))
    if problems:
        raise SystemExit("Recovery incomplete; see recovery_report.json")
    runset = a.RunSet(id=allocated.run_set_id, plan=execution.plan, runs=tuple(
        runs[x.id] for x in execution.plan.assignments),
        grading_inventory_complete=observed(True, "No native grading was performed"))
    runset.save(output / "capture")
    print(json.dumps({"saved": str(output / "capture"), "runs": len(runset.runs)}))


if __name__ == "__main__":
    main()
