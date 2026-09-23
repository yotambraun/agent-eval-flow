"""Build hash-pinned review fixtures and ground truth from upstream fix commits.

For every advisory in ``cves.json`` this downloads the review scope at the
vulnerable commit (the fix's parent) and at the fix commit, and derives the
changed line ranges from the upstream diff itself:

- vulnerable variant: the reviewed ranges in ``cves.json``, each checked against
  the diff's removed lines (or, for a fix that only adds code, the two lines around
  the insertion point);
- patched variant: added lines in the post-fix file, or the deletion point.

Run: python -m examples.security_review.fetch --output <dir>
Writes <dir>/fixtures/<task_id>/{MANIFEST.json,files/...} and <dir>/dataset.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def get(url, attempts=4):
    for attempt in range(attempts):
        try:
            with urlopen(Request(url, headers={"User-Agent": "agent-eval-flow-security-review"}), timeout=60) as r:
                return r.read()
        except HTTPError as exc:
            if exc.code == 404:
                raise
            time.sleep(2 ** attempt)
        except OSError:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Could not fetch {url}")


def owner_repo(url):
    match = re.match(r"https://github\.com/([^/]+)/([^/.]+)", url)
    if not match:
        raise ValueError(f"Unsupported repository URL {url}")
    return match.group(1), match.group(2)


def ranges(lines):
    out = []
    for line in sorted(set(lines)):
        if out and line == out[-1][1] + 1:
            out[-1][1] = line
        else:
            out.append([line, line])
    return out


def changed_lines(diff_text):
    """Per file: old-side and new-side line ranges touched by the diff.

    A hunk that only inserts lines contributes the two old-side lines around its
    insertion point; a hunk that only deletes contributes the new-side point.
    """
    files, hunk, current = {}, None, None
    old = new = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current, hunk = None, None
        elif line.startswith("--- ") and hunk is None:
            continue
        elif line.startswith("+++ ") and hunk is None:
            path = line[4:]
            current = path[2:] if path.startswith("b/") else None
            if current is not None:
                files.setdefault(current, [])
        elif current is not None and (match := HUNK.match(line)):
            old, new = int(match.group(1)), int(match.group(3))
            hunk = {"old": [], "new": [], "old_anchor": None, "new_anchor": None}
            files[current].append(hunk)
        elif hunk is not None:
            if line.startswith("-"):
                hunk["old"].append(old)
                hunk["new_anchor"] = new if hunk["new_anchor"] is None else hunk["new_anchor"]
                old += 1
            elif line.startswith("+"):
                hunk["new"].append(new)
                hunk["old_anchor"] = old if hunk["old_anchor"] is None else hunk["old_anchor"]
                new += 1
            elif not line.startswith("\\"):
                old += 1
                new += 1
    result = {}
    for path, hunks in files.items():
        old_lines, new_lines = [], []
        for h in hunks:
            old_lines += h["old"] or [max(1, h["old_anchor"] - 1), h["old_anchor"]]
            new_lines += h["new"] or [max(1, h["new_anchor"] - 1), h["new_anchor"]]
        result[path] = {"old": ranges(old_lines), "new": ranges(new_lines)}
    return result


def task_id(advisory, variant):
    return hashlib.sha256(f"{advisory}:{variant}".encode()).hexdigest()[:12]


def build(cves, output):
    fixtures = output / "fixtures"
    units, truth_rows, report = [], [], []
    for cve in cves:
        owner, repo = owner_repo(cve["repo_url"])
        diff = get(f"https://github.com/{owner}/{repo}/commit/{cve['fix_commit']}.diff").decode("utf-8", "replace")
        changed = changed_lines(diff)
        truth_files = [f["path"] for f in cve["vulnerable_files"]]
        missing = [p for p in truth_files if p not in changed]
        if missing:
            report.append({"id": cve["id"], "error": f"fix diff does not touch {missing}"})
            continue
        for variant, commit, side in (("vulnerable", cve["vulnerable_commit"], "old"),
                                      ("patched", cve["fix_commit"], "new")):
            tid = task_id(cve["id"], variant)
            root = fixtures / tid
            rows = []
            for path in cve["review_scope"]:
                try:
                    data = get(f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{path}")
                except HTTPError:
                    continue  # File absent at this commit; the manifest records what exists.
                target = root / "files" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                rows.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                             "lines": data.count(b"\n") + 1})
            scope = [row["path"] for row in rows]
            if side == "old":
                # Reviewed ranges exclude import- or docstring-only edits; each must
                # overlap (within 2 lines) a region the upstream diff changed.
                locations = [{"path": f["path"], "ranges": f["vulnerable_line_ranges"]}
                             for f in cve["vulnerable_files"] if f["path"] in scope]
                for location in locations:
                    derived = changed[location["path"]]["old"]
                    for start, end in location["ranges"]:
                        if not any(start <= e + 2 and s - 2 <= end for s, e in derived):
                            raise ValueError(f"{cve['id']}: reviewed range {start}-{end} in "
                                             f"{location['path']} is not in the fix diff {derived}")
            else:
                locations = [{"path": p, "ranges": changed[p][side]} for p in truth_files
                             if p in scope and changed[p][side]]
            manifest = {"task_id": tid, "repository": f"{owner}/{repo}", "commit": commit, "files": rows}
            (root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            units.append({"task_id": tid, "scope": scope})
            truth_rows.append({"task_id": tid, "truth": {
                "advisory": cve["id"], "cve": cve.get("cve"), "project": cve["project"],
                "published": cve["published"], "cwe": cve.get("cwe"), "category": cve["category"],
                "variant": variant, "commit": commit, "locations": locations}})
        curated = {f["path"]: f.get("vulnerable_line_ranges") for f in cve["vulnerable_files"]}
        report.append({"id": cve["id"], "derived_old": {p: changed[p]["old"] for p in truth_files},
                       "curated": curated})
    dataset = {"units": units, "truth": truth_rows}
    (output / "dataset.json").write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    return dataset, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cves", type=Path, default=HERE / "cves.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cves = json.loads(args.cves.read_text(encoding="utf-8"))
    _, report = build(cves, args.output.resolve())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
