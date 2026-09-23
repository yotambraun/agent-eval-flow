"""Optional deterministic Toolscore evaluator with complete, retained receipts."""
from collections import Counter
from importlib import metadata
import json
import math
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .. import objects as o
from ..objects.identity import plain, semantic_fingerprint
from ..objects.tool_trace import trace_for_run, scoring_calls
from ..objects.values import zero_resources


SUPPORTED_VERSION = "1.8.1"
RECEIPT_TYPE = "application/vnd.agent-eval-flow.toolscore+json"
METRICS = ("score", "invocation_accuracy", "selection_accuracy", "argument_f1",
           "sequence_accuracy", "redundant_rate", "required_call_recall",
           "matched_call_recall", "forbidden_calls")
DEFAULT_WEIGHTS = {"selection_accuracy": 0.4, "argument_f1": 0.3,
                   "sequence_accuracy": 0.2, "redundant_rate": 0.1}
# Plain-JSON spellings of Toolscore matchers. A mapping whose only key is one of
# these is a matcher; every other mapping is a literal value.
MATCHERS = ("$any", "$regex", "$contains", "$one_of", "$type")
_TYPES = {"string": (str,), "number": (int, float), "integer": (int,), "boolean": (bool,),
          "object": (dict,), "array": (list, tuple), "null": (type(None),)}


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class _ExpectedCall(_Model):
    tool: str = Field(min_length=1)
    args: dict[str, o.JSONValue] | None = None


class _Contract(_Model):
    schema_version: Literal["1", "2"] = "1"
    id: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    calls: list[_ExpectedCall]
    alternatives: list[list[_ExpectedCall]] = Field(default_factory=list)
    # Version 2: argument matchers and calls that must never be requested.
    forbidden: list[_ExpectedCall] = Field(default_factory=list)


class _Request(_Model):
    metric: Literal[METRICS] = "score"
    reference_table: str = "tool_expectations"
    boundary: str = Field(min_length=1)
    strict: bool = True
    ordering: Literal["ordered", "unordered"] = "ordered"
    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))


def _load_toolscore():
    try:
        version = metadata.version("tool-scorer")
    except metadata.PackageNotFoundError as exc:
        raise ImportError("Install agent-eval-flow[toolscore] to score tool traces") from exc
    if version != SUPPORTED_VERSION:
        raise ImportError(f"Unsupported tool-scorer {version}; this adapter requires {SUPPORTED_VERSION}")
    import toolscore
    return toolscore


def _matcher_key(value):
    if isinstance(value, dict) and len(value) == 1:
        key = next(iter(value))
        if key.startswith("$"):
            if key not in MATCHERS:
                raise ValueError(f"Unknown argument matcher {key}; use one of {', '.join(MATCHERS)}")
            return key
    return None


def _check_matchers(value, version):
    """Reject matchers in version 1 contracts and malformed matcher operands."""
    key = _matcher_key(value)
    if key is not None:
        if version == "1":
            raise ValueError("Argument matchers require contract schema_version '2'")
        operand = value[key]
        if key == "$any" and operand is not True:
            raise ValueError("$any takes true")
        if key == "$regex":
            if not isinstance(operand, str):
                raise ValueError("$regex takes a pattern string")
            try:
                re.compile(operand)
            except re.error as exc:
                raise ValueError(f"Invalid $regex: {exc}") from exc
        if key == "$one_of" and (not isinstance(operand, list) or not operand):
            raise ValueError("$one_of takes a non-empty list")
        if key == "$type" and operand not in _TYPES:
            raise ValueError(f"$type takes one of {', '.join(_TYPES)}")
        if key in ("$contains", "$one_of"):
            _check_matchers(operand, version)
    elif isinstance(value, dict):
        for item in value.values():
            _check_matchers(item, version)
    elif isinstance(value, list):
        for item in value:
            _check_matchers(item, version)


def _decode(value, toolscore):
    """Plain JSON contract values to Toolscore matcher objects, recursively."""
    key = _matcher_key(value)
    if key == "$any":
        return toolscore.ANY
    if key == "$regex":
        return toolscore.Regex(value[key])
    if key == "$contains":
        return toolscore.Contains(_decode(value[key], toolscore))
    if key == "$one_of":
        return toolscore.OneOf(*(_decode(item, toolscore) for item in value[key]))
    if key == "$type":
        return _json_type(toolscore, value[key])
    if isinstance(value, dict):
        return {k: _decode(v, toolscore) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v, toolscore) for v in value]
    return value


def _json_type(toolscore, name):
    class JSONType(toolscore.Matcher):
        def matches(self, value):
            # bool is an int in Python; JSON numbers must not accept booleans.
            if isinstance(value, bool) and name != "boolean":
                return False
            return isinstance(value, _TYPES[name])

        def __repr__(self):
            return f"JSONType({name!r})"
    return JSONType()


def _value_matches(expected, actual):
    """Strict, type-exact comparison; decoded matchers decide their own values."""
    if hasattr(expected, "matches"):
        return expected.matches(actual)
    if isinstance(expected, dict):
        return isinstance(actual, dict) and set(expected) == set(actual) and all(
            _value_matches(expected[k], actual[k]) for k in expected)
    if isinstance(expected, list):
        return isinstance(actual, (list, tuple)) and len(expected) == len(actual) and all(
            _value_matches(e, a) for e, a in zip(expected, actual))
    return type(expected) is type(actual) and expected == actual


def _call_matches(expected, actual):
    """A call pattern matches when the name is equal and every declared argument
    matches. Undeclared (None) arguments match any; declared keys are a subset."""
    if expected["tool"] != actual["tool"]:
        return False
    if expected.get("args") is None:
        return True
    args = actual.get("args") or {}
    return all(key in args and _value_matches(value, args[key]) for key, value in expected["args"].items())


def _matched_recall(expected, actual):
    """Maximum one-to-one assignment of actual requests to expected calls."""
    owner = {}

    def assign(i, seen):
        for j, call in enumerate(actual):
            if j in seen or not _call_matches(expected[i], call):
                continue
            seen.add(j)
            if j not in owner or assign(owner[j], seen):
                owner[j] = i
                return True
        return False

    matched = sum(assign(i, set()) for i in range(len(expected)))
    return matched, [i for i in range(len(expected)) if i not in owner.values()]


def _json_safe(value):
    """Upstream metrics can echo decoded matchers; retain them by description."""
    if hasattr(value, "matches"):
        return {"$matcher": repr(value)}
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _settings(request):
    weights = dict(request.weights)
    if set(weights) != set(DEFAULT_WEIGHTS):
        raise ValueError("Provide all four Toolscore weight names explicitly")
    if any(not math.isfinite(v) or v < 0 for v in weights.values()):
        raise ValueError("Weights must be finite and nonnegative")
    if request.ordering == "unordered":
        weights["sequence_accuracy"] = 0.0
    total = sum(weights.values())
    if total <= 0:
        raise ValueError("Applicable weights must sum to a positive value")
    return {key: value / total for key, value in weights.items()}


def _ordered(calls, ordering):
    if ordering == "ordered":
        return calls
    # Deterministic canonical ordering, retaining multiplicity. This is not
    # dependency-graph matching or a claim of optimal repeated-call alignment.
    return sorted(calls, key=lambda c: (c["tool"], json.dumps(c.get("args"), sort_keys=True, ensure_ascii=False)))


def _score(toolscore, expected, actual, request, weights, forbidden=()):
    decoded = [dict(call, args=_decode(call.get("args"), toolscore))
               for call in _ordered(expected, request.ordering)]
    result = toolscore.evaluate(expected=decoded, actual=_ordered(actual, request.ordering),
        weights=weights, strict=request.strict)
    values = {"score": float(result.score), "invocation_accuracy": float(result.metrics["invocation_accuracy"]),
        "selection_accuracy": float(result.selection_accuracy), "argument_f1": float(result.argument_f1),
        "sequence_accuracy": float(result.sequence_accuracy),
        "redundant_rate": float(result.metrics["efficiency_metrics"]["redundant_rate"])}
    needed, used = Counter(c["tool"] for c in expected), Counter(c["tool"] for c in actual)
    values["required_call_recall"] = sum((needed & used).values()) / len(expected) if expected else None
    # Argument-aware, one-to-one: a repeated or look-alike request cannot satisfy
    # two expectations, and arguments must match, unlike name-only recall.
    matched, unmatched = _matched_recall([dict(c, args=_decode(c.get("args"), toolscore)) for c in expected], actual)
    values["matched_call_recall"] = matched / len(expected) if expected else None
    patterns = [dict(c, args=_decode(c.get("args"), toolscore)) for c in forbidden]
    violations = [index for index, call in enumerate(actual) if any(_call_matches(p, call) for p in patterns)]
    values["forbidden_calls"] = float(len(violations))
    statuses = {name: "ok" if value is not None else "not_applicable" for name, value in values.items()}
    reasons = {}
    if not expected:
        reasons["required_call_recall"] = "No required tool calls in this contract"
        reasons["matched_call_recall"] = "No required tool calls in this contract"
    if not forbidden:
        reasons["forbidden_calls"] = "No forbidden calls declared; zero is vacuous"
    if not expected and not actual:
        # Upstream gives argument F1 zero here. Keep its raw score, but do not
        # grade an intentionally empty trace with an argument-weighted composite.
        for name in ("score", "argument_f1"):
            values[name], statuses[name] = None, "not_applicable"
            reasons[name] = "No calls expected or observed; invocation accuracy establishes correct no-tool behavior"
    if request.ordering == "unordered":
        values["sequence_accuracy"], statuses["sequence_accuracy"] = None, "not_applicable"
        reasons["sequence_accuracy"] = "Contract ignores call order; sequence has zero weight"
    return {"values": values, "statuses": statuses, "reasons": reasons,
            "raw_score": float(result.score), "raw_metrics": _json_safe(result.metrics),
            "unmatched_expected": unmatched, "forbidden_violations": violations}


class ToolscoreEvaluator:
    """Score an explicitly scoped trace and retain a source-linked JSON receipt.

    All native calls remain in their original order in the receipt. Unordered
    scoring uses canonical sorting and zero sequence weight. Predeclared
    alternative traces are evaluated in full; highest native score wins, with
    ties resolved by declaration order. No model, server, or side-effect checker
    is invoked. Other outcome checks remain independent.
    """
    ref = o.VersionRef(name="agent-eval-flow.toolscore", revision="1+tool-scorer.1.8.1")

    def __init__(self, *, artifacts):
        self.artifacts = artifacts

    def compute(self, spec, context, run):
        evidence = []
        receipt = {"schema_version": "1", "kind": "agent-eval-flow.toolscore", "run_id": run.id,
            "assignment_id": run.assignment_id, "run_fingerprint": run.fingerprint(),
            "unit": plain(context.unit), "evaluator": plain(self.ref), "toolscore_version": None,
            "required_toolscore_version": SUPPORTED_VERSION,
            "settings": {k: plain(v) for k, v in spec.params.items() if k != "metric"}, "trace": None, "contract": None,
            "metrics": {}, "status": "missing", "reason": "No complete tool evidence", "resources": {
                "tool_duration_s": None, "tool_cost_usd": None,
                "reason": "Per-tool timing and cost are not measured by this adapter"}}
        selected_metric = spec.params.get("metric", "score")
        try:
            if spec.output_type != "float":
                raise ValueError("Toolscore metrics require output_type='float'")
            request = _Request.model_validate(plain(spec.params))
            if not request.boundary.strip() or not request.reference_table.strip():
                raise ValueError("Boundary and reference table must not be blank")
            weights = _settings(request)
            receipt["settings"] = {**request.model_dump(exclude={"metric"}), "weights": weights}
            trace = trace_for_run(run, request.boundary)
            if trace is not None:
                receipt["trace"] = plain(trace)
                evidence.extend(trace.evidence())
            references = context.references.get(request.reference_table, ())
            if len(references) > 1:
                raise ValueError("Expected exactly one tool contract row for this task")
            contract = None
            if references:
                receipt["contract_input"] = plain(references[0].get("contract"))
                contract = _Contract.model_validate(receipt["contract_input"])
                if not contract.id.strip() or not contract.revision.strip():
                    raise ValueError("Contract identity must not be blank")
                choices = [contract.calls, *contract.alternatives]
                if any(not call.tool.strip() for calls in (*choices, contract.forbidden) for call in calls):
                    raise ValueError("Expected tool names must not be blank")
                if contract.forbidden and contract.schema_version == "1":
                    raise ValueError("Forbidden calls require contract schema_version '2'")
                for calls in (*choices, contract.forbidden):
                    for call in calls:
                        _check_matchers(call.args, contract.schema_version)
                receipt["contract"] = contract.model_dump()
                receipt["contract_fingerprint"] = semantic_fingerprint("tool-contract", receipt["contract"])
            if trace is None:
                receipt["reason"] = "No versioned tool trace for this boundary; absence is not an empty trace"
            elif contract is None:
                receipt["reason"] = "No expected tool contract for this task"
            else:
                actual = scoring_calls(trace)  # Invalid captured args never become {}.
                if trace.coverage.status != "observed" or trace.coverage.value is not True:
                    receipt["reason"] = "Tool request coverage is partial or unknown: " + trace.coverage.reason
                else:
                    toolscore = _load_toolscore()
                    receipt["toolscore_version"] = SUPPORTED_VERSION
                    alternatives = []
                    for calls in choices:
                        expected = [call.model_dump() for call in calls]
                        scored = _score(toolscore, expected, actual, request, weights,
                                        [call.model_dump() for call in contract.forbidden])
                        alternatives.append({"expected": expected, **scored})
                    # A deliberately empty matching alternative wins over an
                    # inapplicable native composite, without changing raw values.
                    index = max(range(len(alternatives)), key=lambda i: (
                        1.0 if not alternatives[i]["expected"] and not actual else alternatives[i]["raw_score"]))
                    selected = alternatives[index]
                    receipt.update(status="ok", reason="Scored captured requests against the declared tool contract; "
                        "completion and task success are separate evidence", selected_alternative=index,
                        alternatives=alternatives, actual=actual)
                    receipt["metrics"] = {name: {"value": selected["values"][name],
                        "status": selected["statuses"][name], "reason": selected["reasons"].get(name, receipt["reason"])}
                        for name in METRICS}
                    receipt["executions"] = [{"id": ex.id, "parent_id": ex.parent_id,
                        "retry_index": ex.retry_index, "role": ex.role} for ex in run.executions]
        except (ValueError, KeyError, TypeError, ImportError) as exc:
            receipt["status"], receipt["reason"] = "error", f"Toolscore evaluation: {exc}"
        payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")
        artifact = self.artifacts.write_bytes("toolscore-receipt", payload, RECEIPT_TYPE)
        evidence.append(o.EvidenceRef(artifact=artifact, description="Toolscore evaluation receipt"))
        metric = receipt["metrics"].get(selected_metric, {"status": receipt["status"],
            "value": None, "reason": receipt["reason"]})
        row = o.Measurement(run_id=run.id, metric=spec.id, value=metric["value"], status=metric["status"],
            basis="observed" if metric["status"] == "ok" else None, reason=metric["reason"],
            evidence=tuple(dict.fromkeys(evidence)))
        return o.MetricOutput(task=row, evaluation_resources=zero_resources(context.evaluation_cost_scope))


def toolscore_metrics(*, boundary, reference_table="tool_expectations", prefix="tools", **settings):
    """Ordinary diagnostic specs; opt into acceptance gates separately."""
    return tuple(o.MetricSpec(id=f"{prefix}.{metric}", source=o.EvaluatorSource(ref=ToolscoreEvaluator.ref),
        output_type="float", role="diagnostic", params={"metric": metric, "boundary": boundary,
            "reference_table": reference_table, **settings}) for metric in METRICS)
