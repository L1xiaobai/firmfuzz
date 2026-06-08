#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List


REQUIRED_KEYS = [
    "schema_version",
    "init_candidates",
    "service_candidates",
    "config_hints",
    "recommended_init_script",
    "confidence",
    "reasoning_short",
    "fallback_required",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate LLM inference plan for firmware init generation.")
    p.add_argument("--llm-infer", required=True, help="Input llm_infer.json")
    p.add_argument("--output", required=True, help="Output validation result JSON")
    p.add_argument("--min-confidence", type=float, default=0.6, help="Minimum confidence threshold")
    p.add_argument("--strict", action="store_true", help="Enable stricter checks")
    p.add_argument("--pretty", action="store_true", help="Pretty-print output")
    return p.parse_args()


def read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, obj: Dict[str, Any], pretty: bool) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(obj, f, ensure_ascii=True, indent=2, sort_keys=True)
            f.write("\n")
        else:
            json.dump(obj, f, ensure_ascii=True)


def find_dangerous_patterns(script: str) -> List[str]:
    patterns = [
        r"rm\s+-rf\s+/",
        r"mkfs\.",
        r"\bdd\s+if=.*of=/dev/",
        r"\breboot\b",
        r"\bhalt\b",
        r"\bpoweroff\b",
        r"\bshutdown\b",
        r"\bmtd\b.*\b(write|erase)\b",
        r"\bflash_erase\b",
        r">\s*/dev/mtd",
        r"chmod\s+-R\s+777\s+/",
    ]
    hits: List[str] = []
    lowered = script.lower()
    for p in patterns:
        if re.search(p, lowered):
            hits.append(p)
    return hits


def find_suspicious_patterns(script: str) -> List[str]:
    patterns = [
        r"\bcurl\b.+\|\s*sh",
        r"\bwget\b.+\|\s*sh",
        r"\bpython\b.+-c",
        r"\bbusybox\s+nc\b",
        r"\btelnetd\b",
    ]
    hits: List[str] = []
    lowered = script.lower()
    for p in patterns:
        if re.search(p, lowered):
            hits.append(p)
    return hits


def validate_schema(obj: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for k in REQUIRED_KEYS:
        if k not in obj:
            errors.append(f"missing key: {k}")
    if errors:
        return errors

    if not isinstance(obj["init_candidates"], list):
        errors.append("init_candidates must be list")
    if not isinstance(obj["service_candidates"], list):
        errors.append("service_candidates must be list")
    if not isinstance(obj["config_hints"], dict):
        errors.append("config_hints must be object")
    if not isinstance(obj["recommended_init_script"], str):
        errors.append("recommended_init_script must be string")
    if not isinstance(obj["reasoning_short"], str):
        errors.append("reasoning_short must be string")
    if not isinstance(obj["fallback_required"], bool):
        errors.append("fallback_required must be bool")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or conf < 0.0 or conf > 1.0:
        errors.append("confidence must be [0,1]")
    return errors


def validate_paths(obj: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for p in obj.get("init_candidates", []):
        if not isinstance(p, str):
            errors.append("init candidate must be string")
            continue
        if not p.startswith("/"):
            errors.append(f"init candidate must be absolute fw path: {p}")
    for s in obj.get("service_candidates", []):
        if not isinstance(s, dict):
            errors.append("service candidate must be object")
            continue
        sp = s.get("path", "")
        if sp and not isinstance(sp, str):
            errors.append("service candidate path must be string")
        if isinstance(sp, str) and sp and not sp.startswith("/"):
            errors.append(f"service path must be absolute fw path: {sp}")
    return errors


def main() -> int:
    args = parse_args()
    obj = read_json(args.llm_infer)

    schema_errors = validate_schema(obj)
    path_errors = validate_paths(obj) if not schema_errors else []
    script = obj.get("recommended_init_script", "")
    dangerous_hits = find_dangerous_patterns(script) if isinstance(script, str) else ["non_string_script"]
    suspicious_hits = find_suspicious_patterns(script) if isinstance(script, str) else []

    confidence = float(obj.get("confidence", 0.0)) if not schema_errors else 0.0
    fallback_required = bool(obj.get("fallback_required", True)) if not schema_errors else True

    hard_fail_reasons: List[str] = []
    hard_fail_reasons.extend(schema_errors)
    hard_fail_reasons.extend(path_errors)
    if dangerous_hits:
        hard_fail_reasons.append("dangerous_script_pattern_detected")
    if confidence < args.min_confidence:
        hard_fail_reasons.append(f"low_confidence<{args.min_confidence}")
    if fallback_required:
        hard_fail_reasons.append("llm_requested_fallback")
    if args.strict and suspicious_hits:
        hard_fail_reasons.append("strict_mode_suspicious_pattern_detected")

    valid = len(hard_fail_reasons) == 0

    result = {
        "schema_version": "1.0",
        "input": os.path.abspath(args.llm_infer),
        "valid": valid,
        "should_fallback": not valid,
        "min_confidence": args.min_confidence,
        "confidence": confidence,
        "fallback_required_from_llm": fallback_required,
        "dangerous_pattern_hits": dangerous_hits,
        "suspicious_pattern_hits": suspicious_hits,
        "errors": hard_fail_reasons,
        "summary": "pass" if valid else "fallback",
    }

    write_json(args.output, result, args.pretty)
    print(os.path.abspath(args.output))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
