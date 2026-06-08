#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_SYSTEM_PROMPT = """You are a firmware emulation inference engine.
Given facts JSON, decide:
1) best init candidates (ordered)
2) best web service candidates (ordered)
3) config hints
4) generate a safe init script content for firmware bootstrapping

Output MUST be strict JSON with keys:
- schema_version: string
- init_candidates: array of string
- service_candidates: array of objects {path, kind, score, reason}
- config_hints: object
- recommended_init_script: string
- confidence: number between 0 and 1
- reasoning_short: string
- fallback_required: boolean

Do not output markdown. JSON only.
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LLM inference layer for firmware boot/service selection.")
    p.add_argument("--facts", required=True, help="Input facts JSON path from collectFacts.py")
    p.add_argument("--output", required=True, help="Output llm inference JSON path")
    p.add_argument("--provider", default="mock", choices=["mock", "openai-compatible"], help="LLM provider")
    p.add_argument("--model", default="gpt-4.1", help="Model name for provider")
    p.add_argument("--base-url", default="https://api.v3.cm/v1", help="OpenAI-compatible base URL")
    p.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""), help="API key")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--temperature", type=float, default=0.1, help="Sampling temperature")
    p.add_argument("--max-output-tokens", type=int, default=1600, help="Max output tokens")
    p.add_argument("--confidence-threshold", type=float, default=0.6, help="Fallback threshold")
    p.add_argument("--pretty", action="store_true", help="Pretty-print output JSON")
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


def heuristic_pick_service(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    preferred = [
        "/etc/init.d/uhttpd",
        "/usr/sbin/uhttpd",
        "/usr/sbin/httpd",
        "/usr/bin/httpd",
        "/bin/httpd",
        "/usr/sbin/lighttpd",
        "/usr/sbin/nginx",
        "/bin/boa",
        "/usr/sbin/boa",
        "/bin/goahead",
        "/usr/sbin/goahead",
        "/bin/alphapd",
    ]
    candidates = facts.get("web_service_candidates", [])
    by_path = {c.get("path", ""): c for c in candidates if c.get("path")}
    ranked: List[Dict[str, Any]] = []

    for idx, path in enumerate(preferred):
        if path in by_path:
            c = by_path[path]
            score = max(0.5, 0.95 - idx * 0.03)
            ranked.append(
                {
                    "path": path,
                    "kind": c.get("kind", "binary_or_script"),
                    "score": round(score, 3),
                    "reason": "preferred_known_path",
                }
            )

    for c in candidates:
        path = c.get("path", "")
        if path and path not in {x["path"] for x in ranked}:
            ranked.append(
                {
                    "path": path,
                    "kind": c.get("kind", "binary_or_script"),
                    "score": 0.45,
                    "reason": c.get("source", "candidate"),
                }
            )
    return ranked[:20]


def heuristic_pick_init(facts: Dict[str, Any]) -> List[str]:
    candidates = facts.get("init_candidates", [])
    preferred_patterns = [
        r"/etc/init\.d/rcS$",
        r"/etc/rc\.d/rcS$",
        r"/init$",
        r"/sbin/init$",
        r"/preinit$",
        r"/firmadyne/preInit\.sh$",
    ]
    scored: List[Tuple[int, str]] = []
    for c in candidates:
        score = 100
        for i, pat in enumerate(preferred_patterns):
            if re.search(pat, c):
                score = i
                break
        scored.append((score, c))
    scored.sort(key=lambda x: (x[0], x[1]))
    return [c for _, c in scored][:20]


def build_init_script(init_candidates: List[str], service_candidates: List[Dict[str, Any]]) -> str:
    primary_init = init_candidates[0] if init_candidates else "/firmadyne/preInit.sh"
    service = service_candidates[0]["path"] if service_candidates else ""
    lines = [
        "#!/firmadyne/sh",
        "BUSYBOX=/firmadyne/busybox",
        "set +e",
        "",
        "# pre-flight mounts",
        "[ -d /proc ] || mkdir -p /proc",
        "[ -d /sys ] || mkdir -p /sys",
        "[ -d /dev ] || mkdir -p /dev",
        "${BUSYBOX} mount -t proc proc /proc 2>/dev/null || true",
        "${BUSYBOX} mount -t sysfs sysfs /sys 2>/dev/null || true",
        "",
        "# launch selected init candidate",
        f'if [ -x "{primary_init}" ] || [ -f "{primary_init}" ]; then',
        f'  "{primary_init}" &',
        "fi",
        "",
    ]
    if service:
        lines.extend(
            [
                "# launch selected web service candidate",
                f'if [ -x "{service}" ] || [ -f "{service}" ]; then',
                f'  "{service}" &',
                "fi",
                "",
            ]
        )
    lines.extend(
        [
            "# keep pid 1 helper alive",
            "${BUSYBOX} sleep 36000",
        ]
    )
    return "\n".join(lines) + "\n"


def mock_infer(facts: Dict[str, Any], threshold: float) -> Dict[str, Any]:
    init_candidates = heuristic_pick_init(facts)
    service_candidates = heuristic_pick_service(facts)
    confidence = 0.55
    if init_candidates and service_candidates:
        confidence = 0.82
    elif init_candidates:
        confidence = 0.68

    out = {
        "schema_version": "1.0",
        "init_candidates": init_candidates,
        "service_candidates": service_candidates,
        "config_hints": {
            "port_hints": facts.get("port_hints", []),
            "web_config_candidates": facts.get("web_config_candidates", []),
            "startup_script_hints": facts.get("startup_script_hints", [])[:30],
        },
        "recommended_init_script": build_init_script(init_candidates, service_candidates),
        "confidence": round(confidence, 3),
        "reasoning_short": "mock heuristic inference based on known path ranking and startup hints",
        "fallback_required": confidence < threshold,
    }
    return out


def openai_compatible_infer(args: argparse.Namespace, facts: Dict[str, Any], threshold: float) -> Dict[str, Any]:
    if not args.api_key:
        raise RuntimeError("API key missing. Set --api-key or OPENAI_API_KEY.")

    user_prompt = {
        "task": "Infer init and web service launch plan from firmware facts",
        "facts": facts,
        "constraints": {
            "safe_script_only": True,
            "no_destructive_commands": True,
            "prefer_existing_paths": True,
        },
    }

    payload = {
        "model": args.model,
        "temperature": args.temperature,
        "max_tokens": args.max_output_tokens,
        "messages": [
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_prompt, ensure_ascii=True)},
        ],
    }

    url = args.base_url.rstrip("/") + "/chat/completions"
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {args.api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {e.code}: {detail}") from e
    except Exception as e:
        raise RuntimeError(f"Request failed: {e}") from e

    data = json.loads(body)
    text = data["choices"][0]["message"]["content"]
    inferred = parse_json_from_text(text)
    inferred["fallback_required"] = bool(inferred.get("confidence", 0.0) < threshold)
    return inferred


def parse_json_from_text(text: str) -> Dict[str, Any]:
    text = text.strip()
    # direct JSON
    try:
        return json.loads(text)
    except Exception:
        pass

    # JSON block fallback
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("LLM response is not valid JSON")


def validate_output(obj: Dict[str, Any]) -> None:
    required_keys = [
        "schema_version",
        "init_candidates",
        "service_candidates",
        "config_hints",
        "recommended_init_script",
        "confidence",
        "reasoning_short",
        "fallback_required",
    ]
    for k in required_keys:
        if k not in obj:
            raise ValueError(f"missing key: {k}")
    if not isinstance(obj["init_candidates"], list):
        raise ValueError("init_candidates must be list")
    if not isinstance(obj["service_candidates"], list):
        raise ValueError("service_candidates must be list")
    if not isinstance(obj["config_hints"], dict):
        raise ValueError("config_hints must be object")
    if not isinstance(obj["recommended_init_script"], str):
        raise ValueError("recommended_init_script must be string")
    if not isinstance(obj["reasoning_short"], str):
        raise ValueError("reasoning_short must be string")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or conf < 0 or conf > 1:
        raise ValueError("confidence must be in [0,1]")
    if not isinstance(obj["fallback_required"], bool):
        raise ValueError("fallback_required must be boolean")


def main() -> int:
    args = parse_args()
    facts = read_json(args.facts)

    try:
        if args.provider == "mock":
            output = mock_infer(facts, args.confidence_threshold)
        else:
            output = openai_compatible_infer(args, facts, args.confidence_threshold)

        validate_output(output)
        write_json(args.output, output, args.pretty)
        print(os.path.abspath(args.output))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
