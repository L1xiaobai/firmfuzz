#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Set, Tuple


WEB_BIN_CANDIDATES = [
    "/usr/sbin/uhttpd",
    "/etc/init.d/uhttpd",
    "/usr/bin/httpd",
    "/usr/sbin/httpd",
    "/bin/httpd",
    "/bin/boa",
    "/usr/sbin/boa",
    "/bin/goahead",
    "/usr/sbin/goahead",
    "/bin/alphapd",
    "/usr/sbin/lighttpd",
    "/usr/sbin/nginx",
]

WEB_CONFIG_CANDIDATES = [
    "/etc/config/uhttpd",
    "/etc/uhttpd.conf",
    "/etc/lighttpd/lighttpd.conf",
    "/etc/boa/boa.conf",
    "/etc/boa.conf",
    "/etc/nginx/nginx.conf",
    "/etc/httpd.conf",
]

INIT_NAME_CANDIDATES = {"preinit", "preinitMT", "rcS"}

PORT_REGEX = re.compile(r"(?:^|[^0-9])(80|81|443|8080|8443)(?:[^0-9]|$)")
INIT_REGEX = re.compile(r"(^|[ \"'])init=/[^ \"']+")


def to_host_path(rootfs: str, fw_path: str) -> str:
    if fw_path.startswith("/"):
        fw_path = fw_path[1:]
    return os.path.join(rootfs, fw_path)


def fw_from_host(rootfs: str, host_path: str) -> str:
    rel = os.path.relpath(host_path, rootfs).replace("\\", "/")
    if rel == ".":
        return "/"
    return "/" + rel


def file_exists(rootfs: str, fw_path: str) -> bool:
    return os.path.exists(to_host_path(rootfs, fw_path))


def safe_read_text(path: str, limit: int = 1024 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def gather_kernel_init_hints(rootfs: str) -> List[str]:
    hints: List[str] = []
    kernel_init = to_host_path(rootfs, "kernelInit")
    if not os.path.exists(kernel_init):
        return hints

    data = safe_read_text(kernel_init)
    for token in data.split():
        if token.startswith("init=/"):
            hints.append(token[len("init="):])

    # keep order + dedup
    seen: Set[str] = set()
    out: List[str] = []
    for x in hints:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def gather_init_candidates(rootfs: str) -> List[str]:
    candidates: List[str] = []
    candidates.extend(gather_kernel_init_hints(rootfs))

    if file_exists(rootfs, "/init") and not os.path.isdir(to_host_path(rootfs, "/init")):
        candidates.append("/init")

    for dirpath, _, filenames in os.walk(rootfs):
        for name in filenames:
            if name in INIT_NAME_CANDIDATES:
                candidates.append(fw_from_host(rootfs, os.path.join(dirpath, name)))

    # default fallback used by existing pipeline
    candidates.append("/firmadyne/preInit.sh")

    seen: Set[str] = set()
    out: List[str] = []
    for c in candidates:
        c = c.strip()
        if not c:
            continue
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def gather_web_binaries(rootfs: str) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for fw_path in WEB_BIN_CANDIDATES:
        host = to_host_path(rootfs, fw_path)
        if os.path.exists(host):
            kind = "script_or_init" if fw_path.startswith("/etc/init.d/") else "binary"
            if fw_path not in seen:
                seen.add(fw_path)
                found.append({"path": fw_path, "kind": kind, "source": "known_path"})

    # fallback keyword scan for files named as common web services
    names = {"httpd", "uhttpd", "boa", "goahead", "lighttpd", "nginx", "alphapd"}
    for dirpath, _, filenames in os.walk(rootfs):
        for name in filenames:
            if name not in names:
                continue
            fw_path = fw_from_host(rootfs, os.path.join(dirpath, name))
            if fw_path not in seen:
                seen.add(fw_path)
                found.append({"path": fw_path, "kind": "binary_or_script", "source": "name_scan"})

    return found


def gather_web_configs(rootfs: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for fw_path in WEB_CONFIG_CANDIDATES:
        if file_exists(rootfs, fw_path) and fw_path not in seen:
            seen.add(fw_path)
            out.append(fw_path)
    return out


def gather_port_hints(rootfs: str, config_paths: List[str]) -> List[int]:
    ports: Set[int] = set()
    for fw_path in config_paths:
        host = to_host_path(rootfs, fw_path)
        data = safe_read_text(host)
        for m in PORT_REGEX.finditer(data):
            try:
                ports.add(int(m.group(1)))
            except Exception:
                continue
    return sorted(list(ports))


def gather_startup_script_hints(rootfs: str) -> List[str]:
    hints: List[str] = []
    for dirpath, _, filenames in os.walk(rootfs):
        for name in filenames:
            if not (name.endswith(".sh") or name in {"rcS", "preinit", "preinitMT"}):
                continue
            host = os.path.join(dirpath, name)
            text = safe_read_text(host, limit=256 * 1024)
            if not text:
                continue
            if any(k in text for k in ["httpd", "uhttpd", "boa", "goahead", "lighttpd", "nginx", "alphapd", "init="]):
                hints.append(fw_from_host(rootfs, host))
    hints.sort()
    return hints[:200]


def gather_kernel_cmd_hints(work_dir: str) -> List[str]:
    path = os.path.join(work_dir, "kernelCmd")
    if not os.path.exists(path):
        return []
    data = safe_read_text(path)
    out: List[str] = []
    for line in data.splitlines():
        if INIT_REGEX.search(line):
            out.append(line.strip())
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect firmware facts for LLM-assisted boot/service inference.")
    p.add_argument("--iid", type=int, help="Image ID. Uses scratch/<iid>/image as rootfs by default.")
    p.add_argument("--rootfs", help="Mounted rootfs directory to scan.")
    p.add_argument("--work-dir", default=".", help="Project root containing scratch/ (default: current dir).")
    p.add_argument("--output", help="Output JSON path. Default: scratch/<iid>/facts.json if --iid else ./facts.json")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return p.parse_args()


def resolve_paths(args: argparse.Namespace) -> Tuple[str, str, str]:
    base = os.path.abspath(args.work_dir)
    iid = args.iid
    rootfs = args.rootfs
    if rootfs:
        rootfs = os.path.abspath(rootfs)
    elif iid is not None:
        rootfs = os.path.join(base, "scratch", str(iid), "image")
    else:
        raise ValueError("Either --rootfs or --iid must be provided.")

    if iid is not None:
        work = os.path.join(base, "scratch", str(iid))
        default_output = os.path.join(work, "facts.json")
    else:
        work = base
        default_output = os.path.join(base, "facts.json")

    output = os.path.abspath(args.output) if args.output else default_output
    return rootfs, work, output


def main() -> int:
    args = parse_args()
    try:
        rootfs, work_dir, output = resolve_paths(args)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if not os.path.isdir(rootfs):
        print(f"Error: rootfs directory not found: {rootfs}", file=sys.stderr)
        return 2

    init_candidates = gather_init_candidates(rootfs)
    web_bins = gather_web_binaries(rootfs)
    web_cfgs = gather_web_configs(rootfs)
    port_hints = gather_port_hints(rootfs, web_cfgs)
    startup_hints = gather_startup_script_hints(rootfs)
    kernel_cmd_hints = gather_kernel_cmd_hints(work_dir)

    facts = {
        "schema_version": "1.0",
        "rootfs": rootfs,
        "work_dir": work_dir,
        "iid": args.iid,
        "init_candidates": init_candidates,
        "web_service_candidates": web_bins,
        "web_config_candidates": web_cfgs,
        "port_hints": port_hints,
        "startup_script_hints": startup_hints,
        "kernel_cmd_hints": kernel_cmd_hints,
        "stats": {
            "init_candidate_count": len(init_candidates),
            "web_service_candidate_count": len(web_bins),
            "web_config_candidate_count": len(web_cfgs),
            "port_hint_count": len(port_hints),
            "startup_script_hint_count": len(startup_hints),
        },
    }

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        if args.pretty:
            json.dump(facts, f, ensure_ascii=True, indent=2, sort_keys=True)
            f.write("\n")
        else:
            json.dump(facts, f, ensure_ascii=True)

    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
