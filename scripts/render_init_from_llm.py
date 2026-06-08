#!/usr/bin/env python3

import argparse
import json
import os
import re
import stat
import sys
from typing import Any, Dict, List


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Render LLM init script + fallback wrapper without overriding original firmadyne/init."
    )
    p.add_argument("--llm-infer", required=True, help="Path to llm_infer.json")
    p.add_argument("--rootfs", required=True, help="Mounted rootfs directory")
    p.add_argument(
        "--orig-init",
        default="/firmadyne/init",
        help="Original init list path in firmware fs (default: /firmadyne/init)",
    )
    p.add_argument(
        "--llm-init",
        default="/firmadyne/llm_init.sh",
        help="Generated LLM init script path in firmware fs (default: /firmadyne/llm_init.sh)",
    )
    p.add_argument(
        "--wrapper",
        default="/firmadyne/llm_entry.sh",
        help="Generated wrapper script path in firmware fs (default: /firmadyne/llm_entry.sh)",
    )
    p.add_argument(
        "--meta-out",
        help="Optional host path for generation metadata JSON (default: <rootfs>/firmadyne/llm_render_meta.json)",
    )
    return p.parse_args()


def to_host_path(rootfs: str, fw_path: str) -> str:
    p = fw_path[1:] if fw_path.startswith("/") else fw_path
    return os.path.join(rootfs, p)


def read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_likely_valid_script(text: str) -> bool:
    if not text or not text.strip():
        return False
    dangerous = [
        r"rm\s+-rf\s+/",
        r"\breboot\b",
        r"\bhalt\b",
        r"\bpoweroff\b",
        r"\bmtd\b.*\b(write|erase)\b",
    ]
    lowered = text.lower()
    for pat in dangerous:
        if re.search(pat, lowered):
            return False
    if "sleep" not in lowered and "&" not in lowered:
        # Very weak signal: init script usually starts/stays alive or backgrounds.
        return False
    return True


def ensure_shebang(script: str) -> str:
    s = script.lstrip()
    if s.startswith("#!"):
        return script if script.endswith("\n") else script + "\n"
    return "#!/firmadyne/sh\n" + script + ("" if script.endswith("\n") else "\n")


def read_orig_init_entries(rootfs: str, orig_init_fw: str) -> List[str]:
    path = to_host_path(rootfs, orig_init_fw)
    if not os.path.exists(path):
        return []
    entries: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            x = line.strip()
            if x:
                entries.append(x)
    return entries


def make_wrapper_script(
    llm_init_fw: str,
    orig_init_fw: str,
    service_names: List[str],
) -> str:
    checks = ""
    for name in service_names[:5]:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "", name)
        if safe:
            checks += f'  if $BUSYBOX ps | $BUSYBOX grep -v grep | $BUSYBOX grep -qi "{safe}"; then return 0; fi\n'

    check_code = checks if checks else "  return 1\n"

    return f"""#!/firmadyne/sh
        BUSYBOX=/firmadyne/busybox
        LLM_INIT="{llm_init_fw}"
        ORIG_INIT="{orig_init_fw}"

        has_service_started() {{
        {check_code}
        }}

        run_original_init_chain() {{
        if [ ! -f "$ORIG_INIT" ]; then
            return 1
        fi
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            if [ -x "$entry" ] || [ -f "$entry" ]; then
            "$entry" &
            /firmadyne/busybox sleep 1
            fi
        done < "$ORIG_INIT"
        return 0
        }}

        if [ -x "$LLM_INIT" ] || [ -f "$LLM_INIT" ]; then
        "$LLM_INIT" &
        /firmadyne/busybox sleep 8
        if has_service_started; then
            /firmadyne/busybox sleep 36000
            exit 0
        fi
        fi

        run_original_init_chain || true
        /firmadyne/busybox sleep 36000
        """


def write_exec_file(path: str, data: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main() -> int:
    args = parse_args()
    rootfs = os.path.abspath(args.rootfs)
    if not os.path.isdir(rootfs):
        print(f"Error: rootfs not found: {rootfs}", file=sys.stderr)
        return 2

    llm = read_json(args.llm_infer)
    llm_script = llm.get("recommended_init_script", "")
    service_candidates = llm.get("service_candidates", [])
    service_names = [os.path.basename(x.get("path", "")) for x in service_candidates if x.get("path")]

    script_valid = is_likely_valid_script(llm_script) and (not llm.get("fallback_required", False))
    llm_init_host = to_host_path(rootfs, args.llm_init)
    wrapper_host = to_host_path(rootfs, args.wrapper)
    orig_entries = read_orig_init_entries(rootfs, args.orig_init)

    if script_valid:
        llm_script_final = ensure_shebang(llm_script)
    else:
        # If invalid, create a no-op script and force wrapper fallback.
        llm_script_final = """#!/firmadyne/sh
BUSYBOX=/firmadyne/busybox
exit 1
"""

    wrapper = make_wrapper_script(args.llm_init, args.orig_init, service_names)

    write_exec_file(llm_init_host, llm_script_final)
    write_exec_file(wrapper_host, wrapper)

    meta = {
        "schema_version": "1.0",
        "llm_init_fw_path": args.llm_init,
        "wrapper_fw_path": args.wrapper,
        "orig_init_fw_path": args.orig_init,
        "llm_script_valid": script_valid,
        "fallback_mode": not script_valid,
        "service_name_hints": service_names[:10],
        "orig_init_entry_count": len(orig_entries),
        "orig_init_preview": orig_entries[:20],
    }

    meta_out = (
        os.path.abspath(args.meta_out)
        if args.meta_out
        else to_host_path(rootfs, "/firmadyne/llm_render_meta.json")
    )
    os.makedirs(os.path.dirname(meta_out), exist_ok=True)
    with open(meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=True, indent=2, sort_keys=True)
        f.write("\n")

    print(json.dumps(
        {
            "llm_init": llm_init_host,
            "wrapper": wrapper_host,
            "meta": meta_out,
            "llm_script_valid": script_valid,
        },
        ensure_ascii=True,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
