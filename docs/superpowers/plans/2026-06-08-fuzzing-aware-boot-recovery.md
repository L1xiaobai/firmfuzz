# Fuzzing-Aware Boot Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve firmware emulation success rate by enriching LLM/rule-based boot and service inference, while producing structured fuzzing targets for later dynamic analysis.

**Architecture:** Keep the existing `run.sh` interface, `FIRMAE_LLM` switch, and legacy `scratch/<iid>/ping`, `web`, `ip`, `result` files unchanged. Add optional JSON artifacts beside existing scratch files: richer facts, LLM boot/service candidates, per-init emulation attempts, and `fuzz_targets.json` for the fuzzer. All risky LLM output remains behind validation and fallback behavior.

**Tech Stack:** Python 3 standard library, shell scripts, existing FirmAE scratch-file workflow, unittest-based tests runnable without QEMU/root privileges.

---

## File Structure

- Modify `scripts/collectFacts.py`
  - Add static web/fuzzing discovery from mounted rootfs.
  - New fact key: `fuzz_hints`.

- Modify `scripts/llm_infer.py`
  - Preserve existing output keys.
  - Add `boot_plan_candidates` and `fuzz_hints` to mock and OpenAI-compatible outputs.

- Modify `scripts/validate_llm_plan.py`
  - Keep old schemas accepted only if compatibility is needed during direct use.
  - Validate new optional keys when present.

- Modify `scripts/makeNetwork.py`
  - Add pure helper functions for attempt records.
  - Write `scratch/<iid>/emulation_attempts.json`.
  - Do not change existing success criteria or legacy files.

- Create `scripts/export_fuzz_targets.py`
  - Merge `facts.json`, `llm_infer.json`, `emulation_attempts.json`, and scratch status files into `fuzz_targets.json`.
  - Return success even when inputs are partially missing, as long as output can be written.

- Modify `run.sh`
  - After `makeNetwork.py`, best-effort invoke `export_fuzz_targets.py`.
  - Do not fail emulation if export fails.

- Create `tests/test_collect_facts_fuzz_hints.py`
- Create `tests/test_llm_infer_extensions.py`
- Create `tests/test_validate_llm_plan_extensions.py`
- Create `tests/test_make_network_attempts.py`
- Create `tests/test_export_fuzz_targets.py`

---

### Task 1: Add Fuzzing Hints To Facts Collection

**Files:**
- Modify: `scripts/collectFacts.py`
- Test: `tests/test_collect_facts_fuzz_hints.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_collect_facts_fuzz_hints.py`:

```python
import importlib.util
import os
import stat
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(ROOT, "scripts", "collectFacts.py")


def load_module():
    spec = importlib.util.spec_from_file_location("collectFacts", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CollectFactsFuzzHintsTest(unittest.TestCase):
    def test_gather_fuzz_hints_discovers_web_roots_and_entrypoints(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, "www", "cgi-bin"))
            os.makedirs(os.path.join(rootfs, "etc"))
            index = os.path.join(rootfs, "www", "index.html")
            cgi = os.path.join(rootfs, "www", "cgi-bin", "apply.cgi")
            soap = os.path.join(rootfs, "www", "HNAP1.xml")
            auth = os.path.join(rootfs, "www", "login.asp")
            conf = os.path.join(rootfs, "etc", "httpd.conf")
            for path, data in [
                (index, "<form action='/cgi-bin/apply.cgi'></form>"),
                (cgi, "#!/bin/sh\n"),
                (soap, "<soap>HNAP</soap>"),
                (auth, "password login auth"),
                (conf, "Listen 8080\nDocumentRoot /www\n"),
            ]:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(data)
            os.chmod(cgi, os.stat(cgi).st_mode | stat.S_IXUSR)

            hints = mod.gather_fuzz_hints(rootfs)

        self.assertEqual(hints["web_roots"], ["/www"])
        self.assertIn("/www/cgi-bin/apply.cgi", hints["web_entrypoints"])
        self.assertIn("/www/HNAP1.xml", hints["api_entrypoints"])
        self.assertIn("/www/login.asp", hints["auth_hints"])
        self.assertIn("/etc/httpd.conf", hints["config_files"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest tests.test_collect_facts_fuzz_hints -v
```

Expected: FAIL with `AttributeError: module 'collectFacts' has no attribute 'gather_fuzz_hints'`.

- [ ] **Step 3: Implement minimal facts collection**

In `scripts/collectFacts.py`, add constants near existing candidate constants:

```python
WEB_ROOT_CANDIDATES = [
    "/www",
    "/wwwroot",
    "/htdocs",
    "/home/httpd",
    "/usr/www",
    "/var/www",
    "/web",
]

FUZZ_ENTRY_EXTENSIONS = {".cgi", ".php", ".asp", ".aspx", ".jsp", ".htm", ".html", ".xml"}
API_KEYWORDS = ("hnap", "soap", "upnp", "api", "ajax", "json", "xml")
AUTH_KEYWORDS = ("login", "auth", "password", "passwd", "session", "token", "credential")
```

Add these helper functions before `parse_args()`:

```python
def is_under_any(path: str, roots: List[str]) -> bool:
    normalized = path.rstrip("/")
    for root in roots:
        if normalized == root or normalized.startswith(root.rstrip("/") + "/"):
            return True
    return False


def gather_fuzz_hints(rootfs: str) -> Dict[str, List[str]]:
    web_roots: List[str] = []
    for fw_path in WEB_ROOT_CANDIDATES:
        host = to_host_path(rootfs, fw_path)
        if os.path.isdir(host):
            web_roots.append(fw_path)

    web_entrypoints: Set[str] = set()
    api_entrypoints: Set[str] = set()
    auth_hints: Set[str] = set()
    config_files: Set[str] = set(gather_web_configs(rootfs))

    scan_roots = web_roots if web_roots else ["/"]
    for fw_root in scan_roots:
        host_root = to_host_path(rootfs, fw_root)
        if not os.path.isdir(host_root):
            continue
        for dirpath, _, filenames in os.walk(host_root):
            for name in filenames:
                host_path = os.path.join(dirpath, name)
                fw_path = fw_from_host(rootfs, host_path)
                lowered = fw_path.lower()
                _, ext = os.path.splitext(lowered)
                if ext in FUZZ_ENTRY_EXTENSIONS:
                    web_entrypoints.add(fw_path)
                if any(k in lowered for k in API_KEYWORDS):
                    api_entrypoints.add(fw_path)
                if any(k in lowered for k in AUTH_KEYWORDS):
                    auth_hints.add(fw_path)
                if lowered.endswith((".conf", ".cfg", ".ini")) and is_under_any(fw_path, ["/etc"] + web_roots):
                    config_files.add(fw_path)

    return {
        "web_roots": sorted(web_roots),
        "web_entrypoints": sorted(web_entrypoints)[:500],
        "api_entrypoints": sorted(api_entrypoints)[:300],
        "auth_hints": sorted(auth_hints)[:300],
        "config_files": sorted(config_files)[:300],
    }
```

In `main()`, after `kernel_cmd_hints = gather_kernel_cmd_hints(work_dir)`, add:

```python
    fuzz_hints = gather_fuzz_hints(rootfs)
```

In the `facts` object, add:

```python
        "fuzz_hints": fuzz_hints,
```

In `stats`, add:

```python
            "web_root_count": len(fuzz_hints["web_roots"]),
            "web_entrypoint_count": len(fuzz_hints["web_entrypoints"]),
            "api_entrypoint_count": len(fuzz_hints["api_entrypoints"]),
            "auth_hint_count": len(fuzz_hints["auth_hints"]),
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python3 -m unittest tests.test_collect_facts_fuzz_hints -v
python3 -m py_compile scripts/collectFacts.py
```

Expected: both PASS / no output from `py_compile`.

- [ ] **Step 5: Commit**

```bash
git add scripts/collectFacts.py tests/test_collect_facts_fuzz_hints.py
git commit -m "feat: collect fuzzing hints from firmware rootfs"
```

---

### Task 2: Extend LLM Inference With Boot Plans And Fuzz Hints

**Files:**
- Modify: `scripts/llm_infer.py`
- Test: `tests/test_llm_infer_extensions.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_llm_infer_extensions.py`:

```python
import importlib.util
import os
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(ROOT, "scripts", "llm_infer.py")


def load_module():
    spec = importlib.util.spec_from_file_location("llm_infer", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LlmInferExtensionsTest(unittest.TestCase):
    def test_mock_infer_outputs_boot_plan_candidates_and_fuzz_hints(self):
        mod = load_module()
        facts = {
            "init_candidates": ["/etc/init.d/rcS", "/firmadyne/preInit.sh"],
            "web_service_candidates": [{"path": "/usr/sbin/httpd", "kind": "binary", "source": "known_path"}],
            "web_config_candidates": ["/etc/httpd.conf"],
            "port_hints": [80, 8080],
            "startup_script_hints": ["/etc/init.d/rcS"],
            "fuzz_hints": {
                "web_roots": ["/www"],
                "web_entrypoints": ["/www/index.html", "/www/apply.cgi"],
                "api_entrypoints": ["/www/HNAP1.xml"],
                "auth_hints": ["/www/login.asp"],
                "config_files": ["/etc/httpd.conf"],
            },
        }

        result = mod.mock_infer(facts, 0.6)

        self.assertIn("boot_plan_candidates", result)
        self.assertEqual(result["boot_plan_candidates"][0]["init"], "/etc/init.d/rcS")
        self.assertEqual(result["boot_plan_candidates"][0]["service"], "/usr/sbin/httpd")
        self.assertIn("fuzz_hints", result)
        self.assertEqual(result["fuzz_hints"]["web_roots"], ["/www"])
        mod.validate_output(result)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest tests.test_llm_infer_extensions -v
```

Expected: FAIL because `boot_plan_candidates` is missing.

- [ ] **Step 3: Implement minimal LLM output extension**

In `DEFAULT_SYSTEM_PROMPT`, append these required keys to the JSON contract:

```text
- boot_plan_candidates: array of objects {init, service, score, reason}
- fuzz_hints: object {web_roots, web_entrypoints, api_entrypoints, auth_hints, config_files}
```

Add this helper after `build_init_script()`:

```python
def build_boot_plan_candidates(
    init_candidates: List[str],
    service_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    plans: List[Dict[str, Any]] = []
    services = service_candidates[:5] if service_candidates else [{"path": "", "score": 0.0, "reason": "no_service"}]
    for init_idx, init in enumerate(init_candidates[:5]):
        for service_idx, service in enumerate(services):
            service_path = service.get("path", "")
            score = 0.9 - (init_idx * 0.08) - (service_idx * 0.04)
            if not service_path:
                score -= 0.2
            plans.append(
                {
                    "init": init,
                    "service": service_path,
                    "score": round(max(score, 0.1), 3),
                    "reason": "ranked_by_init_and_service_confidence",
                }
            )
    return plans[:10]
```

In `mock_infer()`, before `out = {`, add:

```python
    fuzz_hints = facts.get("fuzz_hints", {})
```

In the `out` object, add:

```python
        "boot_plan_candidates": build_boot_plan_candidates(init_candidates, service_candidates),
        "fuzz_hints": {
            "web_roots": fuzz_hints.get("web_roots", []),
            "web_entrypoints": fuzz_hints.get("web_entrypoints", []),
            "api_entrypoints": fuzz_hints.get("api_entrypoints", []),
            "auth_hints": fuzz_hints.get("auth_hints", []),
            "config_files": fuzz_hints.get("config_files", []),
        },
```

In `openai_compatible_infer()`, after `inferred = parse_json_from_text(text)`, add compatibility fill-ins:

```python
    init_candidates = inferred.get("init_candidates", [])
    service_candidates = inferred.get("service_candidates", [])
    if "boot_plan_candidates" not in inferred:
        inferred["boot_plan_candidates"] = build_boot_plan_candidates(init_candidates, service_candidates)
    if "fuzz_hints" not in inferred:
        inferred["fuzz_hints"] = facts.get("fuzz_hints", {})
```

In `validate_output()`, add:

```python
    if "boot_plan_candidates" in obj and not isinstance(obj["boot_plan_candidates"], list):
        raise ValueError("boot_plan_candidates must be list")
    if "fuzz_hints" in obj and not isinstance(obj["fuzz_hints"], dict):
        raise ValueError("fuzz_hints must be object")
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python3 -m unittest tests.test_llm_infer_extensions -v
python3 -m py_compile scripts/llm_infer.py
```

Expected: PASS / no syntax errors.

- [ ] **Step 5: Commit**

```bash
git add scripts/llm_infer.py tests/test_llm_infer_extensions.py
git commit -m "feat: infer boot plans and fuzz hints"
```

---

### Task 3: Validate Extended LLM Plan Schema

**Files:**
- Modify: `scripts/validate_llm_plan.py`
- Test: `tests/test_validate_llm_plan_extensions.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_validate_llm_plan_extensions.py`:

```python
import importlib.util
import os
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(ROOT, "scripts", "validate_llm_plan.py")


def load_module():
    spec = importlib.util.spec_from_file_location("validate_llm_plan", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ValidateLlmPlanExtensionsTest(unittest.TestCase):
    def test_validate_schema_accepts_extended_keys(self):
        mod = load_module()
        obj = {
            "schema_version": "1.0",
            "init_candidates": ["/etc/init.d/rcS"],
            "service_candidates": [{"path": "/usr/sbin/httpd", "kind": "binary", "score": 0.9, "reason": "test"}],
            "config_hints": {},
            "recommended_init_script": "#!/firmadyne/sh\n/firmadyne/busybox sleep 36000\n",
            "confidence": 0.9,
            "reasoning_short": "test",
            "fallback_required": False,
            "boot_plan_candidates": [{"init": "/etc/init.d/rcS", "service": "/usr/sbin/httpd", "score": 0.9, "reason": "test"}],
            "fuzz_hints": {"web_roots": ["/www"], "web_entrypoints": ["/www/index.html"]},
        }

        self.assertEqual(mod.validate_schema(obj), [])
        self.assertEqual(mod.validate_paths(obj), [])

    def test_validate_schema_rejects_bad_boot_plan_type(self):
        mod = load_module()
        obj = {
            "schema_version": "1.0",
            "init_candidates": ["/etc/init.d/rcS"],
            "service_candidates": [],
            "config_hints": {},
            "recommended_init_script": "#!/firmadyne/sh\n/firmadyne/busybox sleep 36000\n",
            "confidence": 0.9,
            "reasoning_short": "test",
            "fallback_required": False,
            "boot_plan_candidates": "bad",
            "fuzz_hints": {},
        }

        self.assertIn("boot_plan_candidates must be list", mod.validate_schema(obj))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest tests.test_validate_llm_plan_extensions -v
```

Expected: FAIL because bad `boot_plan_candidates` is not rejected.

- [ ] **Step 3: Implement validation**

In `validate_schema()`, after the existing required type checks, add:

```python
    if "boot_plan_candidates" in obj and not isinstance(obj["boot_plan_candidates"], list):
        errors.append("boot_plan_candidates must be list")
    if "fuzz_hints" in obj and not isinstance(obj["fuzz_hints"], dict):
        errors.append("fuzz_hints must be object")
```

In `validate_paths()`, after service candidate validation, add:

```python
    for plan in obj.get("boot_plan_candidates", []):
        if not isinstance(plan, dict):
            errors.append("boot plan candidate must be object")
            continue
        init = plan.get("init", "")
        service = plan.get("service", "")
        if init and (not isinstance(init, str) or not init.startswith("/")):
            errors.append(f"boot plan init must be absolute fw path: {init}")
        if service and (not isinstance(service, str) or not service.startswith("/")):
            errors.append(f"boot plan service must be absolute fw path: {service}")
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python3 -m unittest tests.test_validate_llm_plan_extensions -v
python3 -m py_compile scripts/validate_llm_plan.py
```

Expected: PASS / no syntax errors.

- [ ] **Step 5: Commit**

```bash
git add scripts/validate_llm_plan.py tests/test_validate_llm_plan_extensions.py
git commit -m "test: validate extended llm plan schema"
```

---

### Task 4: Record Emulation Attempts During Network Inference

**Files:**
- Modify: `scripts/makeNetwork.py`
- Test: `tests/test_make_network_attempts.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_make_network_attempts.py`:

```python
import importlib.util
import json
import os
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(ROOT, "scripts", "makeNetwork.py")


def load_module():
    spec = importlib.util.spec_from_file_location("makeNetwork", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MakeNetworkAttemptsTest(unittest.TestCase):
    def test_build_attempt_record_serializes_network_and_ports(self):
        mod = load_module()
        record = mod.build_attempt_record(
            init="/etc/init.d/rcS",
            qemu_init="rdinit=/firmadyne/preInit.sh",
            network_list=[("192.168.0.1", "eth0", None, None, "br0")],
            filtered_network=[("192.168.0.1", "eth0", None, None, "br0")],
            network_type="normal",
            ports=[("tcp", "0.0.0.0", 80)],
            ping="true",
            web="true",
            ip="192.168.0.1",
            error=None,
        )

        self.assertEqual(record["init"], "/etc/init.d/rcS")
        self.assertEqual(record["ping"], True)
        self.assertEqual(record["web"], True)
        self.assertEqual(record["ports"][0]["port"], 80)
        self.assertEqual(record["filtered_network"][0]["ip"], "192.168.0.1")

    def test_write_attempts_json_writes_schema(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "emulation_attempts.json")
            mod.write_attempts_json(out, [{"init": "/init", "web": False}])
            with open(out, "r", encoding="utf-8") as f:
                data = json.load(f)

        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["attempt_count"], 1)
        self.assertEqual(data["attempts"][0]["init"], "/init")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest tests.test_make_network_attempts -v
```

Expected: FAIL because `build_attempt_record` and `write_attempts_json` do not exist.

- [ ] **Step 3: Implement attempt helpers**

In `scripts/makeNetwork.py`, add these helpers after `readWithException()`:

```python
def parse_bool_text(value):
    return str(value).strip().lower() == "true"


def network_tuple_to_dict(item):
    ip, dev, vlan, mac, brif = item
    return {
        "ip": ip,
        "device": dev,
        "vlan": vlan,
        "mac": mac,
        "bridge": brif,
    }


def port_tuple_to_dict(item):
    proto, addr, port = item
    return {
        "protocol": proto,
        "address": addr,
        "port": int(port),
    }


def build_attempt_record(
    init,
    qemu_init,
    network_list,
    filtered_network,
    network_type,
    ports,
    ping,
    web,
    ip,
    error=None,
):
    return {
        "schema_version": "1.0",
        "init": init,
        "qemu_init": qemu_init,
        "network_type": network_type,
        "network": [network_tuple_to_dict(x) for x in network_list],
        "filtered_network": [network_tuple_to_dict(x) for x in filtered_network],
        "ports": [port_tuple_to_dict(x) for x in ports],
        "ping": parse_bool_text(ping),
        "web": parse_bool_text(web),
        "ip": ip if ip else "None",
        "error": error,
    }


def write_attempts_json(path, attempts):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "attempt_count": len(attempts),
        "attempts": attempts,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=True, indent=2, sort_keys=True)
        f.write("\n")
```

In `process()`, after `success = False`, add:

```python
    attempts = []
    attempts_path = SCRATCHDIR + "/" + str(iid) + "/emulation_attempts.json"
```

Inside the `except Exception as e:` block, before `continue`, add:

```python
            attempts.append(build_attempt_record(init, "", [], [], "None", [], "false", "false", "None", str(e)))
            write_attempts_json(attempts_path, attempts)
```

After reading `ping_res`, `web_res`, and `ip_res`, before the `print("[*] emulation check result...")`, add:

```python
            attempts.append(
                build_attempt_record(
                    init,
                    qemuInitValue,
                    networkList,
                    filterNetworkList,
                    network_type,
                    ports,
                    ping_res,
                    web_res,
                    ip_res,
                    None,
                )
            )
            write_attempts_json(attempts_path, attempts)
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python3 -m unittest tests.test_make_network_attempts -v
python3 -m py_compile scripts/makeNetwork.py
```

Expected: PASS / no syntax errors.

- [ ] **Step 5: Commit**

```bash
git add scripts/makeNetwork.py tests/test_make_network_attempts.py
git commit -m "feat: record emulation attempt outcomes"
```

---

### Task 5: Export Fuzz Targets From Facts And Attempts

**Files:**
- Create: `scripts/export_fuzz_targets.py`
- Test: `tests/test_export_fuzz_targets.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_export_fuzz_targets.py`:

```python
import importlib.util
import json
import os
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(ROOT, "scripts", "export_fuzz_targets.py")


def load_module():
    spec = importlib.util.spec_from_file_location("export_fuzz_targets", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ExportFuzzTargetsTest(unittest.TestCase):
    def test_build_fuzz_targets_prefers_successful_web_attempt(self):
        mod = load_module()
        facts = {
            "iid": 7,
            "web_service_candidates": [{"path": "/usr/sbin/httpd", "kind": "binary", "source": "known_path"}],
            "port_hints": [80, 8080],
            "fuzz_hints": {
                "web_roots": ["/www"],
                "web_entrypoints": ["/www/index.html", "/www/apply.cgi"],
                "api_entrypoints": ["/www/HNAP1.xml"],
                "auth_hints": ["/www/login.asp"],
                "config_files": ["/etc/httpd.conf"],
            },
        }
        llm = {
            "service_candidates": [{"path": "/usr/sbin/httpd", "kind": "binary", "score": 0.9, "reason": "test"}],
            "fuzz_hints": facts["fuzz_hints"],
        }
        attempts = {
            "attempts": [
                {"init": "/bad", "web": False, "ping": False, "ip": "None", "ports": []},
                {"init": "/etc/init.d/rcS", "web": True, "ping": True, "ip": "192.168.0.1", "ports": [{"protocol": "tcp", "address": "0.0.0.0", "port": 80}]},
            ]
        }

        result = mod.build_fuzz_targets(iid=7, brand="dlink", facts=facts, llm=llm, attempts=attempts, scratch_status={})

        self.assertEqual(result["iid"], 7)
        self.assertEqual(result["target"]["ip"], "192.168.0.1")
        self.assertEqual(result["target"]["ports"], [80])
        self.assertIn("/www/apply.cgi", result["fuzzing"]["web_entrypoints"])
        self.assertEqual(result["service_candidates"][0]["path"], "/usr/sbin/httpd")

    def test_write_json_creates_output(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "fuzz_targets.json")
            mod.write_json(out, {"schema_version": "1.0"}, pretty=True)
            self.assertTrue(os.path.exists(out))
            with open(out, "r", encoding="utf-8") as f:
                self.assertEqual(json.load(f)["schema_version"], "1.0")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest tests.test_export_fuzz_targets -v
```

Expected: FAIL because `scripts/export_fuzz_targets.py` does not exist.

- [ ] **Step 3: Implement exporter**

Create `scripts/export_fuzz_targets.py`:

```python
#!/usr/bin/env python3

import argparse
import json
import os
import sys
from typing import Any, Dict, List


def read_json(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return ""


def write_json(path: str, obj: Dict[str, Any], pretty: bool = True) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(obj, f, ensure_ascii=True, indent=2, sort_keys=True)
            f.write("\n")
        else:
            json.dump(obj, f, ensure_ascii=True)


def unique_ints(values: List[Any]) -> List[int]:
    out: List[int] = []
    seen = set()
    for value in values:
        try:
            item = int(value)
        except Exception:
            continue
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def select_best_attempt(attempts: Dict[str, Any], scratch_status: Dict[str, str]) -> Dict[str, Any]:
    records = attempts.get("attempts", [])
    web_records = [x for x in records if x.get("web") is True]
    if web_records:
        return web_records[0]
    ping_records = [x for x in records if x.get("ping") is True]
    if ping_records:
        return ping_records[0]
    if records:
        return records[-1]
    return {
        "init": scratch_status.get("current_init", ""),
        "web": scratch_status.get("web", "").lower() == "true",
        "ping": scratch_status.get("ping", "").lower() == "true",
        "ip": scratch_status.get("ip", "None") or "None",
        "ports": [],
    }


def merge_fuzz_hints(facts: Dict[str, Any], llm: Dict[str, Any]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    fact_hints = facts.get("fuzz_hints", {}) if isinstance(facts.get("fuzz_hints", {}), dict) else {}
    llm_hints = llm.get("fuzz_hints", {}) if isinstance(llm.get("fuzz_hints", {}), dict) else {}
    for key in ["web_roots", "web_entrypoints", "api_entrypoints", "auth_hints", "config_files"]:
        seen = set()
        values: List[str] = []
        for source in [fact_hints, llm_hints]:
            for value in source.get(key, []):
                if isinstance(value, str) and value not in seen:
                    seen.add(value)
                    values.append(value)
        merged[key] = values
    return merged


def build_fuzz_targets(
    iid: int,
    brand: str,
    facts: Dict[str, Any],
    llm: Dict[str, Any],
    attempts: Dict[str, Any],
    scratch_status: Dict[str, str],
) -> Dict[str, Any]:
    best = select_best_attempt(attempts, scratch_status)
    ports = unique_ints([p.get("port") for p in best.get("ports", []) if isinstance(p, dict)])
    if not ports:
        ports = unique_ints(facts.get("port_hints", []))
    service_candidates = llm.get("service_candidates") or facts.get("web_service_candidates", [])
    fuzz_hints = merge_fuzz_hints(facts, llm)
    return {
        "schema_version": "1.0",
        "iid": iid,
        "brand": brand,
        "target": {
            "ip": best.get("ip", scratch_status.get("ip", "None") or "None"),
            "ports": ports,
            "ping": bool(best.get("ping", False)),
            "web": bool(best.get("web", False)),
            "selected_init": best.get("init", ""),
        },
        "service_candidates": service_candidates,
        "fuzzing": fuzz_hints,
        "attempt_summary": {
            "attempt_count": len(attempts.get("attempts", [])),
            "best_error": best.get("error"),
        },
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export fuzzing targets from FirmAE emulation artifacts.")
    p.add_argument("--iid", type=int, required=True)
    p.add_argument("--brand", default="")
    p.add_argument("--scratch", required=True, help="scratch/<iid> directory")
    p.add_argument("--facts", help="facts.json path")
    p.add_argument("--llm-infer", help="llm_infer.json path")
    p.add_argument("--attempts", help="emulation_attempts.json path")
    p.add_argument("--output", required=True)
    p.add_argument("--pretty", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    scratch_status = {
        "ip": read_text(os.path.join(args.scratch, "ip")),
        "ping": read_text(os.path.join(args.scratch, "ping")),
        "web": read_text(os.path.join(args.scratch, "web")),
        "current_init": read_text(os.path.join(args.scratch, "current_init")),
    }
    facts = read_json(args.facts or os.path.join(args.scratch, "facts.json"))
    llm = read_json(args.llm_infer or os.path.join(args.scratch, "llm_infer.json"))
    attempts = read_json(args.attempts or os.path.join(args.scratch, "emulation_attempts.json"))
    out = build_fuzz_targets(args.iid, args.brand, facts, llm, attempts, scratch_status)
    write_json(args.output, out, args.pretty)
    print(os.path.abspath(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python3 -m unittest tests.test_export_fuzz_targets -v
python3 -m py_compile scripts/export_fuzz_targets.py
```

Expected: PASS / no syntax errors.

- [ ] **Step 5: Commit**

```bash
git add scripts/export_fuzz_targets.py tests/test_export_fuzz_targets.py
git commit -m "feat: export fuzz targets from emulation artifacts"
```

---

### Task 6: Integrate Fuzz Target Export Into The Existing Run Flow

**Files:**
- Modify: `run.sh`
- Test: no unit test; verify by shell syntax and exporter unit tests.

- [ ] **Step 1: Add a best-effort export call**

In `run.sh`, immediately after the `makeNetwork.py` command block and before symlink creation, insert:

```bash
        if [ -e "${WORK_DIR}" ]; then
          python3 -u ./scripts/export_fuzz_targets.py \
            --iid "${IID}" \
            --brand "${BRAND}" \
            --scratch "${WORK_DIR}" \
            --facts "${WORK_DIR}/facts.json" \
            --llm-infer "${WORK_DIR}/llm_infer.json" \
            --attempts "${WORK_DIR}/emulation_attempts.json" \
            --output "${WORK_DIR}/fuzz_targets.json" \
            --pretty \
            2>&1 > "${WORK_DIR}/fuzz_targets.log" || true
        fi
```

This preserves existing behavior because `|| true` prevents export failure from failing emulation.

- [ ] **Step 2: Run shell syntax verification**

Run:

```bash
bash -n run.sh
python3 -m unittest tests.test_export_fuzz_targets -v
```

Expected: `bash -n` produces no output; unittest PASS.

- [ ] **Step 3: Commit**

```bash
git add run.sh
git commit -m "feat: export fuzz targets during emulation"
```

---

### Task 7: Full Local Verification

**Files:**
- No new file changes expected.

- [ ] **Step 1: Run all new unit tests**

Run:

```bash
python3 -m unittest \
  tests.test_collect_facts_fuzz_hints \
  tests.test_llm_infer_extensions \
  tests.test_validate_llm_plan_extensions \
  tests.test_make_network_attempts \
  tests.test_export_fuzz_targets \
  -v
```

Expected: all tests PASS.

- [ ] **Step 2: Run Python syntax checks**

Run:

```bash
python3 -m py_compile \
  scripts/collectFacts.py \
  scripts/llm_infer.py \
  scripts/validate_llm_plan.py \
  scripts/render_init_from_llm.py \
  scripts/makeNetwork.py \
  scripts/export_fuzz_targets.py
```

Expected: no output and exit code 0.

- [ ] **Step 3: Run shell syntax checks**

Run:

```bash
bash -n run.sh
bash -n scripts/makeImage.sh
```

Expected: no output and exit code 0.

- [ ] **Step 4: Optional full emulation smoke test**

Run with a small firmware already present in `firmwares/`:

```bash
sudo ./run.sh -c dlink firmwares/DIR-816L_REVB1_FW_v2.00b01.bin
```

Expected:
- Existing `scratch/<iid>/result` behavior remains unchanged.
- New optional files exist when the flow reaches their stages:
  - `scratch/<iid>/facts.json`
  - `scratch/<iid>/llm_infer.json`
  - `scratch/<iid>/llm_validate.json`
  - `scratch/<iid>/emulation_attempts.json`
  - `scratch/<iid>/fuzz_targets.json`

- [ ] **Step 5: Commit verification-only updates if any**

If verification required small fixes, commit them with:

```bash
git add scripts tests run.sh
git commit -m "fix: stabilize fuzzing-aware boot recovery"
```

If no fixes were needed, do not create an empty commit.

---

## Compatibility Guarantees

- Existing CLI remains unchanged:

```bash
sudo ./run.sh -c <brand> <firmware>
sudo ./run.sh -a <brand> <firmware>
sudo ./run.sh -r <brand> <firmware>
```

- Existing config remains compatible:
  - `FIRMAE_LLM=false` skips LLM inference as before.
  - `FIRMAE_LLM=true` enables the existing pipeline plus new optional artifacts.

- Existing scratch status files remain authoritative:
  - `result`
  - `ping`
  - `web`
  - `ip`

- New artifacts are additive:
  - `facts.json` gains `fuzz_hints`.
  - `llm_infer.json` gains `boot_plan_candidates` and `fuzz_hints`.
  - `emulation_attempts.json` is new.
  - `fuzz_targets.json` is new.

## Self-Review

- Spec coverage: The plan improves emulation success observability through boot/service candidates and attempt recording, and helps fuzzing through static fuzz hints plus exported target metadata.
- Placeholder scan: The plan contains no unresolved placeholder markers or unspecified implementation steps.
- Type consistency: The same JSON keys are used across tasks: `fuzz_hints`, `boot_plan_candidates`, `emulation_attempts.json`, and `fuzz_targets.json`.
