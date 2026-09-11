"""
pre/execute/flagd.py — execute TOGGLE_FLAG actions by editing the flagd
ConfigMap; flagd hot-reloads it with no pod restart.

    from pre.execute.flagd import execute, set_flag
    result = execute(action)          # from an Action
    set_flag("acquirerTimeout", True) # direct, for the smoke script

The A13 testbed mounts the `flagd-config` ConfigMap straight into flagd's
/etc/flagd (see deploy/a13/values-slim.yaml). Mechanism: patch
`.flags[<name>].defaultVariant` in the JSON held in the ConfigMap ->
`kubectl apply` -> wait for kubelet to project the change into the pod and for
flagd to fsnotify-reload, confirmed via flagd's OFREP endpoint. No restart, so
the flag-consuming services keep their flagd streams open and see the change.

Set FLAGD_RESTART_DEPLOY (e.g. "flagd") to fall back to a rollout restart for a
chart layout that copies the config into an emptyDir at init.
"""

from __future__ import annotations

import json
import os
import sys
import time

import httpx

from pre.execute import ExecutionResult, ExecutorError, _now
from pre.execute._kubectl import get_json, run
from pre.policy.action_catalog import Action, ActionType

CONFIGMAP = os.getenv("FLAGD_CONFIGMAP", "flagd-config")
CONFIGMAP_KEY = os.getenv("FLAGD_CONFIGMAP_KEY", "demo.flagd.json")
RESTART_DEPLOY = os.getenv("FLAGD_RESTART_DEPLOY", "")  # non-empty -> rollout restart instead
OFREP_URL = os.getenv("FLAGD_OFREP_URL", "http://localhost:8016").rstrip("/")
# ConfigMap->pod projection can take up to the kubelet sync period (~1 min) plus
# flagd's reload debounce.
RELOAD_TIMEOUT = float(os.getenv("FLAGD_RELOAD_TIMEOUT", "150"))
_POLL = 2.0


def _read_config() -> dict:
    cm = get_json("get", "configmap", CONFIGMAP)
    raw = cm.get("data", {}).get(CONFIGMAP_KEY)
    if raw is None:
        raise ExecutorError(
            f"ConfigMap {CONFIGMAP!r} has no key {CONFIGMAP_KEY!r} "
            f"(keys: {sorted(cm.get('data', {}))})"
        )
    return json.loads(raw)


def _write_config(doc: dict) -> None:
    # merge-patch just the one key, so we don't fight helm's or kubectl-apply's
    # field ownership on the ConfigMap
    patch = json.dumps({"data": {CONFIGMAP_KEY: json.dumps(doc, indent=2)}})
    run("patch", "configmap", CONFIGMAP, "--type", "merge", "-p", patch)


def _resolve(flag_name: str) -> bool | None:
    """OFREP read; None if flagd/OFREP is unreachable."""
    try:
        resp = httpx.post(
            f"{OFREP_URL}/ofrep/v1/evaluate/flags/{flag_name}", json={}, timeout=5.0
        )
        resp.raise_for_status()
        return bool(resp.json().get("value"))
    except Exception as exc:
        print(f"flagd.py: OFREP unreachable at {OFREP_URL}: {exc!r}", file=sys.stderr)
        return None


def _confirm(flag_name: str, want: bool, timeout: float) -> bool | None:
    """Poll OFREP until it reflects `want`. None = OFREP never answered."""
    deadline = time.time() + timeout
    seen_any = False
    while time.time() < deadline:
        v = _resolve(flag_name)
        if v is not None:
            seen_any = True
            if v == want:
                return True
        time.sleep(_POLL)
    return False if seen_any else None


def set_flag(
    flag_name: str,
    enable: bool | str,
    *,
    timeout: float | None = None,
    restart_deploys: list[str] | None = None,
) -> ExecutionResult:
    """Set a flag's defaultVariant and wait for flagd to reload it.

    `enable` may be a bool (-> the flag's "on"/"off" variant) or an explicit
    variant name for flags that aren't boolean (e.g. paymentFailure's "100%").

    `restart_deploys` are rolled after the flag change and before confirmation —
    for flag consumers whose OpenFeature SDK does not pick up a flagd hot-reload
    on its own (the Kotlin fraud-detection client is one; the Go clients are not).
    """
    started = _now()
    timeout = RELOAD_TIMEOUT if timeout is None else timeout

    doc = _read_config()
    flags = doc.get("flags", {})
    if flag_name not in flags:
        raise ExecutorError(f"flag {flag_name!r} not in {CONFIGMAP_KEY} (have {len(flags)} flags)")
    variants = flags[flag_name].get("variants", {})
    variant = enable if isinstance(enable, str) else ("on" if enable else "off")
    if variant not in variants:
        raise ExecutorError(
            f"flag {flag_name!r} has no {variant!r} variant (has {sorted(variants)})"
        )
    on = bool(variants[variant]) and variant != "off"

    flags[flag_name]["defaultVariant"] = variant
    _write_config(doc)

    to_restart = list(restart_deploys or [])
    if RESTART_DEPLOY and RESTART_DEPLOY not in to_restart:
        to_restart.append(RESTART_DEPLOY)
    for dep in to_restart:
        run("rollout", "restart", f"deploy/{dep}")
    for dep in to_restart:
        run("rollout", "status", f"deploy/{dep}",
            f"--timeout={int(timeout)}s", timeout=timeout + 10)
    restarted = bool(to_restart)

    confirmed = _confirm(flag_name, on, timeout)
    success = confirmed is True or (restarted and confirmed is None)

    return ExecutionResult(
        action_type=ActionType.TOGGLE_FLAG.value,
        target_service="flagd",
        success=success,
        detail=f"set flag {flag_name} -> {variant}"
        + ("" if success else f" — OFREP did not reflect it within {timeout:.0f}s"),
        observed_state={
            "flag": flag_name, "default_variant": variant,
            "deploy_restarted": restarted, "restarted_deploys": to_restart,
            "ofrep_confirms": confirmed,
        },
        started_ts=started,
        finished_ts=_now(),
    )


def execute(action: Action, *, timeout: float | None = None) -> ExecutionResult:
    """Carry out a TOGGLE_FLAG action. Raises ExecutorError for other types."""
    if action.action_type != ActionType.TOGGLE_FLAG:
        raise ExecutorError(
            f"pre.execute.flagd handles TOGGLE_FLAG, not {action.action_type.value}"
        )
    flag_name = action.parameters.get("flag_name")
    if not flag_name:
        raise ExecutorError("TOGGLE_FLAG action missing parameters['flag_name']")
    return set_flag(flag_name, bool(action.parameters.get("enable", True)), timeout=timeout)
