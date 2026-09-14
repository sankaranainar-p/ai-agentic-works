"""pre/agents/training/featurize.py — System-agnostic feature vectors for the
fault_class triage model.

Two feature sources, both over fixed vocabularies so RE1-OB / RE1-SS / RE2-TT /
OpenRCA Bank all produce the same schema with zero train/test drift:

  A5 alert  (`featurize_alert`) — rule_id + payment_sli one-hot + KPI shape.
            KNOWN LIMITATION: near-uniform across fault classes because the
            synthesised alert collapses ~65% of cases to memory_saturation
            regardless of true fault (alert-synthesis race; see
            docs/a7_multisystem_training_report.md).

  A8 pack   (`featurize_pack`) — per metric-family aggregates over the ranked
            EvidencePack: strongest |z|, best rank, top-k count, and the
            family of the #1 candidate. This is where the fault-class signal
            actually lives (which metric family moved most, post-injection).

`featurize(case, alert, pack)` returns the concatenation (A5 ++ A8).

Deliberately excluded from both: service one-hot (system-specific, all-zero on
a held-out system) and TF-IDF over the rendered alert string.
"""

from __future__ import annotations

import numpy as np

from pre.agents.evidence import EvidencePack
from pre.agents.triage import KPIFeatures
from pre.signals.alert_synth import _RULES, Alert
from pre.signals.types import FailureCase

# --------------------------------------------------------------------------- #
# Shared: coarse metric family from a metric key / evidence id
# --------------------------------------------------------------------------- #
METRIC_FAMILIES: list[str] = ["cpu", "memory", "disk", "socket", "latency", "network", "other"]

_FAMILY_NEEDLES: list[tuple[str, str]] = [
    ("cpu", "cpu"),
    ("mem", "memory"),
    ("disk", "disk"), ("fs-", "disk"), ("diskio", "disk"),
    ("socket", "socket"), ("sockstat", "socket"),
    ("latency", "latency"), ("lag", "latency"),
    ("network", "network"), ("packet", "network"), ("receive", "network"), ("transmit", "network"),
]


def metric_family(key_or_id: str | None) -> str:
    """Family of a metric, by substring — robust to the different naming
    conventions across RCAEval RE1/RE2 (normalised suffixes) and OpenRCA /
    unmatched RE1-SS columns (raw Prometheus names)."""
    if not key_or_id:
        return "other"
    k = key_or_id.lower()
    for needle, fam in _FAMILY_NEEDLES:
        if needle in k:
            return fam
    return "other"


# --------------------------------------------------------------------------- #
# A5 alert features
# --------------------------------------------------------------------------- #
RULE_VOCAB: list[str] = [r.id for r in _RULES] + ["SILENT"]
SLI_VOCAB: list[str] = ["availability", "latency", "error_rate", "throughput", "consistency"]

ALERT_FEATURE_NAMES: list[str] = (
    [f"rule_{r}" for r in RULE_VOCAB]
    + [f"sli_{s}" for s in SLI_VOCAB]
    + ["kpi_breach_magnitude", "kpi_slope_60s", "kpi_co_breaching_services", "alert_silent"]
)


def featurize_alert(case: FailureCase, alert: Alert) -> np.ndarray:
    rule = alert.rule_id if (alert.rule_id and not alert.silent) else "SILENT"
    rule_oh = [1.0 if rule == r else 0.0 for r in RULE_VOCAB]
    sli_oh = KPIFeatures.sli_embedding(alert.payment_sli).astype(float).tolist()
    kpi = [
        float(KPIFeatures.breach_magnitude(alert, case)),
        float(KPIFeatures.slope_60s(case, alert.metric_key)),
        float(KPIFeatures.co_breaching_services(alert, case)),
    ]
    return np.array(rule_oh + sli_oh + kpi + [1.0 if alert.silent else 0.0], dtype=np.float64)


# --------------------------------------------------------------------------- #
# A8 evidence-pack features
# --------------------------------------------------------------------------- #
_TOPK = 10

PACK_FEATURE_NAMES: list[str] = (
    [f"ev_{f}_maxz" for f in METRIC_FAMILIES]
    + [f"ev_{f}_rankrecip" for f in METRIC_FAMILIES]
    + [f"ev_{f}_topk_count" for f in METRIC_FAMILIES]
    + [f"ev_top1_{f}" for f in METRIC_FAMILIES]
    + ["ev_item_count"]
)


def featurize_pack(pack: EvidencePack) -> np.ndarray:
    kpi_items = [(rank, it) for rank, it in enumerate(pack.items, start=1) if it.type == "kpi"]

    max_z = {f: 0.0 for f in METRIC_FAMILIES}
    best_rank = {f: None for f in METRIC_FAMILIES}
    topk_count = {f: 0 for f in METRIC_FAMILIES}

    for rank, it in kpi_items:
        fam = metric_family(it.id)
        z = abs(it.z_score) if it.z_score is not None else 0.0
        if z > max_z[fam]:
            max_z[fam] = z
        if best_rank[fam] is None:
            best_rank[fam] = rank
        if rank <= _TOPK:
            topk_count[fam] += 1

    top1_fam = metric_family(pack.items[0].id) if pack.items else "other"

    return np.array(
        [np.log1p(max_z[f]) for f in METRIC_FAMILIES]
        + [1.0 / best_rank[f] if best_rank[f] else 0.0 for f in METRIC_FAMILIES]
        + [float(topk_count[f]) for f in METRIC_FAMILIES]
        + [1.0 if top1_fam == f else 0.0 for f in METRIC_FAMILIES]
        + [float(len(pack.items))],
        dtype=np.float64,
    )


# --------------------------------------------------------------------------- #
# Combined
# --------------------------------------------------------------------------- #
FEATURE_NAMES: list[str] = ALERT_FEATURE_NAMES + PACK_FEATURE_NAMES


def featurize(case: FailureCase, alert: Alert, pack: EvidencePack) -> np.ndarray:
    return np.concatenate([featurize_alert(case, alert), featurize_pack(pack)])
