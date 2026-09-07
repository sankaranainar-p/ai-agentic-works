"""
pre/signals/alert_synth.py — Alert synthesiser (A5).

Turns a FailureCase's raw metric time series into a single synthetic
monitoring `Alert`, the way a real Prometheus/Datadog alerting pipeline
would: compute a robust z-score for every `svc:metric` series against
its own pre-injection baseline, find the first (earliest) timestamp at
which any metric breaches an ordered, versioned rule set
(`data/alert_rules.yaml`), and render alert text from a template chosen
deterministically per case. This gives every downstream classifier/agent
a uniform "what did monitoring actually see" signal instead of raw
telemetry, matching how incidents are actually detected in production
(a threshold alert fires, not "here are 1700 metric series, go look").

Design decisions:

- **Robust z-score, not mean/stddev.** Uses median and MAD (median
  absolute deviation, scaled by 1.4826 to be a consistent estimator of
  the standard deviation for normally-distributed data) computed over
  the pre-injection window, rather than mean/stddev. This matters
  because real telemetry pre-windows are not always clean: OpenRCA's
  own metric_container.csv has real sampling gaps (see
  pre/signals/openrca.py's forward-fill flags) and RCAEval's `workload`
  metrics can have occasional legitimate spikes even pre-fault. A single
  outlier in the pre-window inflates mean/stddev and can mask a real
  breach; median/MAD is far more resistant to that. `bench/baselines/
  rules.py` (B1) deliberately uses plain mean/stddev instead — that is
  intentional divergence (B1 is meant to be the "simplest possible"
  floor baseline; this module is meant to be the more realistic
  alerting simulation the actual pipeline would see), not an
  inconsistency to reconcile.

- **`t0` (the earliest data point in `case.metrics`) is the delay
  reference, not `GroundTruth.inject_time`; the pre/post baseline SPLIT
  point is the midpoint of the case's time range, matching
  `bench/baselines/rules.py` (B1)'s existing convention.** A FailureCase
  must never carry or receive GroundTruth (see pre/signals/types.py's
  isolation invariant, enforced across every adapter's tests) — an alert
  synthesiser simulating a real monitoring pipeline cannot legitimately
  know the "true" fault injection time either, since a real monitor
  doesn't get told that. This module therefore needs two distinct
  reference points, both derived only from the case's own timestamps:
    - the **baseline/breach boundary** (`all_times[len(all_times)//2]`,
      i.e. the temporal midpoint): everything strictly before this is
      the "pre-window" a metric's median/MAD is computed from; everything
      at or after it is scanned for breaches. Using the midpoint (not,
      say, "the first timestamp", which would leave zero pre-window
      samples to establish a baseline from) mirrors B1's own
      `inject_time is None` fallback exactly, so both baselines agree on
      what "pre-injection" means when the true injection time isn't
      available to either of them.
    - **`t0`** (`min(all_times)`, i.e. the start of the window): the
      reference `Alert.detection_delay_seconds` is measured from,
      approximating "time since the evidence window started" — the same
      frame of reference a human on-call engineer would have (they don't
      know the true injection time either; they know when their
      dashboard's data starts).
  Callers scoring against ground truth (e.g. bench/run_benchmark.py) can
  separately compute the *true* injection-to-detection delay using
  `GroundTruth.inject_time` and `Alert.breach_time` directly, but that
  arithmetic belongs to the scoring harness, not this module.

- **First breach = earliest breaching timestamp, not the single largest
  z-score.** See data/alert_rules.yaml's module comment for the full
  tie-breaking rationale (rule order, then service:metric key order,
  used only to break same-timestamp ties).

- **Deterministic template selection.** The specific rendering style
  (Prometheus- vs Datadog-flavoured text) for a given case is chosen by
  `int(sha1(case_id).hexdigest(), 16) % 2` — a case_id-derived, stable
  seed, not Python's randomized `hash()` (which varies per-process via
  PYTHONHASHSEED) and not the rule's own choice (a fixed rule->template
  mapping would make every case using that rule render identically,
  defeating the point of testing that both template families work).
  This makes `render(case)` a pure function of `case`: same case_id,
  same metrics -> byte-identical Alert.text every time, in every
  process, forever — the exact property tests/test_alert_synth.py's
  Hypothesis property test checks.

- **`Alert.silent` on no breach, and it must be counted.** A benchmark
  run over real fault-injection cases will legitimately have some cases
  where no configured rule's threshold is crossed (metrics too noisy
  pre-window, or the fault type isn't metric-visible at all — e.g.
  OpenRCA's own README FAQ notes network faults often aren't visible in
  metrics alone). Silently dropping these from a report would make
  detection-delay statistics look better than reality by only ever
  reporting delays for the *detected* subset. `synthesize_alerts_summary`
  (see below) and scripts/alert_detection_delay_report.py both report
  the silent count/rate alongside the delay distribution for exactly
  this reason.

- **KNOWN LIMITATION, verified against real data — a multiple-comparisons
  false-positive effect dominates detection delay on wide-metric-count
  cases.** OpenRCA Bank cases carry ~1700 scored metric series per case
  (versus RCAEval's ~49-75); at this module's z_threshold=3.0, the
  per-series-per-sample false-positive rate under a normal-ish
  distribution is ~0.27% two-sided, so `P(at least one series crosses
  threshold at any given sample) = 1 - (1 - 0.0027)^1700 ≈ 99%` for
  OpenRCA cases versus only ~12% for RCAEval's smaller cases (computed
  with scipy.stats.norm — see CONVERSION.md's alert_synth section for
  the exact numbers and the real-data run that surfaced this: 13
  independently-verified real OpenRCA cases ALL detected a breach at
  exactly the same delay, 900 seconds — the very first post-boundary
  sample — regardless of the case's actual injected fault). This is not
  a bug in the z-score computation (verified separately, see
  tests/test_alert_synth.py's `_robust_z_scores` unit tests and the two
  real floor-related bugs already found and fixed here) — it is a
  structural property of scanning thousands of independent series at a
  fixed per-series significance threshold without any multiple-testing
  correction (e.g. Bonferroni). A production alerting system facing this
  many series would need such a correction (or a smarter multivariate
  anomaly score); this module intentionally does not add one, since
  doing so would require the same claims-need-evidence rigor as
  everything else in this codebase and hasn't been separately verified
  — reporting the raw finding here and in
  scripts/alert_detection_delay_report.py's output is the honest
  alternative to silently presenting a misleadingly uniform delay
  distribution as if it reflected true detection latency.
"""

from __future__ import annotations

import hashlib
import re
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from pre.classifier.taxonomy import sli_map
from pre.signals.types import FailureCase

_RULES_PATH = Path(__file__).parent.parent.parent / "data" / "alert_rules.yaml"

_MAD_TO_STD = 1.4826  # scales MAD to be a consistent estimator of stddev for normal data
_MAD_ABSOLUTE_FLOOR = 1e-9  # avoid exact divide-by-zero when median_before is also 0
_MAD_RELATIVE_FLOOR = 0.01  # minimum scaled-MAD as a fraction of the pre-window's value scale


@dataclass(frozen=True)
class Rule:
    id: str
    metric_pattern: str
    z_threshold: float
    payment_sli_hint: str
    templates: dict[str, str]  # {"prometheus": ..., "datadog": ...}

    def __post_init__(self) -> None:
        # Validate the pattern compiles at load time, not at first use —
        # a bad regex in data/alert_rules.yaml should fail loudly and
        # immediately, not silently never-match deep inside a benchmark run.
        re.compile(self.metric_pattern)


@dataclass(frozen=True)
class Alert:
    """A single synthesised monitoring alert for one FailureCase.

    `silent=True` means no rule breached anywhere in the case's
    post-baseline-boundary window; every other field is then a
    placeholder default (empty string / None / 0), never fabricated
    data — see `Alert.silent_alert`.
    """

    case_id: str
    silent: bool
    rule_id: Optional[str]
    service: Optional[str]
    metric_key: Optional[str]  # full "svc:metric" key that breached
    z_score: Optional[float]
    breach_value: Optional[float]
    breach_time: Optional[int]  # unix seconds, the sample that first breached
    t0: int  # unix seconds, min timestamp across all of the case's metrics
    detection_delay_seconds: int  # breach_time - t0; 0 for silent alerts
    payment_sli: Optional[str]
    sli_source: Optional[str]  # "sli_map_exact" | "sli_map_keyword" | "rule_hint" | None
    template_style: Optional[str]  # "prometheus" | "datadog" | None
    text: str  # rendered alert text; "" for silent alerts
    rules_version: int

    @staticmethod
    def silent_alert(case_id: str, t0: int, rules_version: int) -> "Alert":
        return Alert(
            case_id=case_id,
            silent=True,
            rule_id=None,
            service=None,
            metric_key=None,
            z_score=None,
            breach_value=None,
            breach_time=None,
            t0=t0,
            detection_delay_seconds=0,
            payment_sli=None,
            sli_source=None,
            template_style=None,
            text="",
            rules_version=rules_version,
        )


def _load_rules() -> tuple[int, list[Rule]]:
    with _RULES_PATH.open() as fh:
        data = yaml.safe_load(fh)
    version = int(data["version"])
    rules = [
        Rule(
            id=r["id"],
            metric_pattern=r["metric_pattern"],
            z_threshold=float(r["z_threshold"]),
            payment_sli_hint=r["payment_sli_hint"],
            templates=dict(r["templates"]),
        )
        for r in data["rules"]
    ]
    return version, rules


# Loaded once at import time — data/alert_rules.yaml is a committed,
# versioned config file, not something that changes mid-process. Callers
# needing to test a modified rule set should monkeypatch _RULES/_RULES_VERSION
# or pass an explicit `rules` override to the functions below.
_RULES_VERSION, _RULES = _load_rules()


def _robust_z_scores(
    times: tuple[int, ...], values: tuple[float, ...], t0_breach_boundary: int
) -> list[tuple[int, float, float]]:
    """Return [(time, value, z_score), ...] for every sample at or after
    `t0_breach_boundary`, scored against the median/MAD of samples strictly
    before it. Returns [] if there are fewer than 2 pre-boundary samples
    (not enough to estimate a baseline) or no post-boundary samples.

    The MAD floor is relative to the pre-window's own value SCALE
    (`_MAD_RELATIVE_FLOOR * max(|median_before|, max(|v| for v in
    before))`), not the median alone and not a fixed absolute constant.
    Two distinct real failure modes were found and fixed here against
    real OpenRCA Bank telemetry (see CONVERSION.md's alert_synth
    section for the exact cases and numbers):
      1. A metric that is real but only barely noisy in its pre-window
         (e.g. a percentage metric sitting at ~52.25%, moving by
         hundredths of a percent between samples) can have a MAD that
         rounds to exactly 0.0 in floating point while the metric is
         nowhere near perfectly constant. Flooring at a fixed absolute
         epsilon there produces z-scores in the millions from a
         genuinely tiny, unremarkable fluctuation.
      2. A metric whose pre-window straddles zero (e.g. a disk I/O
         counter with values `[0.0, 0.0, 2.0, 5.0, 6.0]`, median 0)
         defeats a floor defined only as `_MAD_RELATIVE_FLOOR *
         |median_before|`, since that's also ~0 — this was the first fix
         attempted and it was NOT sufficient; a single real case
         (Tomcat04's DSKBps metric) still produced a z-score of
         ~2 x 10^9 from this exact shape of data before the floor was
         widened to use the pre-window's max absolute value, not just
         its median, as the scale reference.
    `_MAD_ABSOLUTE_FLOOR` remains as the final fallback only for the
    genuinely-all-zero pre-window case (both scale references are 0
    there).
    """
    before = [v for t, v in zip(times, values) if t < t0_breach_boundary]
    after = [(t, v) for t, v in zip(times, values) if t >= t0_breach_boundary]
    if len(before) < 2 or not after:
        return []

    median_before = statistics.median(before)
    mad = statistics.median(abs(v - median_before) for v in before)
    scale_reference = max(abs(median_before), max(abs(v) for v in before))
    relative_floor = _MAD_RELATIVE_FLOOR * scale_reference
    scaled_mad = max(mad * _MAD_TO_STD, relative_floor, _MAD_ABSOLUTE_FLOOR)

    return [(t, v, abs(v - median_before) / scaled_mad) for t, v in after]


def _select_template_style(case_id: str) -> str:
    """Deterministic, case_id-derived choice between "prometheus" and
    "datadog" rendering styles. Uses sha1 (not Python's built-in hash(),
    which is randomised per-process via PYTHONHASHSEED unless
    PYTHONHASHSEED=0) so this is stable across processes/machines/runs,
    which is exactly the property tests/test_alert_synth.py's
    determinism property test checks.
    """
    digest = hashlib.sha1(case_id.encode("utf-8")).hexdigest()
    return "prometheus" if int(digest, 16) % 2 == 0 else "datadog"


def _attach_payment_sli(system: str, service: str, rule: Rule) -> tuple[Optional[str], Optional[str]]:
    """Return (payment_sli, source) for a breach on `service` in `system`.

    Three tiers, tried in order (see module docstring for why an exact
    sli_map match often isn't available — service/metric naming in
    sli_map is aspirational for some systems, e.g. openrca_bank's
    "payment-gateway"/"core-banking" don't match any of OpenRCA Bank's
    real component names like "Tomcat01"):
      1. sli_map_exact: `sli_map[system]` has a `{service}.{metric}` key
         whose metric-name half shares a keyword with this rule's family
         (see _RULE_SLI_KEYWORDS) — the closest this module gets to a
         literal sli_map hit without requiring an exact metric-name match
         data/taxonomy.yaml doesn't promise (see below).
      2. sli_map_keyword: same as above but matched by keyword only
         (used when tier 1's stricter same-service check fails but this
         rule family is unambiguous, e.g. "latency" mapping to a SLI
         whose name contains "latency" anywhere in sli_map, regardless
         of which system/service, since the SLI list is small and
         globally shared).
      3. rule_hint: falls back to the rule's own `payment_sli_hint` —
         always succeeds, since every rule defines one. This is the
         common case for openrca_bank given the naming mismatch above.
    """
    mapping = sli_map().get(system, {})
    keywords = _RULE_SLI_KEYWORDS.get(rule.id, ())

    # Tier 1: same service, metric-name keyword overlap.
    for key, sli in mapping.items():
        svc, _, metric_name = key.partition(".")
        if svc == service and any(kw in metric_name.lower() for kw in keywords):
            return sli, "sli_map_exact"

    # Tier 2: any service in this system, metric-name keyword overlap.
    for key, sli in mapping.items():
        _, _, metric_name = key.partition(".")
        if any(kw in metric_name.lower() for kw in keywords):
            return sli, "sli_map_keyword"

    # Tier 3: rule's own hint.
    return rule.payment_sli_hint, "rule_hint"


# Keywords used to match a rule's family against sli_map's metric-name
# vocabulary (see _attach_payment_sli). Kept separate from
# data/alert_rules.yaml's `payment_sli_hint` since these are about
# matching existing sli_map key text, not choosing a fallback value.
_RULE_SLI_KEYWORDS: dict[str, tuple[str, ...]] = {
    "memory_saturation": ("availability",),
    "cpu_saturation": ("availability",),
    "latency_degradation": ("latency", "lag"),
    "error_rate_spike": ("error", "auth", "success"),
    "disk_pressure": ("availability",),
    "socket_saturation": ("queue", "lag", "consumer"),
    "generic_anomaly": ("availability",),
}


def synthesize_alert(case: FailureCase, rules: Optional[list[Rule]] = None, rules_version: Optional[int] = None) -> Alert:
    """Compute and render one Alert for `case`.

    `rules`/`rules_version` are overridable for testing a modified rule
    set without touching the committed data/alert_rules.yaml; production
    callers should omit both and get the loaded committed rules.
    """
    active_rules = rules if rules is not None else _RULES
    active_version = rules_version if rules_version is not None else _RULES_VERSION

    all_times = sorted({t for series in case.metrics.values() for t in series.times})
    t0 = all_times[0] if all_times else 0
    baseline_boundary = all_times[len(all_times) // 2] if all_times else 0

    if not case.metrics or not all_times:
        return Alert.silent_alert(case.case_id, t0, active_version)

    # For each rule (in file order), for each metric key matching that
    # rule's pattern, compute all breaches at/after the baseline boundary
    # (see module docstring for why this differs from t0). Keep the
    # single earliest breach across ALL rules/metrics; ties broken by
    # rule order (active_rules' list order) then by service:metric key
    # (alphabetical) — see data/alert_rules.yaml's module comment.
    best: Optional[tuple[int, int, str, str, float, float, Rule]] = None
    # tuple shape: (breach_time, rule_priority_index, metric_key, service, z_score, value, rule)

    for rule_priority_index, rule in enumerate(active_rules):
        for metric_key, series in case.metrics.items():
            _service, _, suffix = metric_key.partition(":")
            if not re.search(rule.metric_pattern, suffix):
                continue
            breaches = _robust_z_scores(series.times, series.values, baseline_boundary)
            crossing = [(t, v, z) for t, v, z in breaches if z >= rule.z_threshold]
            if not crossing:
                continue
            first_time, first_value, first_z = min(crossing, key=lambda x: x[0])
            candidate = (first_time, rule_priority_index, metric_key, _service, first_z, first_value, rule)
            if best is None or (candidate[0], candidate[1], candidate[2]) < (best[0], best[1], best[2]):
                best = candidate

    if best is None:
        return Alert.silent_alert(case.case_id, t0, active_version)

    breach_time, _priority, metric_key, service, z_score, value, rule = best
    payment_sli, sli_source = _attach_payment_sli(case.system, service, rule)
    style = _select_template_style(case.case_id)
    duration = max(breach_time - t0, 0)
    _svc, _, suffix = metric_key.partition(":")

    text = rule.templates[style].format(
        service=service,
        metric=suffix,
        value=value,
        z_score=z_score,
        duration=duration,
        monitor_id=_monitor_id(case.case_id, rule.id),
    )

    return Alert(
        case_id=case.case_id,
        silent=False,
        rule_id=rule.id,
        service=service,
        metric_key=metric_key,
        z_score=z_score,
        breach_value=value,
        breach_time=breach_time,
        t0=t0,
        detection_delay_seconds=duration,
        payment_sli=payment_sli,
        sli_source=sli_source,
        template_style=style,
        text=text,
        rules_version=active_version,
    )


def _monitor_id(case_id: str, rule_id: str) -> str:
    """Deterministic 5-digit "monitor id" for Datadog-style templates,
    derived the same way _select_template_style is (sha1, not hash()) so
    it's stable across processes.
    """
    digest = hashlib.sha1(f"{case_id}:{rule_id}".encode("utf-8")).hexdigest()
    return str(int(digest, 16) % 100000).zfill(5)


@dataclass
class AlertsSummary:
    total_cases: int
    silent_count: int
    detected_count: int
    detection_delays_seconds: list[int] = field(default_factory=list)

    @property
    def silent_rate(self) -> float:
        return self.silent_count / self.total_cases if self.total_cases else 0.0


def synthesize_alerts_summary(cases: list[FailureCase]) -> tuple[list[Alert], AlertsSummary]:
    """Synthesise one Alert per case and summarise the silent rate and
    detection-delay distribution across all of them — the shared logic
    behind scripts/alert_detection_delay_report.py, factored out so tests
    can exercise it without shelling out to the script.
    """
    alerts = [synthesize_alert(case) for case in cases]
    silent = [a for a in alerts if a.silent]
    detected = [a for a in alerts if not a.silent]
    summary = AlertsSummary(
        total_cases=len(cases),
        silent_count=len(silent),
        detected_count=len(detected),
        detection_delays_seconds=[a.detection_delay_seconds for a in detected],
    )
    return alerts, summary
