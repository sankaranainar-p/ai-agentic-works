"""
pre/classifier/model.py — Scikit-learn ML classifier for payment alerts.

TF-IDF + LinearSVC + CalibratedClassifierCV pipeline trained on synthetic
payment incident examples, labelled with the shared fault taxonomy from
data/taxonomy.yaml (see pre/classifier/taxonomy.py). Always runs — no
external dependencies at inference time.

The trained pipeline is persisted to models/ml_classifier.joblib with a
fixed random seed (RANDOM_SEED) so that:
  - training is fully reproducible, and
  - startup loads the cached model instead of refitting on every process
    start (see get_classifier()).

Delete models/ml_classifier.joblib (or bump MODEL_VERSION) to force a
retrain, e.g. after editing _TRAINING_DATA or data/taxonomy.yaml.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from pre.classifier.taxonomy import UNKNOWN_CATEGORY, all_categories

# ---------------------------------------------------------------------------
# Domain tables — keyed on the shared fault taxonomy (data/taxonomy.yaml)
# ---------------------------------------------------------------------------

CATEGORIES: list[str] = all_categories()

# Runbook URL per category
RUNBOOKS: dict[str, str] = {
    "cpu":                       "https://wiki.internal/runbooks/cpu-saturation",
    "memory":                    "https://wiki.internal/runbooks/memory-exhaustion",
    "disk":                      "https://wiki.internal/runbooks/disk-saturation",
    "socket":                    "https://wiki.internal/runbooks/socket-exhaustion",
    "delay":                     "https://wiki.internal/runbooks/latency-degradation",
    "loss":                      "https://wiki.internal/runbooks/packet-loss",
    "logic_error":               "https://wiki.internal/runbooks/logic-error",
    "concurrency_issue":         "https://wiki.internal/runbooks/concurrency-issue",
    "api_compatibility_issue":   "https://wiki.internal/runbooks/api-compatibility",
    "performance_bottleneck":    "https://wiki.internal/runbooks/performance-bottleneck",
    "exception_handling_error":  "https://wiki.internal/runbooks/exception-handling",
    "configuration_error":       "https://wiki.internal/runbooks/configuration-error",
    "dependency_failure":        "https://wiki.internal/runbooks/dependency-failure",
    UNKNOWN_CATEGORY:            "https://wiki.internal/runbooks/general",
}

# Escalation team per category
ROUTE_TO: dict[str, str] = {
    "cpu":                       "infrastructure-sre",
    "memory":                    "infrastructure-sre",
    "disk":                      "infrastructure-sre",
    "socket":                    "network-ops",
    "delay":                     "platform-engineering",
    "loss":                      "network-ops",
    "logic_error":               "payment-reliability",
    "concurrency_issue":         "payment-reliability",
    "api_compatibility_issue":   "platform-engineering",
    "performance_bottleneck":    "platform-engineering",
    "exception_handling_error":  "payment-reliability",
    "configuration_error":       "platform-engineering",
    "dependency_failure":        "payment-reliability",
    UNKNOWN_CATEGORY:            "payment-reliability",
}

# Default severity per category (may be overridden by severity_override rules)
SEVERITY_MAP: dict[str, str] = {
    "cpu":                       "SEV-2",
    "memory":                    "SEV-2",
    "disk":                      "SEV-2",
    "socket":                    "SEV-2",
    "delay":                     "SEV-2",
    "loss":                      "SEV-3",
    "logic_error":               "SEV-1",
    "concurrency_issue":         "SEV-2",
    "api_compatibility_issue":   "SEV-2",
    "performance_bottleneck":    "SEV-3",
    "exception_handling_error":  "SEV-1",
    "configuration_error":       "SEV-2",
    "dependency_failure":        "SEV-1",
    UNKNOWN_CATEGORY:            "SEV-3",
}


# ---------------------------------------------------------------------------
# Severity override rules  (evaluated in order; first match wins)
# ---------------------------------------------------------------------------

def _apply_severity_overrides(category: str, alert_text: str) -> Optional[str]:
    """Return an overriding SEV-N string or None to keep the SEVERITY_MAP default."""
    text = alert_text.lower()

    if category == "delay":
        import re
        match = re.search(r"(\d{2,6})\s*ms", text)
        if match and int(match.group(1)) > 3000:
            return "SEV-1"
        return "SEV-2"

    if category == "loss":
        import re
        match = re.search(r"(\d{1,3}(?:\.\d+)?)\s*%", text)
        if match and float(match.group(1)) > 10.0:
            return "SEV-1"
        return "SEV-3"

    return None


# ---------------------------------------------------------------------------
# Training data — alert phrases labelled with shared fault_class taxonomy
# ---------------------------------------------------------------------------

_TRAINING_DATA: list[tuple[str, str]] = [
    # cpu
    ("cpu utilization 98% payment service nodes", "cpu"),
    ("cpu stress detected on payment worker pods", "cpu"),
    ("high cpu load average payment processing host", "cpu"),
    ("cpu throttling detected payment container", "cpu"),
    ("sustained cpu saturation payment gateway node", "cpu"),
    # memory
    ("memory oom killed payment worker containers", "memory"),
    ("memory leak detected payment service heap growing", "memory"),
    ("out of memory error payment processing job", "memory"),
    ("memory usage 95% payment pod approaching limit", "memory"),
    ("garbage collection pauses increasing payment service memory pressure", "memory"),
    # disk
    ("disk io saturation payment service host", "disk"),
    ("disk usage 95% critical threshold payment database", "disk"),
    ("disk space exhausted payment log volume full", "disk"),
    ("write latency spike disk contention payment host", "disk"),
    ("disk read errors detected payment storage volume", "disk"),
    # socket
    ("database connection pool exhausted max connections reached", "socket"),
    ("socket exhaustion too many open file descriptors payment service", "socket"),
    ("connection refused payment service socket limit reached", "socket"),
    ("tcp connection pool exhausted payment gateway", "socket"),
    ("mysql connection timeout too many connections", "socket"),
    # delay
    ("p99 latency increased to 4500ms payment processing", "delay"),
    ("network delay injected between payment service and database", "delay"),
    ("inter-datacenter latency increased 200ms payment traffic", "delay"),
    ("slow response times detected average 3s payment checkout", "delay"),
    ("p99 latency spike 3200ms on checkout service", "delay"),
    # loss
    ("network packet loss 15% between payment services", "loss"),
    ("packet loss 18% between payment service and database", "loss"),
    ("tcp retransmit rate elevated network congestion payment", "loss"),
    ("packet loss injected on payment service network interface", "loss"),
    ("intermittent packet drops payment gateway uplink", "loss"),
    # logic_error
    ("payment service returning 500 errors spike detected", "logic_error"),
    ("http 500 error rate increased to 12% payment api", "logic_error"),
    ("null pointer exception in payment authorization logic", "logic_error"),
    ("incorrect discount calculation logic error checkout service", "logic_error"),
    ("internal server error rate above threshold payment endpoint", "logic_error"),
    # concurrency_issue
    ("db deadlock detected transaction rollback payment orders", "concurrency_issue"),
    ("race condition detected duplicate payment charges", "concurrency_issue"),
    ("thread pool deadlock payment processing service hung", "concurrency_issue"),
    ("concurrent modification exception payment order state", "concurrency_issue"),
    ("lock contention causing timeouts payment ledger service", "concurrency_issue"),
    # api_compatibility_issue
    ("api version mismatch payment gateway integration failing", "api_compatibility_issue"),
    ("schema incompatible payment service rejecting requests", "api_compatibility_issue"),
    ("breaking api change upstream payment provider integration failing", "api_compatibility_issue"),
    ("deprecated api endpoint returning errors payment client", "api_compatibility_issue"),
    ("protocol version mismatch payment service handshake failing", "api_compatibility_issue"),
    # performance_bottleneck
    ("throughput degraded transactions per second below baseline", "performance_bottleneck"),
    ("query execution time exceeding 30 seconds slow query payment db", "performance_bottleneck"),
    ("payment processing slow 10x baseline latency", "performance_bottleneck"),
    ("kafka consumer lag 500k messages payment events topic", "performance_bottleneck"),
    ("etl pipeline backlog growing payment analytics stalled", "performance_bottleneck"),
    # exception_handling_error
    ("unhandled exception crashing payment worker process", "exception_handling_error"),
    ("uncaught error payment service returning 502", "exception_handling_error"),
    ("exception swallowed silently payment retries failing", "exception_handling_error"),
    ("stack trace panic payment processing goroutine crashed", "exception_handling_error"),
    ("unrecovered exception loop payment queue consumer restarting", "exception_handling_error"),
    # configuration_error
    ("ssl certificate expiring in 24 hours payment gateway", "configuration_error"),
    ("misconfigured feature flag disabled payment checkout button", "configuration_error"),
    ("environment variable missing payment service failed to start", "configuration_error"),
    ("incorrect timeout configuration payment client dropping requests", "configuration_error"),
    ("wrong region endpoint configured payment service routing errors", "configuration_error"),
    # dependency_failure
    ("upstream payment provider unavailable third party outage", "dependency_failure"),
    ("saml assertion failures identity provider unreachable", "dependency_failure"),
    ("downstream fraud detection service unresponsive payment blocked", "dependency_failure"),
    ("third-party api down payment gateway calls failing", "dependency_failure"),
    ("dns resolution failures intermittent payment domain", "dependency_failure"),
    # unknown
    ("unknown alert payment system anomaly", "unknown"),
    ("unclassified incident payment platform", "unknown"),
    ("alert without clear category payment service", "unknown"),
]

RANDOM_SEED = 42
MODEL_VERSION = 1
_MODEL_PATH = Path(__file__).parent.parent.parent / "models" / f"ml_classifier_v{MODEL_VERSION}.joblib"


# ---------------------------------------------------------------------------
# MLResult (imported by llm.py; defined here as canonical source)
# ---------------------------------------------------------------------------

@dataclass
class MLResult:
    category: str
    severity: str
    confidence: float
    reasoning: str = ""


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class MLClassifier:
    """TF-IDF + LinearSVC classifier with probability calibration.

    Trained once with a fixed RANDOM_SEED and persisted to
    models/ml_classifier_v{MODEL_VERSION}.joblib. Subsequent process starts
    load the cached pipeline instead of refitting (see get_classifier()).
    """

    def __init__(self, pipeline: Optional[Pipeline] = None) -> None:
        self._pipeline = pipeline or self._train()

    @staticmethod
    def _train() -> Pipeline:
        texts, labels = zip(*_TRAINING_DATA)
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
            ("clf", CalibratedClassifierCV(
                LinearSVC(max_iter=2000, random_state=RANDOM_SEED),
                cv=3,
            )),
        ])
        pipeline.fit(list(texts), list(labels))
        return pipeline

    @classmethod
    def load_or_train(cls, model_path: Path = _MODEL_PATH) -> "MLClassifier":
        """Load the persisted pipeline from *model_path* if present,
        otherwise train fresh with RANDOM_SEED and persist it there.
        """
        if model_path.exists():
            pipeline = joblib.load(model_path)
            return cls(pipeline=pipeline)

        instance = cls()
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(instance._pipeline, model_path)
        return instance

    def classify(self, alert_text: str) -> MLResult:
        """Return the best category, its calibrated confidence, and severity."""
        probs = self._pipeline.predict_proba([alert_text])[0]
        classes = self._pipeline.classes_
        best_idx = int(probs.argmax())
        category = classes[best_idx]
        confidence = float(probs[best_idx])

        severity = (
            _apply_severity_overrides(category, alert_text)
            or SEVERITY_MAP.get(category, "SEV-3")
        )

        return MLResult(
            category=category,
            severity=severity,
            confidence=confidence,
            reasoning=f"ML classifier ({confidence:.0%} confidence)",
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_instance: Optional[MLClassifier] = None


def get_classifier() -> MLClassifier:
    """Return (and lazily initialise) the shared MLClassifier singleton.

    Loads the persisted model from models/ if present; otherwise trains
    once (with a fixed seed) and persists it, so later startups skip
    training entirely.
    """
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = MLClassifier.load_or_train()
    return _instance
