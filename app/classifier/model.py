"""
app/classifier/model.py — Scikit-learn ML classifier for payment alerts.

TF-IDF + LinearSVC + CalibratedClassifierCV pipeline trained on synthetic
payment incident examples.  Always runs — no external dependencies at
inference time.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

# ---------------------------------------------------------------------------
# Domain tables
# ---------------------------------------------------------------------------

CATEGORIES: list[str] = [
    "http_500_spike",
    "ddos_attack",
    "availability_drop",
    "performance_degradation",
    "database",
    "authentication",
    "network",
    "data_pipeline",
    "infrastructure",
    "security",
    "unknown",
]

# Runbook URL per category
RUNBOOKS: dict[str, str] = {
    "http_500_spike":         "https://wiki.internal/runbooks/http-500-spike",
    "ddos_attack":            "https://wiki.internal/runbooks/ddos-attack",
    "availability_drop":      "https://wiki.internal/runbooks/availability-drop",
    "performance_degradation":"https://wiki.internal/runbooks/performance-degradation",
    "database":               "https://wiki.internal/runbooks/database",
    "authentication":         "https://wiki.internal/runbooks/authentication",
    "network":                "https://wiki.internal/runbooks/network",
    "data_pipeline":          "https://wiki.internal/runbooks/data-pipeline",
    "infrastructure":         "https://wiki.internal/runbooks/infrastructure",
    "security":               "https://wiki.internal/runbooks/security",
    "unknown":                "https://wiki.internal/runbooks/general",
}

# Escalation team per category
ROUTE_TO: dict[str, str] = {
    "http_500_spike":         "payment-reliability",
    "ddos_attack":            "security-ops",
    "availability_drop":      "payment-reliability",
    "performance_degradation":"platform-engineering",
    "database":               "database-reliability",
    "authentication":         "identity-platform",
    "network":                "network-ops",
    "data_pipeline":          "data-engineering",
    "infrastructure":         "infrastructure-sre",
    "security":               "security-ops",
    "unknown":                "payment-reliability",
}

# Default severity per category (may be overridden by severity_override rules)
SEVERITY_MAP: dict[str, str] = {
    "http_500_spike":         "SEV-1",
    "ddos_attack":            "SEV-1",
    "availability_drop":      "SEV-1",
    "performance_degradation":"SEV-3",
    "database":               "SEV-2",
    "authentication":         "SEV-2",
    "network":                "SEV-3",
    "data_pipeline":          "SEV-2",
    "infrastructure":         "SEV-3",
    "security":               "SEV-2",
    "unknown":                "SEV-3",
}


# ---------------------------------------------------------------------------
# Severity override rules  (evaluated in order; first match wins)
# ---------------------------------------------------------------------------

def _apply_severity_overrides(category: str, alert_text: str) -> Optional[str]:
    """Return an overriding SEV-N string or None to keep the SEVERITY_MAP default."""
    text = alert_text.lower()

    if category == "ddos_attack":
        return "SEV-1"

    if category == "availability_drop":
        import re
        # e.g. "availability 98.5%", "uptime: 99.0%", "99.8% availability"
        match = re.search(r"(\d{1,3}(?:\.\d+)?)\s*%", text)
        if match:
            pct = float(match.group(1))
            if pct < 99.9:
                return "SEV-1"
        return "SEV-2"

    if category == "http_500_spike":
        import re
        # e.g. "error rate 7%", "8.3% errors", "12% 5xx"
        match = re.search(r"(\d{1,3}(?:\.\d+)?)\s*%", text)
        if match:
            rate = float(match.group(1))
            if rate > 5.0:
                return "SEV-1"
        return "SEV-2"

    if category in ("database", "authentication", "data_pipeline", "security"):
        return "SEV-2"

    if category in ("performance_degradation", "infrastructure", "network"):
        return "SEV-3"

    return None


# ---------------------------------------------------------------------------
# Training data
# ---------------------------------------------------------------------------

_TRAINING_DATA: list[tuple[str, str]] = [
    # http_500_spike
    ("payment service returning 500 errors spike detected", "http_500_spike"),
    ("http 500 error rate increased to 12%", "http_500_spike"),
    ("internal server error rate above threshold", "http_500_spike"),
    ("5xx responses spiking on checkout endpoint", "http_500_spike"),
    ("server errors 503 gateway error payment api", "http_500_spike"),
    ("error rate 8% on /api/payments endpoint", "http_500_spike"),
    ("500 internal server errors high volume", "http_500_spike"),
    # ddos_attack
    ("volumetric attack detected 500k requests per minute", "ddos_attack"),
    ("ddos botnet traffic overwhelming payment gateway", "ddos_attack"),
    ("waf triggered flood of requests from multiple ips", "ddos_attack"),
    ("request flood detected abnormal traffic spike", "ddos_attack"),
    ("distributed denial of service attack in progress", "ddos_attack"),
    ("syn flood attack detected on port 443", "ddos_attack"),
    ("bot traffic 1M rps WAF rate limit triggered", "ddos_attack"),
    # availability_drop
    ("payment service unavailable health check failing", "availability_drop"),
    ("service down uptime 97% below threshold", "availability_drop"),
    ("availability dropped to 98.5% last 5 minutes", "availability_drop"),
    ("payment endpoint returning 503 service unavailable", "availability_drop"),
    ("all payment nodes unresponsive health probe failed", "availability_drop"),
    ("uptime 99.1% SLA breach imminent", "availability_drop"),
    ("checkout service not responding", "availability_drop"),
    # performance_degradation
    ("p99 latency increased to 4500ms payment processing", "performance_degradation"),
    ("slow response times detected average 3s timeout approaching", "performance_degradation"),
    ("throughput degraded transactions per second below baseline", "performance_degradation"),
    ("latency spike p95 above 2000ms", "performance_degradation"),
    ("payment processing slow 10x baseline latency", "performance_degradation"),
    ("response time degradation detected on payment api", "performance_degradation"),
    # database
    ("database connection pool exhausted max connections reached", "database"),
    ("postgres replication lag 45 seconds primary replica", "database"),
    ("query execution time exceeding 30 seconds slow query log", "database"),
    ("database disk usage 95% critical threshold", "database"),
    ("mysql connection timeout too many connections", "database"),
    ("db deadlock detected transaction rollback", "database"),
    ("payment database read replica lag 120s", "database"),
    # authentication
    ("oauth token validation failures increased 400%", "authentication"),
    ("ssl certificate expiring in 24 hours payment gateway", "authentication"),
    ("jwt signature verification failing auth service down", "authentication"),
    ("authentication service 401 errors spike", "authentication"),
    ("api key invalid unauthorized payment requests", "authentication"),
    ("saml assertion failures identity provider unreachable", "authentication"),
    # network
    ("network packet loss 15% between payment services", "network"),
    ("dns resolution failures intermittent payment domain", "network"),
    ("bgp route flap detected upstream provider", "network"),
    ("inter-datacenter latency increased 200ms packet loss", "network"),
    ("tcp retransmit rate elevated network congestion", "network"),
    ("mtu mismatch causing fragmentation payment vlan", "network"),
    # data_pipeline
    ("kafka consumer lag 500k messages payment events topic", "data_pipeline"),
    ("etl pipeline failed payment transactions not processed", "data_pipeline"),
    ("data ingestion backlog growing realtime pipeline stalled", "data_pipeline"),
    ("stream processing job crashed payment analytics pipeline", "data_pipeline"),
    ("message queue full dropping payment events", "data_pipeline"),
    # infrastructure
    ("kubernetes pod crashlooping payment deployment", "infrastructure"),
    ("cpu utilization 98% payment service nodes", "infrastructure"),
    ("memory oom killed payment worker containers", "infrastructure"),
    ("disk io saturation payment service host", "infrastructure"),
    ("node not ready kubernetes cluster payment namespace", "infrastructure"),
    ("container restart loop payment microservice", "infrastructure"),
    # security
    ("unusual login attempts brute force payment admin", "security"),
    ("sql injection attempt detected payment api", "security"),
    ("data exfiltration alert large outbound transfer", "security"),
    ("privilege escalation detected payment service account", "security"),
    ("xss attempt blocked payment checkout form", "security"),
    ("suspicious api access pattern payment credentials", "security"),
    # unknown
    ("unknown alert payment system anomaly", "unknown"),
    ("unclassified incident payment platform", "unknown"),
    ("alert without clear category payment service", "unknown"),
]


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
    """TF-IDF + LinearSVC classifier with probability calibration."""

    def __init__(self) -> None:
        texts, labels = zip(*_TRAINING_DATA)
        self._pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
            ("clf", CalibratedClassifierCV(LinearSVC(max_iter=2000), cv=3)),
        ])
        self._pipeline.fit(list(texts), list(labels))

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
    """Return (and lazily initialise) the shared MLClassifier singleton."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = MLClassifier()
    return _instance
