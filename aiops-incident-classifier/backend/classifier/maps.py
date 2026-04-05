"""Shared routing and runbook maps for all classifiers."""
from backend.models.schemas import Category

ROUTING_MAP: dict[Category, str] = {
    Category.INFRASTRUCTURE:          "Platform SRE",
    Category.APPLICATION:             "App Engineering On-Call",
    Category.DATABASE:                "Database Reliability",
    Category.NETWORK:                 "Network Ops",
    Category.SECURITY:                "Security Response",
    Category.DATA_PIPELINE:           "Data Engineering",
    Category.PERFORMANCE_DEGRADATION: "Performance Engineering",
    Category.AVAILABILITY:            "SRE On-Call",
    Category.DDOS_ATTACK:             "Security Response",
    Category.AVAILABILITY_DROP:       "SRE On-Call",
    Category.HTTP_500_SPIKE:          "App Engineering On-Call",
}

RUNBOOK_MAP: dict[Category, list[str]] = {
    Category.INFRASTRUCTURE:          ["Check host metrics via Datadog/Dynatrace", "Restart affected services", "Review system logs", "Escalate if OOM persists"],
    Category.APPLICATION:             ["Check APM traces", "Review recent deployments", "Scale pods if needed", "Check feature flags"],
    Category.DATABASE:                ["Check replication lag", "Review slow query log", "Check connection pool", "Initiate failover if primary down"],
    Category.NETWORK:                 ["Check BGP routes", "Verify firewall rules", "Test connectivity", "Contact ISP if external"],
    Category.SECURITY:                ["Isolate affected systems", "Rotate credentials immediately", "Open P1 security ticket", "Notify CISO"],
    Category.DATA_PIPELINE:           ["Check pipeline DAG in Airflow", "Review task failures", "Validate source data schema", "Reprocess failed batches"],
    Category.PERFORMANCE_DEGRADATION: ["Profile hot paths", "Check cache hit rate", "Scale horizontally", "Review recent config changes"],
    Category.AVAILABILITY:            ["Check health endpoints", "Failover to DR region", "Page secondary on-call", "Engage incident commander"],
    Category.DDOS_ATTACK:             ["Enable rate limiting via CDN WAF", "Block offending IP ranges", "Engage CDN WAF rules", "Contact upstream ISP for null-routing"],
    Category.AVAILABILITY_DROP:       ["Check load balancer targets", "Review error rates", "Drain unhealthy pods", "Trigger auto-scaling"],
    Category.HTTP_500_SPIKE:          ["Check app logs for stack traces", "Review recent config changes", "Roll back if needed", "Check upstream dependencies"],
}
