"""
pre/remediation/handlers — One async handler per fault_class category.

Categories are the shared taxonomy from data/taxonomy.yaml (see
pre/classifier/taxonomy.py): cpu, memory, disk, socket, delay, loss,
logic_error, concurrency_issue, api_compatibility_issue,
performance_bottleneck, exception_handling_error, configuration_error,
dependency_failure, plus the operational "unknown" fallback.

All handlers are simulated (no real infra changes).  Each inspects the
alert_text to tailor its response message.  Replace the bodies with real
kubectl / API calls as your infrastructure allows.
"""

from __future__ import annotations

from pre.remediation import RemediationResult


async def handle_cpu(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Triggered horizontal pod autoscaler and evicted low-priority workloads",
        simulated=True,
        success=True,
        details="CPU load distributing across new pods; utilisation dropping.",
        escalate=severity == "SEV-1",
        escalation_reason="SEV-1 CPU saturation — payment throughput at risk" if severity == "SEV-1" else "",
    )


async def handle_memory(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Restarted OOM-killed pods and adjusted memory limits upward",
        simulated=True,
        success=True,
        details="Pods restarted with increased memory limits; no further OOM events.",
        escalate=severity == "SEV-1",
        escalation_reason="SEV-1 memory exhaustion — payment throughput at risk" if severity == "SEV-1" else "",
    )


async def handle_disk(alert_text: str, severity: str) -> RemediationResult:
    text = alert_text.lower()
    if "log" in text or "temp" in text:
        action = "Triggered emergency log rotation and freed temp files"
        details = "Disk space recovered; alerting if usage climbs above 80% again."
    else:
        action = "Migrated hot data to faster storage tier and cleared stale temp files"
        details = "Disk I/O pressure relieved; storage metrics normalising."
    return RemediationResult(
        action_taken=action,
        simulated=True,
        success=True,
        details=details,
        escalate=severity == "SEV-1",
        escalation_reason="SEV-1 disk saturation — payment persistence at risk" if severity == "SEV-1" else "",
    )


async def handle_socket(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Reset connection pool and terminated idle long-running connections",
        simulated=True,
        success=True,
        details="Pool reset complete; connection count normalising.",
        escalate=severity in ("SEV-1", "SEV-2"),
        escalation_reason="Socket exhaustion escalates to database-reliability" if severity in ("SEV-1", "SEV-2") else "",
    )


async def handle_delay(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Enabled request hedging and reduced downstream timeout budgets",
        simulated=True,
        success=True,
        details="Latency mitigation applied; p99 should improve within 5 min.",
        escalate=severity == "SEV-1",
        escalation_reason="SEV-1 latency degradation — checkout SLO breach risk" if severity == "SEV-1" else "",
    )


async def handle_loss(alert_text: str, severity: str) -> RemediationResult:
    text = alert_text.lower()
    if "bgp" in text:
        action = "Rerouted payment traffic to alternate network path"
    else:
        action = "Failed over to secondary network path and reset affected interfaces"
    return RemediationResult(
        action_taken=action,
        simulated=True,
        success=True,
        details="Traffic rerouted; packet loss on primary path being investigated with carrier.",
        escalate=severity == "SEV-1",
        escalation_reason="SEV-1 packet loss — payment connectivity at risk" if severity == "SEV-1" else "",
    )


async def handle_logic_error(alert_text: str, severity: str) -> RemediationResult:
    text = alert_text.lower()
    if "checkout" in text or "payment" in text:
        action = "Rolled back last payment-service deployment and cleared CDN cache"
        details = "Deployment rollback triggered; error rate should normalise within 2 min."
    else:
        action = "Reverted feature flag and restarted affected service replicas"
        details = "Rollback complete; error rate being monitored."
    return RemediationResult(
        action_taken=action,
        simulated=True,
        success=True,
        details=details,
        escalate=True,
        escalation_reason="Logic errors in payment path always escalate to payment-reliability",
    )


async def handle_concurrency_issue(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Released stuck locks and restarted affected worker threads",
        simulated=True,
        success=True,
        details="Deadlocked transactions rolled back; lock contention clearing.",
        escalate=severity in ("SEV-1", "SEV-2"),
        escalation_reason="Concurrency issues risk duplicate payment charges" if severity in ("SEV-1", "SEV-2") else "",
    )


async def handle_api_compatibility_issue(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Pinned client to last known-good API version and notified integration owner",
        simulated=True,
        success=True,
        details="Compatibility shim applied; requests succeeding against pinned version.",
        escalate=severity in ("SEV-1", "SEV-2"),
        escalation_reason="API compatibility break requires provider coordination" if severity in ("SEV-1", "SEV-2") else "",
    )


async def handle_performance_bottleneck(alert_text: str, severity: str) -> RemediationResult:
    text = alert_text.lower()
    if "kafka" in text or "consumer" in text or "lag" in text:
        action = "Scaled Kafka consumer group and reset consumer offsets for stale partitions"
        details = "Consumer lag decreasing; pipeline throughput increasing."
    elif "query" in text or "db" in text:
        action = "Identified and killed top-5 slow queries; updated query cache"
        details = "Slow queries terminated; execution plan cache refreshed."
    else:
        action = "Scaled payment workers horizontally to restore throughput"
        details = "Additional workers provisioned; throughput recovering."
    return RemediationResult(
        action_taken=action,
        simulated=True,
        success=True,
        details=details,
        escalate=False,
    )


async def handle_exception_handling_error(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Restarted crashed worker process and added exception guard around failing call",
        simulated=True,
        success=True,
        details="Worker restarted; hotfix deployed to catch and retry the failing call path.",
        escalate=True,
        escalation_reason="Unhandled exceptions in payment path always escalate to payment-reliability",
    )


async def handle_configuration_error(alert_text: str, severity: str) -> RemediationResult:
    text = alert_text.lower()
    if "certificate" in text or "cert" in text or "ssl" in text or "tls" in text:
        action = "Triggered emergency certificate rotation via cert-manager"
        details = "New certificate issued; old cert will be revoked after 5 min grace period."
    else:
        action = "Reverted misconfigured setting to last known-good value"
        details = "Configuration rolled back; service behaviour restored."
    return RemediationResult(
        action_taken=action,
        simulated=True,
        success=True,
        details=details,
        escalate=severity in ("SEV-1", "SEV-2"),
        escalation_reason="Configuration errors escalate to platform-engineering" if severity in ("SEV-1", "SEV-2") else "",
    )


async def handle_dependency_failure(alert_text: str, severity: str) -> RemediationResult:
    text = alert_text.lower()
    if "dns" in text:
        action = "Flushed DNS caches and failed over to secondary DNS resolvers"
        details = "DNS resolution restored via backup resolvers."
    else:
        action = "Failed over to backup provider and queued affected requests for replay"
        details = "Traffic shifted to backup dependency; queued requests replaying."
    return RemediationResult(
        action_taken=action,
        simulated=True,
        success=True,
        details=details,
        escalate=True,
        escalation_reason="Upstream dependency failures always escalate to payment-reliability",
    )


async def handle_unknown(alert_text: str, severity: str) -> RemediationResult:
    return RemediationResult(
        action_taken="Collected diagnostic bundle and engaged on-call engineer",
        simulated=True,
        success=True,
        details=(
            "Alert could not be automatically classified. "
            "Diagnostic logs collected; on-call engineer paged for manual triage."
        ),
        escalate=True,
        escalation_reason="Unknown category — manual triage required",
    )
