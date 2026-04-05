"""
Generates a synthetic dataset of ~500 labeled incidents across 11 categories.
Run: python backend/data/generate_dataset.py
"""
import json
import random
import uuid
from pathlib import Path

random.seed(42)

TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "infrastructure": [
        ("Host CPU above 95% — {host}", "CPU utilization on {host} has exceeded 95% for over 5 minutes. Load average: {load}. Processes: high java heap usage detected."),
        ("Disk usage critical on {host}", "Disk /var/log on {host} is at 98% capacity. Log rotation may have failed. Free space: {free}MB."),
        ("OOM killer triggered on {host}", "The OOM killer terminated process {pid} on {host}. Available memory: {mem}MB. Swap usage: 100%."),
        ("Kubernetes node NotReady: {node}", "Node {node} transitioned to NotReady state. Kubelet heartbeat missed for 120s. Check node health and network connectivity."),
        ("EC2 instance terminated unexpectedly: {host}", "Instance {host} was terminated by AWS auto-scaling. Replacement launching. Check instance health metrics."),
        ("Container restart loop on {node}", "Container {svc} on {node} has restarted 10 times in 15 minutes. Exit code: 137. Possible OOM or crash."),
    ],
    "application": [
        ("Service {svc} error rate above 5%", "Error rate for service {svc} has reached {rate}% over the last 10 minutes. P99 latency: {lat}ms. Check recent deployments."),
        ("Unhealthy pods in deployment {dep}", "{dep} has {pods} unhealthy pods out of {total}. CrashLoopBackOff detected. Last exit code: 137."),
        ("API gateway returning 502s for {svc}", "Upstream {svc} is unreachable from API gateway. Connection refused on port 8080. Health check failing."),
        ("Memory leak detected in {svc}", "Heap usage for {svc} growing 50MB/hr. JVM GC overhead limit exceeded. Restart recommended."),
        ("Deployment rollout stalled for {dep}", "Deployment {dep} rollout stalled at 60%. New pods not becoming ready. Check resource limits and liveness probes."),
        ("Feature flag misconfiguration in {svc}", "Feature flag 'enable_new_checkout' in {svc} toggled for 100% of users. Unexpected behavior reported."),
    ],
    "database": [
        ("PostgreSQL replication lag > 30s on {db}", "Replica {replica} is {lag}s behind primary {db}. WAL receiver disconnected. Writes may be at risk."),
        ("Slow query detected: {query_time}s on {db}", "Query exceeded {query_time}s on {db}: {query}. Table scan on payments.transactions (200M rows). Index missing."),
        ("Connection pool exhausted on {db}", "Max connections ({max_conn}) reached on {db}. New connections queued. Application response times degrading."),
        ("Redis eviction rate spiking on {cache}", "Evictions/sec: {evictions} on {cache}. maxmemory-policy: allkeys-lru. Cache hit rate dropped to {hit_rate}%."),
        ("Database failover triggered on {db}", "Primary {db} became unreachable. Automatic failover to {replica} initiated. Expected downtime: 30-60 seconds."),
        ("Deadlock detected on {db}", "Deadlock between transactions on {db}.payments table. Frequency: {evictions} deadlocks/hr. Query optimization needed."),
    ],
    "network": [
        ("Network packet loss > 10% on {interface}", "Packet loss of {loss}% detected on {interface}. Affecting {services}. Check cable/transceiver health."),
        ("BGP session down with peer {peer}", "BGP session to {peer} (AS{asn}) went down at {time}. Failover to secondary path activated."),
        ("Firewall rule change detected on {fw}", "Unauthorized change to firewall {fw}: rule 42 modified. Source IP: {src_ip}. Review access logs."),
        ("VPN tunnel flapping to {site}", "VPN tunnel to {site} established/torn down 8 times in 15 minutes. Possible ISP instability."),
        ("DNS resolution failure for {svc}", "DNS lookup for {svc}.internal failing. NXDOMAIN response. Service discovery impacted across {region}."),
        ("Load balancer health checks failing", "ALB target group health: 2/8 targets healthy. {svc} traffic partially disrupted. Unhealthy reason: timeout."),
    ],
    "security": [
        ("Brute force login attempt from {ip}", "{count} failed login attempts from {ip} in 5 minutes. Account {user} locked. GeoIP: {country}."),
        ("Unusual data exfiltration pattern for {user}", "User {user} accessed {records} records in 1 hour — 50x their baseline. DLP alert triggered."),
        ("Dependency vulnerability CVE-{cve} in {svc}", "Critical CVE-{cve} found in {lib} v{ver} used by {svc}. CVSS: {score}. Patch available."),
        ("API key exposed in public repository", "API key for service {svc} detected in public GitHub repo {repo}. Immediate rotation required."),
        ("Privilege escalation detected for {user}", "User {user} executed sudo commands {count} times in 10 minutes without prior authorization pattern."),
        ("Malicious IP accessing payment API", "Known malicious IP {ip} ({country}) made {count} requests to /api/v2/payments. Rate limiting applied. Block recommended."),
    ],
    "data_pipeline": [
        ("Airflow DAG {dag} failed at task {task}", "DAG {dag} failed at task {task} after {retries} retries. Error: {error}. Downstream pipelines affected."),
        ("Kafka consumer lag > 100k for topic {topic}", "Consumer group {group} is {lag} messages behind on {topic}. Producer rate exceeds consumer rate."),
        ("ETL job {job} producing null values", "ETL job {job} wrote {nulls}% null values to {table}. Schema change in source detected."),
        ("S3 data quality check failed for {bucket}", "Data quality check failed for {bucket}/{prefix}. {bad_rows} rows failed validation rules."),
        ("Spark job OOM on {job}", "Spark job {job} failed with OutOfMemoryError on executor. Executor memory: 4g. Increase partition count or memory."),
        ("Pipeline SLA breach: {dag} not completed", "DAG {dag} did not complete by SLA deadline. Downstream reports will be delayed. Business impact: {users} users affected."),
    ],
    "performance_degradation": [
        ("P99 latency spike on {endpoint}", "P99 latency for {endpoint} reached {lat}ms (threshold: 500ms). Throughput: {tps} TPS. Possible GC pause."),
        ("Cache hit rate dropped to {rate}% on {cache}", "Cache {cache} hit rate dropped from 95% to {rate}%. Cold start or TTL misconfiguration suspected."),
        ("Thread pool saturation on {svc}", "Worker threads at 100% utilization on {svc}. Queue depth: {queue}. Consider increasing pool size."),
        ("Slow rendering on checkout page", "Checkout page P95 load time: {time}ms. Third-party script {script} taking {script_time}ms. Async load recommended."),
        ("Database query performance regression", "Average query time on {db} increased 3x after recent migration. Execution plan changed. Analyze and re-index."),
        ("API response time degradation for {svc}", "Median response time for {svc} increased from 120ms to {lat}ms over past hour. No errors yet, but trending up."),
    ],
    "availability": [
        ("Health check failing for {svc}", "Health check endpoint /health on {svc} returning 503 for {duration}. Dependencies: {deps}. Circuit breaker open."),
        ("Service {svc} not responding in {region}", "All instances of {svc} in {region} unreachable. Auto-scaling group unhealthy. ELB target count: 0."),
        ("Upstream dependency {dep} unavailable", "{dep} returning 503. {svc} circuit breaker tripped after {threshold} failures. Manual override required."),
        ("Multi-region failover required for {svc}", "{svc} primary region {region} fully down. Traffic failover to secondary region initiated. ETA: 5 minutes."),
        ("Service mesh connectivity failure", "Istio sidecar injection failing in {region}. New pods cannot register with service mesh. All traffic blocked."),
    ],
    "ddos_attack": [
        ("Traffic surge {rate}x normal on {endpoint}", "Inbound requests on {endpoint} at {rate}x baseline ({rps} RPS). Anomalous User-Agent patterns. CDN WAF triggered."),
        ("SYN flood detected from {count} IPs", "SYN flood: {pps} packets/sec from {count} source IPs. TCP half-open connections: {conns}. Rate limiting applied."),
        ("Layer 7 DDoS targeting {endpoint}", "Volumetric HTTP GET flood on {endpoint}. {rps} RPS from {countries} countries. Bot signatures matched: {sigs}."),
        ("Amplification attack via DNS/NTP", "DNS amplification attack detected. {pps} packets/sec inbound. Source IPs spoofed. Upstream ISP null-routing applied."),
        ("Slow loris attack on payment endpoint", "Slow HTTP attack detected on /api/v2/payments. {count} connections holding sockets open. Apache worker pool exhausted."),
    ],
    "availability_drop": [
        ("Availability dropped to {avail}% for {svc}", "{svc} availability: {avail}% (SLO: 99.9%). Errors in {dc} datacenter. {users} users impacted."),
        ("Partial outage in {region} for {svc}", "{svc} in {region}: {error_rate}% of requests failing. Healthy regions: {healthy}. Traffic rerouting in progress."),
        ("SLO breach imminent for {svc}", "{svc} error budget at 15% remaining for this month. Current error rate: {error_rate}%. Freeze non-critical deployments."),
        ("Multi-AZ degradation for {svc}", "{svc} experiencing degraded performance in 2/3 availability zones. Root cause under investigation. ELB routing to healthy AZ."),
    ],
    "http_500_spike": [
        ("HTTP 500 spike on {svc}: {count} errors/min", "{svc} returning {count} 500s/min (baseline: {baseline}). Stack trace: NullPointerException in {class}."),
        ("5xx errors on payment endpoint", "POST /api/v2/payments returning 502. Upstream {upstream} unreachable. {errors} failed transactions in 5 minutes."),
        ("Internal server error storm on {svc}", "{svc} throwing unhandled exception: {exception}. Affects {endpoints}. Heap dump triggered automatically."),
        ("Config change caused 500s in {svc}", "Recent config push to {svc} introduced {count} 500s/min. Rollback to previous version recommended immediately."),
        ("Third-party dependency causing 500s", "Calls to external payment processor returning 500. {errors} failed transactions. Failover to secondary processor available."),
    ],
}

FILLERS = {
    "host": ["web-prod-01", "api-prod-03", "db-replica-02", "worker-07", "payments-host-04"],
    "load": ["12.4", "8.9", "15.1"],
    "free": ["120", "45", "89"],
    "pid": ["34521", "12089", "78234"],
    "mem": ["512", "256", "128"],
    "node": ["k8s-node-4", "k8s-node-9", "k8s-node-11"],
    "svc": ["payment-service", "auth-service", "order-service", "notification-svc", "fraud-detection"],
    "rate": ["7.2", "12.4", "5.8"],
    "lat": ["1200", "850", "2400", "650"],
    "dep": ["payments-v2", "user-service", "inventory-api", "kyc-service"],
    "pods": ["3", "5", "2"],
    "total": ["10", "8", "6"],
    "db": ["payments-primary", "users-rds", "analytics-db", "transactions-pg"],
    "replica": ["replica-1", "replica-2", "replica-standby"],
    "lag": ["45", "120", "89"],
    "query_time": ["15.4", "32.1", "8.9"],
    "query": ["SELECT * FROM transactions WHERE ...", "UPDATE payments SET status=..."],
    "max_conn": ["100", "200", "50"],
    "cache": ["redis-prod-01", "redis-session-02", "elasticache-payments"],
    "evictions": ["1200", "800", "2400"],
    "hit_rate": ["42", "31", "58"],
    "interface": ["eth0", "bond0", "ens3"],
    "loss": ["12", "18", "25"],
    "services": ["payment-gateway, api-gateway", "auth-service, order-service"],
    "peer": ["192.168.1.1", "10.0.0.254"],
    "asn": ["64512", "65001"],
    "time": ["14:32 UTC", "09:15 UTC"],
    "fw": ["fw-prod-01", "fw-edge-02"],
    "src_ip": ["185.234.12.5", "91.108.4.1"],
    "site": ["DR-datacenter", "EU-office"],
    "ip": ["185.234.12.5", "91.108.4.1", "45.33.32.156", "198.51.100.42"],
    "count": ["487", "1203", "89", "3421"],
    "user": ["user@company.com", "svc-account-payments", "analyst@fintech.com"],
    "country": ["RU", "CN", "NG", "KP"],
    "records": ["45000", "120000", "8900"],
    "cve": ["2024-1234", "2023-44228", "2024-5678", "2024-9999"],
    "lib": ["log4j", "spring-core", "requests", "jackson-databind"],
    "ver": ["2.14.0", "5.3.1", "2.27.0"],
    "score": ["9.8", "8.1", "7.5"],
    "repo": ["company/infra", "org/backend", "fintech/api-gateway"],
    "dag": ["payments-etl", "user-sync-daily", "analytics-rollup", "fraud-scoring-pipeline"],
    "task": ["validate_schema", "load_to_warehouse", "send_notifications", "enrich_transactions"],
    "retries": ["3", "5", "2"],
    "error": ["Connection refused", "Timeout after 30s", "Schema mismatch", "Null pointer in mapper"],
    "topic": ["payments.events", "user.activity", "orders.created", "fraud.signals"],
    "group": ["analytics-consumer", "notification-consumer", "fraud-processor"],
    "job": ["payments-transform", "user-enrichment", "daily-reconciliation"],
    "nulls": ["23", "45", "8"],
    "table": ["fact_transactions", "dim_users", "staging_payments"],
    "bucket": ["prod-data-lake", "analytics-raw", "compliance-archive"],
    "prefix": ["payments/2024/", "events/daily/", "transactions/hourly/"],
    "bad_rows": ["12453", "4500", "891"],
    "endpoint": ["/api/v2/payments", "/api/v1/auth", "/api/v3/orders", "/api/v1/transactions"],
    "tps": ["1200", "450", "3400"],
    "queue": ["450", "1200", "89"],
    "script": ["analytics.js", "tracking-pixel.js", "payment-widget.js"],
    "script_time": ["850", "1200", "450"],
    "duration": ["5 minutes", "12 minutes", "3 minutes"],
    "deps": ["redis, postgres", "kafka, elasticsearch"],
    "region": ["us-east-1", "eu-west-1", "ap-south-1", "us-west-2"],
    "threshold": ["5", "10", "3"],
    "rps": ["45000", "120000", "8900", "250000"],
    "pps": ["1200000", "450000", "5000000"],
    "conns": ["45000", "120000", "80000"],
    "countries": ["15", "42", "7"],
    "sigs": ["bot-net-v2", "scraper-pattern", "mirai-variant"],
    "avail": ["97.2", "95.1", "98.8", "93.5"],
    "dc": ["us-east-1a", "eu-west-1b", "ap-south-1a"],
    "users": ["12000", "45000", "890", "100000"],
    "error_rate": ["15", "32", "8", "25"],
    "healthy": ["us-west-2, eu-central-1", "ap-southeast-1"],
    "baseline": ["12", "5", "20"],
    "class": ["PaymentProcessor", "OrderService", "AuthHandler", "FraudDetector"],
    "upstream": ["payment-gateway", "bank-api", "card-network"],
    "errors": ["1234", "567", "89", "4521"],
    "exception": ["NullPointerException", "TimeoutException", "IllegalStateException", "OutOfMemoryError"],
    "endpoints": ["/payments, /refunds", "/auth, /token", "/transactions, /ledger"],
}


def fill(template: str) -> str:
    for key, choices in FILLERS.items():
        placeholder = "{" + key + "}"
        if placeholder in template:
            template = template.replace(placeholder, random.choice(choices))
    return template


def generate(n_per_category: int = 46) -> list[dict]:
    """Generate ~500 incidents (46 per category × 11 = 506)."""
    sources = ["Datadog", "PagerDuty", "Prometheus", "Grafana", "CloudWatch", "Splunk", "Dynatrace"]
    records = []
    for category, templates in TEMPLATES.items():
        for _ in range(n_per_category):
            title_tmpl, desc_tmpl = random.choice(templates)
            title = fill(title_tmpl)
            description = fill(desc_tmpl)
            records.append({
                "id": str(uuid.uuid4()),
                "title": title,
                "description": description,
                "alert_text": f"{title} {description}",
                "category": category,
                "severity": random.choice(["SEV-1", "SEV-2", "SEV-3", "SEV-4"]),
                "source": random.choice(sources),
            })
    random.shuffle(records)
    return records


if __name__ == "__main__":
    dataset = generate()
    out_path = Path(__file__).parent / "incidents.json"
    with open(out_path, "w") as f:
        json.dump(dataset, f, indent=2)
    print(f"Generated {len(dataset)} incidents → {out_path}")
