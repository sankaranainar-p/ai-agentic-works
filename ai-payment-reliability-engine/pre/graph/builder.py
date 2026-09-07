"""
pre/graph/builder.py — Build weighted service dependency graphs from traces.

Constructs DiGraphs with edges annotated by call count, error ratio, and p99
latency. Helpers for traversing upstream/downstream dependencies and finding
high-error paths.

Fallback to topology YAML for systems without trace data.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Optional

import networkx as nx
import yaml

from pre.signals.types import Span


def build_weighted_graph(spans: list[Span]) -> nx.DiGraph:
    """Build a weighted service dependency graph from spans.

    Each edge (caller -> callee) carries attributes:
    - call_count: number of calls on this edge
    - error_ratio: fraction of calls with status_code >= 400
    - p99_latency_us: 99th percentile latency in microseconds

    status_code is treated as HTTP-like (>= 400 is error, or None is ok).
    """
    graph = nx.DiGraph()
    by_id: dict[str, Span] = {s.span_id: s for s in spans}

    # Collect call statistics per edge
    edges: dict[tuple[str, str], list[Span]] = defaultdict(list)

    for span in spans:
        graph.add_node(span.service)
        if (
            span.parent_span_id
            and span.parent_span_id in by_id
        ):
            parent = by_id[span.parent_span_id]
            # Skip self-edges
            if parent.service and span.service and parent.service != span.service:
                edges[(parent.service, span.service)].append(span)

    # Add edges with attributes
    for (caller, callee), calls in edges.items():
        call_count = len(calls)
        error_count = sum(1 for s in calls if s.status_code and s.status_code >= 400)
        error_ratio = error_count / call_count if call_count > 0 else 0.0

        # p99 latency
        latencies = sorted([s.duration_us for s in calls])
        p99_idx = max(0, int(len(latencies) * 0.99) - 1)
        p99_latency_us = latencies[p99_idx] if latencies else 0

        graph.add_edge(
            caller,
            callee,
            call_count=call_count,
            error_ratio=error_ratio,
            p99_latency_us=p99_latency_us,
        )

    return graph


def load_topology_yaml(path: str | Path) -> nx.DiGraph:
    """Load a service topology from YAML.

    YAML format:
    ```yaml
    edges:
      - [service_a, service_b]  # a calls b
      - [service_b, service_c]
    ```

    Falls back to all-zeros for edge attributes if not specified.
    """
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    graph = nx.DiGraph()
    for caller, callee in data.get("edges", []):
        graph.add_edge(
            caller,
            callee,
            call_count=0,
            error_ratio=0.0,
            p99_latency_us=0,
        )

    return graph


def upstream(graph: nx.DiGraph, service: str) -> set[str]:
    """Return all services that call this one (immediate predecessors)."""
    return set(graph.predecessors(service))


def downstream(graph: nx.DiGraph, service: str) -> set[str]:
    """Return all services that this one calls (immediate successors)."""
    return set(graph.successors(service))


def shortest_error_path(
    graph: nx.DiGraph, start: str, end: str
) -> Optional[list[str]]:
    """Find the path from start to end with lowest cumulative error ratio.

    Uses 1 - error_ratio as edge weight (lower error paths preferred).
    Returns None if no path exists.
    """
    if start not in graph or end not in graph:
        return None

    try:
        # Invert error_ratio to make it a cost (1 - ratio minimizes errors)
        for _, _, data in graph.edges(data=True):
            data["_weight"] = 1.0 - data.get("error_ratio", 0.0)

        path = nx.shortest_path(graph, start, end, weight="_weight")
        return path
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def to_graphviz(graph: nx.DiGraph) -> str:
    """Export graph to Graphviz dot format for visualization.

    Edges are labeled with call_count and error_ratio.
    """
    lines = ["digraph G {"]
    lines.append("  rankdir=LR;")

    for node in graph.nodes():
        lines.append(f'  "{node}";')

    for caller, callee, data in graph.edges(data=True):
        call_count = data.get("call_count", 0)
        error_ratio = data.get("error_ratio", 0.0)
        label = f"calls={call_count}\\nerr={error_ratio:.2%}"
        lines.append(f'  "{caller}" -> "{callee}" [label="{label}"];')

    lines.append("}")
    return "\n".join(lines)
