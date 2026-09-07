"""
pre/graph/evidence.py — Utility functions for evidence agents using dependency graphs.

Helpers for analyzing service dependency graphs to identify root causes,
propagation paths, and impact zones.
"""

from __future__ import annotations

from typing import Optional

import networkx as nx

from pre.signals.types import FailureCase


def build_from_case(case: FailureCase) -> nx.DiGraph:
    """Extract or build weighted graph from a FailureCase.

    If the case has trace data, rebuilds the graph with weighted edges.
    Otherwise uses the provided topology graph as-is.
    """
    from pre.graph.builder import build_weighted_graph

    if case.traces:
        return build_weighted_graph(case.traces)
    return case.topology


def impacted_services(
    graph: nx.DiGraph, root: str
) -> set[str]:
    """Find all services downstream of a root-cause service.

    Returns the transitive closure of successors (all services that could be
    affected if the root service fails).
    """
    if root not in graph:
        return set()
    return set(nx.descendants(graph, root)) | {root}


def propagation_paths(
    graph: nx.DiGraph, root: str
) -> dict[str, list[str]]:
    """Find all paths from root cause to each affected service.

    Returns {affected_service: [path from root to service]}.
    """
    if root not in graph:
        return {}

    paths = {}
    for target in nx.descendants(graph, root):
        if nx.has_path(graph, root, target):
            path = nx.shortest_path(graph, root, target)
            paths[target] = path

    return paths
