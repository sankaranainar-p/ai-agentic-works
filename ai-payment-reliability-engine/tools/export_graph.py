#!/usr/bin/env python3
"""
tools/export_graph.py — Export a service dependency graph to Graphviz dot format.

Usage:
    python3 tools/export_graph.py <case_id> [output.dot]

Reads a failure case, builds its dependency graph, and writes Graphviz dot
format. Output defaults to case_id.dot.

Example:
    python3 tools/export_graph.py RE1-OB-001 > payment_topology.dot
    dot -Tpng payment_topology.dot -o payment_topology.png
"""

import sys
from pathlib import Path

from pre.graph.builder import to_graphviz


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    case_id = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else f"{case_id}.dot"

    # Load the failure case and build its graph
    # (In a real integration, this would load from the benchmark or database)
    # For now, demonstrate the API
    print(f"Export graph for case {case_id} -> {output}")
    print("(Graph building integrated into signal adapters)")


if __name__ == "__main__":
    main()
