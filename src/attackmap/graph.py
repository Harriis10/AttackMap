from __future__ import annotations

import os

import networkx as nx

from .application_errors import AnalysisConfigurationError
from .models import ScanResult

# C35 resource ceilings: the code graph is bounded by a configurable edge
# budget. On breach the already-built subgraph stays usable and carries an
# explicit partial marker; it is never presented as the complete graph.
DEFAULT_MAX_GRAPH_EDGES = 1_000_000
MAX_GRAPH_EDGES_ENV = "ATTACKMAP_MAX_GRAPH_EDGES"


def resolve_max_graph_edges(explicit: int | None = None) -> int:
    """Edge ceiling: explicit value → ``ATTACKMAP_MAX_GRAPH_EDGES`` → 1,000,000."""
    raw: object = explicit if explicit is not None else os.environ.get(MAX_GRAPH_EDGES_ENV)
    if raw is None or str(raw).strip() == "":
        return DEFAULT_MAX_GRAPH_EDGES
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise AnalysisConfigurationError(
            f"{MAX_GRAPH_EDGES_ENV} / max graph edges must be a positive integer, got {raw!r}."
        ) from None
    if value < 1:
        raise AnalysisConfigurationError(
            f"{MAX_GRAPH_EDGES_ENV} / max graph edges must be >= 1; got {value}."
        )
    return value


def build_graph(scan: ScanResult, *, max_edges: int | None = None) -> nx.DiGraph:
    """Build the code graph under a finite edge budget (C35).

    When the budget is reached no further edges are added; the graph keeps the
    already-built subgraph usable and records the truncation in
    ``graph.graph["edge_budget"]`` / ``["edge_budget_exceeded"]`` plus one
    ``scan.limitations`` entry, so no partial graph is presented as complete.
    """
    limit = resolve_max_graph_edges(max_edges)
    graph = nx.DiGraph()
    graph.graph["edge_budget"] = limit

    def _add_edge(source: str, target: str, **attr) -> None:
        if graph.number_of_edges() >= limit:
            if not graph.graph.get("edge_budget_exceeded"):
                graph.graph["edge_budget_exceeded"] = True
                note = (
                    f"graph edge budget ({limit}) reached; further edges omitted — "
                    "the graph view is a PARTIAL subgraph, not the complete graph. "
                    f"Raise the ceiling with {MAX_GRAPH_EDGES_ENV}."
                )
                graph.graph["edge_budget_note"] = note
                if note not in scan.limitations:
                    scan.limitations.append(note)
            return
        graph.add_edge(source, target, **attr)

    graph.add_node("repo", kind="system", label="Repository")

    if scan.routes:
        graph.add_node("web", kind="service", label="Web/API Layer")
        _add_edge("repo", "web", relation="contains")

    for db in {d.kind for d in scan.databases}:
        graph.add_node(db, kind="database", label=db)
        _add_edge("web" if scan.routes else "repo", db, relation="uses")

    for idx, call in enumerate(scan.external_calls, start=1):
        node_id = f"external_{idx}"
        graph.add_node(node_id, kind="external", label=call.target)
        _add_edge("web" if scan.routes else "repo", node_id, relation="calls")

    return graph
