"""
Runtime ↔ Static Reconciliation Engine (spec Milestone 2 §10)

Cross-references Static AST Inventory against Live Runtime Observations (DOM & Routes):
- Unrendered static controls (potential dead code, unreachable branches, unmounted modals)
- Ghost runtime controls (untracked third-party injections, dynamic unaccounted widgets)
- Discrepancy reporting and verification delta
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from packages.project_graph.models import GraphNode, NodeType
from packages.project_graph.store import ProjectGraph


@dataclass
class ReconciliationDiscrepancy:
    discrepancy_type: str  # UNRENDERED_STATIC | GHOST_RUNTIME | CONTRACT_MISMATCH
    entity_id: str
    name: str
    details: str
    impact: str


@dataclass
class ReconciliationReport:
    static_ui_count: int
    runtime_observed_count: int
    matched_count: int
    unrendered_static_count: int
    ghost_runtime_count: int
    reconciliation_rate_pct: float
    discrepancies: list[ReconciliationDiscrepancy] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["discrepancies"] = [asdict(disc) for disc in self.discrepancies]
        return d


class ReconciliationEngine:
    def __init__(self, graph: ProjectGraph) -> None:
        self.graph = graph

    def reconcile_ui(self, live_dom_selectors: list[str]) -> ReconciliationReport:
        static_ui_nodes = self.graph.nodes_of_type(NodeType.UI_ELEMENT)
        static_count = len(static_ui_nodes)
        live_count = len(live_dom_selectors)

        matched: list[GraphNode] = []
        unrendered: list[GraphNode] = []
        discrepancies: list[ReconciliationDiscrepancy] = []

        for node in static_ui_nodes:
            label = node.metadata.get("label", node.name).lower()
            name = node.name.lower()
            # Check if selector or label appears in live dom
            is_matched = False
            for sel in live_dom_selectors:
                s = sel.lower()
                if s in label or label in s or s in name or name in s:
                    is_matched = True
                    break
                # Handle JSX conditional text like "{loading ? 'Generating...' : 'Generate Resume'}"
                cleaned_label = label.replace("{", "").replace("}", "").replace("'", "").replace('"', "")
                if any(chunk.strip() and chunk.strip() in s for chunk in cleaned_label.split(":")):
                    is_matched = True
                    break

            if is_matched:
                matched.append(node)
            else:
                unrendered.append(node)
                discrepancies.append(
                    ReconciliationDiscrepancy(
                        discrepancy_type="UNRENDERED_STATIC",
                        entity_id=node.id,
                        name=node.name,
                        details=f"Static UI control '{node.name}' declared in {node.metadata.get('file', '')}:{node.metadata.get('line', 1)} was not rendered in runtime DOM.",
                        impact="Potential dead code, conditional branch unmounted, or route unreached.",
                    )
                )

        matched_count = len(matched)
        unrendered_count = len(unrendered)
        ghost_count = max(0, live_count - matched_count)
        rate = round((matched_count / static_count * 100.0), 1) if static_count > 0 else 100.0

        return ReconciliationReport(
            static_ui_count=static_count,
            runtime_observed_count=live_count,
            matched_count=matched_count,
            unrendered_static_count=unrendered_count,
            ghost_runtime_count=ghost_count,
            reconciliation_rate_pct=rate,
            discrepancies=discrepancies,
        )
