"""Dependency graph and blast-radius helpers without a runtime graph dependency."""

from __future__ import annotations

from collections import deque
from typing import Any


def dependency_adjacency(sbom: dict[str, Any]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for component in sbom.get("components", []):
        if isinstance(component, dict):
            reference = str(component.get("bom-ref", component.get("name", "unknown")))
            graph.setdefault(reference, set())
    for relationship in sbom.get("dependencies", []):
        if not isinstance(relationship, dict):
            continue
        parent = str(relationship.get("ref", ""))
        graph.setdefault(parent, set())
        for child in relationship.get("dependsOn", []):
            graph[parent].add(str(child))
            graph.setdefault(str(child), set())
    return graph


def reverse_adjacency(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    reverse = {node: set() for node in graph}
    for parent, children in graph.items():
        for child in children:
            reverse.setdefault(child, set()).add(parent)
    return reverse


def impacted_nodes(graph: dict[str, set[str]], compromised_node: str) -> list[str]:
    reverse = reverse_adjacency(graph)
    visited = {compromised_node}
    queue = deque([compromised_node])
    while queue:
        node = queue.popleft()
        for dependent in reverse.get(node, set()):
            if dependent not in visited:
                visited.add(dependent)
                queue.append(dependent)
    return sorted(visited)

