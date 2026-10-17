"""Shared evidence labels for static analysis and all report consumers.

Source observations establish declarations, not deployment reachability. The
current surface model has no runtime observation, so exposure never upgrades
the evidence class to runtime-observed.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import AttackSurface

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/")
SURFACE_EVIDENCE_CLASSES = ("static_observed", "inferred_protocol", "low_quality")


def classify_source_path(path: str | None) -> str:
    """Version 1 path conventions; absence of a convention never proves production."""
    parts = set((path or "").replace("\\", "/").lower().split("/"))
    for role, names in (("test", {"tests", "__tests__"}), ("fixture", {"fixtures"}),
                        ("mock", {"mocks"}), ("example", {"examples"}),
                        ("generated", {"generated", "__generated__"})):
        if parts & names:
            return role
    return "unknown"


def is_low_quality_source(path_or_text: str) -> bool:
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def is_protocol_derived_surface(surface: AttackSurface) -> bool:
    # A real XRPC handler is still a source observation. A route name or auth
    # keyword alone cannot turn executable code into a protocol declaration.
    file_lower = surface.file.lower()
    return "lexicon" in file_lower and file_lower.endswith(".json")


def surface_evidence_class(surface: AttackSurface) -> str:
    if is_low_quality_source(surface.file):
        return "low_quality"
    if is_protocol_derived_surface(surface):
        return "inferred_protocol"
    return "static_observed"


def surface_evidence_counts(surfaces: list[AttackSurface]) -> dict[str, int]:
    counts = dict.fromkeys(SURFACE_EVIDENCE_CLASSES, 0)
    for surface in surfaces:
        counts[surface_evidence_class(surface)] += 1
    return counts


def surface_evidence_basis(surfaces: list[AttackSurface]) -> str:
    classes = {surface_evidence_class(surface) for surface in surfaces}
    if not classes:
        return "unknown"
    return classes.pop() if len(classes) == 1 else "mixed"
