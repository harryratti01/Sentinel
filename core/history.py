"""Evidence-backed history queries and conservative finding interpretation."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .database import list_evidence_observations


def target_timeline(connection: sqlite3.Connection, target_id: int) -> list[dict[str, object]]:
    """Return raw observations in durable database order, not timestamp order."""
    return [dict(row) for row in list_evidence_observations(connection, target_id)]


def _comparison(finding: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    signature = json.loads(str(finding["signature"]))
    return signature.get("baseline") or {}, signature.get("current") or {}


def interpret_finding(
    finding: dict[str, Any], preceding_findings: list[dict[str, Any]] | None = None
) -> list[str]:
    """State only conclusions supported by persisted reconciliation snapshots."""
    baseline, current = _comparison(finding)
    statements: list[str] = []
    if baseline and current:
        if current.get("path") != baseline.get("path"):
            statements.append("Current path differs from the trusted baseline path.")
        if current.get("sha256") == baseline.get("sha256"):
            statements.append("Current content matches the trusted baseline.")
            if current.get("modified_time_ns") != baseline.get("modified_time_ns"):
                statements.append("Supported metadata differs: modification time differs from the trusted baseline.")
            prior_changed = any(
                _comparison(previous)[0].get("path") == baseline.get("path")
                and _comparison(previous)[1].get("sha256") not in (None, baseline.get("sha256"))
                for previous in preceding_findings or []
            )
            if prior_changed:
                statements.append("Historical evidence indicates content changed and later returned to the trusted baseline.")
        elif current.get("sha256") is not None:
            statements.append("Current content differs from the trusted baseline.")
    elif finding.get("finding_type") == "AMBIGUOUS_IDENTICAL_CONTENT":
        statements.append("Identity could not be established with sufficient confidence.")
    return statements
