"""Scan Diff -- Compare two scans to track security regression/improvement."""

from src.db.database import Database
from src.utils.logger import get_logger

log = get_logger("diff")


async def compare_scans(db: Database, scan_id_old: int, scan_id_new: int) -> dict:
    """Compare two scans and return the differences.

    Returns:
        {
            "old_scan": dict, "new_scan": dict,
            "score_change": float,
            "new_findings": list,     # Issues that appeared
            "resolved_findings": list, # Issues that disappeared
            "persistent_findings": list, # Issues that remain
            "summary": str,
        }
    """
    old_scan = await db.get_scan(scan_id_old)
    new_scan = await db.get_scan(scan_id_new)

    if not old_scan or not new_scan:
        return {"error": "One or both scans not found"}

    old_findings = await db.get_findings(scan_id_old)
    new_findings = await db.get_findings(scan_id_new)

    # Create fingerprints for comparison (category + title)
    old_set = {_fingerprint(f): f for f in old_findings}
    new_set = {_fingerprint(f): f for f in new_findings}

    old_keys = set(old_set.keys())
    new_keys = set(new_set.keys())

    appeared = [new_set[k] for k in new_keys - old_keys]
    resolved = [old_set[k] for k in old_keys - new_keys]
    persistent = [new_set[k] for k in old_keys & new_keys]

    old_score = old_scan.get("score") or 0
    new_score = new_scan.get("score") or 0
    score_change = new_score - old_score

    # Generate summary
    parts = []
    if score_change > 0:
        parts.append(f"Score improved: {old_score:.0f} -> {new_score:.0f} (+{score_change:.0f})")
    elif score_change < 0:
        parts.append(f"Score degraded: {old_score:.0f} -> {new_score:.0f} ({score_change:.0f})")
    else:
        parts.append(f"Score unchanged: {new_score:.0f}/100")

    if resolved:
        parts.append(f"{len(resolved)} issue(s) resolved")
    if appeared:
        parts.append(f"{len(appeared)} new issue(s) found")
    if persistent:
        parts.append(f"{len(persistent)} issue(s) persist")

    return {
        "old_scan": {"id": scan_id_old, "score": old_score, "findings": len(old_findings)},
        "new_scan": {"id": scan_id_new, "score": new_score, "findings": len(new_findings)},
        "score_change": score_change,
        "new_findings": appeared,
        "resolved_findings": resolved,
        "persistent_findings": persistent,
        "summary": ". ".join(parts),
    }


def _fingerprint(finding: dict) -> str:
    """Create a stable fingerprint for a finding to track across scans."""
    return f"{finding.get('category', '')}::{finding.get('title', '')}"
