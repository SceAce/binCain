from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, update_summary

_VALID_STATUS = {"verified", "plausible", "unverified", "rejected"}


def assert_pc(*, workspace: Path | str, crash_report: Path | str) -> dict[str, Any]:
    report_path = Path(crash_report)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    controlled = report.get("controlled_registers", [])
    status = "verified" if controlled else "rejected"
    evidence = f"Controlled register {controlled[0]['register']} at offset {controlled[0]['offset']}" if controlled else "No controlled register evidence"
    return _write_proof(
        workspace=Path(workspace),
        proof_id=f"proof_{report.get('id', report_path.stem)}_pc",
        level=3,
        claim="controllable instruction pointer",
        status=status,
        target=report.get("binary", "unknown"),
        reproducer=report.get("gdb_command"),
        evidence=[str(report_path)],
        confidence="high" if status == "verified" else "low",
        limitations=[] if status == "verified" else [evidence],
        extra={"controlled_registers": controlled},
    )


def assert_offset(*, workspace: Path | str, crash_report: Path | str) -> dict[str, Any]:
    report_path = Path(crash_report)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    controlled = report.get("controlled_registers", [])
    has_offset = any("offset" in item for item in controlled)
    return _write_proof(
        workspace=Path(workspace),
        proof_id=f"proof_{report.get('id', report_path.stem)}_offset",
        level=3,
        claim="cyclic offset proof",
        status="verified" if has_offset else "rejected",
        target=report.get("binary", "unknown"),
        reproducer=report.get("gdb_command"),
        evidence=[str(report_path)],
        confidence="high" if has_offset else "low",
        limitations=[] if has_offset else ["No cyclic offset found in controlled registers"],
        extra={"controlled_registers": controlled},
    )


def assert_leak(
    *,
    workspace: Path | str,
    candidates: list[str],
    maps_file: Path | str | None = None,
    reproducer: str | None = None,
) -> dict[str, Any]:
    regions = _parse_maps(Path(maps_file)) if maps_file is not None else []
    mapped_region = None
    for candidate in candidates:
        parsed = _parse_int(candidate)
        if parsed is None:
            continue
        mapped_region = _find_region(parsed, regions)
        if mapped_region is not None:
            break
    if mapped_region is not None:
        status = "verified"
        confidence = "high"
        limitations: list[str] = []
    elif candidates:
        status = "plausible"
        confidence = "medium"
        limitations = ["No memory map match was available for candidate leak values"]
    else:
        status = "unverified"
        confidence = "low"
        limitations = ["No candidate leak values were provided"]
    return _write_proof(
        workspace=Path(workspace),
        proof_id="proof_leak_000001",
        level=1,
        claim="stable data leak candidate",
        status=status,
        target="unknown",
        reproducer=reproducer,
        evidence=[str(maps_file)] if maps_file else [],
        confidence=confidence,
        limitations=limitations,
        extra={"candidates": candidates, "mapped_region": mapped_region},
    )


def assert_write(
    *,
    workspace: Path | str,
    target: str = "unknown",
    reproducer: str | None = None,
    watch: str | None = None,
    verified: bool = False,
) -> dict[str, Any]:
    return _write_proof(
        workspace=Path(workspace),
        proof_id="proof_write_000001",
        level=2,
        claim="controlled write candidate",
        status="verified" if verified else "unverified",
        target=target,
        reproducer=reproducer,
        evidence=[],
        confidence="high" if verified else "low",
        limitations=[] if verified else ["No watchpoint or before/after memory evidence was provided"],
        extra={"watch": watch},
    )


def _write_proof(
    *,
    workspace: Path,
    proof_id: str,
    level: int,
    claim: str,
    status: str,
    target: str,
    reproducer: str | None,
    evidence: list[str],
    confidence: str,
    limitations: list[str],
    extra: dict[str, Any],
) -> dict[str, Any]:
    if status not in _VALID_STATUS:
        raise ValueError(f"invalid primitive proof status: {status}")
    proofs_dir = workspace / "proofs"
    proofs_dir.mkdir(parents=True, exist_ok=True)
    path = proofs_dir / f"{proof_id}.json"
    proof = {
        "schema": "bincain.primitive_proof.v1",
        "id": proof_id,
        "level": level,
        "claim": claim,
        "status": status,
        "target": target,
        "reproducer": reproducer,
        "evidence": evidence,
        "confidence": confidence,
        "limitations": limitations,
    }
    proof.update(extra)
    proof["path"] = str(path)
    path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    append_event(
        workspace,
        source="binCain-primitive",
        kind="primitive_asserted",
        summary=f"{status} Level {level} primitive assertion: {claim}",
        artifact=_workspace_relative(workspace, path),
        related=[_workspace_relative(workspace, Path(item)) for item in evidence],
    )
    update_summary(
        workspace,
        primitive_candidates=[
            {
                "id": proof_id,
                "level": level,
                "claim": claim,
                "status": status,
                "artifact": _workspace_relative(workspace, path),
                "confidence": confidence,
            }
        ],
    )
    return proof


def _parse_maps(path: Path) -> list[dict[str, Any]]:
    regions = []
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split(None, 5)
        if not fields or "-" not in fields[0]:
            continue
        start_s, end_s = fields[0].split("-", 1)
        regions.append(
            {
                "start": int(start_s, 16),
                "end": int(end_s, 16),
                "perms": fields[1] if len(fields) > 1 else "",
                "path": fields[5] if len(fields) > 5 else "",
            }
        )
    return regions


def _find_region(value: int, regions: list[dict[str, Any]]) -> dict[str, Any] | None:
    for region in regions:
        if region["start"] <= value < region["end"]:
            return region
    return None


def _parse_int(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        return None


def _workspace_relative(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)
