from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def build_exploit_chain_report(
    *,
    crash_report: Path | str,
    proof_report: Path | str,
    workspace: Path | str,
    summary_path: Path | str | None = None,
) -> str:
    workspace_path = Path(workspace)
    crash = _read_json(Path(crash_report))
    proof = _read_json(Path(proof_report))
    summary = _read_json(Path(summary_path)) if summary_path else _read_optional_json(workspace_path / "findings" / "summary_latest.json")

    crash_id = crash.get("id", "unknown")
    binary = crash.get("binary", "unknown")
    signal = crash.get("signal", "unknown")
    controlled = crash.get("controlled_registers", [])
    proof_id = proof.get("id", "unknown")
    proof_level = proof.get("level", "unknown")
    proof_status = proof.get("status", "unknown")
    summary_seq = summary.get("latest_event_seq", "unknown") if summary else "unknown"
    summary_ref = "findings/summary_latest.json" if summary else "未提供"

    exploit_hint = _render_attack_chain_hint(controlled, proof_level, proof_status)

    lines = [
        "# 漏洞点与攻击链简述",
        "",
        f"**目标二进制：** `{binary}`",
        f"**Crash：** `{crash_id}`",
        f"**信号：** `{signal}`",
        f"**Primitive Proof：** `{proof_id}`",
        f"**Proof 等级：** `{proof_level}`",
        f"**Proof 状态：** `{proof_status}`",
        f"**摘要版本：** `{summary_seq}`",
        f"**摘要引用：** `{summary_ref}`",
        "",
        "## 漏洞点",
        "",
        _render_vulnerability_point(crash, controlled),
        "",
        "## 攻击链",
        "",
        exploit_hint,
        "",
        "## 还缺什么",
        "",
        _render_missing_evidence(summary),
        "",
        "## 证据来源",
        "",
        f"- crash report: `{Path(crash_report)}`",
        f"- proof report: `{Path(proof_report)}`",
    ]
    return "\n".join(lines).strip() + "\n"


def write_exploit_chain_report(
    *,
    crash_report: Path | str,
    proof_report: Path | str,
    workspace: Path | str,
    output: Path | str | None = None,
    summary_path: Path | str | None = None,
) -> str:
    workspace_path = Path(workspace)
    text = build_exploit_chain_report(
        crash_report=crash_report,
        proof_report=proof_report,
        workspace=workspace_path,
        summary_path=summary_path,
    )
    output_path = Path(output) if output is not None else _default_report_path(workspace_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return text


def _render_vulnerability_point(crash: dict[str, Any], controlled: list[dict[str, Any]]) -> str:
    if controlled:
        first = controlled[0]
        return (
            f"该 crash 已显示出可控寄存器 `{first.get('register', 'unknown')}`，"
            f"偏移为 `{first.get('offset', 'unknown')}`。"
            f"这说明输入可以稳定推进到控制流相关位置，属于高价值漏洞点。"
        )
    signal = crash.get("signal", "unknown")
    return f"当前 crash 至少可确认收到 `{signal}`，但还没有足够的寄存器控制证据，需要继续把崩溃和输入位置对齐。"


def _render_attack_chain_hint(
    controlled: list[dict[str, Any]],
    proof_level: Any,
    proof_status: Any,
) -> str:
    if controlled:
        first = controlled[0]
        register = first.get("register", "unknown")
        offset = first.get("offset", "unknown")
        return (
            f"攻击链目前可以先从输入长度控制开始，"
            f"把 `{register}` 的 `{offset}` 字节偏移稳定复现，再进一步寻找返回地址、函数指针或间接调用点。"
            f"如果 proof 状态为 `{proof_status}`，则说明这一段链路已经达到可验证阶段。"
        )
    return (
        "攻击链暂时还停留在崩溃确认阶段。下一步应继续把输入与调用路径对齐，"
        "先确定哪一个分支、菜单项或协议状态能把程序推进到可控位置。"
    )


def _render_missing_evidence(summary: dict[str, Any] | None) -> str:
    if not summary:
        return "未读取到 summary_latest.json，下一步应补齐摘要索引，确认哪些 crash 和 proof 已经被纳入当前视野。"
    primitives = summary.get("primitive_candidates", [])
    if primitives:
        first = primitives[0]
        return (
            f"当前 summary 已记录 primitive 候选 `{first.get('id', 'unknown')}`，"
            f"但仍应补齐它的利用链细节、触发条件和是否能继续延伸到更强 primitive 的证据。"
        )
    selected = summary.get("selected_crashes", [])
    if selected:
        first = selected[0]
        return (
            f"当前 summary 已选中 crash `{first.get('id', 'unknown')}`，"
            "但还需要补齐从 crash 到可利用 primitive 的连续解释。"
        )
    return "summary 中暂时没有足够的 primitive 或 crash 证据，建议继续推进 triage 和 proof。"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return _read_json(path)


def _default_report_path(workspace: Path) -> Path:
    findings_dir = workspace / "findings"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    candidate = findings_dir / f"exploit_chain_summary_{stamp}.md"
    index = 1
    while candidate.exists():
        candidate = findings_dir / f"exploit_chain_summary_{stamp}_{index}.md"
        index += 1
    return candidate
