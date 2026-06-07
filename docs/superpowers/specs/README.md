# binCain Specs 索引

binCain 的设计文档分层组织。本索引确立**阅读次序与权威性**，避免后续实现在多份 spec 之间迷失。

## 先读这一份

➡️ **[2026-05-30 · 架构与 Cairn 集成契约](./2026-05-30-bincain-architecture-and-cairn-integration-contract-design.md)** —— **权威基线（authoritative baseline）。**
钉死 binCain 与 Cairn 的集成契约：三个交付物（prompt 组 / worker 镜像 / dispatch 配置）、精确的 prompt 占位符与 JSON 输出契约、worker 镜像硬约束、证据流、不可漂移清单、已知缺口。**任何接口 / 契约冲突均以本文为准。**

## 分层阅读次序

按下表从上到下阅读，逐层从「理念」走向「策略」：

| # | 文档 | 一句话角色 | 权威性 |
| --- | --- | --- | --- |
| 0 | [架构与 Cairn 集成契约](./2026-05-30-bincain-architecture-and-cairn-integration-contract-design.md) | 集成契约基线 | **契约权威** |
| 1 | [cairn-compatible-binary-affordance](./2026-05-29-bincain-cairn-compatible-binary-affordance-design.md) | 理念锚：binCain 是 affordance 层，不是工作流引擎 | 理念权威 |
| 2 | [pwn-fuzz-design](./2026-05-28-bincain-pwn-fuzz-design.md) | V1 工具集、primitive 层级（Level 1/2/3）、完成语义、工具护栏 | 工具细节权威 |
| 3 | [operational-hardening](./2026-05-29-bincain-operational-hardening-design.md) | run profiles / event log / 摘要快照 / primitive assertion | 运行期机制权威 |
| 4 | [llm-first-probe-and-vuln-surface](./2026-05-30-bincain-llm-first-probe-and-vuln-surface-design.md) | probe packet + 大模型首轮全局漏洞面判断 | 写入 prompt 散文 |
| 5 | [llm-guided-reverse-and-exploit-discovery](./2026-05-30-bincain-llm-guided-reverse-and-exploit-discovery-design.md) | static/hybrid/fuzz 分析姿态 + 中文攻击链报告 | 写入 prompt 散文 |

**冲突消解：** 第 1–5 层若与第 0 层在「接入形态 / 协议字段 / JSON 契约」上冲突，以第 0 层为准。第 0 层 §7「不可漂移清单」是最终防线。

## 实现计划（plans）

- [2026-05-28 · V1 worker scaffold](../plans/2026-05-28-bincain-v1-worker-scaffold.md) —— 已落地：`init` / `triage` + cyclic + AGENTS.md。
- [2026-05-30 · 大模型引导逆向与攻击链发现](../plans/2026-05-30-bincain-llm-guided-reverse-and-exploit-discovery.md) —— 目标测量 + 中文报告模块。

## 代码现状（main vs worktree，需调和）

实现散落在两处，**尚未合并**，后续应统一为规范模块集：

- **`main` 分支：** `cyclic` / `init` / `triage` / `report`。
- **worktree `bincain-operational-hardening`（领先未合并）：** 额外有 `artifacts`（event log + summary）/ `run_profiles` / `repro` / `primitive` / `protocol`，即 operational-hardening（spec #3）的实现，外加 `docker-compose.yml`、`entrypoint.sh`。

> **建议规范模块集 = `{cyclic, init, triage, report, artifacts, run_profiles, repro, primitive, protocol}`**，并把 worktree 合并为规范实现。详见集成契约 §8「已知缺口」。

## 尚未存在、待实现的集成产物

集成契约 §3 要求、但目前**还没有**的东西：

1. pwn prompt 组的 5 个文件（`prompts/pwn/{bootstrap,bootstrap_conclude,reason,explore,explore_conclude}.md`）。
2. 合规的 worker 镜像（补齐 agent CLI / CLAUDE.md / git init）。
3. `dispatch.yaml` 的 pwn profile。
4. prompt 组同步进 Cairn 包的机制。
