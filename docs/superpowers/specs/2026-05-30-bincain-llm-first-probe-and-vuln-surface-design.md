# binCain 大模型首轮探测与漏洞面分析设计

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**目标：** 在不改变 Cairn 的 `Fact / Intent / Hint` 图模型前提下，让 binCain 在 `Bootstrap / Reason / Explore` 三段式流程中完成大模型首轮探测，对整个二进制形成初步全局判断，输出漏洞面排序、攻击链假设和后续验证方向。

**架构：** worker 仍然保持轻量，不新增新的中间控制层，也不把 binCain 变成固定流水线。`Bootstrap` 负责把目标测绘、静态信息、短运行证据和已有事实压缩成 probe packet；`Reason` 负责让大模型基于 probe packet 做全局分析；`Explore` 负责围绕模型提出的假设做定向探测并把结果写回 Facts。中文报告是最终汇总产物，不是分析主流程本身。

**技术栈：** Python、Click CLI、GDB、pwntools、反汇编/反编译输出、JSON/Markdown artifacts、Docker Compose。

---

## 范围

这个阶段的目标不是“再做一个报告器”，而是让大模型真正参与第一次全局分析。

这一阶段应完成的事情是：

1. 收集目标的基础测绘信息
2. 将测绘信息压缩成 probe packet
3. 让大模型对整个二进制做首轮判断
4. 输出漏洞面排序和可验证的攻击链假设
5. 围绕假设执行定向探测
6. 将结果写回 Facts / summary / proof artifacts
7. 在最后生成一份中文的漏洞点与攻击链简述报告

这个阶段不新增新的调度器、分析控制器或 posture 状态机。

## 不可突破的边界

binCain 不能：

- 新增一个独立的分析中间层
- 要求 Dispatcher 参与漏洞分析决策
- 把大模型决策写成新的 Cairn 协议字段
- 用固定流水线替代 `Fact / Intent / Hint` 图模型
- 把中文报告当成主分析结果而不是最终汇总结果

binCain 可以：

- 在 worker 侧生成 probe packet
- 用 prompt 让大模型看到更完整的分析上下文
- 让 `Bootstrap / Reason / Explore` 复用现有图结构
- 将测绘、探测、验证结果写回 worker artifacts
- 生成中文攻击链报告作为最终输出

## 首轮探测输入

首轮探测不应只看 crash 或 proof，而应尽量覆盖整个二进制的可用分析面。

必要输入包括：

- 文件大小、可执行性和基础元数据
- `main` 或等价入口的反编译 / 反汇编摘要
- imports / symbols / section 等轻量静态信息
- 一次短运行探测得到的真实交互形态
- 既有 crash / triage / proof 证据
- `summary_latest.json` 或等价摘要快照
- 需要时可引用的 `run_profiles.json` 与 `connection_profiles.json`

这些输入不直接变成新的协议对象，只进入 worker 侧 probe packet 和 prompt 上下文。

## 首轮探测输出

大模型首轮探测的输出应至少包含以下内容：

- 对程序整体复杂度的判断
- 漏洞面排序
- 最可疑的入口、状态或输入路径
- 每个可疑方向对应的验证假设
- 缺失证据列表
- 下一步建议执行的探测动作
- 是否已足以进入 primitive 证明阶段

输出应优先写回：

- `findings/summary_latest.json`
- `findings/snapshots/summary_<seq>.json`
- `findings/events.jsonl`

如果已经收敛出可利用链，还应写入：

- `findings/exploit_chain_summary_*.md`

## Bootstrap 阶段

Bootstrap 的职责是测绘，而不是判断结论。

它应完成：

- 目标尺寸和结构摘要
- 入口路径摘要
- 运行模式摘要
- 初始 crash / proof 摘要
- probe packet 的组装

probe packet 应该是一个可读、可压缩、可回放的文本/JSON 组合，内容要足够让模型看见“整个问题长什么样”，而不是只看见一个 crash 点。

优秀的 probe packet 应包含：

- 程序基本属性
- 入口复杂度
- 可疑区域索引
- 已有证据链
- 当前缺失的关键事实

## Reason 阶段

Reason 的职责是让大模型完成首轮全局判断。

模型应被提示：

- 这是一次全局探测，不是局部总结
- 需要先排序漏洞面，再谈攻击链
- 不要只围绕已有 crash 复述
- 需要说明哪些证据支持当前判断
- 需要明确下一步该验证什么

Reason 的输出应尽量形成以下结构：

- 程序总体判断
- 漏洞面排序
- 每个面对应的假设
- 证据充分度
- 下一步建议
- 中文简述报告的草稿要点

Reason 不应该决定最终结论，而应该产出“值得去 Explore 的假设集合”。

## Explore 阶段

Explore 的职责是围绕 Reason 输出的假设做定向探测。

可执行动作包括：

- 静态局部复查
- 短时运行验证
- fuzz 或动作序列探测
- debugger 复现
- primitive 验证

Explore 的结果必须回写为 Facts，并更新 summary。
如果某个假设被证实，应明确写出：

- 证实了什么
- 排除了什么
- 下一步还能怎么延伸

如果某个假设被否定，应写成可复用的负向证据，而不是简单失败。

## 中文报告产物

中文报告是最后的汇总产物，不是替代分析本身。

当漏洞点已经分析出来，worker 应生成一份中文简述报告，至少写清：

- 漏洞点在哪里
- 漏洞成立的关键证据是什么
- 攻击链如何从入口延伸到可利用状态
- 当前还缺什么证据

建议产物路径：

- `findings/exploit_chain_summary_*.md`

这份报告应短、清晰、可继续接着分析，不要写成长篇复盘。

## Artifact 预期

整个阶段应能看到以下 artifact 演进：

- `findings/init.json`
- `findings/run_profiles.json`
- `findings/connection_profiles.json`
- `findings/summary_latest.json`
- `findings/snapshots/summary_<seq>.json`
- `findings/events.jsonl`
- `findings/crash_*.json`
- `findings/repro_*.json`
- `proofs/proof_*.json`
- `findings/exploit_chain_summary_*.md`

summary 里应能压缩出：

- 当前程序被判断为何种复杂度
- 当前最值得追的漏洞面
- 当前已经验证到哪一级 primitive
- 哪些证据已足够，哪些还缺

## 验收标准

满足以下条件即视为这一阶段完成：

1. worker 能生成包含目标测绘、入口摘要和短运行证据的 probe packet。
2. 大模型能基于 probe packet 对整个二进制做首轮全局判断。
3. 输出能给出漏洞面排序，而不是只对单个 crash 做总结。
4. `Bootstrap / Reason / Explore` 三段式能够承载这次首轮探测，而不新增中间控制层。
5. 探测结果能写回 `Facts / summary / snapshots / events`。
6. 当漏洞点收敛后，worker 能继续推理出攻击链并生成中文简述报告。
7. 中文报告能说明漏洞点、关键证据、攻击链和缺失证据。
8. 整个流程仍然兼容现有 Cairn 图模型，不引入新的协议字段或固定工作流。

## 非目标

这个阶段不要求：

- 自动对所有程序生成完整 exploit
- 新增独立分析服务
- 用状态机替换图模型
- 保证每个目标都能一次命中漏洞
- 用中文报告代替事实和证据本身

