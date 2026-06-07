# binCain 架构与 Cairn 集成契约（Architecture & Cairn Integration Contract）

> **文档地位：权威基线（authoritative baseline）。**
> 本文钉死 binCain 与 Cairn 的集成契约。当其它 spec 在「接口 / 契约 / 接入形态」上与本文冲突时，**以本文为准**；其它 spec 负责在本契约之上补充理念、工具行为与策略。
>
> **核实来源：** Cairn 源码 `/home/source/My_github/Cairn`，重点是 `docs/specs/dispatcher-design.md`、`docs/specs/server-protocol.md`、`cairn/src/cairn/server/models.py`、`cairn/src/cairn/dispatcher/contracts.py`、`cairn/src/cairn/dispatcher/prompts/default/*`、`container/Dockerfile`。本文所有「Cairn 现状」均与这些文件对齐（核实日期 2026-05-30）。

---

## 0. 为什么需要这份文档

binCain 现有 5 份 spec 都在描述 worker 侧的工具、证据标准与分析策略，但**没有任何一份说清 binCain 究竟以什么形态接入 Cairn**。这会在写代码时直接导致漂移：

- 不知道 pwn 特化应该写进哪一层（结果可能误改 Cairn 协议）。
- 不知道 agent 输出必须严格匹配的 JSON 契约（结果可能擅自加字段）。
- 不知道 worker 镜像必须满足的硬性条件（结果做出一个跑不进 Cairn 的镜像）。

本文把这些**硬契约（hard contract）**一次性钉死，使后续实现可以逐条对照验收。

---

## 1. 一句话定位

> **binCain 是 Cairn 的二进制 / pwn 领域适配层。它不分叉（fork）Cairn 核心代码，只交付三样东西：**
>
> 1. **一个 prompt 组**（pwn 特化的 5 个 prompt 文件）
> 2. **一个 worker 容器镜像**（pwn 工具链 + binCain helper + 满足 Cairn worker 契约）
> 3. **一份 dispatch 配置 profile**（`dispatch.yaml`）

Cairn 的 Server、Dispatcher、调度循环、协议、数据模型——**一行代码都不改**。唯一需要往 Cairn 仓库树里「加文件」的动作，是把 pwn prompt 组目录放进 Cairn 包内（见 §3.1），这属于「加资源」而非「改逻辑」。

---

## 2. 已核实的 Cairn 契约（不可改，IMMUTABLE）

这些是 Cairn 的既有事实，binCain 必须无条件遵守。

### 2.1 黑板数据模型

`cairn/src/cairn/server/models.py` 定义的核心对象：

| 对象 | 字段 | 说明 |
| --- | --- | --- |
| `Fact` | `id`, `description` | **只有自由文本，没有任何类型化字段。** |
| `Intent` | `id`, `from`(fact id 列表), `to`, `description`, `creator`, `worker`, 心跳/时间戳 | 一条探索方向。 |
| `Hint` | `id`, `content`, `creator`, `created_at` | 人类随时注入的判断。 |
| `Project` | `id`, `title`, `status`(active/stopped/completed), `created_at`, `reason` | 创建时给 `origin`、`goal`、可选 `hints`。 |

**推论（对 binCain 至关重要）：** 所有 pwn 证据（checksec、架构、crash、寄存器、primitive 等级……）都只能写进 `Fact.description` 文本，并在文本里引用 workspace 文件路径。**不存在「pwn 专用字段」可加。** 这不是限制，而是和 Cairn 原生规则一致：Cairn 自己的 prompt 就明文要求 *“Do not put long data blobs in description. Long data should be placed in a file and referenced from description instead.”*

### 2.2 三类任务

`bootstrap` / `reason` / `explore`，外加两个兜底阶段 `bootstrap_conclude` / `explore_conclude`。语义（见 `dispatcher-design.md`）：

| 任务 | 触发 | 输入占位符 | 产出 |
| --- | --- | --- | --- |
| `bootstrap` | 项目初始态（facts 只有 origin/goal） | `{origin}` `{goal}` `{hints}` | 解决时返回 `fact + complete`；超时由 `bootstrap_conclude` 只产 `fact` |
| `reason` | 无未认领 intent 时读全图判断 | `{graph_yaml}` `{fact_ids}` `{open_intents}`（`{max_intents}` 可选） | `complete` / `intents` / 空 `data` |
| `explore` | 认领一条 intent | `{graph_yaml}` `{intent_id}` `{intent_description}` | 一个 Fact `description`；超时由 `explore_conclude` 收尾 |

### 2.3 控制面与执行面的边界

- **Dispatcher 是唯一的协议写入者（sole protocol writer）。**
- **Agent 不调用 Cairn API、不 claim intent、不发心跳。** Agent 只做一件事：收到 Dispatcher 渲染好的 prompt，在容器内干活，把**一个 JSON 对象**打到 stdout。
- Dispatcher 解析该 JSON（`output_parser.extract_json_object` + `contracts.validate_*`），再代为调用 Server 接口写图。

### 2.4 容器与记忆

- **每个 project 一个常驻 worker 容器**；多个 agent worker 可并发跑在里面。
- 容器在任务之间**不销毁**（`container.completed_action: stop` 保留现场）。
- **workspace 文件系统 = 跨任务记忆。** 这正是 binCain 把证据沉淀成 artifacts 的依据：上一轮 `explore` 写下的 `findings/crash_*.json`，下一轮任务能直接读。

### 2.5 链路（一句话版）

```
Dispatcher 读图 → 选任务/worker → 渲染 prompt → claim(对 explore/bootstrap) →
在项目容器内 exec agent CLI → agent 回 JSON → Dispatcher 校验 → 写回 Server(complete/intents/conclude/release)
```

---

## 3. binCain 的三个交付物（接入点，DELIVERABLES）

### 3.1 交付物一：pwn prompt 组

**位置（硬约束）：** prompt 由 `prompting.load_prompt` 经 `importlib.resources.files("cairn.dispatcher.prompts").joinpath(group)` 加载。因此 pwn prompt 组**必须位于 Cairn 包内**：

```
cairn/src/cairn/dispatcher/prompts/pwn/
```

由 `dispatch.yaml` 的 `runtime.prompt_group: "pwn"` 选中。落地方式二选一（实现阶段定）：

- **方式 A（推荐起步）：** 直接把 `prompts/pwn/` 放进本地 Cairn checkout 的包目录。binCain 仓库保留一份权威副本（如 `binCain/integration/cairn/prompts/pwn/`），用脚本同步。
- **方式 B：** 向上游 Cairn 贡献该 prompt 组。

> 命名约定：prompt 组名定为 **`pwn`**（与 Cairn 既有的 `default` / `mock` 同级风格）。

**必含文件与必需占位符（硬约束）：** 该组**必须**含以下 5 个文件，且各自**必须保留**下列占位符（Dispatcher 启动时做静态校验，缺占位符直接启动失败）：

| 文件 | 必需占位符 | 可选占位符 |
| --- | --- | --- |
| `bootstrap.md` | `{origin}` `{goal}` `{hints}` | — |
| `bootstrap_conclude.md` | `{origin}` `{goal}` `{hints}` | — |
| `reason.md` | `{graph_yaml}` `{fact_ids}` `{open_intents}` | `{max_intents}` |
| `explore.md` | `{graph_yaml}` `{intent_id}` `{intent_description}` | — |
| `explore_conclude.md` | `{graph_yaml}` `{intent_id}` `{intent_description}` | — |

**输出 JSON 契约（硬约束，一个字段都不能加 / 改）：** 由 `cairn/src/cairn/dispatcher/contracts.py` 强制校验。pwn prompt 只能改散文、不能改契约。逐任务精确形态：

`bootstrap`（主阶段，必须同时给 `fact` 和 `complete`）：
```json
{"accepted": true, "data": {"fact": {"description": "..."}, "complete": {"description": "..."}}}
```

`bootstrap_conclude`（只产 `fact`，不许带 `complete`）：
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
```

`reason`（三选一）：
```json
{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "..."}}}
{"accepted": true, "data": {"intents": [{"from": ["f001"], "description": "..."}]}}
{"accepted": true, "data": {}}
```
> 规则：`{open_intents}` 为空且未 `complete` 时，**必须**返回 `intents`。`intents` 会被截断到 `{max_intents}`。Cairn 亦兼容单数 `intent` 对象。

`explore` / `explore_conclude`：
```json
{"accepted": true, "data": {"description": "..."}}
```

任何任务的拒绝形态（pwn 场景下**不应**拒绝）：
```json
{"accepted": false, "reason": "policy_refusal"}
```

**pwn 特化只能写在哪里：** 既然 JSON 契约和占位符都锁死，所有 pwn 智能只能落在**散文（prompt 正文）+ workspace 内的 AGENTS.md/CLAUDE.md**。要在 prompt 散文里注入的 binCain 内容（来自其它 spec）：

- primitive 层级与默认完成判据（Level 1/2/3，spec #1/#2）
- 证据标准：结论进 `description`、长数据落文件并引用路径（spec #2/#3）
- 重工具护栏：首轮不上 angr、长 fuzz 必须有预算（spec #1）
- 可证伪 intent 纪律：重复失败要换成可证伪实验（spec #3）
- 分析姿态建议：static / hybrid / fuzz 优先（spec #5）
- 首轮全局判断：bootstrap/reason 阶段组装并参考 probe packet（spec #4）

### 3.2 交付物二：worker 容器镜像

由 `dispatch.yaml` 的 `container.image` 指定。binCain 镜像 = **Cairn worker 契约（必须满足）** + **pwn 增量**。

**Cairn worker 契约（硬约束，来自 `Cairn/container/Dockerfile` 与 `claudecode.py`）：**

| 要求 | 说明 |
| --- | --- |
| 安装 agent CLI | 至少安装 `dispatch.yaml` 里用到的 worker 后端对应 CLI：`claude`(@anthropic-ai/claude-code)、`codex`(@openai/codex)、可选 `pi`。Dispatcher 会 exec 形如 `claude --session-id <s> --dangerously-skip-permissions -p -- "<prompt>"`。 |
| workspace 路径 | 工作目录 `/home/kali/workspace`，`WORKDIR` 指向它，且对 exec 用户可写。 |
| AGENTS.md + CLAUDE.md | workspace 内**同时**存在 `AGENTS.md`（codex 读）与 `CLAUDE.md`（claude 读）。Cairn 的做法是把同一份 AGENTS.md 复制成两份；`.agents` 同样复制成 `.claude`。 |
| git init | workspace 初始化为 git 仓库（Cairn 依赖此点做现场管理）。 |
| 非 root exec 用户 | 用户 `kali`，home 与 workspace 归属一致。 |

**pwn 增量：**

- pwn 工具链：pwntools、gdb / gdb-multiarch、qemu-user(-static)、AFL++ / honggfuzz、radare2 / rizin、ROPgadget / ropper / one_gadget、capstone / unicorn / z3 / angr、seccomp-tools、patchelf / pwninit 等（见 spec #1 工具清单）。
- 安装 `bincain` 包，使 agent 能直接调用 `binCain-init` / `binCain-triage` / `binCain-report` 等命令。
- workspace 约定目录：`target/ scripts/ fuzz/ crashes/ findings/ proofs/ notes/`（见 spec #2/#3）。

> **当前 Dockerfile 的不合规项见 §8（已知缺口），实现镜像时必须逐条补齐。**

### 3.3 交付物三：dispatch.yaml profile

关键字段（完整字段见 `dispatcher-design.md`）：

```yaml
runtime:
  prompt_group: "pwn"          # 选中 pwn prompt 组
container:
  image: "bincain-worker:<tag>" # 选中 binCain worker 镜像
  completed_action: "stop"      # 保留现场，承载跨任务记忆
tasks:
  explore:
    timeout: <较大但有界>         # 见下方「长 fuzz 张力」
    conclude_timeout: <较小>
workers:
  - type: "claudecode"           # 或 codex；镜像里必须装对应 CLI
    task_types: [bootstrap, reason, explore]
    env: { ANTHROPIC_MODEL/BASE_URL/AUTH_TOKEN ... }
```

**长 fuzz 与 explore 超时的张力（设计约定）：** 单个 `explore` 有 `timeout` 上限，无法承载数小时 fuzz。约定解法（依赖 §2.4 的常驻容器 + spec #3 的 event log）：

1. 长 fuzz 以**后台进程 / tmux 会话**形式跑在常驻容器里，受显式时间预算约束；
2. 启动 fuzz 的 `explore` 立即返回一个客观 Fact（命令行、预算、产出目录）；
3. fuzz 在容器内持续产出 crash，由 `events.jsonl` / `summary_latest.json` 承载状态；
4. 后续 `explore` 任务消费已选中的 crash 做 triage / primitive。

---

## 4. 证据流（端到端，EVIDENCE FLOW）

这是把「工具 / 协议 / agent」三者串起来的主线，实现时必须保持这条流不被短路：

```
binCain-* 工具  ──写──▶  workspace 文件(findings/ crashes/ proofs/ ...)
                                   │
agent 读取工具产出 + 自行分析 ──▶  在 Fact.description 写「客观结论 + 文件路径引用」
                                   │
Dispatcher conclude ──▶  Server 落 Fact（只存那段文本）
```

一个具体例子（pwn 典型链）：

1. `explore` agent 跑 `binCain-init`，得到 `findings/init.json`、`scripts/run_target.sh`；
2. 同/下一个 `explore` 跑 fuzz，得到 `crashes/id_000017`；
3. `explore` 跑 `binCain-triage` → `findings/crash_000017.json`（含 `rip` 偏移）；
4. `explore` 跑 `binCain-primitive assert-pc` → `proofs/proof_000017.json`（`status: verified`）；
5. agent 在 explore 的 `data.description` 写：
   > “Confirmed Level 3 控制 PC：crash_000017 cyclic offset 40，proof=proofs/proof_000017.json(status verified)，复现 scripts/repro_000017.sh。证据：findings/crash_000017.json。”
6. `reason` 读全图后判定 goal 达成，返回 `complete.from=[该 fact]`。

---

## 5. 项目约定（origin / goal / hint，CONVENTIONS）

Cairn 在建项目时要求 `origin` / `goal`，binCain 约定其语义（仅约定，不改协议）：

- **origin：** 挑战材料的描述——挂载进容器 workspace 的挑战目录（如 `target/` 下的二进制、libc、Dockerfile、README）+ 可选 remote `host:port`。
- **goal（默认）：** *“复现一个可重放的利用 primitive 证明（Level 1/2/3），并在 Fact 中给出 artifact 证据。”* 这是 V1 默认完成判据。
- **goal（可选更强）：** local shell / remote shell / capture flag。由用户在建项目时显式设置。
- **hints：** libc 版本、是否 menu-driven、聚焦 heap、协议拓扑、禁用某工具等加速信息（spec #2/#3）。

---

## 6. 五份 spec 如何分层（AUTHORITY & LAYERING）

| 顺序 | 文档 | 角色 | 与本文的关系 |
| --- | --- | --- | --- |
| 0 | **本文（集成契约）** | 权威契约基线 | —— |
| 1 | `…cairn-compatible-binary-affordance-design`（#2） | **理念锚**：affordance 而非工作流引擎 | 本文是其契约化落地 |
| 2 | `…pwn-fuzz-design`（#1） | V1 工具集、primitive 层级、完成语义、工具护栏 | 工具细节以其为准；接入形态以本文为准 |
| 3 | `…operational-hardening-design`（#3） | run profile / event log / 摘要 / primitive assertion | 提供 §3.3「长 fuzz 张力」所需的状态承载机制 |
| 4 | `…llm-first-probe-and-vuln-surface-design`（#4） | probe packet + 首轮全局漏洞面判断 | 写进 §3.1 的 prompt 散文，不新增控制层 |
| 5 | `…llm-guided-reverse-and-exploit-discovery-design`（#5） | static/hybrid/fuzz 分析姿态 + 中文攻击链报告 | 写进 §3.1 的 prompt 散文；报告是 worker artifact |

**冲突消解原则：** 任何 spec 若暗示「新增协议字段 / 让 Dispatcher 做 pwn 决策 / 用固定流水线替代图模型」，一律以本文 §7 为准否决——这些都是被 5 份 spec 一致禁止、也被 Cairn 现实排除的。

---

## 7. 不可漂移清单（NO-DRIFT CHECKLIST）

实现任何 binCain 代码 / prompt / 镜像前，逐条对照：

**硬约束（违反即破坏集成）：**

- [ ] 不给 Cairn `Fact/Intent/Hint` 或 Reason/Explore JSON 增加任何字段。
- [ ] pwn prompt 组保留 §3.1 表中全部必需占位符。
- [ ] 各任务 agent 输出严格匹配 §3.1 的 JSON 契约（含 bootstrap 主阶段必须 `fact+complete`、bootstrap_conclude 只 `fact`）。
- [ ] worker 镜像满足 §3.2 全部 Cairn worker 契约（agent CLI / workspace / AGENTS.md+CLAUDE.md / git init / 非 root）。
- [ ] binCain helper 工具**只写 workspace 文件**，绝不调用 Cairn API。
- [ ] agent 把结论写进 `description`、长数据落文件并引用路径。
- [ ] 不引入新的调度器 / posture 状态机 / 分析中间层。

**软策略（鼓励自由发挥，不要锁死）：**

- 分析姿态选择（static/hybrid/fuzz）、具体工具、intent 内容、prompt 措辞、报告风格。

---

## 8. 已知缺口与待决（KNOWN GAPS / TODO）

诚实记录当前与本契约的差距，供后续实现消化（本轮不改代码）：

1. **worker 镜像不合规：** 当前 `worker/Dockerfile` 缺：① 未安装 `claude`/`codex`/`pi` agent CLI；② `AGENTS.md` 放在 `/home/kali`（home）而非 workspace，且无 `CLAUDE.md`；③ workspace 未 `git init`。需按 §3.2 补齐后才能作为 `container.image`。
2. **主分支 vs worktree 模块分叉：** 主分支只有 `init/triage/report/cyclic`；worktree `bincain-operational-hardening` 多了 `artifacts/run_profiles/repro/primitive/protocol`（spec #3 的实现）。**建议规范模块集 = `{cyclic, init, triage, report, artifacts, run_profiles, repro, primitive, protocol}`，并将 worktree 合并为规范实现。**
3. **pwn prompt 组（§3.1 的 5 个文件）尚未编写。** 这是接入 Cairn 的核心缺口。
4. **dispatch.yaml pwn profile（§3.3）尚未编写。**
5. **prompt 组的同步 / 贡献机制（§3.1 方式 A/B）未定。**

---

## 9. 非目标（NON-GOALS）

- 不分叉或修改 Cairn 核心逻辑代码。
- 不把 binCain 变成 CRS 流水线或自动完整 exploit 生成器。
- 不保证任意二进制一次命中漏洞。
- 不用中文报告代替事实与证据本身。
