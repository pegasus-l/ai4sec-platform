# 资讯洞察 GLM-5.2 批量验收报告

## 1. 验收结论

DashScope `glm-5.2` 已完成资讯洞察两阶段批量验收，可以继续作为默认评审模型。

- 40 条候选全部完成技术地图门控，门控调用成功率 100%。
- 32 条进入深度评审，首次成功 30 条；2 条读取超时，重试后均成功。
- 最终 21 条精选、8 条观察、11 条淘汰，精选率 52.5%。
- 8 条对照样本中没有条目进入精选，第二阶段能够过滤门控阶段保留的弱相关候选。
- 32 条深评结果均包含合法技术路径和完整中文展示内容。
- 当前 `pass >= 70/55`、`needs_review >= 55 或潜力 >= 70` 的门控阈值暂不调整。
- 验收后已补充模型调用自动重试和指数退避，覆盖网络超时、连接错误、HTTP `429` 与 `5xx`。

## 2. 数据与方法

验收基线来自 `ai-for-sec-report/output/raw/` 中 `2026-07-10` 的固定原始数据：

- arXiv：29 篇论文中分层抽取 20 篇。
- GitHub：60 个项目中分层抽取 20 个。
- 明显相关：20 条。
- 边界相关：12 条。
- 对照样本：8 条。

分层仅用于构造覆盖不同难度的固定样本，不作为模型评审的规则输入或绝对真值。模型仍基于原始候选信息和技术地图独立判断。

执行流程：

```text
40 条候选
  → GLM-5.2 技术地图门控
  → 26 pass + 6 needs_review + 8 reject
  → 32 条 GLM-5.2 深度评审
  → 21 selected + 8 watch + 3 rejected
```

完整本地验收产物：

```text
output/glm52-acceptance/sample.json
output/glm52-acceptance/gated.json
output/glm52-acceptance/results.json
```

## 3. 核心指标

| 指标 | 结果 |
|---|---:|
| 门控候选 | 40 |
| 门控通过或待复核 | 32（80%） |
| 门控直接淘汰 | 8（20%） |
| 深评精选 | 21（52.5%） |
| 深评观察 | 8（20%） |
| 深评淘汰 | 3（7.5%） |
| 最终淘汰 | 11（27.5%） |
| 门控平均延迟 | 24.4 秒 |
| 门控 P95 延迟 | 44.3 秒 |
| 深评平均延迟 | 49.3 秒 |
| 深评 P95 延迟 | 82.4 秒 |
| 中文内容完整率 | 32/32 |
| 合法技术路径覆盖率 | 32/32 |
| 首次深评成功率 | 30/32（93.75%） |
| 重试后深评成功率 | 32/32（100%） |

按类型统计：

| 类型 | 精选 | 观察 | 深评淘汰 | 门控淘汰 |
|---|---:|---:|---:|---:|
| 论文 | 13 | 4 | 1 | 2 |
| 项目 | 8 | 4 | 2 | 6 |

按分层统计：

| 分层 | 样本 | 精选 | 观察 | 淘汰 |
|---|---:|---:|---:|---:|
| 明显相关 | 20 | 16 | 2 | 2 |
| 边界相关 | 12 | 5 | 4 | 3 |
| 对照样本 | 8 | 0 | 2 | 6 |

## 4. 精选结果

精选论文 13 篇：

| ID | 分数 | 标题 |
|---|---:|---|
| paper-00 | 71.95 | Workflow as Knowledge: Semantic Persistence for LLM-Mediated Workflows |
| paper-01 | 78.60 | Game Theory Driven Multi-Agent Framework Mitigates Language Model Hallucination |
| paper-05 | 80.85 | Persuasion Attacks Can Decrease Effectiveness of CoT Monitoring |
| paper-06 | 76.00 | AutoPersonas: A Multi-Timescale Loop Engine for Open-Ended Persona Evolution |
| paper-08 | 85.50 | What to Keep, What to Forget: A Rate--Distortion View of Memory Compaction in LLMs and Agents |
| paper-14 | 80.65 | Context Graphs for Proactive Enterprise Agents |
| paper-15 | 85.00 | From Legacy Documentation to OSCAL: An MCP-Based Agent Pipeline for Threat-Informed Continuous Compliance in Critical Infrastructure |
| paper-16 | 71.25 | Harness VLA: Steering Frozen VLAs into Reliable Manipulation Primitives via Memory-Guided Agents |
| paper-17 | 77.45 | WebSwarm: Recursive Multi-Agent Orchestration for Deep-and-Wide Web Search |
| paper-21 | 81.60 | DeepSearch-World: Self-Distillation for Deep Search Agents in a Verifiable Environment |
| paper-22 | 76.25 | SolarChain-Eval: A Physics-Constrained Benchmark for Trustworthy Economic Agents in Decentralized Energy Markets |
| paper-24 | 83.25 | Who Broke the System? Failure Localization in LLM-Based Multi-Agent Systems |
| paper-26 | 81.60 | ScopeJudge: Cost-Aware Pre-Execution Gating for Offensive Security Agents |

精选项目 8 个：

| ID | 分数 | 项目 |
|---|---:|---|
| project-01 | 74.75 | agentuniverse-ai/agentUniverse |
| project-02 | 71.75 | Joooook/12306-mcp |
| project-03 | 77.55 | symgraph/GhidrAssistMCP |
| project-18 | 83.50 | leesgit/claude-session-continuity-mcp |
| project-21 | 72.20 | adam-eques/langgraph-research-agent |
| project-22 | 79.00 | metric-space-ai/greppy |
| project-31 | 78.40 | rob925/mcp-shield |
| project-47 | 75.50 | mohansagark/claude-graph |

## 5. 边界与对照检查

4 条对照样本通过了高召回门控，但均未进入精选：

| 条目 | 最终结果 | 分数 |
|---|---|---:|
| WCog-VLA 自动驾驶模型 | watch | 62.00 |
| MASTE 情感抽取多 Agent Pipeline | rejected | 53.50 |
| 保险核保 Agentic RAG | watch | 58.25 |
| Worry-Free-Travel-Backend | rejected | 51.50 |

这说明第一阶段可以保持高召回，第二阶段利用技术深度、工程价值、可复现性和影响力进一步过滤泛 Agent/RAG 条目。

对三个“存在合法技术路径但被门控淘汰”的项目进行了不改变正式规则的反事实深评：

| 项目 | 门控相关/潜力 | 反事实深评分 | 结论 |
|---|---:|---:|---|
| prest/prest | 45 / 30 | 46.75 | 仅 MCP 暴露接口，不具备足够 Agent 技术深度 |
| squirrelscan/squirrelscan | 35 / 40 | 28.50 | 通用网站 QA 工具，与 Agent 安全护栏关联较弱 |
| Agentic-Security-GRC | 40 / 45 | 34.50 | 描述信息不足且偏 GRC 控制原型 |

三条反事实深评仍全部淘汰，因此没有证据支持降低当前门控灰区阈值。

## 6. 输出质量

- 32/32 深评结果都生成了中文主题、摘要、宣传一句话、亮点一句话和评审意见。
- 32/32 深评结果至少包含一个经过技术地图校验的合法路径。
- 31/32 原始结果严格只返回约定的七个评分字段。
- `paper-21` 额外返回了一个未约定字段，后端白名单归一化已安全忽略，不影响评分。
- 40 条门控中有 9 条模型原始 `decision` 与其自身分数不符合约定阈值；后端根据百分制分数重新确定 decision，最终结果稳定。
- 高频技术点包括 MCP 协议、Manager 进程调度、危险操作拦截、跨 session 持久化、知识图谱和上下文窗口管理。

## 7. 风险与后续动作

### P0：自动重试（已完成）

32 次深评中有 2 次首次读取超时，说明生产流水线不能在第一次网络异常后直接降级。验收后已实现：

- 网络超时、连接错误和 429/5xx 最多额外重试 2 次。
- 使用 `1s → 2s` 指数退避并加入 `0–0.5s` 随机抖动。
- JSON 解析失败可以追加一次“仅修复 JSON 格式”的重试。
- 每次尝试继续写入模型调用审计，最终指标区分首次成功和重试成功。

### P1：保留后端确定性决策

模型的 decision 字段存在 22.5% 的阈值不一致，必须继续由后端基于合法技术路径、相关分和潜力分重新计算，不能直接信任模型 decision。

### P1：补充项目信息后再评估

GitHub 项目的门控淘汰率高于论文。正式联网采集应确保项目描述、README 摘要、star、更新时间和论文关联尽可能完整；但门控阶段仍需限制 README 长度，避免扩大首阶段成本。

### P2：扩大新鲜数据验收

本次固定数据适合比较模型与提示词。下一轮应从真实联网采集器获取最新论文和项目，重点检查新项目、低 star 项目以及由 RSS/Awesome/ASIS 发现的间接引用。

## 8. 最终判断

`glm-5.2` 在固定 40 条样本上表现出可接受的技术地图相关性、对照过滤能力、评分尺度和中文内容质量。维持当前提示词、评分权重和门控阈值，先补齐自动重试，再进入六个数据源的真实增量采集验收。

## 9. 命名主题刷新（v3）

深评提示词后续升级为“工作名 + 中文技术定位”契约，后端统一拼接为 `工作名：技术定位`，以对齐旧日报和大屏风格。例如：

```text
AgentLocate：面向大模型多智能体系统的失败定位与归因框架
ScopeJudge：面向攻击性安全Agent的成本感知执行前门控框架
GhidrAssistMCP：面向逆向工程场景的原生 Ghidra MCP 服务端扩展
```

对本报告中 21 条既有精选仅重跑深评后，21/21 都生成了该格式的主题；其中 18 条仍达到精选阈值，3 条因模型评分波动转为观察。预览页面采用这 18 条新版结果。工作名均可在原始标题、摘要或仓库信息中找到，避免无依据编造缩写。
