# AGENTS.md

## 适用范围

本文件适用于以下目录下的所有工作：

```text
/mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform
```

本目录是 AI4SEC 统一平台的新工程目录，用于重新设计和实现平台级架构。它不是旧 `insight-platform` 的继续堆叠，也不是当前生产大屏。

除非用户明确要求生产变更，否则本目录中的所有实现都必须保持：

```text
shadow-only
不写生产库
不改生产脚本
不推送远端
不覆盖旧报告
```

---

## 当前最高优先级文档

新目录的主设计文档是：

```text
docs/平台总体架构设计.md
```

后续开发、重构、目录创建、模块拆分、API 设计、pipeline 设计，都必须优先参考这份文档。

如果实现细节和旧 `insight-platform` 文档冲突，以本目录下的 `docs/平台总体架构设计.md` 为准。

---

## 前端 demo 参考

当前产品信息架构和前端交互原型来自：

```text
/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v3.html
/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/PAGE_IA_REFERENCE.md
```

这两个文件是平台产品形态的重要参考，尤其是：

```text
资讯洞察
能力洞察
威胁洞察
漏洞洞察
统一运营入口
```

后端 API、业务域服务、数据对象和页面返回结构，应尽量服务这个 demo 中表达的用户动线。

注意：

- `index-v3.html` 是产品原型，不是正式前端工程。
- 未经用户明确要求，不要直接修改 demo 文件。
- 如果需要设计正式前端，应以 demo 的信息架构为基础，而不是重新发明导航结构。
- 如果后端接口和 demo 发生冲突，先说明冲突点，再最小调整后端或提出 demo 更新建议。

---

## 平台总目标

AI4SEC 平台不是单独的日报流程，而是统一的 AI 安全洞察平台。

目标流程：

```text
外部数据源
  → 原始制品
  → 结构化条目
  → 领域对象
  → 模型审阅 / 规则评分 / 复现验证 / 质量审计
  → 前端工作台
  → 人工队列和后续行动
```

平台需要融合：

| 旧流程 | 新平台归属 |
|---|---|
| AI-for-Sec 日报 | 资讯洞察 + 能力洞察上游 |
| 华为 repo / CVE / 固件情报 | 威胁洞察 |
| 漏洞素材采集 | 漏洞洞察 |
| 代码复现系统 | 多业务域共用执行能力 |

---

## 与旧目录的关系

### 可参考目录

可以读取和参考：

```text
/mnt/d/漏洞挖掘/洞察工具/dashboard/insight-platform
/home/liuqi777/ai-for-sec-report
/mnt/d/漏洞挖掘/洞察工具/dashboard/repo-info/huawei
/mnt/d/漏洞挖掘/洞察工具/dashboard/vul-info/project_demo_0626
/mnt/d/漏洞挖掘/洞察工具/dashboard/test/ai-sec-dashboard-static
```

这些目录用于理解旧流程、迁移逻辑和字段含义。

### 不要直接延续的问题

不要把旧 `insight-platform/scripts/` 的堆叠方式复制到新目录。

新目录必须遵守：

```text
核心逻辑进入 src/ai4sec_platform/
scripts 只保留薄 CLI 入口
旧系统通过 adapters 接入
公共能力先成型
四个业务域按 domains/* 接入
```

---

## 推荐代码结构

新代码应按以下结构组织：

```text
ai4sec-platform/
├── configs/
├── docs/
├── src/
│   └── ai4sec_platform/
│       ├── app/
│       ├── core/
│       ├── db/
│       ├── schemas/
│       ├── sources/
│       ├── artifacts/
│       ├── pipelines/
│       ├── domains/
│       ├── agents/
│       ├── models/
│       ├── ops/
│       └── cli/
├── tests/
└── output/
```

如果需要更详细的文件级说明，先看：

```text
docs/平台总体架构设计.md
```

不要在没有说明的情况下新增平行目录或发明新的顶层结构。

---

## 公共能力放置规则

以下是平台公共能力，不属于任何单个业务域：

| 能力 | 代码位置 | 说明 |
|---|---|---|
| SourceConnector | `src/ai4sec_platform/sources/` | 外部数据源连接器接口和实现 |
| CollectorTask / CollectStep | `src/ai4sec_platform/pipelines/steps/collect.py` | 调 connector 获取数据 |
| ArtifactStore | `src/ai4sec_platform/artifacts/store.py` | 保存原始和中间制品 |
| ArtifactManifest | `src/ai4sec_platform/artifacts/manifest.py` | 记录 run 输出清单和 checksum |
| Normalizer 编排 | `src/ai4sec_platform/pipelines/steps/normalize.py` | 通用 normalize step |
| Deduper 编排 | `src/ai4sec_platform/pipelines/steps/dedupe.py` | 通用 dedupe step |
| PipelineRun / TaskRun | `src/ai4sec_platform/db/models/runs.py` | 数据库运行记录 |
| PipelineRunner | `src/ai4sec_platform/pipelines/runner.py` | 执行 pipeline 和 step |
| QualityAudit | `src/ai4sec_platform/ops/quality.py` | 公共质量审计框架 |
| HumanQueue | `src/ai4sec_platform/ops/human_queue.py` | 公共人工复核队列 |

业务域只写各自的规则、builder、adapter 和 service。

---

## 四个业务域放置规则

四个业务域必须放在：

```text
src/ai4sec_platform/domains/
```

标准结构：

```text
domains/{domain}/
├── schemas.py
├── service.py
├── pipelines.py
├── normalizers.py
├── dedupe.py
├── selectors.py
├── builders.py
├── audits.py
└── adapters/
```

对应关系：

| 业务域 | 目录 |
|---|---|
| 资讯洞察 | `domains/news/` |
| 能力洞察 | `domains/capabilities/` |
| 威胁洞察 | `domains/threats/` |
| 漏洞洞察 | `domains/vulnerabilities/` |

不要使用中文 Python 包名，中文用于文档和页面标题即可。

---

## 调用链规则

### 前端查询业务数据

标准调用链：

```text
前端页面
  → app/api/*.py
  → domains/*/service.py
  → db/repositories/*.py
  → db/models/*.py
```

### 前端触发任务

标准调用链：

```text
前端页面
  → POST /api/runs
  → app/api/runs.py
  → pipelines/registry.py
  → pipelines/runner.py
  → pipelines/steps/*.py
  → sources / domains / agents / artifacts / db
```

### Pipeline 内部

标准调用链：

```text
PipelineRunner
  → PipelineStep
  → 公共模块或 domain 模块
  → ArtifactStore
  → Repository
  → TaskRun 更新
  → Manifest 更新
```

### 禁止调用链

禁止：

```text
前端 → 旧 JSON 文件
API → 旧脚本
API → connector 细节
业务 service → 直接执行 shell
LLM Agent → 任意读写文件
scripts → 堆 pipeline 核心逻辑
```

---

## scripts 规则

新目录中 `scripts/` 只能作为薄入口。

允许：

```text
解析参数
调用 src/ai4sec_platform/cli/*
返回退出码
```

禁止：

```text
写 pipeline 主逻辑
写数据源采集逻辑
写模型调用逻辑
写渲染逻辑
写质量审计逻辑
```

---

## 自动化分工

必须区分三类自动化。

### 1. 纯代码模块

例如：

```text
Loader
Normalizer
Deduper
Selector
Fetcher
Renderer
Comparer
Indexer
```

要求：可测试、可复现、不调用模型。

### 2. 任务型 LLM Agent

位置：

```text
src/ai4sec_platform/agents/
```

要求：

```text
固定输入 schema
固定输出 schema
通过 LLMRouter 调模型
记录 ModelCall
不能任意读写文件
不能执行 shell
```

### 3. 工具型 Agent / 复现执行器

只用于：

```text
代码复现
未知仓库探索
自动调试
PoC 运行
复杂依赖排错
```

不能作为主 pipeline 的核心逻辑。必须受控、可审计、有日志、可人工复核。

---

## 前端 demo 对接原则

后端 API 应优先支持 demo 中的页面结构。

### 一级业务域

```text
资讯洞察      → /api/news
能力洞察      → /api/capabilities
威胁洞察      → /api/threats
漏洞洞察      → /api/vulnerabilities
统一运营后台  → /api/operations
```

### 统一运营入口

四个业务域都应支持统一运营视角：

```text
采集任务
数据源
规则配置
质量审计
人工队列
```

后端实现时，不要为每个业务域重新发明一套运营模型，而应复用：

```text
pipeline_runs
task_runs
data_sources
quality_audits
human_queue_items
```

---

## Shadow first 和生产安全

除非用户明确要求，否则禁止修改或写入：

```text
/mnt/d/漏洞挖掘/洞察工具/dashboard/test/daily_update.sh
/home/liuqi777/ai-for-sec-report/output/raw/review_history.json
/home/liuqi777/ai-for-sec-report/output/raw/selected_entries.json
/mnt/d/漏洞挖掘/洞察工具/version6/*.md
*/dashboard.db
/opt/dashboard/test/ai-sec-dashboard-static
/opt/dashboard2
```

禁止默认运行：

```text
生产 seed.py
云同步
远端部署
会覆盖旧报告的命令
```

新功能默认输出到：

```text
output/shadow_runs/
```

并记录：

```text
PipelineRun
TaskRun
Artifact
Manifest
checksum
production_writes=false
```

---

## 密钥处理规则

禁止提交密钥。

不要把 token 写进代码、prompt、文档或测试数据。

敏感字段包括：

```text
GITHUB_TOKEN
DEEPSEEK_API_KEY
DASHSCOPE_API_KEY
ANTHROPIC_AUTH_TOKEN
GETXAPI_KEY
```

密钥只能放在 `.env` 或本地部署密钥系统中。

提交或交付前至少扫描常见 token 模式。

---

## 开发顺序建议

第一阶段只做平台骨架和一个真实样板流程：

```text
1. 建 core/config/logging/errors/ids
2. 建 db/session/models/repositories
3. 建 artifacts/store/manifest/checksum
4. 建 pipelines/base/context/registry/runner
5. 建 app/main/api/runs/api/news
6. 建 domains/news 最小模块
7. 导入 AI-for-Sec V2 shadow 输出作为样板数据
```

第一阶段不要做：

```text
不要迁移所有旧脚本
不要同时接入四个旧系统
不要做生产写入
不要上复杂队列
不要把 demo 直接改成正式前端
不要在 scripts 里继续堆逻辑
```

---

## 验证规则

如果新增代码，优先补测试。

建议验证顺序：

```bash
python -m compileall -q src tests
pytest -q
```

如果只改文档，至少做一次敏感信息自检：

```text
扫描常见 GitHub token、OpenAI-style key、GITHUB_TOKEN、DEEPSEEK_API_KEY、DASHSCOPE_API_KEY 等模式。
排除 .git、output 和 .env。
```

如果本目录尚未初始化 Git，不要擅自 `git init` 或提交，除非用户明确要求。

---

## 最重要的判断标准

写任何代码前先回答：

1. 这个功能属于公共能力，还是某个业务域？
2. 如果是公共能力，应该在 `sources`、`artifacts`、`pipelines`、`ops`、`db` 还是 `models`？
3. 如果是业务域能力，应该在 `domains/news`、`domains/capabilities`、`domains/threats` 还是 `domains/vulnerabilities`？
4. 它被谁调用？API、PipelineStep、Service、Agent，还是 CLI？
5. 它输出什么？数据库记录、artifact、manifest、API 响应，还是人工队列项？
6. 它是否写生产？如果写生产，是否已经明确获得用户要求？

回答不清楚时，不要继续堆代码，先更新 `docs/平台总体架构设计.md` 或向用户确认。
