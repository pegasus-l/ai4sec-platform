# AI4SEC Platform

AI4SEC 统一洞察平台新工程目录。

当前阶段目标：在 shadow-only 约束下走新平台自己的采集、标准化、去重、证据、评估和展示链路；资讯洞察支持本地 raw 回归导入和 arXiv/GitHub/RSS shadow 采集，不写生产库、不覆盖旧报告。

## 快速开始

```bash
cd /mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.legacy_raw_pipeline --reset
PYTHONPATH=src uvicorn ai4sec_platform.app.main:app --reload --host 127.0.0.1 --port 8000
```

浏览器打开：

```text
http://127.0.0.1:8000/
```

## 核心接口

```text
GET /api/health
GET /api/dashboard/overview
GET /api/runs/pipelines
POST /api/runs
GET /api/runs
GET /api/runs/{run_id}
GET /api/news/today
GET /api/news/items
GET /api/news/reports
GET /api/news/topics
GET /api/capabilities/today
GET /api/threats/today
GET /api/threats/cve-scout
GET /api/threats/attack-surface
GET /api/threats/assets
GET /api/threats/reports
GET /api/vulnerabilities/today
GET /api/operations/tasks
GET /api/operations/sources
GET /api/operations/audits
GET /api/operations/human-queue
```

## 文档

```text
docs/平台总体架构设计.md
docs/Beta到生产级实施总计划.md
docs/开发记录.md
AGENTS.md
```

## 安全边界

- `.env` 被 Git 忽略。
- 输出数据库位于 `output/ai4sec_platform.db`，也被 Git 忽略。
- 当前实现 `production_writes=false`，不写生产路径。
- 资讯洞察支持 arXiv/GitHub/RSS shadow 采集，也支持本地 raw 回归导入；漏洞当前仍按既定范围读取本地 raw 输入。
- 模型配置从 `.env` 自动读取，优先使用 DeepSeek / DashScope / Local LLM 这类 OpenAI-compatible 配置；测试环境默认回退到 `local_rules`，避免单测触发真实模型费用。

## SQLite 运维

单机部署默认启用 WAL、外键校验、30 秒 busy timeout 和 `synchronous=NORMAL`。可以通过 `AI4SEC_SQLITE_BUSY_TIMEOUT_MS` 与 `AI4SEC_SQLITE_SYNCHRONOUS` 调整；生产环境建议保持 `NORMAL` 或 `FULL`。

在线创建一致性备份并校验：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.database backup
PYTHONPATH=src python3 -m ai4sec_platform.cli.database verify output/backups/ai4sec-platform-*.db
```

恢复到指定文件：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.database restore \
  output/backups/ai4sec-platform-20260728T000000000000Z.db \
  --destination output/ai4sec-platform-restored.db
```

覆盖已有数据库必须显式增加 `--overwrite`。替换正在使用的主数据库前必须停止 API、Pipeline Worker 和复现 Worker，并先保留当前数据库备份。


## 前端页面

当前前端已重建为 React + Vite + TypeScript 工程，资讯洞察提供今日精选、全部动态、日报、专题时间线四个页签；威胁洞察参考 `/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v12.html` 的功能布局，并沿用 v9 的深色视觉风格。FastAPI 会直接提供 `frontend/dist` 构建产物。

```text
http://127.0.0.1:8000/
```

页面会调用 `/api/news/*`、威胁域接口和统一运营接口。首次访问前建议先运行资讯本地 raw 导入或 shadow 采集 pipeline。

前端开发：

```bash
cd frontend
npm install
npm run dev
```

前端构建：

```bash
cd frontend
npm run build
```

## 后端任务触发

生产形态使用独立单机 Pipeline Worker。先启动 Worker：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.pipeline_worker --poll-interval 1
```

API 提交的任务会先写入 SQLite `pipeline_jobs`，`wait=false` 时立即返回可轮询的 `run_id`：

```text
POST /api/runs
{"pipeline_name": "news.legacy_raw_pipeline", "reset": true, "wait": false, "params": {"date": "2026-07-10"}}
```

`wait=true` 暂时保留给本地开发、测试和管理命令：它仍先持久入队，再在单 Worker 文件锁保护下同步领取该任务。正式部署的页面和调度器应使用 `wait=false`，由独立 Worker 执行。

Worker 重启时，尚未领取的 `queued` 任务会保留。已经处于 `running` 的中断任务会明确标记为 `failed`，在 Step checkpoint 和幂等重放完成前不会自动从头执行，避免重复写入和重复模型调用。

任务可以通过以下接口请求取消：

```text
POST /api/runs/{run_id}/cancel
```

排队任务会立即变为 `cancelled`；运行中任务会设置取消请求，并在当前 Pipeline Step 完成后的安全边界停止。该接口目前不是进程、浏览器或容器级强制终止，阻塞 Step 的 timeout 和 kill switch 仍需单独实现。

失败或取消的 Run 如果存在校验通过的 checkpoint，并且下一个 Step 已显式声明 `resume_safe=true`，可以创建新的续跑任务：

```text
POST /api/runs/{run_id}/retry
{"wait": false}
```

Checkpoint 绑定 Pipeline、业务参数、Step 顺序、Step 类实现源码摘要和版本。参数或实现变化时拒绝恢复；待恢复 Step 还必须显式声明 `resume_input_keys`，只持久化经过审核的必要上下文字段。未完成幂等和输出敏感性审计的 Step 默认不生成可恢复 checkpoint。当前四个业务域仍需逐 Step 完成审核，不能把历史任务存在等同于可安全重放。

也可以绕过队列直接通过 CLI 执行调试 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.legacy_raw_pipeline --reset
```

该 pipeline 会创建总控 PipelineRun，读取本地原始 JSON，执行标准化、去重、资讯对象构建、日报生成和质量审计，写入 TaskRun、Artifact 和 manifest，仍保持 `production_writes=false`。

如需获取最新资讯，可运行 shadow 采集：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline news.shadow_collect_pipeline \
  --reset
```

## 本地原始数据导入说明

当前正式主线已经迁移到 local raw import。这里的 `raw` 指“旧系统已经保存到磁盘的原始 JSON 文件”，不是联网采集；旧的 `importers/` 兼容导入目录已经删除，避免继续依赖旧处理结果。

新闻洞察本地原始数据导入：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline news.legacy_raw_pipeline \
  --reset
```

该 pipeline 从 AI-for-Sec 本地 raw 六源文件读取数据，写入 `raw_artifacts`、`normalized_items`，再构造 `news` 的 `domain_items`、证据、日报和质量审计。它不联网，也不以旧 `selected_entries.json` 作为正式主输入；能力候选只在用户操作或能力域 pipeline 中生成。

对应 API：

```text
POST /api/runs {"pipeline_name": "news.legacy_raw_pipeline", "reset": true, "params": {"date": "2026-07-10"}}
```

## 工程骨架状态

当前已按 `docs/平台总体架构设计.md` 补齐长期架构目录和关键文件：

```text
app / core / db / schemas / sources / artifacts / pipelines / domains / agents / models / ops / cli
```

其中资讯本地 raw 导入、漏洞素材本地 raw 导入、漏洞外部素材发现与威胁 connector pipeline 已可运行；其他业务域继续在标准目录、service/pipeline/adapter/builder/audit 文件边界内填实逻辑，不再新增散乱脚本。

## 已实现核心 Pipelines

当前已实现资讯、威胁、漏洞核心输入处理 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.legacy_raw_pipeline --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.shadow_collect_pipeline --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline threats.huawei_raw_pipeline --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.material_local_raw_import --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.external_material_discovery_pipeline --params '{"queries":["CVE-2024 exploit root cause analysis"],"max_results":5,"crawl_limit":5}'
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.full_knowledge_discovery_pipeline --params '{"queries":["CVE-2024 exploit root cause analysis"],"max_results":5,"crawl_limit":5}'
```

说明：

- `news.legacy_raw_pipeline` 从 AI-for-Sec 六类本地 raw 文件导入。
- `news.shadow_collect_pipeline` 从 arXiv/GitHub/RSS 获取最新资讯并走同一套处理链路。
- `threats.huawei_raw_pipeline` 通过威胁 connector 获取华为 repo、issue/security 文件、固件和镜像数据并生成威胁目标。
- `vulnerabilities.material_local_raw_import` 从漏洞素材 report 本地 JSON 导入。
- `vulnerabilities.external_material_discovery_pipeline` 通过 AnySearch 获取候选 URL，经 crawl4ai/urllib 抓取、规则审核后构建优质漏洞素材；未配置 `ANYSEARCH_API_KEY` 时可通过 `seed_candidates` 参数做 shadow/测试运行。
- `vulnerabilities.full_knowledge_discovery_pipeline` 在外部发现后继续完成 CVE 事件聚合与本地规则知识抽取，用于端到端 shadow 验证。
- 这些 pipeline 都会写 `raw_artifacts`、`normalized_items`、`domain_items`、`evidence_items`、`pipeline_runs`、`task_runs` 和 manifest。
- 所有 pipeline 仍保持 `production_writes=false`，不写生产路径。

### 漏洞外部发现链路和模型使用

旧 `vul-info/project_demo_0626` 中，AnySearch 负责候选 URL 检索，crawl4ai 负责抓取网页，之后有三个模型阶段：

1. `ContentExtractor`：从抓取 markdown 中抽取正文；
2. `ContentChecker`：判断是否为高质量漏洞素材，并输出 `is_relevant/confidence/reason/key_findings`；
3. `UrlClassifier`：对相关 URL 做 PoC/技术分析/内核安全/学术会议等分类。

当前新平台保持能力不降级：

- `extract_crawled_content` 阶段优先使用 OpenAI-compatible 模型抽正文，失败或测试环境回退本地规则；
- `review_crawled_materials` 阶段优先使用 OpenAI-compatible 模型做素材审核，输出 `accept/needs_review/reject`，失败或测试环境回退本地规则；
- 素材审核对齐旧实现的“高质量漏洞技术分析”口径：CVE/NVD/OpenCVE 页面、厂商公告、补丁列表如果缺少独立根因/触发条件/PoC/利用链/修复分析，不会直接 `accept`；CVE 只作为事件聚合连接键，不作为优质素材通过依据；
- `extract_vulnerability_knowledge` 阶段优先使用 OpenAI-compatible 模型抽取结构化漏洞知识，失败或测试环境回退 `LocalRuleProvider`。

模型配置从 `.env` 读取，支持 `AI4SEC_OPENAI_*`、`OPENAI_*`、`DEEPSEEK_*`、`DASHSCOPE_*` 等 OpenAI-compatible 配置。`ANYSEARCH_API_KEY` / `ANYSEARCH_BASE_URL` 可从旧漏洞工程 `.env` 同步到本目录 `.env`；这些本地配置被 `.gitignore` 忽略，不提交。

## 核心数据处理逻辑

当前已实现第一版真实处理逻辑，不再只是字段搬运：

- 资讯：按 AI 安全、Agent 安全、漏洞攻防、代码仓库线索分类，并按相关性、安全价值、可复现性、影响力、新鲜度和完整度评分。
- 能力：从资讯候选中识别可复现代码/论文线索，按复现性、研究价值和安全价值评分。
- 威胁：从 repo/CVE/固件/镜像 raw 中抽 CVE、security issue、advisory、exploit/PoC、暴露面信号，并输出可解释风险分。
- 漏洞素材：从搜索/报告 raw 中优先保留 PoC/Exploit、深度技术分析和具备完整技术证据的研究文章；CVE/公告/影响范围线索用于聚合和复核，缺少独立分析时不作为展示素材直接通过。

公共结构位于 `schemas/classification.py` 和 `schemas/scoring.py`；公共编排位于 `pipelines/steps/classify.py` 和 `pipelines/steps/score.py`；领域规则继续放在 `domains/*/` 下。

## 华为威胁完整迁移 Pipeline

旧 `/repo-info/huawei` 的核心逻辑已迁入当前架构：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline threats.huawei_full_migration_pipeline --reset
```

如需像旧脚本一样先按源采集并保存中间结果，再复用该结果跑后续处理：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline threats.huawei_collect_sources_pipeline \
  --reset

PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline threats.huawei_full_migration_pipeline \
  --reset \
  --params '{"resume_from_run_id":"上一步_run_id"}'
```

也可以用 `source_records_path` 指向 `output/shadow_runs/{run_id}/threats/huawei_source_records.json`。默认不启用缓存；如需复用相同参数的 connector 输出，可传 `use_source_cache=true`，强制刷新传 `refresh_source_cache=true`。

source 级缓存也支持选择性采集和刷新：

```text
sources=["repos", "firmware"]          # 只采集指定 source
refresh_sources=["repos"]              # 只刷新 repos，其他 source 读缓存
use_source_cache=true                   # 显式启用缓存复用
```

性能相关参数：

```text
max_workers=4          # repo 按组织并发抓取
issue_max_workers=4    # 普通项目 issue/PR 并发抓取
asset_max_workers=2    # firmware/AscendHub/mirror/OpenX 并发抓取
timeout_seconds=15     # 单请求超时
```

包含：security repo 发现、CVE/SA/broad security 侦察、平台攻击面评分/过滤、固件/AscendHub/镜像资产导入、LLM 语义复核、迁移报告 artifact。

威胁洞察生产链路不读取旧 processed 输出，不生成 baseline/compare artifact。CVE scout、攻击面评分和报告都由 connector 获取的数据在当前 pipeline 内生成。

默认威胁扫描覆盖旧实现同一批 25 个组织，但为了避免一次运行阻塞，默认每个组织抓取 1 页、每页 50 个 repo，security 深挖限制为少量仓库/文件，风险语义复核默认 Top 5。需要放大时通过 API/CLI 参数传 `scan_profile=full` 或显式设置 `page_limit`、`per_page`、`security_repo_limit`、`security_file_limit`、`risk_review_limit`。

示例：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline threats.huawei_full_migration_pipeline \
  --reset

PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline threats.huawei_full_migration_pipeline \
  --reset
```

## 能力洞察 Pipeline

在 `news.legacy_raw_pipeline` 运行后，可以继续运行：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline capabilities.from_news_pipeline
```

该 pipeline 会复用或生成能力候选，优先使用 `.env` 中配置的真实模型完成能力评估；如未配置模型则回退到本地规则引擎，并写入 `model_calls`。
