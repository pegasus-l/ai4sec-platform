# AI4SEC Platform

AI4SEC 统一洞察平台新工程目录。

当前阶段目标：只读取旧系统已经落盘的本地原始数据文件，走新平台自己的导入、标准化、去重、证据、评估和展示链路；暂不做联网数据源获取、真实模型重跑、复现执行或生产写入。

## 快速开始

```bash
cd /mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.ai_for_sec_local_raw_import --reset
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
GET /api/frontend/v9
GET /api/frontend/v9/files/{path}
```

## 文档

```text
docs/平台总体架构设计.md
docs/开发记录.md
AGENTS.md
```

## 安全边界

- `.env` 被 Git 忽略。
- 输出数据库位于 `output/ai4sec_platform.db`，也被 Git 忽略。
- 当前实现 `production_writes=false`，不写生产路径。
- 威胁洞察 connector 默认直接获取外部数据；资讯/漏洞当前仍按既定范围读取本地 raw 输入。
- 模型配置从 `.env` 自动读取，优先使用 DeepSeek / DashScope / Local LLM 这类 OpenAI-compatible 配置；测试环境默认回退到 `local_rules`，避免单测触发真实模型费用。


## 前端页面

当前前端已重建为 React + Vite + TypeScript 工程，威胁洞察参考 `/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v12.html` 的功能布局，并沿用 v9 的深色视觉风格。FastAPI 会直接提供 `frontend/dist` 构建产物。

```text
http://127.0.0.1:8000/
```

页面会调用 `/api/dashboard/overview`、四个业务域接口和统一运营接口。首次访问前请先运行本地原始数据导入 pipeline。

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

当前已支持通过 API 或 CLI 触发第一版最小 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.ai_for_sec_local_raw_import --reset
```

或通过 HTTP：

```text
POST /api/runs
{"pipeline_name": "news.ai_for_sec_local_raw_import", "reset": true, "params": {"date": "2026-07-10"}}
```

该 pipeline 会创建总控 PipelineRun，读取本地原始 JSON，执行标准化和领域对象构建，写入 TaskRun、Artifact 和 manifest，仍保持 `production_writes=false`。

## 本地原始数据导入说明

当前正式主线已经迁移到 local raw import。这里的 `raw` 指“旧系统已经保存到磁盘的原始 JSON 文件”，不是联网采集；旧的 `importers/` 兼容导入目录已经删除，避免继续依赖旧处理结果。

新闻洞察本地原始数据导入：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline news.ai_for_sec_local_raw_import \
  --reset
```

该 pipeline 从 AI-for-Sec 本地 raw 六源文件读取数据，写入 `raw_artifacts`、`normalized_items`，再构造 `news` 和 `capabilities` 的 `domain_items`。它不联网，也不以旧 `selected_entries.json` 作为正式主输入。

对应 API：

```text
POST /api/runs {"pipeline_name": "news.ai_for_sec_local_raw_import", "reset": true, "params": {"date": "2026-07-10"}}
```

## 工程骨架状态

当前已按 `docs/平台总体架构设计.md` 补齐长期架构目录和关键文件：

```text
app / core / db / schemas / sources / artifacts / pipelines / domains / agents / models / ops / cli
```

其中资讯本地 raw 导入、漏洞素材本地 raw 导入、漏洞外部素材发现与威胁 connector pipeline 已可运行；其他业务域继续在标准目录、service/pipeline/adapter/builder/audit 文件边界内填实逻辑，不再新增散乱脚本。

## 已实现核心 Pipelines

当前已实现资讯、威胁、漏洞三条核心输入处理 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.ai_for_sec_local_raw_import --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline threats.huawei_raw_pipeline --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.material_local_raw_import --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.external_material_discovery_pipeline --params '{"queries":["CVE-2024 exploit root cause analysis"],"max_results":5,"crawl_limit":5}'
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.full_knowledge_discovery_pipeline --params '{"queries":["CVE-2024 exploit root cause analysis"],"max_results":5,"crawl_limit":5}'
```

说明：

- `news.ai_for_sec_local_raw_import` 从 AI-for-Sec 六类本地 raw 文件导入。
- `threats.huawei_raw_pipeline` 通过威胁 connector 获取华为 repo、issue/security 文件、固件和镜像数据并生成威胁目标。
- `vulnerabilities.material_local_raw_import` 从漏洞素材 report 本地 JSON 导入。
- `vulnerabilities.external_material_discovery_pipeline` 通过 AnySearch 获取候选 URL，经 crawl4ai/urllib 抓取、规则审核后构建优质漏洞素材；未配置 `ANYSEARCH_API_KEY` 时可通过 `seed_candidates` 参数做 shadow/测试运行。
- `vulnerabilities.full_knowledge_discovery_pipeline` 在外部发现后继续完成 CVE 事件聚合与本地规则知识抽取，用于端到端 shadow 验证。
- 这些 pipeline 都会写 `raw_artifacts`、`normalized_items`、`domain_items`、`evidence_items`、`pipeline_runs`、`task_runs` 和 manifest。
- 所有 pipeline 仍保持 `production_writes=false`，不写生产路径。

## 核心数据处理逻辑

当前已实现第一版真实处理逻辑，不再只是字段搬运：

- 资讯：按 AI 安全、Agent 安全、漏洞攻防、代码仓库线索分类，并按相关性、代码线索、影响力和新鲜度评分。
- 能力：从资讯候选中识别可复现代码/论文线索，按复现性、研究价值和安全价值评分。
- 威胁：从 repo/CVE/固件/镜像 raw 中抽 CVE、security issue、advisory、exploit/PoC、暴露面信号，并输出可解释风险分。
- 漏洞素材：从搜索/报告 raw 中判断 PoC/Exploit、深度技术分析、漏洞公告、影响范围线索，抽取 CVE、影响版本、PoC 和修复线索，并计算素材有效性分。

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

在 `news.ai_for_sec_local_raw_import` 运行后，可以继续运行：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline capabilities.from_news_pipeline
```

该 pipeline 会复用或生成能力候选，优先使用 `.env` 中配置的真实模型完成能力评估；如未配置模型则回退到本地规则引擎，并写入 `model_calls`。

## 前端 v9 数据契约

后端已提供聚合接口，直接返回 `/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v9.html` 所需的主要数据块：

```text
GET /api/frontend/v9
```

同时提供兼容 demo 样例 JSON 目录的路径别名：

```text
GET /api/frontend/v9/files/manifest.json
GET /api/frontend/v9/files/news/items.json
GET /api/frontend/v9/files/capability/today.json
GET /api/frontend/v9/files/threat/targets.json
GET /api/frontend/v9/files/vuln/materials.json
GET /api/frontend/v9/files/ops/tasks.json
```

这些数据仍来自本地原始数据导入后的新处理链路，不读取旧系统已处理完成的展示结果作为正式主输入。
