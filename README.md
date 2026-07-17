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
- 当前实现 `live_source_fetch_enabled=false`，所有 source connector 只能读本地 JSON 原始文件；HTTP/HTTPS 路径会被拒绝。
- 模型配置从 `.env` 自动读取，优先使用 DeepSeek / DashScope / Local LLM 这类 OpenAI-compatible 配置；测试环境默认回退到 `local_rules`，避免单测触发真实模型费用。


## 前端页面

当前已内置前端工作台，页面壳会继续向 `/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v9.html` 的信息架构迁移，并由 FastAPI 直接提供服务。

```text
http://127.0.0.1:8000/
```

页面会调用 `/api/dashboard/overview`、四个业务域接口和统一运营接口。首次访问前请先运行本地原始数据导入 pipeline。

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

其中三条 local raw import 已可运行；其他业务域继续在标准目录、service/pipeline/adapter/builder/audit 文件边界内填实逻辑，不再新增散乱脚本。

## 已实现本地原始数据导入 Pipelines

当前已实现三条本地原始数据导入 pipeline，兼容旧 `*_raw_pipeline` 名称，但建议使用 `*_local_raw_import`：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.ai_for_sec_local_raw_import --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline threats.huawei_local_raw_import --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.material_local_raw_import --reset
```

说明：

- `news.ai_for_sec_local_raw_import` 从 AI-for-Sec 六类本地 raw 文件导入。
- `threats.huawei_local_raw_import` 从华为 repo/CVE/固件/镜像本地 raw JSON 导入。
- `vulnerabilities.material_local_raw_import` 从漏洞素材 report 本地 JSON 导入。
- 三者都会写 `raw_artifacts`、`normalized_items`、`domain_items`、`evidence_items`、`pipeline_runs`、`task_runs` 和 manifest。
- 所有 pipeline 仍保持 `production_writes=false` 和 `live_source_fetch_enabled=false`。

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
