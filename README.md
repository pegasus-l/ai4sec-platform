# AI4SEC Platform

AI4SEC 统一洞察平台新工程目录。

当前阶段目标：先用旧系统现有数据导入 SQLite，提供四个业务域和统一运营入口的展示 API；暂不做真实采集、模型重跑、复现执行或生产写入。

## 快速开始

```bash
cd /mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform
PYTHONPATH=src python3 -m ai4sec_platform.cli.import_legacy_samples --reset
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


## 前端页面

当前已内置前端工作台，页面壳对齐 `/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v6.html`，并由 FastAPI 直接提供服务。

```text
http://127.0.0.1:8000/
```

页面会调用 `/api/dashboard/overview`、四个业务域 `today` 接口和统一运营接口。首次访问前请先运行旧数据导入命令。

## 后端任务触发

当前已支持通过 API 或 CLI 触发第一版最小 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline legacy.sample_import --reset
```

或通过 HTTP：

```text
POST /api/runs
{"pipeline_name": "legacy.sample_import", "reset": true}
```

该 pipeline 会创建总控 PipelineRun，执行旧数据导入 step，写入 TaskRun、Artifact 和 manifest，仍保持 `production_writes=false`。

## Raw Pipeline 纠偏说明

当前保留 `legacy.sample_import` 作为临时展示导入，但正式主线已经开始迁移到 raw pipeline。

第一条 raw pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline news.ai_for_sec_raw_pipeline \
  --reset
```

该 pipeline 从 AI-for-Sec raw 六源文件读取数据，写入 `raw_artifacts`、`normalized_items`，再构造 `news` 和 `capabilities` 的 `domain_items`。它不以旧 `selected_entries.json` 作为正式主输入。

对应 API：

```text
POST /api/runs {"pipeline_name": "news.ai_for_sec_raw_pipeline", "reset": true, "params": {"date": "2026-07-10"}}
```

## 工程骨架状态

当前已按 `docs/平台总体架构设计.md` 补齐长期架构目录和关键文件：

```text
app / core / db / schemas / sources / artifacts / pipelines / domains / agents / models / ops / cli
```

其中 `news.ai_for_sec_raw_pipeline` 已可运行；其他业务域已具备标准目录、service/pipeline/adapter/builder/audit 文件边界和 placeholder pipeline，后续继续在这些文件中填实真实逻辑，不再新增散乱脚本。
