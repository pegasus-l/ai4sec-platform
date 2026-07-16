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
