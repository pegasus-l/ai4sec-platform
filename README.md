# AI4SEC Platform

AI4SEC 统一洞察平台新工程目录。

当前阶段目标：在 shadow-only 约束下走新平台自己的采集、标准化、去重、证据、评估和展示链路；资讯洞察正式运行使用在线连接器，本地历史 raw 仅保留受控一次性迁移入口，不写生产库、不覆盖旧报告。

## 快速开始

```bash
cd /mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform
PYTHONPATH=src uvicorn ai4sec_platform.app.main:app --reload --host 127.0.0.1 --port 8000
```

浏览器打开：

```text
http://127.0.0.1:8000/
```

## 核心接口

```text
GET /api/health
GET /api/health/ready
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
- 资讯洞察正式入口只提供在线 shadow/daily Pipeline；历史 raw 只能通过一次性迁移 CLI 导入，不能从 HTTP API 或普通 Pipeline CLI 触发。
- 模型配置从 `.env` 自动读取，优先使用 DeepSeek / DashScope / Local LLM 这类 OpenAI-compatible 配置；测试环境默认回退到 `local_rules`，避免单测触发真实模型费用。

### CORS

平台默认采用同源部署，不挂载 CORS 中间件，也不会向任意来源返回跨域许可。正式前端由 FastAPI 提供 `frontend/dist`，本地 Vite 开发通过 `/api` 反向代理访问后端，因此两种默认路径都不需要开启跨域。

只有前后端确实使用不同可信 Origin 时，才配置逗号分隔的白名单：

```bash
AI4SEC_CORS_ALLOWED_ORIGINS=https://console.internal.example,http://127.0.0.1:5173
```

只接受完整的 `http://` 或 `https://` Origin。禁止 `*`、路径、查询参数、URL 凭据和 `file://`；非法配置会阻止应用启动。跨域请求仅允许 `GET`、`POST`、`OPTIONS` 及 `Accept`、`Content-Type` 请求头。进程环境变量优先于 `.env`，适合部署平台进行受控覆盖。

## SQLite 运维

单机部署默认启用 WAL、外键校验、30 秒 busy timeout、`synchronous=NORMAL` 和每 1000 WAL 页自动 passive checkpoint。可以通过 `AI4SEC_SQLITE_BUSY_TIMEOUT_MS`、`AI4SEC_SQLITE_SYNCHRONOUS` 与 `AI4SEC_SQLITE_WAL_AUTOCHECKPOINT_PAGES` 调整；生产环境建议保持 `NORMAL` 或 `FULL`，自动 checkpoint 页数必须为正数。

威胁洞察在线连接器默认使用系统 CA 校验证书；如部署环境需要额外的 PEM CA，可通过 `AI4SEC_THREAT_CA_BUNDLE` 指定。未配置时不关闭证书校验，证书错误会使采集失败并进入失败记录。

漏洞洞察抓取仅接受不含 URL 凭据的 HTTP(S) 公网地址，并在连接前校验 DNS 解析结果。localhost、私网、链路本地、保留地址、云 metadata 地址和指向这些地址的重定向均会被拒绝；生产部署仍需使用主机防火墙或容器网络策略阻断内部网段出口，作为 DNS 重绑定的最终防线。

资讯 X 数据源当前在 `configs/news.yaml` 中正式禁用。原因是当前没有完成可用 Provider、凭据、额度和真实采集验收；运营页会持续展示禁用原因，但不会把它计为采集失败或允许单源重跑。重新启用前必须先完成真实健康检查、错误分类、增量状态和完整日更验收，不能只把 `enabled` 改为 `true`。

需要主动探测资讯数据源时使用独立 CLI；它会执行最小真实请求并将连通性、认证、额度、限流、上游错误和延迟写入 `data_sources`，不通过未认证 HTTP 触发：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.news_health
PYTHONPATH=src python3 -m ai4sec_platform.cli.news_health --source arxiv --source github --timeout-seconds 10
PYTHONPATH=src python3 -m ai4sec_platform.cli.main news-health --timeout-seconds 10
```

连续日更验收使用统一报告 CLI。默认读取最近最多九个 `news.daily_pipeline` Run，避免同日失败重跑挤掉更早的有效日期，并在 `output/acceptance/news/` 写入最新 JSON 与 Markdown 报告：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.main news-acceptance
PYTHONPATH=src python3 -m ai4sec_platform.cli.main news-acceptance --run-id RUN_1 --run-id RUN_2 --run-id RUN_3
```

单个周期只有同时满足以下条件才计入生产验收：Run 为 `success`；所有启用源均产生来源记录且没有错误；日报步骤成功并具有业务日期；门控与深评实际执行且没有模型/Schema 失败；模型调用 Provider 不是 `local_rules`。同一业务日期的补跑只计一个周期。当前健康探针或真实模型未配置时，报告的 `ready_to_start_cycle` 为 `false`，不会把离线规则运行冒充真实日更。

RSS 和 ASIS 的已扫描来源 ID 保存在 SQLite `source_incremental_states` 表，不再使用本地 JSON 状态文件。水位线与采集步骤的 Artifact 在同一事务中提交；连接器返回错误时不推进水位线，健康探测也不会修改水位线。状态默认每个来源最多保留 20,000 个 ID。普通资讯域 reset 会保留水位线，防止运维重置后回放全部历史数据；确需全量重采时应先备份数据库，再由管理员显式清理对应来源状态。X 当前禁用，未来替换 Provider 必须接入同一状态契约后才能启用。

资讯条目按 `canonical_key` 跨运行 upsert，同一日期只保留一份日报；当同日增量重跑没有新条目时，日报会合并并保留既有精选，不会被空结果覆盖。资讯门控和深度评审的成功模型调用按 agent、模型 profile、prompt 版本和规范化输入生成稳定 `request_key`，成功结果只保存一次并可跨运行复用；prompt 升级会自动形成新键。失败调用保留逐次审计记录且不进入成功缓存，因此仍可按失败重跑语义再次执行。

资讯失败重跑按业务阶段区分：在线来源存在错误时运行标记为 `partial`，成功来源继续处理，失败来源不推进水位线；运营页“重跑失败来源”会继承原运行的日期、模型和限额参数，只采集该来源。门控或深评在自动重试耗尽后将当前步骤标记为 `failed`，运营运行详情可从 checkpoint 创建恢复任务；已成功候选命中 `request_key` 缓存，只有失败候选再次调用模型。日报及后续步骤异常同样从最近安全 checkpoint 恢复。禁用来源不能重跑，成功运行也不提供任意阶段重跑入口。

门控与深评对模型 JSON 执行严格 Schema 校验。传输成功但字段缺失、分值越界、技术地图路径非法或深评分项不完整时，调用记录为 `schema_invalid`，不写入成功缓存、不进入资讯发布，并将降级结果和错误原因写入去重人工队列。运营页可以重试原模型阶段，或“忽略该候选”让 checkpoint 恢复时跳过该请求；后续返回合格 Schema 时待处理队列自动标记为 resolved。prompt 已升级到 gate v2 / review v4，历史宽松缓存不会绕过新校验。本地规则 Provider 也输出同一正式 Schema。

数据库初始化会创建 `schema_migrations` 并按版本顺序执行迁移。迁移名称和 checksum 已写入历史后不可静默修改；版本不匹配或迁移失败会阻止启动并回滚当前版本。生产升级前仍应先执行数据库备份，再启动新版本 API 和 Worker。

在线创建一致性备份并校验：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.database backup
PYTHONPATH=src python3 -m ai4sec_platform.cli.database verify \
  output/backups/ai4sec-platform-20260729T000000000000Z.db
```

每个备份会同时生成 `.db.manifest.json` 清单，记录文件大小、SHA-256 和 schema 版本；`verify` 与 `restore` 会自动校验清单。备份文件默认禁止覆盖。CLI 每次成功备份后自动执行分层保留：最近 7 天保留全部日备，之后 4 周每周保留一份，再之后 6 个月每月保留一份；三个周期可通过 `AI4SEC_BACKUP_DAILY_RETENTION_DAYS`、`AI4SEC_BACKUP_WEEKLY_RETENTION_WEEKS` 和 `AI4SEC_BACKUP_MONTHLY_RETENTION_MONTHS` 调整。最新一份受管备份始终保留。

查看 readiness 中的数据库/WAL/迁移指标，或执行受控 WAL checkpoint：

```bash
curl http://127.0.0.1:8000/api/health/ready
PYTHONPATH=src python3 -m ai4sec_platform.cli.database checkpoint --mode passive
PYTHONPATH=src python3 -m ai4sec_platform.cli.database checkpoint --mode truncate
```

`/api/health/ready` 除只读连通性和 WAL 指标外，还会在 `schema_migrations` 内执行一次 `SAVEPOINT` 隔离的真实写入并立即回滚，确认 SQLite 文件当前可写且不会留下探测记录。探测默认最多等待数据库写锁 1 秒，可通过 `AI4SEC_READINESS_WRITE_TIMEOUT_MS` 调整。锁占用、只读文件或迁移历史异常会返回 HTTP 503 和稳定错误码，不返回内部 SQLite 错误文本。

日常检查使用 `passive`；`truncate` 用于备份或维护窗口，并应确认没有长事务和持续读连接。WAL checkpoint 只提供 CLI，不在当前未完成认证的 HTTP API 中暴露。

执行组合维护任务：采样写锁等待、运行完整性检查、执行 WAL checkpoint，并将结果写入 `database_maintenance_runs` 和 `output/operations/database-maintenance/`：

```bash
# 建议每小时执行；并发读写期间使用 quick + passive
PYTHONPATH=src python3 -m ai4sec_platform.cli.database maintain \
  --integrity-mode quick --checkpoint-mode passive --lock-timeout-ms 5000

# 建议每周低峰维护窗口执行
PYTHONPATH=src python3 -m ai4sec_platform.cli.database maintain \
  --integrity-mode full --checkpoint-mode truncate --lock-timeout-ms 30000
```

维护命令自带单机文件锁，不会与另一维护任务重叠。退出码 `0` 表示成功，`2` 表示 checkpoint 因活跃连接只完成部分工作，`1` 表示完整性、锁或其他维护失败；均会尝试生成权限为 `0640` 的 JSON 报告。历史 JSON 默认保留 30 天，可通过 `AI4SEC_DATABASE_MAINTENANCE_REPORT_RETENTION_DAYS` 调整。`/api/health/ready` 的 `database.maintenance` 会展示维护历史表中的执行次数、失败次数、累计/最大锁等待和最近结果。

在 Compose 落地前，可由宿主机 cron/systemd timer 调用上述 one-shot 命令；正式 Compose 将使用独立维护服务调用相同入口，不在 API 进程内启动定时线程。

恢复到指定文件：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.database restore \
  output/backups/ai4sec-platform-20260728T000000000000Z.db \
  --destination output/ai4sec-platform-restored.db
```

覆盖已有旁路恢复文件必须显式增加 `--overwrite`。维护工具禁止直接把备份恢复到当前 `AI4SEC_DATABASE_PATH`，避免运行中的 API 或 Worker 与文件替换竞争。正式切换时先恢复到旁路文件并完成校验，再停止 API、Pipeline Worker、Scheduler 和复现 Worker，由运维人员保留故障库后执行离线文件切换，最后启动服务并检查 readiness。首次正式上线前仍须在实际部署磁盘完成一次计时恢复演练。


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

Worker 启动后写入 `pipeline_workers` 注册记录，空闲和执行任务期间持续 heartbeat；领取任务时写入 `lease_expires_at`。默认 heartbeat 为 10 秒、Job 租约为 300 秒，可通过 `AI4SEC_PIPELINE_WORKER_HEARTBEAT_SECONDS` 和 `AI4SEC_PIPELINE_JOB_LEASE_SECONDS` 调整，租约会自动收紧为不少于三个 heartbeat 周期。单机 SQLite 的原子 Step 可能短暂阻塞 heartbeat 写入，heartbeat 遇到临时数据库锁会继续下一轮而不是退出；300 秒默认租约覆盖当前实测约 53 秒的资讯规范化事务。Worker 崩溃后任务不会在刚启动新进程时被立即误杀，只有租约到期后才标记为 `failed` 并要求通过受控重试恢复。

统一调度器与 Worker 分开运行，只负责把到期任务写入同一持久队列：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.scheduler --poll-interval 30
PYTHONPATH=src python3 -m ai4sec_platform.cli.scheduler --once
```

在 `configs/schedules.yaml` 配置计划。默认配置为空，不会自动触发真实采集；每个计划需显式 `enabled: true`。时间统一按 `Asia/Shanghai` 解释，`grace_minutes` 定义错过时隙后的单次补跑窗口。Scheduler 使用计划 ID 与时隙生成确定性 Run ID，重启不会重复入队；如果同 Pipeline 仍有活动任务，会在宽限窗口内继续尝试，窗口结束后不再补跑。

紧急停止或维护时使用本机 CLI，不通过尚未鉴权的 HTTP API 暴露 kill switch：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.pipeline_control status
PYTHONPATH=src python3 -m ai4sec_platform.cli.pipeline_control stop --reason "maintenance"
PYTHONPATH=src python3 -m ai4sec_platform.cli.pipeline_control resume
```

`stop` 会持久关闭新 Pipeline/Repro 任务领取，取消 queued Pipeline 和复现任务，并向 running 任务写入取消请求。普通 Pipeline 在当前 Step 的可中断边界退出；能力复现 Runner 最多约 0.5 秒轮询一次停止请求，随后执行 `docker stop` 和宿主进程 `terminate`。恢复前应先确认旧浏览器、线程或容器资源已经回收。

漏洞 crawl4ai 批处理会在每个 URL 完成时检查取消信号；取消后不再向线程池提交剩余 URL，并取消尚未开始的 Future。已经进入运行状态的 URL 不使用不安全的线程强杀，而是等待其 HTTP/浏览器 timeout 和 crawler context 正常关闭，因此停止延迟上限仍取决于单 URL timeout 与当前并发数。

API 提交的任务只写入 SQLite `pipeline_jobs`，立即返回可轮询的 `run_id`：

```text
POST /api/runs
{"pipeline_name": "news.daily_pipeline", "reset": false, "params": {}}
```

API 不接受 `wait` 或其他未声明字段，也不会在 Uvicorn 请求进程内创建 Worker。需要同步调试时使用 Pipeline CLI，集成测试则显式提交任务后调用测试 Worker 领取。

Worker 重启时，尚未领取的 `queued` 任务会保留。已经处于 `running` 的中断任务会明确标记为 `failed`，在 Step checkpoint 和幂等重放完成前不会自动从头执行，避免重复写入和重复模型调用。

能力复现使用独立的单机持久 Worker。API 和能力 Pipeline 只创建 `queued` 任务，不在请求进程中启动 Docker 后台线程：

```bash
PYTHONPATH=src python -m ai4sec_platform.cli repro-worker --profile standard
PYTHONPATH=src python -m ai4sec_platform.cli repro-worker --profile nested_docker
```

运维检查可使用 `--once --task-id <id>` 只领取指定任务，或使用 `--recover-only` 对账该 Profile 异常退出时遗留的 `running` 任务。每个 Profile 各自使用单机文件锁；数据库领取条件保证全机同时最多一个复现任务处于 `running`。停止和清理接口只写持久请求，Worker 负责终止容器、删除 workspace 并更新最终状态；API 重启不会丢失尚未领取的任务。

Worker 启动后会写入独立注册表，默认每 10 秒更新心跳；连续 30 秒没有心跳即视为不可用。运行任务期间会同时记录当前 `task_id`，正常退出会写入 `stopped`，因此不能只用进程 PID 或任务表猜测执行面是否健康：

```text
GET /api/capabilities/repro-worker-status
GET /api/capabilities/repro-limits
```

生产进程管理器应以长驻 `repro-worker` CLI 作为唯一 ExecStart，并配置异常自动重启；不要使用 `--once` 作为正式服务。双 Worker 会被单机文件锁拒绝，资源和队列配置不合法、模型 Secret 不安全或 Runner 镜像含长期认证文件时，Worker 会在领取任务前退出。

任务可以通过以下接口请求取消：

```text
POST /api/runs/{run_id}/cancel
```

排队任务会立即变为 `cancelled`；运行中任务会设置取消请求，并在当前 Pipeline Step 完成后的安全边界停止。该接口目前不是进程、浏览器或容器级强制终止，阻塞 Step 的 timeout 和 kill switch 仍需单独实现。

失败或取消的 Run 如果存在校验通过的 checkpoint，并且下一个 Step 已显式声明 `resume_safe=true`，可以创建新的续跑任务：

```text
POST /api/runs/{run_id}/retry
{}
```

Checkpoint 绑定 Pipeline、业务参数、Step 顺序、Step 类实现源码摘要和版本。参数或实现变化时拒绝恢复；待恢复 Step 还必须显式声明 `resume_input_keys`，只持久化经过审核的必要上下文字段。未完成幂等和输出敏感性审计的 Step 默认不生成可恢复 checkpoint。当前四个业务域仍需逐 Step 完成审核，不能把历史任务存在等同于可安全重放。

也可以绕过队列直接通过 CLI 执行调试 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.daily_pipeline
```

该 pipeline 会创建总控 PipelineRun，通过在线连接器采集数据，执行标准化、去重、资讯对象构建、日报生成和质量审计，写入 TaskRun、Artifact 和 manifest，仍保持 `production_writes=false`。

能力复现强制通过平台内 Model Gateway 调用模型。`REPRO_LLM_BASE_URL` 必须指向容器可访问的 `/api/model-gateway/v1` 端点。Worker 每个任务签发独立 `rmt_` 短令牌，只在 Linux 运行目录创建 `0600` 临时文件并只读挂载；OpenCode 通过 `{file:...}` 引用。任务成功、失败、取消或超时后数据库令牌立即撤销且临时文件删除。真实 Provider Key 只存在于平台 API 环境，不进入 Worker、复现容器、Prompt、Docker 命令行、`opencode.json`、SQLite 日志或 SSE。

```bash
cp .env.example .env
REPRO_LLM_BASE_URL=http://host.docker.internal:8000/api/model-gateway/v1
PYTHONPATH=src python -m ai4sec_platform.cli repro-worker --check-config
```

短令牌限制任务 ID、模型、有效期、最大调用次数和预留 Token 总量，默认分别为当前任务、`glm-5.2`、4200 秒、200 次和 1,000,000 Token，可通过 `REPRO_MODEL_TOKEN_TTL_SECONDS`、`REPRO_MODEL_MAX_CALLS`、`REPRO_MODEL_MAX_TOKENS` 收紧。数据库只保存 SHA-256 哈希，不保存明文令牌。模型网关将任务声明模型映射到平台配置的真实模型，并由平台注入 Provider Key。

复现 Worker 使用 Docker `bridge` 和宿主机 `DOCKER-USER` 链强制执行出口白名单，不能只依赖可被任务清除的代理环境变量。任务启动前校验 GitHub 仓库 URL 并解析批准的软件包仓域名，只将审核后的公网 IPv4 写入容器 `/etc/hosts`；容器外部 DNS 指向不可用的本地地址，IPv6 显式关闭。防火墙仅允许这些固定公网 IP 的 TCP 80/443，以及 Docker bridge gateway 上的 Model Gateway 端口，其他公网、回环、RFC1918、链路本地、metadata、Docker 网桥和平台管理端口统一 REJECT。任务结束记录链计数并删除规则。

Worker 启动预检要求能够读取 Docker `bridge` 并操作 `iptables -S DOCKER-USER`。生产复现 Worker 系统账号必须仅获得维护 AI4SEC 专用防火墙链所需的受控权限；如果宿主机使用 rootless Docker/nftables，必须先提供等价执行器，不能关闭预检绕过隔离。固定扩展依赖域名可由管理员通过 `REPRO_EGRESS_EXTRA_DOMAINS` 配置。任务需要额外业务 API 时，在启动请求中提交精确域名、用途和申请人；任务进入 `awaiting_egress_approval`，不会被 Worker 领取。操作员通过 `/api/capabilities/repro/{task_id}/egress` 查看请求，并使用对应 `approve` 或 `reject` 端点记录复核人和理由。所有域名批准且再次通过公网 DNS 校验后任务才进入 `queued`，任一拒绝则任务停止。通配符、URL、端口、IP、localhost 和解析到私网的域名均被拒绝；运行时批准域名到实际 IP 的映射写入持久任务日志，未知域名仍不可解析且不可连接。

能力复现提供两个镜像。`nested_docker` 使用包含内部 Docker daemon 的 `repro-runner:v4`；`standard` 使用不含 Docker daemon、systemd 和 Docker CLI 的 `repro-runner-standard:v1`：

```bash
docker build --tag repro-runner:v4 configs/repro-runner
docker build --file configs/repro-runner/Dockerfile.standard --tag repro-runner-standard:v1 configs/repro-runner
# 当前网络无法稳定访问 npm 官方仓时，可显式使用镜像仓
docker build --build-arg NPM_REGISTRY=https://registry.npmmirror.com --tag repro-runner:v4 configs/repro-runner
```

Worker 启动前会运行镜像审计；镜像不存在，或镜像中存在 `/root/.local/share/opencode/auth.json`、`/home/repro/.local/share/opencode/auth.json` 时拒绝领取任务。旧 `repro-runner:v3` 已确认含认证文件，禁止继续创建新任务；其中的凭据必须轮换，旧容器完成迁移后再删除容器和镜像。

新任务默认使用 `standard`。该 Profile 要求专用 rootless Docker daemon，容器只读根文件系统、`cap-drop ALL`、无嵌套 Docker；容器内 root 映射为宿主普通用户，以便继续只读访问任务级 `0600` 模型令牌。当前宿主机没有 rootless Docker，而且 rootless 网络尚未实现与现有 `DOCKER-USER` 等价的强制出口适配器，因此 standard Worker 会失败关闭，不能为恢复运行而改用 rootful `runc`。`nested_docker` 仅用于明确依赖 Docker/Compose 的项目，启动后先进入 `awaiting_profile_approval`；必须记录复核人和风险接受理由，全部批准后才可能进入队列。其默认 CPU、内存和 PIDs 上限低于 standard，且全机并发仍为 1。

能力复现默认限制为 `REPRO_CPUS=2.0`、`REPRO_MEMORY=4g`、`REPRO_MEMORY_SWAP=4g`、`REPRO_PIDS_LIMIT=1024`、workspace 10 GiB 软上限和数据库日志 5 MiB 上限。Web 端口代理只监听 `127.0.0.1`。workspace 上限通过周期扫描实现，不是文件系统硬 quota；生产部署仍建议为复现目录使用独立受限文件系统或项目配额。

如需获取最新资讯，可运行 shadow 采集：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline \
  --pipeline news.shadow_collect_pipeline \
  --reset
```

## 资讯历史数据一次性迁移

资讯正式主线使用在线连接器。旧系统保存的六源原始 JSON 仅在首次迁移历史数据时使用，不属于日常采集、调度或运营菜单。

迁移必须显式提供源目录、日期和确认参数：

```bash
 PYTHONPATH=src python3 -m ai4sec_platform.cli.import_news_legacy_raw \
  --source-dir /path/to/ai-for-sec-report/output/raw \
  --date 2026-07-10 \
  --confirm-one-time-import
```

该命令默认要求六源文件齐全；确知历史批次本来就缺源时才增加 `--allow-missing-sources`，缺失源会记录为 degraded。命令不联网、不重置资讯域，将输入文件名、内容和日期计算为迁移 checksum；同一批成功数据禁止重复导入。迁移定义不注册到 `/api/runs/pipelines`，`news.legacy_raw_pipeline` 已删除，HTTP API 会返回 404。

## 工程骨架状态

当前已按 `docs/平台总体架构设计.md` 补齐长期架构目录和关键文件：

```text
app / core / db / schemas / sources / artifacts / pipelines / domains / agents / models / ops / cli
```

其中资讯在线采集、资讯历史一次性迁移、漏洞素材导入、漏洞外部素材发现与威胁 connector pipeline 已可运行；其他业务域继续在标准目录、service/pipeline/adapter/builder/audit 文件边界内填实逻辑，不再新增散乱脚本。

## 已实现核心 Pipelines

当前已实现资讯、威胁、漏洞核心输入处理 pipeline：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.shadow_collect_pipeline --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline news.daily_pipeline
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline threats.huawei_raw_pipeline --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.material_local_raw_import --reset
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.external_material_discovery_pipeline --params '{"queries":["CVE-2024 exploit root cause analysis"],"max_results":5,"crawl_limit":5}'
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline vulnerabilities.full_knowledge_discovery_pipeline --params '{"queries":["CVE-2024 exploit root cause analysis"],"max_results":5,"crawl_limit":5}'
```

说明：

- `news.shadow_collect_pipeline` 从 arXiv/GitHub/RSS 获取最新资讯并走同一套处理链路。
- `news.daily_pipeline` 是资讯正式日更入口；默认使用 `daily` 轮换 Profile、每查询 1 页/30 条、论文和项目各评审 20 条。GitHub 基础查询按业务日期分块轮换，连续三天覆盖完整查询集合；需要旧规模深扫时显式传 `collection_profile=full_legacy`、`max_pages`、`max_results` 和评审限额。历史 raw 迁移不属于 Pipeline Registry。
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

在 `news.daily_pipeline` 或 `news.shadow_collect_pipeline` 产生资讯后，可以继续运行：

```bash
PYTHONPATH=src python3 -m ai4sec_platform.cli.run_pipeline --pipeline capabilities.from_news_pipeline
```

该 pipeline 会复用或生成能力候选，优先使用 `.env` 中配置的真实模型完成能力评估；如未配置模型则回退到本地规则引擎，并写入 `model_calls`。
