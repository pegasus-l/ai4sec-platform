# AI4SEC Platform Beta 到生产级实施总计划

## 0. 文档定位

本文是 `ai4sec-platform-production` 分支从 Beta 走向生产级可用的统一工作计划，也是后续跨会话开发的上下文记录和验收依据。

本文解决四个问题：

1. 哪些能力由平台统一建设，哪些能力由四个业务模块分别负责。
2. 哪些事项需要用户决策，为什么需要决策，可选方案分别有什么后果。
3. 应按什么顺序实施，如何避免业务模块和平台基础设施互相阻塞。
4. 每一阶段完成到什么程度才算通过，后续如何持续记录进展。

本文不替代 `docs/平台总体架构设计.md`。目录分层、调用链、公共能力边界仍以该架构文档和 `AGENTS.md` 为准；本文负责生产化路线、技术决策和交付验收。

---

## 1. 当前上下文快照

### 1.1 工作区

```text
原始 Beta 仓库：/mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform
生产化工作区：/mnt/d/漏洞挖掘/洞察工具/dashboard/ai4sec-platform-production
生产化分支：beta-production-hardening
基线提交：2a885e8bc5b5b2c560eca4b3a5c927913a13250a
```

新仓库当前 `origin` 指向本地原始 Beta 仓库，并非 GitLab、GitHub 或 Gitea 等外部远端。

### 1.2 不可破坏的默认边界

在用户明确批准生产切换前，所有开发和验证继续遵守：

```text
shadow-only
production_writes=false
不写旧生产库
不覆盖旧报告
不修改旧生产脚本
不部署到生产环境
不推送远端
```

真实外部采集、真实模型调用、长时间 full scan、产生费用的 API 调用，应在执行前说明范围、预算和预期输出。

### 1.3 当前技术形态

```text
后端：Python 3.10+ / FastAPI / Pydantic
数据库：SQLite + WAL
前端：React 18 / Vite / TypeScript / React Query / Zustand / React Flow
任务执行：FastAPI 进程内 daemon Thread
制品存储：本地 output 目录
模型：OpenAI-compatible Provider + Local Rules fallback
部署：尚无正式生产拓扑和 CI/CD
```

### 1.4 当前成熟度判断

四个业务域已经具有 Beta 核心链路：

| 模块 | 当前核心能力 | 主要生产差距 |
|---|---|---|
| 资讯洞察 | 六源采集、受控历史迁移、分类评分、两阶段评审、日报、专题 | 在线链路收口、增量幂等、X 数据源、真实健康检查、连续日更验收 |
| 能力洞察 | 候选评估、复现任务、Docker 执行、报告与转化 | 正式前端、持久恢复、容器隔离、配额、SSE/API 测试、批量样本验收 |
| 威胁洞察 | Huawei repo/CVE/固件/镜像采集、攻击面、风险研判、图谱 | TLS、CVE/资产/AI 覆盖、攻击面空值、API 性能、前端关联和专项测试 |
| 漏洞洞察 | 检索、抓取、素材审核、事件聚合、知识抽取、字段审核 | 事件人工治理、证据定位、字段版本、增量更新、大规模质量校准 |

平台公共层的主要差距是：持久任务、单机互斥、步骤恢复、SQLite 生产加固、认证授权、操作审计、日志指标告警、备份恢复、Secret 管理和 CI/CD。

---

## 2. 总体目标与完成定义

### 2.1 两级完成标准

#### 模块 Production Ready

某个业务模块只有同时满足以下条件，才可称为模块生产就绪：

- 业务链路基于真实输入连续稳定运行。
- 增量、幂等、失败恢复和业务重跑语义明确。
- 业务输出达到量化质量门槛。
- 专项单测、API 测试和关键前端交互测试通过。
- 业务指标、失败原因和人工处理入口可观察。
- 不依赖人工修改数据库或临时执行未受控脚本完成日常运行。

#### 平台 Production Deployable

整个平台只有同时满足以下条件，才可称为可生产部署：

- 任务持久化，服务重启和 Worker 故障不会静默丢任务。
- 单机 API、Worker 和 Scheduler 之间具备互斥、并发限制和一致状态。
- 数据库具有迁移、事务、备份和恢复能力。
- 具备登录、RBAC、操作审计、Secret 管理和基本 API 安全。
- 日志、指标、健康检查和关键告警可用。
- 前后端有可重复构建、部署、回滚流程。
- 四个模块均达到各自 Production Ready 门槛。
- 通过集成测试、并发测试、安全检查和恢复演练。

### 2.2 实施原则

1. 先修复可能破坏数据或造成安全事故的问题。
2. 公共能力只实现一次，四个模块通过稳定接口复用。
3. 平台定义运行机制，模块定义业务语义。
4. 先建立可观测、可恢复的执行底座，再扩大真实任务规模。
5. 不以“大重写”为目标，优先沿用现有分层和 Repository/Pipeline/Artifact 设计。
6. 所有生产化变化必须具备回滚路径和验收证据。

---

## 3. 用户决策总览

以下决策会影响架构、部署成本或长期维护方式，需要用户确认。未确认前可以完成接口设计和 P0 安全修复，但不能擅自绑定生产环境。

| 编号 | 决策事项 | 推荐方案 | 当前状态 | 最晚确认时间 |
|---|---|---|---|---|
| D01 | 首期部署形态 | 单机内网 Docker Compose；能力复现 Worker 与 API 逻辑分离 | 已确认 | 已完成 |
| D02 | 生产数据库 | SQLite + WAL，按单机生产边界加固 | 已确认 | 已完成 |
| D03 | 任务队列与锁 | SQLite 持久任务表 + 单 Pipeline Worker + 租约/heartbeat/单机互斥 | 已确认 | 已完成 |
| D04 | 身份认证 | 简单本地账号 + 服务端 Session Cookie + 最小 RBAC，不接企业 SSO | 已确认 | 阶段 4 前 |
| D05 | Secret 管理 | Compose Secret/受控文件挂载；应用支持环境变量文件引用 | 已确认 | 已完成 |
| D06 | Artifact 存储 | 单机受控本地持久卷 + ArtifactStore 抽象 + 容量与生命周期管理 | 已确认 | 已完成 |
| D07 | 能力复现隔离 | 同机独立 Worker；OpenCode 全程受控联网；模型网关短期令牌；标准 rootless 与受审 Sysbox 双 Profile | 已确认 | 已完成 |
| D08 | 监控与告警 | JSON 日志 + Prometheus + Grafana；告警通过内部 Webhook | 已确认 | 已完成 |
| D09 | Git 与代码备份 | 私有 GitHub 仓库；本地阶段性推送，不建设完整 CI/CD 流程 | 已确认，仓库信息待提供 | 阶段 5 前 |
| D10 | 备份目标 | 首期 RPO 24 小时、RTO 4 小时，每日备份并定期恢复演练 | 已确认 | 已完成 |
| D11 | 网络暴露范围 | 暂缓公网暴露和完整网络边界治理，当前保持内网使用 | 暂缓 | 后续需要时 |
| D12 | 外部 API 与模型预算 | 当前 GLM-5.2 无直接费用，暂不建设预算治理；保留基础失败和限流能力 | 暂缓 | 费用或额度变化时 |
| D13 | 日常调度策略 | 统一使用北京时间，模块分别配置日更窗口和漏跑补偿 | 已确认 | 已完成 |

---

## 4. 关键决策详细说明

### D01. 首期部署形态

#### 为什么需要决策

部署形态决定数据库、任务 Worker、Artifact 共享、容器隔离、监控和高可用方案。如果一开始按 Kubernetes 设计，会显著增加建设和运维成本；如果只按开发机进程运行，又无法满足恢复、隔离和标准发布要求。

#### 方案 A：单机 Docker Compose

组成可包括：

```text
reverse-proxy
api
pipeline-worker
scheduler
sqlite-volume
prometheus
grafana
```

优点：

- 部署简单，适合当前内部平台和有限并发。
- 环境可重复，容易备份和回滚。
- 比直接在宿主机运行更容易隔离依赖。
- 后续可以平滑拆分 Worker 或迁移到 Kubernetes。

缺点：

- 单机故障会影响整个平台。
- 横向扩展和自动故障转移能力有限。
- 需要自行管理宿主机、磁盘和容器运行时。

#### 方案 B：Systemd + Python 虚拟环境

优点：组件少，调试直观，对现有代码改动较小。

缺点：环境漂移明显，依赖和回滚管理较弱，能力复现与平台服务容易互相影响，不建议作为长期生产形态。

#### 方案 C：Kubernetes

优点：适合多节点、弹性 Worker、Job 隔离、Secret 和滚动发布。

缺点：需要成熟集群和运维能力，当前规模可能过度建设，复现任务还需要额外容器安全设计。

#### 推荐方案

首期选择**单机核心平台内网 Docker Compose + 能力复现 Worker 独立部署单元**，同时保持以下可维护设计：

- API 无本地内存状态依赖。
- Pipeline 状态全部进入本机 SQLite 持久库。
- Pipeline Worker 固定为单实例，Connector 内部仍可使用受控并发。
- Artifact 通过抽象 Store 访问。
- 配置和 Secret 不打入镜像。

#### 与能力复现功能的关系

Docker Compose 只负责 API、数据库、普通 Pipeline Worker、Scheduler 和监控等平台核心服务，不要求能力复现任务在这些容器内部运行 Docker daemon。

能力复现采用单独的 Worker：

```text
平台核心 Docker Compose
├── reverse-proxy
├── api
├── pipeline-worker
├── scheduler
├── sqlite-volume
└── monitoring

能力复现执行面
└── capability-repro-worker
    └── rootless Docker/Podman
        └── 每个复现任务的受限容器
```

两者通过持久任务记录和受控 Artifact 接口协作：API 创建复现任务，复现 Worker 领取任务并启动容器，随后回写状态、日志摘要、报告和 Artifact 元数据。

明确禁止的生产拓扑：

- API 容器直接挂载 `/var/run/docker.sock`。
- API 请求处理线程直接创建或销毁复现容器。
- 使用 `privileged` Docker-in-Docker 运行未知项目。
- 复现容器与数据库、Secret、平台管理网络处于无隔离的同一网络。

当前确定只做单机部署。核心 Compose 和独立 rootless 复现 Worker 运行在同一宿主机，但必须保持进程、账号、网络、工作目录和权限边界。复现 Worker 通过 API 领取任务和回写状态，不直接通过共享路径打开 SQLite 数据库。

该方案不提供主机故障高可用；生产验收重点是单机服务重启恢复、任务不丢失、复现污染可清理和备份可恢复。

#### 用户需要确认

- 是否有可用的内网 Linux 服务器。
- 服务器 CPU、内存、磁盘和 GPU 情况。
- 是否允许安装 Docker/Podman。
- 是否已有 Kubernetes 平台并要求直接接入。
- 单机服务器的 CPU、内存、磁盘和 GPU 是否满足平台与复现任务共同运行。

### D02. 生产数据库

#### 为什么需要决策

当前确定平台只做单机部署，因此 SQLite + WAL 可以继续作为首期生产数据库。它能够支撑低到中等频率的 API 写入、单 Pipeline Worker、Scheduler 和持久任务表，但必须限制长事务、共享网络文件和多 Worker 并发写入。

#### 方案 A：继续使用 SQLite

优点：零额外服务，迁移工作少。

缺点：写并发有限，不适合多节点和多个 Pipeline Worker，不提供数据库高可用。但这些能力不在当前单机部署目标内。

#### 方案 B：PostgreSQL

优点：

- 事务、并发、索引和 JSON 查询能力成熟。
- 支持 `FOR UPDATE SKIP LOCKED` 构建可靠任务领取。
- 支持 advisory lock 实现跨进程互斥。
- 备份、恢复、监控和迁移工具成熟。
- 可减少额外 Redis 依赖。

缺点：需要部署和维护；当前 SQLite SQL、占位符、DDL 和 JSON 查询需要兼容改造。

#### 方案 C：MySQL/MariaDB

可以满足通用业务存储，但现有任务锁、JSON 查询和后续检索场景更适合 PostgreSQL，除非组织已有强制 MySQL 技术栈。

#### 推荐并确认的方案

首期使用**SQLite + WAL 的单机生产方案**，并完成以下加固：

- SQLite 文件只存放在本机持久磁盘，不放入 NFS、SMB 或其他网络共享目录。
- API、Scheduler 和 Worker 使用短事务，禁止在外部网络调用期间持有写事务。
- 固定单 Pipeline Worker；来源抓取和纯计算可以内部并发，最终写入受控串行提交。
- 配置 `busy_timeout`、WAL checkpoint、数据库容量和锁等待监控。
- 建立 `schema_migrations` 表和可回滚或前向修复的迁移脚本。
- 为任务、领域对象、日报和 ModelCall 增加必要唯一约束与幂等键。
- 每日备份数据库，并在备份前使用 SQLite backup API 或一致性快照。
- 定期执行完整性检查和恢复演练。

PostgreSQL 不再是当前生产化阻断项。只有出现以下任一情况时才重新立项迁移：

- 需要两个以上 Pipeline Worker。
- 需要多个平台节点或多个 API 实例高频写入。
- SQLite 锁等待持续影响正常 API 和任务运行。
- 数据规模、查询复杂度或可用性目标超出单机 SQLite 能力。
- 业务明确要求数据库高可用或更小的恢复点目标。

### D03. 任务队列与单机互斥

#### 为什么需要决策

当前后台线程在 API 进程退出后会直接消失，内存锁在服务重启后也会丢失。四个模块都有长任务，能力模块还涉及外部容器，因此即使只做单机部署，也必须建立可持久、可恢复、可取消的统一执行机制。

#### 方案 A：SQLite 持久任务表 + 单 Pipeline Worker

工作方式：

- API 只创建任务记录。
- 单 Pipeline Worker 使用短事务和条件更新领取任务。
- heartbeat 记录 Worker 存活。
- 租约到期机制回收异常退出任务。
- 数据库唯一约束、运行锁记录和单机文件锁共同控制 Pipeline 互斥。
- Pipeline Step 完成后提交 checkpoint。
- Scheduler 也只向同一任务表投递任务。

优点：状态源唯一，不增加 Redis；与当前 PipelineRun/TaskRun 设计衔接自然；满足单机重启恢复和任务审计。

缺点：只支持一个 Pipeline Worker，不提供跨主机分布式锁；需要严格控制事务时间和数据库写入频率。

#### 方案 B：SQLite + Redis/Dramatiq/RQ

优点：实现较快，Worker、重试和队列生态成熟。

缺点：仍需 SQLite 保存业务状态和 checkpoint，形成 Redis 与数据库双状态源；Redis 不能解决 SQLite 最终写入并发问题。当前单机规模下增加了不必要复杂度。

#### 方案 C：PostgreSQL 或专用 Broker

当未来需要多节点、多 Pipeline Worker 或复杂路由时，再迁移到 PostgreSQL 任务表，或评估 Celery、Dramatiq、Redis、RabbitMQ 等专用队列。

#### 推荐方案

首期采用**SQLite 持久任务表 + 单 Pipeline Worker + 租约/heartbeat/checkpoint + 单机互斥**。

实现边界：

- FastAPI 只创建任务，不再启动 daemon Thread。
- Scheduler 只投递任务，不直接运行 Pipeline。
- 单个 Pipeline Worker 串行领取 Pipeline Run。
- Worker 内的 Connector 网络请求可以受控并发，但数据库提交保持短事务。
- 能力复现 Worker 作为另一类执行器，通过 API 领取任务，不直接打开 SQLite 文件。
- API 使用单实例部署，避免多个 Uvicorn Worker 同时承担高频写入。
- 系统重启后根据租约和 heartbeat 对账 queued/running 任务。
- 当前不宣称支持多节点分布式锁或高可用故障转移。

#### 用户需要确认

该方案已经由用户确认。后续只需根据真实任务耗时确定 heartbeat、租约、重试和超时默认值。

### D04. 身份认证与 RBAC

#### 为什么需要决策

平台存在启动全量采集、调用付费模型、停止容器、清理环境、修改知识和人工审核等高风险动作。没有身份认证时，任何可访问 API 的用户都可以执行这些动作。

#### 方案 A：企业 OIDC/SSO

例如企业统一身份、Keycloak、Authentik、GitLab OIDC 等。

优点：账号生命周期、MFA、禁用和组织信息由统一身份系统管理，适合长期生产。

缺点：需要已有 IdP 或额外部署身份服务；要协调回调地址和用户组映射。

#### 方案 B：项目内本地账号 + JWT/Session

优点：不依赖外部系统，实施可控。

缺点：项目需要承担密码安全、重置、MFA、账号禁用和登录审计，长期维护成本高。

#### 方案 C：仅依赖反向代理 Basic Auth

优点：最快形成访问门槛。

缺点：无法提供细粒度 RBAC 和用户级操作审计，只适合作为临时内测保护。

#### 推荐方案

当前没有企业 SSO，推荐实现**简单本地账号 + 服务端 Session Cookie + 最小 RBAC**，不建设复杂用户中心。

最小实现范围：

1. 用户表只包含用户名、密码哈希、角色、启用状态和必要审计时间。
2. 密码使用 Argon2id 或同等级安全算法哈希，禁止明文和可逆加密存储。
3. 登录成功后使用服务端 Session；浏览器只保存 `HttpOnly`、`Secure`、`SameSite` Cookie，不把长期 JWT 放入 `localStorage`。
4. 所有写操作和高成本查询必须登录；生产页面默认也要求登录。
5. 写请求增加 CSRF 防护，登录接口增加失败次数限制和短期锁定。
6. 不提供公开注册、自助找回密码、短信、邮件和复杂组织管理。
7. 初始管理员通过部署 Secret 创建，首次登录后要求修改密码。
8. 保留统一 `CurrentUser` 和权限接口，未来如有 SSO 可以替换认证 Provider，而不修改四个模块业务代码。

可以把认证实现安排到阶段 4，但不能在正式生产验收时完全省略。即使平台只在内网运行，启动全量任务、调用付费模型、停止复现容器和修改漏洞知识仍属于高风险操作。

初步角色建议：

| 角色 | 权限范围 |
|---|---|
| viewer | 查看业务数据和已脱敏运行结果 |
| operator | 运行常规 Pipeline、处理普通人工队列 |
| reviewer | 审核资讯、漏洞字段和业务质量结果 |
| reproducer | 启动、停止和清理能力复现任务 |
| admin | 配置数据源、模型、配额和用户角色 |

#### 用户需要确认

- 是否接受上述最小本地账号方案。
- 首期预计用户数量。
- 是否所有读页面都要求登录，还是只限制写操作。
- 初始管理员由谁保管和轮换。

### D05. Secret 管理

#### 为什么需要决策

平台使用 GitHub、搜索、资讯源和模型 API Key。生产密钥如果继续散落在 `.env`、日志或容器环境中，会增加泄漏和轮换风险。

#### 方案 A：受控环境变量或只读 Secret 文件

适合 Docker Compose。密钥由部署系统注入，应用支持 `KEY` 和 `KEY_FILE` 两种读取方式。

优点：简单、无额外服务，适合首期。

缺点：轮换和权限审计能力有限，需要严格管理宿主机文件权限。

#### 方案 B：Vault 或云 Secret Manager

优点：集中管理、审计、轮换和短期凭证能力强。

缺点：新增高可用服务和接入成本，开发环境也需要适配。

#### 方案 C：把密钥写入数据库

不推荐。除非引入成熟 KMS 和信封加密，否则数据库泄漏会同时暴露业务数据和密钥。

#### 推荐方案

首期采用**Compose Secret/宿主机只读 Secret 文件**，该方案已确认，并做到：

- 应用支持 `_FILE` 读取。
- 日志统一脱敏。
- API 不返回完整模型配置和密钥。
- 密钥文件不进入 Git、Artifact 和备份明文清单。
- 建立人工轮换流程。

如果已有 Vault 或云 Secret Manager，应直接接入现有设施。

### D06. Artifact 存储

#### 为什么需要决策

原始采集、模型结果、报告、manifest、复现日志和知识证据会持续增长。单机本地目录简单，但多 Worker、多节点、备份和生命周期管理会遇到问题。

#### 方案 A：本地持久卷

优点：当前代码兼容、性能好、成本低。

缺点：单机故障风险，扩容和多节点共享困难。

#### 方案 B：MinIO/S3 对象存储

优点：适合大制品、生命周期、版本和多 Worker；容易迁移到云对象存储。

缺点：需要额外服务和访问控制；小文件数量多时需合理组织对象路径。

#### 方案 C：全部存数据库

不推荐。大日志、HTML、Markdown 和复现制品会显著增加数据库压力和备份体积。

#### 推荐方案

首期单机部署使用**受控本地持久卷**，该方案已确认；同时完成 ArtifactStore 接口稳定化、元数据入库、容量监控和生命周期清理。

满足任一条件时切换 MinIO/S3：

- 出现多个 Worker 节点。
- Artifact 超过约 100 GB。
- 需要跨节点下载和生命周期策略。
- 需要数据库与制品独立恢复。

用户需要确认 Artifact 预计保留周期、容量上限和是否已有对象存储。

### D07. 能力复现容器隔离

#### 为什么需要决策

能力复现会运行未知仓库和潜在 PoC，这是整个平台风险最高的执行面。如果 API 服务直接挂载宿主机 Docker socket，容器内或应用漏洞可能获得宿主机控制权。

#### 方案 A：API 主机直接使用 Docker socket

实现简单，但风险不可接受，不建议用于生产。

#### 方案 B：独立复现 Worker 主机 + rootless Docker/Podman

优点：

- 与业务 API、数据库和内部网络隔离。
- 可以统一限制 CPU、内存、磁盘、PIDs、端口和网络出口。
- Worker 主机可随时重置，不影响平台主服务。

缺点：增加一台主机或虚拟机；部分项目在 rootless 环境需要额外适配。

#### 方案 C：Kubernetes Job + 沙箱运行时

例如 gVisor、Kata Containers。

隔离能力更强，但建设和运维成本最高，适合已有 Kubernetes 和安全运行平台的组织。

#### 推荐方案

当前没有额外主机或 VM，因此确认使用**同机独立复现 Worker**。复现 Worker 与核心 Compose 使用不同系统账号、进程、网络权限和工作目录，并默认：

- 禁止 privileged。
- 禁止挂载宿主机敏感目录。
- 只读根文件系统，按需提供临时目录。
- 限制 CPU、内存、磁盘、PIDs 和运行时间。
- 标准复现 Profile 不挂载系统级 `/var/run/docker.sock`，只使用专用账号自己的 rootless Docker/Podman。
- 平台 API 不持有容器运行时权限，也不直接创建或清理复现容器。
- 复现 Worker 不直接访问 SQLite 文件，只通过受控 API 领取任务和回写结果。

#### 已确认的联网原则

OpenCode 自动部署依赖模型调用，项目复现还需要下载代码、安装依赖并可能调用项目自身 API，因此复现全过程不能断网。

网络策略确认改为：

```text
OpenCode 模型流量：只允许访问 AI4SEC Model Gateway
代码与依赖流量：只允许访问任务代码仓和批准的软件包/模型仓库
项目业务流量：只允许访问任务声明并经策略批准的外部域名
内网流量：默认拒绝，仅显式放行平台提供的受控网关
```

模型真实 Provider Key 不进入复现容器。Model Gateway 为每个任务签发短期令牌，限制任务 ID、模型、调用次数、Token、费用和有效期；任务结束、取消或超时后令牌立即失效。即使不可信仓库读取到任务令牌，也只能在有限时间和额度内访问指定模型。

允许列表只覆盖任务所需范围，例如指定 Git 仓库、PyPI、npm、Maven、Cargo、Go Proxy、系统软件包镜像和模型仓库。出口策略必须阻止回环地址、RFC1918 私网、链路本地地址、云 metadata 地址、Docker 网桥、宿主机管理端口和平台管理网段；Model Gateway 使用专门的显式例外地址。

不能只依赖 `HTTP_PROXY` 环境变量，因为 OpenCode、项目代码或嵌套容器可以清除代理变量。限制必须在宿主机防火墙、专用容器网络或强制透明出口代理层实施，并记录每个任务的目标域名、连接量和拒绝日志。

#### 双复现 Profile

为兼容当前 OpenCode 自动部署和少量需要 Docker Compose 的项目，复现执行分为两类：

| Profile | 默认范围 | 容器能力 | 审批要求 |
|---|---|---|---|
| standard | Python、Node、Go、Rust、普通 Web/CLI 项目 | rootless 容器，不提供嵌套 Docker | 普通复现权限即可 |
| nested_docker | 明确依赖 Docker/Compose 的项目 | Sysbox 嵌套 Docker，严格资源和网络限制 | 人工批准并记录风险 |

当前所有任务都使用 `sysbox-runc`，后续需要将大多数项目迁移到 standard Profile。Sysbox 不能在未经验证的情况下直接等同于 rootless；nested_docker Profile 是高风险例外，必须由专用 Worker 使用，并限制并发为 1。

同机 rootless 容器可以显著降低风险，但仍与平台共享宿主机内核，隔离强度低于独立 VM。正式验收时必须将该剩余风险记录为已接受，并通过容器逃逸防护、内核更新、seccomp/AppArmor、能力删除和任务白名单继续降低风险。

不得将高权限宿主机 Docker socket 挂入 API 容器。若开发期为兼容现有实现临时使用 Docker socket，只能由专用复现 Worker 访问，并应记录为上线前必须关闭的过渡风险。

#### 实施前审计基线

以下内容记录独立 Repro Worker 实施前的 Beta 基线，用于保留问题来源；完成状态以文档后续实施记录为准：

1. API 直接通过全局 ReproManager 和 daemon Thread 调用宿主机 Docker，尚未拆成独立持久 Worker。
2. OpenCode 在 Sysbox 容器内以 root 身份运行，且 bash、读写、webfetch、external directory 等权限全部允许。
3. 容器使用 Docker 默认网络，当前定义的内网 CIDR 列表没有实际应用，公网和内网出口未受控。
4. `REPRO_LLM_API_KEY` 会被写入 Prompt，而完整 Prompt 又被写入任务日志，存在密钥进入 SQLite、SSE 和前端的风险。
5. OpenCode 自身认证从镜像内 `/root/.local/share/opencode/auth.json` 读取，需要确认镜像层是否包含长期密钥。
6. 当前只配置 PIDs 上限，没有 CPU、内存、磁盘、带宽、日志量和嵌套容器数量限制。
7. 超时检查依赖阻塞式 stdout 读取，子进程静默时可能无法按时触发。
8. Web 端口代理未显式绑定回环地址，可能暴露到服务器所有网络接口。
9. 后台线程捕获 API 请求级 SQLite connection，请求结束后可能继续使用已关闭连接。
10. ReproManager 只存在内存，API 重启后可能遗留孤儿容器，且容器名和工作目录没有在启动时可靠持久化。

以上 1、3、4、5、6、8、9 属于能力复现生产化 P0 问题。在这些问题关闭前，只允许对受信任样本执行内部 Beta 验证。

### D08. 监控、日志与告警

#### 为什么需要决策

长任务、外部数据源和模型调用会产生大量非确定性故障。只有日志而没有指标和告警，无法及时发现日报缺失、模型费用异常或 Worker 卡死。

#### 方案 A：JSON 日志 + Prometheus + Grafana

优点：开源、自托管、指标和告警成熟，适合内部环境。

缺点：日志检索还需要 Loki/OpenSearch 或保留文件查询。

#### 方案 B：OpenTelemetry + 完整可观测平台

优点：日志、指标、Trace 标准化，适合多服务。

缺点：首期接入和运维成本较高。

#### 方案 C：云监控/Sentry

接入快，但安全数据和代码复现错误可能离开内网，需要合规确认。

#### 推荐方案

首期采用：

```text
结构化 JSON 日志
Prometheus 指标
Grafana Dashboard
Alertmanager 或内部 Webhook
```

代码先预留 OpenTelemetry 上下文，等服务拆分后再扩展 Trace。敏感错误默认不发送到外部 SaaS。

用户需要确认可用告警渠道，例如企业微信、钉钉、邮件或内部 Webhook。

### D09. GitHub 代码仓与轻量备份

#### 为什么需要决策

当前仓库没有外部远端。即使暂时不建设完整 CI/CD，也需要一个独立远端保存代码，避免本地工作区损坏后无法恢复。

#### 推荐并确认的方案

使用**私有 GitHub 仓库作为代码备份和协作远端**，暂不建设完整 CI/CD：

- 仓库必须设为 Private，不公开漏洞、PoC、企业资产字段和内部配置。
- 保留本地 `beta-production-hardening` 分支作为主开发分支。
- 阶段性完成一个可回滚变更后再推送，不要求每次文件保存都自动推送。
- `.env`、`output/`、数据库、本地复现工作区和敏感模型响应禁止进入 Git。
- 推送前执行敏感信息扫描和 `git diff --check`。
- 暂不建设自动部署、灰度、Registry、发布审批和完整 GitHub Actions 流程。
- 后续如有需要，只增加最小 GitHub Actions，执行 Python 测试、前端构建和敏感信息扫描。

创建和推送前需要提供 GitHub 组织/用户名、仓库名，并确认使用 GitHub CLI 登录或其他受控认证方式。本次决策不授权向未知远端创建仓库或推送代码。

### D10. 备份目标与恢复指标

#### 为什么需要决策

备份频率和保留周期直接影响存储成本。没有明确 RPO/RTO，就无法判断每日备份是否足够，也无法设计恢复演练。

术语：

- RPO：最多可以接受丢失多长时间的数据。
- RTO：发生故障后，最多多长时间恢复服务。

#### 推荐并确认的方案

内部首期建议：

```text
RPO：24 小时
RTO：4 小时
数据库：每日全量备份，条件允许时增加 WAL 归档
Artifact：每日增量备份
保留：最近 7 天每日备份、最近 4 周周备份、最近 6 个月月备份
恢复演练：至少每季度一次，正式上线前必须完成一次
```

如果平台承担每日不可重建的人工审核和知识修改，建议将 RPO 提升到 1 小时以内。

该方案已确认；后续只需确定实际备份目录/设备，并完成首次恢复演练。

### D11. 网络暴露与出口策略

#### 为什么需要决策

平台既处理外部不可信 URL，又能调用模型、运行代码和展示企业资产。如果直接公网暴露，认证、SSRF、容器逃逸和敏感信息风险会显著增加。

#### 当前策略：暂缓公网暴露

首期继续**仅部署在内网**：

- 用户入口通过 HTTPS 反向代理。
- API 和数据库不直接暴露公网。
- 外部采集按域名白名单出网。
- 能力复现 Worker 使用更严格的独立出口策略。
- 外部网页内容按不可信输入处理，不允许控制本地文件和命令。

如果后续必须公网访问，再增加 WAF/API Gateway、MFA、速率限制、安全测试和更严格的网络分区，不直接复用内网最低配置。

D11 暂缓的是公网入口和完整公网暴露治理，不代表复现容器可以任意访问内网。D07 已单独规定复现容器全过程受控联网，并阻断宿主机、私网和平台管理网段。

### D12. 外部 API 与模型预算

#### 为什么需要决策

资讯六源、漏洞 AnySearch、威胁深度扫描和四域模型审核都可能产生调用费用和额度风险。简单放大并发可能在一次 full scan 中消耗大量预算。

#### 当前策略：暂缓费用预算治理

当前使用的 GLM-5.2 不需要项目承担直接模型费用，因此暂不建设完整的月度预算、费用账单和成本熔断系统。但仍必须保留：

- Provider 超时、失败重试和错误记录。
- 单任务最大运行时间和模型调用次数上限。
- 模型不可用时的失败状态和本地规则降级。
- 任务级日志脱敏，禁止真实 Provider Key 进入复现 Prompt、Artifact 或数据库。

未来需要时再建立三级配额：

```text
全平台每日预算
模块每日预算
单次 Run 最大查询数、URL 数、模型调用数和 Token 数
```

达到 80% 时告警，达到 100% 时停止新调用，允许管理员临时提高额度。D12 已暂缓费用预算治理；模型安全、超时、失败和密钥隔离仍属于当前必须实现的基础能力。

### D13. 日常调度策略

#### 为什么需要决策

不同模块任务持续时间和数据时效不同。资讯适合日更，漏洞可能按关键词轮换，威胁 full scan 成本较高，能力复现通常由候选或人工触发。统一调度器不能替模块猜测业务周期。

#### 推荐并确认的初稿

统一使用 `Asia/Shanghai` 时区：

| 模块 | 建议调度 | 说明 |
|---|---|---|
| 资讯 | 每日一次，工作开始前完成 | 失败后在限定窗口内自动补跑一次 |
| 漏洞 daily_watch | 每日一次 | 关键词轮换并保留水位线 |
| 漏洞 full profile | 每周或人工触发 | 受预算和 URL 上限控制 |
| 威胁 default scan | 每日或每周 | 根据源更新频率确定 |
| 威胁 full scan | 每周、每月或人工触发 | 必须有并发和费用上限 |
| 能力评估 | 资讯候选后触发 | 自动任务进入队列 |
| 能力复现 | 人工审批或策略触发 | 高风险项目默认需人工批准 |

该调度策略已确认；具体日报时间、节假日开关、full scan 周期和漏跑补偿窗口在模块验收时配置。

---

## 5. 平台与模块职责边界

### 5.1 平台统一负责

1. 持久任务、单 Pipeline Worker、调度器和单机互斥。
2. 统一运行状态、heartbeat、取消、超时和 checkpoint。
3. 数据库连接、事务、迁移、备份和恢复。
4. 通用 HTTP/浏览器抓取基础设施和 SSRF 防护。
5. 模型路由、超时、重试、限流、成本和调用审计。
6. 身份认证、RBAC、操作审计和 API 安全。
7. Secret 管理和配置环境隔离。
8. Artifact Store、checksum、生命周期和访问权限。
9. 结构化日志、指标、健康检查、异常追踪和告警。
10. 统一运营后台公共组件。
11. CI/CD、发布、回滚、容量和灾难恢复。

### 5.2 资讯洞察负责

1. 六源覆盖范围、分页、补采和来源特有增量规则。
2. X 数据源去留及不可用原因展示。
3. 在线正式链路收口和 legacy raw 迁移退场。
4. 资讯去重、关联、技术地图、两阶段评审和日报幂等。
5. 来源健康业务语义和失败可重跑范围。
6. 资讯模型输出质量、降级和人工复核规则。
7. 六源连续日更和资讯专项测试。

### 5.3 能力洞察负责

1. 复现业务状态转换和异常收尾。
2. 容器、任务和报告的启动对账与恢复语义。
3. 项目选择、复现模式、成功判定和失败重试规则。
4. 报告结构、证据、使用说明、前置条件和能力卡回写。
5. 单任务超时、日志量、重试次数和模块并发声明。
6. SSE/API/报告回写测试和多技术栈样本回归。
7. 能力洞察正式前端工作台。

### 5.4 威胁洞察负责

1. 修复来源连接器 TLS 和特殊来源证书策略。
2. 提升 CVE scout、AscendHub、Firmware 和 OpenX 覆盖。
3. 优化 AI 研判候选分层和覆盖率。
4. 降低攻击面空值并解释未知原因。
5. 优化 surface stats 和 Graph API 数据模型、索引和分页。
6. 修复 RepoDrawer 关联资产和清理前端死代码。
7. 建立威胁 API、数据质量和前端专项测试。

### 5.5 漏洞洞察负责

1. 关键词 Profile、检索策略和素材质量规则。
2. CVE/主题事件聚合，以及人工合并、拆分和 CVE 修正。
3. 漏洞知识字段、证据绑定和置信度规则。
4. 字段证据高亮、原文定位和版本历史。
5. 已有事件、知识的增量更新和冲突处理规则。
6. golden set、大规模 shadow evaluation 和质量阈值。
7. 素材、事件、知识、审核之间的完整运营流程。

### 5.6 必须共同定义的接口契约

| 契约 | 平台职责 | 模块职责 |
|---|---|---|
| Pipeline | 状态机、队列、锁、checkpoint、恢复、取消 | Step 边界、幂等键、业务重跑语义 |
| Connector | HTTP/TLS、限流、重试、健康状态存储 | 分页、来源 ID、水位线、来源错误解释 |
| ModelCall | Provider、配额、缓存、Token、熔断、审计 | Prompt、Schema、质量阈值、业务降级 |
| Artifact | 存储、checksum、生命周期、权限 | 内容、用途、敏感级别、保留要求 |
| Quality | 评估框架、报表、运行对比 | golden set、业务指标、通过阈值 |
| Operations | 公共任务、日志、告警、队列组件 | 业务漏斗、失败原因、业务操作入口 |
| RBAC | 用户、角色、权限判断、审计 | 业务动作名称和所需角色 |

---

## 6. 分阶段可执行计划

### 阶段 0：生产化基线与决策冻结

#### 目标

在改动公共执行底座前，固定术语、接口、风险基线和技术选择。

#### 任务

- [x] 用户确认 D01-D13，或明确哪些决策延后；D01-D10、D13 已确认，D11-D12 已明确暂缓。
- [x] 建立全仓生产风险清单并标记 P0/P1/P2。
- [ ] 固定 PipelineRun、TaskRun、Worker 和 Step 状态机。
- [ ] 已固定 Worker 注册、Job 租约、heartbeat、Step 边界取消和租约过期恢复；统一 timeout、kill switch 与子进程强杀仍待完成。
- [ ] 固定四模块业务动作和权限编码。
- [ ] 固定 ConnectorHealth、ModelCall、Artifact 和 QualityMetric 契约。
- [x] 记录现有数据库 schema、测试结果和前端构建基线。
- [ ] 备份当前 Beta 数据库和有价值的 shadow Artifact。

#### 验收

- 决策状态有明确记录。
- 四模块不再创建平行的任务队列、权限、日志或健康模型。
- 基线测试结果、失败项和环境依赖可重复确认。

### 阶段 1：P0 数据安全和执行安全

#### 目标

先消除可能清空其他模块数据、关闭 TLS、半提交和无限制执行未知代码的风险。

#### 平台任务

- [x] 将 Pipeline reset 从全库重建改为显式领域清理；全库重建只保留给显式数据库初始化 CLI。
- [x] 禁止普通 Pipeline API 请求触发全库 reset。
- [x] Step 默认采用 Runner 管理的 `atomic` SAVEPOINT，失败回滚业务写并清理新 Artifact；仅显式 `checkpointed` 长任务允许分段提交。
- [ ] 为关键业务对象增加唯一约束和幂等键设计。
- [ ] 建立最小备份、校验和恢复流程。
- [x] CORS 默认同源关闭，确需跨域时使用 `AI4SEC_CORS_ALLOWED_ORIGINS` 显式白名单；禁止通配符、路径、查询、URL 凭据和非 HTTP(S) Origin。
- [x] readiness 增加 `SAVEPOINT` 隔离的真实 SQLite 写入/回滚探测；锁占用、只读文件和迁移异常返回 503，不留下探测数据。

#### 模块任务

- [x] 威胁连接器恢复系统默认 TLS 验证；特殊证书后续使用受控 CA，不允许全局跳过验证。
- [ ] 能力复现已增加 CPU、内存、swap、PIDs、墙钟超时、日志和 workspace 软上限；文件系统硬 quota 与嵌套容器资源治理仍待完成。
- [x] 能力复现停止将模型 Key 写入 Prompt，并在日志回调进入 SQLite/SSE 前统一脱敏；任务 token 改为只读 Secret 文件挂载。
- [ ] 已确认 `repro-runner:v3` 镜像含长期认证文件，并构建通过 Sysbox 验收的干净 `v4`；旧凭据轮换、两个运行中 `v3` 容器迁移及旧镜像删除仍需人工完成。
- [x] 能力复现 Web 端口代理默认只绑定 `127.0.0.1`；受认证反向代理将在部署阶段接入。
- [x] 能力 API/Pipeline 只写持久任务，独立 Repro Worker 使用短连接写日志与状态，不再复用请求级 SQLite connection。
- [x] 漏洞抓取 URL 已接入统一公网 URL 策略，阻断非法协议、URL 凭据、localhost、非公网 IP、解析到非公网地址的域名及 urllib 私网重定向；DNS 重绑定最终防线仍由部署出口策略提供。
- [x] 资讯 legacy raw 已从正式 Registry、API、普通 Pipeline CLI、在线 adapter 和默认配置移除，仅保留受控一次性迁移 CLI。

#### 验收

- 运行或重置任一模块不会删除其他模块数据。
- 连接器不存在默认跳过 TLS 校验。
- Step 失败不会留下无法判断的半完成状态。
- 复现任务不能无限使用宿主机资源。
- 复现容器和任务日志中不存在真实 Provider Key。
- 不可信复现容器不能访问平台管理网段和未批准的内网地址。
- 完成一次备份恢复验证。

### 阶段 2：SQLite 加固和可靠任务执行

#### 目标

替换 daemon Thread，使单机任务可持久、可恢复、可取消，并在 API、Scheduler 和单 Pipeline Worker 之间保持一致状态。

#### 数据库任务

- [ ] SQLite 连接已强制数据库目录 `0750`、数据库文件 `0640`，无法收紧权限时拒绝启动；Compose 本机持久卷、统一非 root UID/GID 和宿主目录初始化仍待部署阶段落地。
- [x] 配置并验证 WAL、busy timeout 和显式 `wal_autocheckpoint` 页阈值，并提供受控手动/周期维护 checkpoint。
- [x] 建立 `schema_migrations` 表、顺序迁移执行器、checksum 校验和单版本失败回滚。
- [ ] 已为 PipelineRun 查询、TaskRun、Artifact、DataSource/SourceHealth、QualityAudit 查询和 HumanQueue 补齐首批约束与索引；Worker 注册表、QualityAudit 显式 `run_id` 及审计身份约束仍待补充。
- [ ] 为四域关键业务对象补齐幂等键和唯一约束。
- [x] readiness 已包含数据库/WAL/页/迁移指标及维护次数、失败数、累计/最大锁等待；组合维护任务支持 quick/full integrity、checkpoint、历史表和受控 JSON 报告。
- [x] 建立 SQLite Backup API、一致性校验和恢复到指定文件流程。

#### 任务系统任务

- [x] API 只创建 queued 任务，不实例化 Worker 或执行 Pipeline；已删除 `wait=true` 同步兼容入口。
- [x] 实现单实例 Pipeline Worker 进程和独立 CLI。
- [x] 实现原子任务领取、Worker 注册、空闲/运行 heartbeat、Job 租约续期和租约过期失联判定。
- [x] 实现任务条件领取、同 Pipeline/全局 reset 冲突检查和单机 Worker 文件锁。
- [x] 统一 queued/running/success/partial/failed/timeout/cancelled 状态在 Step、TaskRun、PipelineRun 和 PipelineJob 间的传播。
- [ ] 已实现持久系统 kill switch、拒绝新任务、批量取消 queued、running 协作取消、能力复现容器/宿主进程强停，以及 crawl4ai 取消后停止提交新 URL；已运行浏览器线程仍依赖单 URL deadline 和 context 退出。
- [ ] 已实现严格 JSON Step checkpoint、输入/实现 checksum、陈旧检查点位置校验和恢复框架；首个白名单为漏洞候选选择步骤，四域其余 Step 的 `resume_safe` 审核仍待完成。
- [ ] 已实现失败 Run 的白名单续跑入口；失败条目重跑与完整 Run 重跑策略仍待补充。
- [x] 实现 Worker 启动对账；在 checkpoint 完成前将中断的 running 任务标记失败，不做不安全的自动重放。
- [x] 实现单机统一 Scheduler、`Asia/Shanghai` 时区、确定性 Run ID、宽限窗口漏跑补偿和单机互斥；具体业务时刻默认禁用，待模块验收后配置启用。

#### 验收

- API 服务重启不丢失 queued/running 任务记录。
- Worker 异常退出后任务可以被恢复或明确标记失败。
- API、Scheduler 和 Worker 重启后不会重复执行同一任务。
- 单 Pipeline Worker 保证 Pipeline Run 串行领取，同一互斥 Pipeline 不会重复运行。
- 长任务可以取消并回收浏览器、子进程或容器。
- 可从失败 Step 恢复而不重复已完成模型调用。
- 锁等待和 WAL 增长处于设定阈值内。

### 阶段 3：四模块 Production Ready 闭环

四条模块工作流在统一平台契约上并行推进，但按仓库变更冲突情况串行合并和验证。

#### 3A. 资讯洞察

- [x] 从正式菜单移除 `news.legacy_raw_pipeline`。
- [x] 将历史导入改为受控一次性迁移命令。
- [x] 在线连接器与本地 JSON 基类解耦。
- [x] X 当前正式禁用：仓库未配置可用凭据，原 GetXAPI 方案不可用；替换服务完成连通性、认证、额度和样本质量验收前不得重新启用。
- [x] 六源健康探测、超时错误分类和连接器可靠性契约已完成：arXiv、GitHub、WeRSS、ASIS 支持有界分页，Awesome 使用有界研究子页遍历，启用源统一使用可配置重试；X 保持正式禁用，替换 Provider 上线前必须实现同一契约。
- [x] RSS、ASIS 已建立 SQLite 正式水位线；X 当前禁用，替换 Provider 必须按同一契约实现来源 ID 水位线后才能启用。
- [x] 完成资讯 canonical key upsert、同日日报合并和成功 ModelCall 稳定请求键幂等；失败调用保留审计并允许后续重跑。
- [x] 定义并实现采集单源补跑、门控/深评失败项缓存恢复、日报 checkpoint 恢复语义及运营入口。
- [x] 建立门控/深评严格 Schema 校验、阻断发布、去重人工队列、人工忽略与恢复后自动解决机制。
- [x] 建立三周期验收 CLI，自动汇总各源采集量、失败、去重率、入选率、Schema 通过率、模型 Provider、人工队列和日报状态；本地规则、缺源、同日重复 Run 不计为合格周期。
- [ ] 连续运行至少三个真实日更周期；已完成 `2026-07-31` 第 1 个合格周期，剩余 2 个不同业务日期。

验收指标至少包含：各源采集量、筛选率、重复率、失败率、最终入选率、Schema 通过率、人工纠错率和日报准时率。

#### 3B. 能力洞察

- [x] 固定复现状态转换和所有异常收尾路径。
- [x] 实现启动时容器、任务、报告状态对账。
- [x] 声明任务资源、日志、重试和并发配额。
- [x] 完成独立受限复现 Worker 接入。
- [x] 建立 Model Gateway 短期任务令牌，不向复现容器注入真实 Provider Key。
- [x] 建立代码仓、软件包仓、模型仓基础出口白名单、任务声明外部 API 的持久审批、运行时域名/IP 映射日志和防火墙计数审计。
- [x] 阻断回环、私网、链路本地、云 metadata、Docker 网桥和平台管理网段。
- [ ] 实现 standard rootless 与 nested_docker Sysbox 双 Profile。
- [x] nested_docker 必须人工批准、单并发并使用更严格的资源与网络限制。
- [x] 将 OpenCode 权限从全量 allow 收敛为 Profile 对应的最小权限。
- [x] 修复静默子进程超时、孤儿容器、容器信息持久化和 Web 端口暴露。
- [x] 完善 Web、CLI、官方 Demo 和不可复现项目策略。
- [x] 加强成功判定和证据要求。
- [x] 完成结构化报告与能力卡回写。
- [ ] 完成正式能力洞察前端页面。
- [ ] 补齐 API、SSE、停止、清理、超时和回写测试。
- [ ] 使用 10 至 20 个不同技术栈项目回归。

验收指标至少包含：成功率、部分成功率、失败阶段分布、平均耗时、超时率、资源峰值、报告完整率和模型 Token。

#### 3C. 威胁洞察

- [ ] 建立 CVE 覆盖基线并解释与旧数据差异。
- [ ] 调整 star threshold、issue/PR/security file 扫描策略。
- [ ] 完成 AscendHub、Firmware、OpenX full profile 验收。
- [ ] 优化 AI 研判候选分层和覆盖目标。
- [ ] 降低攻击面空值并记录 unknown reason。
- [ ] 将常用统计字段结构化并建立索引或预聚合。
- [ ] Graph API 增加分页、过滤和节点上限。
- [ ] 修复 RepoDrawer 资产关联和前端错误边界。
- [ ] 清理 unused 代码。
- [ ] 补齐威胁 API、connector、数据质量和前端测试。

验收指标至少包含：CVE 覆盖率、资产覆盖率、AI 研判覆盖率、高风险召回、攻击面空值率、接口 P95 延迟和 full scan 耗时。

#### 3D. 漏洞洞察

- [ ] 实现事件人工合并、拆分和 CVE 修正。
- [ ] 实现多 CVE 素材关联和无 CVE 主题治理。
- [ ] 实现字段证据高亮和原文定位。
- [ ] 实现模型值、人工值和正式值版本历史。
- [ ] 定义新素材更新已有事件和知识的规则。
- [ ] 已人工确认字段默认禁止模型静默覆盖。
- [ ] 扩充 golden set 并执行大规模 shadow evaluation。
- [ ] 验证完整关键词规模的覆盖率、重复率和成本。
- [ ] 完善业务失败重试和素材—事件—知识追溯。

验收指标至少包含：有效素材率、误收率、误杀率、事件聚合准确率、字段准确率、字段证据有效率、人工修改率和重复率。

### 阶段 4：身份、安全、可观测与运营

#### 安全任务

- [ ] 实现最小本地账号、Argon2id 密码哈希、服务端 Session Cookie 和统一 CurrentUser。
- [ ] 实现登录失败限制、Session 失效、管理员禁用账号和首次密码修改。
- [ ] 实现 RBAC 权限检查和默认拒绝策略。
- [ ] 实现用户操作审计。
- [ ] 接入 Compose Secret/宿主机只读 Secret 文件和 `_FILE` 配置读取。
- [ ] 统一日志、错误和 API 响应脱敏。
- [ ] 建立 URL 校验、SSRF 防护和出口白名单。
- [ ] 配置可信 Host、HTTPS、CORS、CSRF 和限流。

#### 可观测任务

- [ ] 结构化 JSON 日志并贯穿 run/task/step/domain ID。
- [ ] 暴露 Prometheus 指标。
- [ ] 建立 API、Worker、Pipeline、Connector、Model 和 DB Dashboard。
- [ ] 建立任务失败、日报缺失、队列积压、模型错误率和磁盘告警。
- [ ] 健康检查覆盖 DB、Worker、Scheduler、Artifact 和必要外部依赖。

#### 运营后台任务

- [ ] 统一任务列表、详情、Step、日志和 Artifact 组件。
- [ ] 统一数据源健康、质量审计、模型调用和人工队列组件。
- [ ] 四模块分别接入领域指标和失败操作。

#### 验收

- 未授权用户不能执行任何写操作或高成本任务。
- 高风险操作可追溯到用户、参数和结果。
- 日志和错误不暴露密钥。
- 关键故障能在约定时间内产生告警。
- 运维人员不需要直接查数据库即可判断任务状态。

### 阶段 5：发布、性能和灾难恢复

#### 任务

- [ ] 建立生产 Dockerfile 和 Compose 文件。
- [ ] 生产使用反向代理提供 HTTPS 和前端静态文件。
- [ ] API 不使用 `--reload`。
- [ ] 配置开发、测试、预发布和生产环境。
- [ ] 创建私有 GitHub 仓库并配置本地 `beta-production-hardening` 远端。
- [ ] 推送前执行敏感信息扫描、`git diff --check` 和本地测试。
- [ ] 暂不建设完整 CI/CD；如需要，仅增加 Python 测试、前端构建和敏感信息扫描 Action。
- [ ] 建立手动的镜像构建、部署、健康检查和回滚流程。
- [ ] 执行 API 并发、数据库写入和长任务稳定性测试。
- [ ] 执行权限、SSRF、容器隔离和依赖漏洞安全测试。
- [ ] 执行数据库和 Artifact 恢复演练。
- [ ] 完成至少一个完整调度周期的预发布 shadow 运行。

#### 最终验收

- 全仓 Python 测试通过。
- 前端 TypeScript 检查和生产构建通过。
- 数据库迁移可从空库执行，也可从上一版本升级。
- 发布失败可以回滚应用，迁移有明确前向修复或回滚策略。
- 备份在独立环境成功恢复。
- 四模块 Production Ready 检查全部通过。
- 平台 Production Deployable 检查全部通过。

---

## 7. 优先级与依赖关系

### P0：立即处理的阻断风险

1. 按领域隔离 reset，禁止跨模块清库。
2. 修复威胁来源 TLS 校验关闭。
3. 明确 Pipeline 事务和幂等约束。
4. 限制能力复现容器资源和权限。
5. 建立最小备份和恢复验证。
6. 按已确认的 SQLite + 单 Pipeline Worker 方案完成详细设计。

### P1：可靠运行核心

1. SQLite WAL、迁移、备份和容量监控。
2. 持久任务、单 Pipeline Worker、租约和单机互斥。
3. checkpoint、恢复、取消和业务重跑。
4. 结构化日志和真实健康检查。
5. 四模块业务闭环和专项测试。

### P2：正式上线保障

1. 登录、RBAC 和操作审计。
2. Secret 管理、SSRF 防护和网络策略。
3. 指标、告警和统一运营后台。
4. Git 远端、CI/CD、灰度和回滚。
5. 压测、安全测试和灾难恢复演练。

### 关键依赖

```text
SQLite 单机边界
  → 持久任务表和单机互斥
  → 单 Pipeline Worker / Scheduler / checkpoint
  → 四模块统一失败恢复

部署形态
  → Secret / Artifact / 监控方案
  → CI/CD 和备份方式

认证方案
  → RBAC / 操作审计
  → 高风险运行和审核动作开放

能力复现隔离方案
  → 能力模块生产验收
  → 平台整体安全验收
```

---

## 8. 测试与质量门禁

### 8.1 每次代码变更的基础检查

```bash
python -m compileall -q src tests
pytest -q
cd frontend && npm run build
```

根据改动范围，先运行专项测试，再运行全仓测试。联网测试、真实模型测试、长时间 full scan 和 Docker 复现测试应单独标记，不混入默认单元测试。

### 8.2 必须补充的测试层级

| 层级 | 目标 |
|---|---|
| Unit | 纯规则、状态转换、幂等键、解析和 Repository 行为 |
| API | 鉴权、校验、错误码、分页、权限和状态响应 |
| Worker Integration | 领取、锁、heartbeat、取消、超时、崩溃恢复 |
| Database Integration | SQLite WAL、事务、锁等待、唯一约束、迁移和备份恢复 |
| Frontend | 核心运营流程、错误状态和高风险操作确认 |
| E2E Shadow | 四模块真实输入到页面展示，不写生产目标 |
| Security | SSRF、权限绕过、Secret 泄漏和容器隔离 |
| Recovery | DB、Artifact、Worker 和发布回滚演练 |

### 8.3 发布门禁

以下任一条件不满足，不进入生产发布：

- 存在 P0 未关闭问题。
- 全仓测试或前端构建失败。
- 数据库迁移未在上一版本副本验证。
- 备份未验证可恢复。
- 高风险 API 无认证和审计。
- 能力复现仍直接暴露高权限 Docker socket。
- 复现容器可获得真实模型 Provider Key 或将其写入日志。
- 复现容器可以任意访问内网、宿主机或云 metadata 地址。
- 健康检查无法发现数据库或 Worker 故障。
- 四模块业务验收指标没有实际运行证据。

---

## 9. 风险登记

| 风险 | 影响 | 当前缓解 | 后续措施 |
|---|---|---|---|
| 全库 reset 影响四域 | 严重数据丢失 | 当前仅 shadow | 阶段 1 改为领域隔离 |
| daemon Thread 丢任务 | 状态不一致、任务静默终止 | PipelineRun 有部分记录 | 阶段 2 持久 Worker |
| SQLite 并发限制 | 锁冲突、API 延迟 | WAL + 单 Pipeline Worker + 短事务 | 锁等待监控；超过升级阈值后再评估 PostgreSQL |
| 威胁连接器关闭 TLS | 中间人攻击、数据不可信 | 尚未完成 | 阶段 1 立即修复 |
| 未知代码复现 | 宿主机、内网和密钥风险 | Sysbox 初步隔离 | 同机独立 Worker、双 Profile、强制出口策略和短期模型令牌 |
| 复现密钥写入 Prompt/日志 | Provider Key 泄漏和滥用 | `.env` 未提交 Git | Model Gateway 短期令牌，禁止真实 Key 进入容器和日志 |
| 复现任务自由出网 | 内网扫描、SSRF、数据外传 | 暂无有效 CIDR 阻断 | 宿主机网络策略、域名允许列表和连接审计 |
| 无认证/RBAC | 任意用户执行高风险操作 | 依赖内网边界 | 阶段 4 认证和审计 |
| 外部 URL 抓取 | SSRF 和恶意内容 | 部分策略分散 | 统一 URL 安全层 |
| 模型/API 无预算 | 费用和额度失控 | 手工参数限制 | 三级配额和告警 |
| 本地 Artifact 增长 | 磁盘占满、备份困难 | Git 忽略 output | 生命周期和容量告警 |
| 无正式远端 | 无审查和自动发布 | 本地分支开发 | 配置企业 Git 平台 |

---

## 10. 用户决策回复模板

用户可以直接复制以下模板填写；不确定的项目可以写“采用推荐方案”或“延后”。

```text
D01 部署形态：已确认核心平台使用内网 Docker Compose，能力复现 Worker 与 API 分离
可用服务器配置：CPU / 内存 / 磁盘 / GPU / 操作系统：
开发期服务器数量：

D02 数据库：已确认采用 SQLite + WAL 单机生产方案
SQLite 持久卷位置和备份位置：

D03 任务队列：已确认采用 SQLite 持久任务表 + 单 Pipeline Worker
任务默认 heartbeat / 租约 / 超时：可采用实施阶段基准测试后的推荐值

D04 身份认证：已确认采用简单本地账号 + Session Cookie + 最小 RBAC
预计用户数量：
读页面是否也要求登录：是 / 否

D05 Secret：已确认采用 Compose Secret/受控只读 Secret 文件

D06 Artifact：已确认采用单机本地持久卷和 ArtifactStore 抽象
预计保留周期和容量：

D07 复现隔离：已确认同机独立 Worker + standard rootless / nested_docker Sysbox 双 Profile
网络策略：已确认 OpenCode 和项目复现全过程受控联网
必要外部域名或软件包仓库：

D08 监控告警：已确认采用 Prometheus + Grafana
告警渠道：企业微信 / 钉钉 / 邮件 / 内部 Webhook / 其他

D09 Git/代码备份：已确认采用私有 GitHub 仓库，暂不建设完整 CI/CD
GitHub 组织/用户名：
GitHub 仓库名：
远端仓库地址：

D10 备份：已确认接受 RPO 24h、RTO 4h
独立备份存储位置：

D11 网络暴露：已暂缓公网暴露，当前仅内网使用
允许访问平台的内网范围：

D12 外部 API 和模型预算：已暂缓费用预算治理，当前使用 GLM-5.2
模型调用安全限制和禁止发送的数据：

D13 调度：已确认采用北京时间和模块化日更/补跑策略
资讯日报最晚完成时间：
威胁 default/full scan 周期：
漏洞 daily/full scan 周期：
节假日是否运行：
```

---

## 11. 进度维护规则

本文是后续工作的单一计划入口。每完成一个阶段或发生架构决策，应同步更新：

1. 第 3 节决策状态。
2. 第 6 节任务复选框。
3. 第 9 节风险状态。
4. 第 12 节实施记录。
5. 如果目录、调用链或长期架构发生变化，再同步更新 `docs/平台总体架构设计.md`。

任务状态解释：

```text
[ ] 未开始
[~] 进行中
[x] 已完成且通过验收
[!] 被外部决策或环境阻塞
[-] 经批准取消
```

不得仅因代码已合并就标记完成；必须同时记录测试或运行验收证据。

---

## 12. 实施记录

### 2026-07-28：建立生产化总计划

完成内容：

- 汇总资讯、能力、威胁、漏洞四个模块的 Beta 到生产差距。
- 去重平台公共能力，明确模块与平台职责边界。
- 提出 D01-D13 十三项用户决策及推荐方案。
- 建立阶段 0 至阶段 5 的实施顺序和验收标准。
- 当前没有修改业务代码、数据库或生产配置。

下一步：

1. 进入阶段 0 全仓基线审计；D01-D10、D13 已确认，D11-D12 已明确暂缓。
2. 执行阶段 0 的全仓基线审计。
3. 在不依赖生产环境决策的范围内开始阶段 1 P0 修复。

### 2026-07-28：确认核心 Compose 与能力复现隔离原则

用户确认 D01 可以采用 Docker Compose，同时要求不能影响能力洞察启动 Docker 复现任务。

确认结论：

- 核心平台使用内网 Docker Compose。
- 能力复现 Worker 与 API 分离，不由 API 容器直接控制 Docker。
- 开发期资源有限时，复现 Worker 可以与核心 Compose 同机运行，但使用独立账号、进程、目录和 rootless 容器运行时。
- 初始建议生产期使用独立复现主机或 VM；后续用户确认只做单机部署，该建议已由下一条实施记录调整为同机逻辑隔离。
- 不采用 privileged Docker-in-Docker。
- 不允许生产 API 容器挂载高权限宿主机 Docker socket。
- D07 的隔离原则已经确认；部署位置由后续决策收口为单机同宿主机。该记录中的出网待确认状态已由后续“全过程受控联网”决策关闭。

### 2026-07-28：确认 SQLite 单机生产和持久任务方案

用户确认当前不需要多节点部署，首期继续使用 SQLite，并接受单机可靠任务执行边界。

确认结论：

- D02 使用 SQLite + WAL，不将 PostgreSQL 迁移作为当前生产化前置条件。
- SQLite 文件只保存在本机持久磁盘，不使用 NFS、SMB 或其他网络共享目录。
- API、Scheduler 和 Worker 必须使用短事务，外部采集和模型调用期间不得持有写事务。
- D03 使用 SQLite 持久任务表、单 Pipeline Worker、任务租约、heartbeat、checkpoint 和启动恢复。
- 当前不建设多节点分布式锁，不引入仅用于队列的 Redis，避免形成双状态源。
- 能力复现 Worker 与平台核心服务运行在同一宿主机，但保持独立账号、进程、目录和 rootless 容器边界。
- 能力复现 Worker 通过 API 领取任务和回写结果，不直接访问 SQLite 文件。
- 当前交付目标定义为单机 Production Deployable，不承诺主机故障自动转移或数据库高可用。
- 当需要多个 Pipeline Worker、多个平台节点，或 SQLite 锁等待持续影响业务时，再启动 PostgreSQL 迁移评估。

### 2026-07-28：确认 Secret、Artifact 与同机复现方向

用户说明当前没有企业 SSO，也没有额外复现主机或 VM，并确认 D05、D06 使用推荐方案。

确认和推荐结论：

- D04 不建设企业 SSO，推荐实现简单本地账号、服务端 Session Cookie 和最小 RBAC。
- 认证可以延后到阶段 4，但正式生产验收前不能完全省略。
- D05 已确认使用 Compose Secret/宿主机只读 Secret 文件，并为应用增加 `_FILE` 配置读取和日志脱敏。
- D06 已确认使用单机受控本地持久卷，通过 ArtifactStore 抽象访问，并增加容量、保留周期和备份管理。
- D07 已确认能力复现 Worker 与平台部署在同一宿主机，但使用独立系统账号、独立进程、独立目录和 rootless Docker/Podman。
- API 不挂载系统 Docker socket，不直接执行容器操作；在当前单机 SQLite 架构下，复现 Worker通过 Repository 和短连接直接认领任务、写心跳与结果，不通过 API 回调，也不持有 API 请求连接。
- 本记录最初建议依赖准备阶段受限联网、复现运行阶段默认断网；后续确认 OpenCode 运行依赖模型，该建议已被“全过程受控联网”方案替代。
- 同机 rootless 容器共享宿主机内核，隔离弱于独立 VM，该剩余风险需要在上线验收时明确接受并记录。

### 2026-07-28：确认 OpenCode 复现全过程受控联网

用户指出能力复现通过 OpenCode 自动部署，复现运行阶段仍需连接模型，不能采用运行阶段断网方案。

代码和环境审计结论（当时状态，后续已有部分关闭）：

- 当前 API 通过内存 ReproManager 和 daemon Thread 直接调用宿主机 Docker。
- 当前统一使用 `sysbox-runc` 和 `repro-runner:v3`，容器内运行 Docker daemon，OpenCode 以 root 身份执行。
- 当前 Docker 网络未限制公网和内网出口，已定义的内网 CIDR 没有实际应用。
- OpenCode 配置允许 bash、读写、webfetch 和 external directory 等操作。
- `REPRO_LLM_API_KEY` 会进入 Prompt，完整 Prompt 又写入任务日志，存在密钥泄漏风险。
- OpenCode 自身认证从镜像内 auth 文件读取，需要审计镜像是否包含长期密钥。
- 当前只有 PIDs 上限，缺少 CPU、内存、磁盘、日志和嵌套容器数量限制。
- 当前超时依赖阻塞式 stdout 读取，静默进程可能绕过超时。
- 当前 Web 端口代理没有显式绑定回环地址。
- 当前后台线程可能继续使用已经关闭的请求级 SQLite connection，API 重启后还可能遗留孤儿容器。

确认方案：

- OpenCode、依赖安装和项目运行全过程允许受控联网，不采用运行阶段断网。
- 模型调用统一经过 AI4SEC Model Gateway，复现容器只获得任务级短期令牌，不获得真实 Provider Key。
- 代码仓、软件包仓、模型仓和项目外部 API 使用任务级允许列表。
- 默认阻断回环、RFC1918 私网、链路本地、云 metadata、Docker 网桥、宿主机管理端口和平台管理网段。
- 网络限制在宿主机防火墙、专用容器网络或强制出口代理实施，不能只依赖容器代理环境变量。
- 建立 standard rootless 和 nested_docker Sysbox 双 Profile；只有明确依赖 Docker/Compose 的任务才能人工批准使用 nested_docker。
- 当前实现审计发现的密钥、网络、线程、资源、端口和恢复问题纳入能力复现 P0。

### 2026-07-28：确认监控、代码备份、备份恢复、网络暴露和调度策略

用户确认以下平台决策：

- D08 采用 JSON 结构化日志、Prometheus、Grafana 和内部 Webhook 告警。
- D09 创建私有 GitHub 代码仓，阶段性将本地代码推送到远端；暂不建设完整 CI/CD、自动部署和灰度发布流程。
- D10 采用 RPO 24 小时、RTO 4 小时、每日备份和定期恢复演练方案。
- D11 暂不考虑公网暴露，当前继续保持单机内网使用；D07 的复现容器出口控制仍然照常执行。
- D12 暂不建设费用预算治理，当前使用无需项目直接付费的 GLM-5.2；模型失败、超时、调用次数、密钥隔离和日志脱敏仍需实现。
- D13 采用北京时间和模块化调度策略，支持日更窗口、漏跑补偿、人工触发和高成本任务的低频调度。
- D04 已由用户确认采用简单本地账号、Session Cookie 和最小 RBAC 方案。

### 2026-07-28：确认最小本地认证方案

用户确认 D04 采用简单本地账号认证，不接企业级 SSO。

确认结论：

- 使用本地账号、Argon2id 密码哈希、服务端 Session Cookie 和最小 RBAC。
- 浏览器不保存长期 JWT 到 `localStorage`，使用 `HttpOnly`、`Secure`、`SameSite` Cookie。
- 登录失败限制、CSRF 防护、管理员创建/禁用账号和首次密码修改属于实现范围。
- 暂不实现公开注册、自助找回密码、短信、邮件和复杂组织管理。
- D04 可以排在阶段 4 实现，但正式生产验收前必须完成。
- D01-D10、D13 已确认，D11-D12 已明确暂缓；用户决策阶段完成，进入阶段 0 基线审计。

### 2026-07-28：完成阶段 0 首轮基线并关闭首批 P0

完成内容：

- Python `compileall` 通过。
- 安装锁定前端依赖后，TypeScript 和 Vite 生产构建通过。
- 前端构建存在单 bundle 超过 500 kB 的警告，生产依赖审计报告 1 个 moderate 和 1 个 high 风险项，未使用 `npm audit fix --force` 做破坏性升级。
- 新增 `reset_domain()`，Pipeline 的 `reset=true` 只删除当前业务域的运行、制品元数据、领域对象、审计和队列数据，不再删除其他三个模块。
- 全库 `reset_db()` 仅保留给显式数据库初始化 CLI，不再由普通 Pipeline Runner 调用。
- 威胁 `LiveJsonConnector.get_text()` 删除 `CERT_NONE` 和 `check_hostname=False`，恢复系统默认 CA 与主机名校验。
- Huawei `CollectHuaweiSourcesStep` 恢复调用统一 `load_huawei_sources()`，重新支持 source cache、`resume_from_run_id`、显式 source records 和合并 Artifact。
- 修复 Huawei API smoke mock，单元测试不再意外执行真实 8k 级在线采集。
- 新增领域 reset 隔离、非法 domain 拒绝和 TLS 默认校验测试。

专项验证：

```text
tests/unit/test_production_safety.py
Huawei full migration API smoke
Huawei source resume/cache
结果：6 passed
```

全仓回归基线：

```text
147 passed
5 failed
2 deselected（已知缺失 /api/frontend/v9 路由）
耗时约 33 秒
```

剩余 5 个既有失败，不由本次 P0 修改引入：

1. 异步运行进度响应新增 `item_progress=None`，旧测试仍要求完全相等。
2. Huawei full scan 页数期望 400，当前实现返回 100。
3. 内容模型 timeout 测试期望 600 秒，当前配置返回 180 秒。
4. 威胁语义评审 Prompt 缺少旧测试要求的 `broad_sec_items` 文本。
5. 威胁语义评审标准化结果缺少 `recommended_tracking_level`。

另外两个既有 API 契约缺口：

- `/api/frontend/v9`
- `/api/frontend/v9/files/{path}`

下一步：

1. 在继续其他 P0 前，修复上述测试契约或明确删除已经废弃的 v9 API 契约。
2. 进入 Pipeline 事务边界、幂等约束和 SQLite 备份恢复设计。
3. 开始能力复现密钥泄漏、后台线程和资源限制修复。

### 2026-07-28：清零阶段 0 全仓回归失败

完成内容：

- 运行进度响应只在存在条目级进度时返回 `item_progress`，恢复异步任务查询接口的兼容契约。
- Huawei full scan 测试改为验证 Pipeline 将分页职责委托给 Connector，避免 Pipeline 和 Connector 重复实现分页。
- 漏洞内容抽取模型的默认超时恢复为 600 秒；素材审核和知识抽取保持 180 秒，其他模型保持 45 秒。
- 威胁语义评审 Prompt 恢复 `broad_sec_items` 分类说明，并补齐旧版字段与当前字段的兼容标准化输出。
- 本轮曾因过期 README、开发记录和测试仍引用 `/api/frontend/v9`，误将已删除的 demo 聚合兼容层恢复；后续经正式 React 前端调用审计确认没有运行时依赖，并在下一条纠偏记录中再次删除。
- 敏感信息模式扫描未发现已跟踪的 GitHub Token、OpenAI 风格 Key 或私钥文件内容。

验证结果：

```text
python -m compileall -q src tests
pytest -q --tb=short
结果：154 passed
耗时约 40 秒
```

阶段 0 当前结论：

- Python 全仓测试已全部通过；5 个真实契约失败已修复，两个 v9 测试随后被确认属于过期 demo 契约并删除。
- 前端生产构建已通过，但 bundle 体积警告和 npm 依赖风险仍需在后续前端生产化阶段处理。
- 下一步进入 SQLite 事务、WAL、幂等约束、持久任务执行器和恢复机制设计与实现。

### 2026-07-28：完成 SQLite 单机生产化第一批基础能力

完成内容：

- SQLite 连接统一启用 WAL、外键校验、可配置 busy timeout 和可配置 synchronous 级别。
- 默认 `AI4SEC_SQLITE_BUSY_TIMEOUT_MS=30000`、`AI4SEC_SQLITE_SYNCHRONOUS=NORMAL`；非法配置回退到安全默认值。
- FastAPI 请求级数据库依赖在正常结束时提交未提交变更，在异常结束时回滚未提交变更并始终关闭连接。
- 新增 SQLite 在线一致性备份，使用 SQLite Backup API 读取包含 WAL 已提交内容的完整快照。
- 备份先写同目录临时文件，通过 `PRAGMA integrity_check` 后再原子替换目标文件，失败时清理临时文件。
- 新增只读完整性校验和恢复到指定数据库文件能力；已有目标默认拒绝覆盖，必须显式使用 `--overwrite`。
- 新增 `ai4sec_platform.cli.database backup|verify|restore` 薄 CLI，并在 README 中记录操作方式和停服恢复要求。

验证结果：

```text
SQLite 专项测试：6 passed
全仓测试：160 passed
compileall：通过
CLI 初始化 → 在线备份 → 恢复 → 完整性校验：通过
恢复数据库表数量：16
```

边界说明：

- 请求级回滚只能回滚尚未提交的事务；部分旧 Service 和 Pipeline Step 为了进度可见性会主动 `commit()`，不能依赖请求级依赖撤销这些已提交阶段结果。
- Pipeline 的正确生产语义应是“步骤级事务 + 幂等结果 + 可恢复状态机”，而不是把长时间采集和模型调用包进一个超长数据库事务。
- 覆盖正式数据库文件前必须停止 API、Pipeline Worker 和复现 Worker；不能在仍有活跃连接时用文件替换方式恢复。
- 本批次尚未实现每日调度、备份保留周期和异地副本，后续由统一调度与运维阶段补齐。

下一步：

1. 设计持久任务表和单 Pipeline Worker 的领取、心跳、超时回收与停机恢复状态机。
2. 为 Pipeline 增加步骤 checkpoint、输入 checksum 和失败步骤续跑语义。
3. 逐步补充领域幂等键，避免恢复和重跑产生重复条目、日报与模型调用。

### 2026-07-28：纠偏删除过期 v9 demo 聚合兼容层

背景与判断：

- `/api/frontend/v9` 和 `/api/frontend/v9/files/{path}` 是旧 `index-v9.html`/静态页面时期的一次性聚合与样例 JSON 兼容接口。
- 正式 React 前端已经按业务域拆分 API，资讯、能力、威胁、漏洞和运营页面均直接调用各自接口。
- 全仓审计确认 `frontend/src` 对 v9 聚合接口没有任何调用；剩余引用只有旧 README、开发记录和两项专门验证旧接口自身的测试。
- “文档和测试仍存在”只能证明清理不完整，不能证明生产功能仍需要保留。恢复该接口会制造重复字段映射、扩大维护面，并掩盖领域 API 契约问题。

纠偏动作：

- 删除 `app/api/frontend.py`、`services/frontend_v9.py` 和路由注册。
- 删除两个只验证旧 v9 聚合层的测试，不用新测试替代不存在的生产需求。
- 从 README 的正式接口清单和使用说明中删除 v9 契约。
- 在开发记录中保留历史实现事实，但明确标注已废弃，防止后续 Agent 再根据旧记录恢复。
- 纠偏后 `compileall` 通过，全仓保留的 158 项有效测试全部通过。

后续兼容性判断规则：

1. 先检查正式前端、外部调用方和部署配置是否存在真实运行时依赖。
2. 再确认该能力是否属于当前产品架构，而不是 demo、迁移脚本或临时适配层。
3. 测试与 README 如果和正式代码调用关系冲突，应优先判定其是否过期，不能为了让旧测试通过而恢复代码。
4. 只有存在明确调用方、用户承诺或迁移窗口时才保留兼容层，并记录下线时间；否则删除历史遗留实现。

### 2026-07-28：完成持久 Pipeline Job 与单机 Worker 第一批实现

完成内容：

- 新增 SQLite `pipeline_jobs` 持久任务表，记录参数、reset 请求、状态、领取次数、Worker、heartbeat、中断原因和起止时间。
- API 的 `wait=false` 不再创建 daemon 执行线程，只原子写入 `pipeline_runs` 和 `pipeline_jobs` 后返回轮询地址。
- 新增原子任务领取：SQLite `BEGIN IMMEDIATE` 与条件更新保证同一任务只能从 `queued` 转为一次 `running`。
- 新增同 Pipeline 重复任务冲突、reset 全局排他和 reset 运行时保留当前 `run_id`，避免领域重置删除任务自身。
- 新增独立 `pipeline_worker` CLI 和宿主机 `flock` 文件锁，阻止两个 Worker 进程并行执行 Pipeline。
- `wait=true` 作为开发和测试兼容入口保留，但同样先持久入队并竞争同一 Worker 文件锁；正式页面和 Scheduler 必须使用 `wait=false`。
- Worker 启动时对账遗留 `running` 任务。由于 Step checkpoint、上下文恢复和领域幂等尚未完成，中断任务安全地转为 `failed` 并要求人工重试，不自动从头重放。
- Run 查询接口返回关联 Job 状态，前端可以区分排队、执行、完成和 Worker 中断。

当前状态机：

```text
queued → running → success
                 → failed
worker interrupted running → failed（人工重试）
```

验证结果：

```text
持久任务、Worker、reset 与安全测试：11 passed
全仓测试：162 passed
compileall：通过
```

明确未完成：

- heartbeat 字段已建立，但长步骤周期心跳、租约过期判定和 Worker 注册尚未完成。
- cancelled、timeout、partial、kill switch 尚未进入统一 Job 状态机。
- Step checkpoint、输入 checksum、上下文 Artifact 恢复和失败步骤续跑尚未完成。
- 在上述恢复能力完成前，不允许自动重放被中断的 running 任务。

### 2026-07-28：补充 Pipeline Job 心跳与协作取消

完成内容：

- Worker 执行 Job 期间使用独立短连接周期更新 `heartbeat_at`，不在 Pipeline 外部调用期间持有数据库写事务。
- 新增 `cancel_requested` 持久字段和 `POST /api/runs/{run_id}/cancel`。
- `queued` 任务取消时原子更新 Job 与 PipelineRun 为 `cancelled`，Worker 不会再领取。
- `running` 任务只写取消请求；Runner 在每个 Step 开始前和完成后检查，在安全边界将 Run 与 Job 收尾为 `cancelled`。
- 所有 `wait=true`、独立 Worker 和单次 Worker CLI 执行仍共享同一宿主机文件锁，避免 API 兼容路径与 Worker 并行执行不同 Pipeline。
- `--recover-only` 同样必须取得 Worker 文件锁，不能在正常 Worker 执行期间误将任务标记为中断。

验证结果：

```text
心跳、排队取消、运行中协作取消与 API 测试：11 passed
全仓测试：165 passed
compileall：通过
```

安全边界：

- 当前取消是 Step 边界协作取消，不会中途杀死正在阻塞的 HTTP、模型、浏览器、子进程或复现容器。
- 强制终止必须由各执行器实现 timeout、进程组终止、浏览器回收和容器 stop/kill，再接入平台 kill switch。
- heartbeat 当前用于运行可见性；在单 Worker 文件锁方案下，启动对账不依据时间自动抢占任务，避免长 Step 被误判后重复执行。

### 2026-07-28：建立校验型 Step Checkpoint 与白名单续跑框架

实现原则：

- 不根据 `task_runs` 状态直接跳过 Step，因为现有 Pipeline 大量依赖 `context.outputs` 内存对象。
- 只有下一个 Step 显式声明 `resume_safe=true` 和 `resume_input_keys` 时，才从 `context.outputs` 选择经过审核的必要字段做严格 JSON 序列化并写入 `pipeline_checkpoint` Artifact。
- Checkpoint 保存已完成 Step、输出快照、下一个 Step 恢复契约和语义输入 checksum。
- checksum 绑定 Pipeline 名称、Domain、业务参数、Step 名称/类型/类、`checkpoint_version`、`resume_safe` 和 Step 类源码 SHA256。
- 恢复时校验 Artifact 路径必须位于来源 Run 目录、文件 SHA256、来源 Run 状态、Pipeline 定义、参数和 Step 顺序。
- 恢复创建新 Run，来源 Run 保持不可变；新 Run 为已恢复 Step 写入 `restored` TaskRun，只执行 checkpoint 之后的 Step。

安全白名单：

- 下一个失败 Step 必须显式声明 `resume_safe=true` 和 `resume_input_keys` 才能续跑；空列表表示只依赖数据库或 Artifact，不需要内存输出。
- 未声明的 Step 默认拒绝，原因是失败前可能已经提交部分数据库、模型调用、外部文件或容器副作用。
- `/api/runs/{run_id}/retry` 在入队前检查 checkpoint 的下一 Step 恢复契约；Runner 执行前再次做完整校验，不能只信 API 预检查。
- 当前框架和测试已完成，但四个业务域的生产 Step 尚未逐项完成幂等审计，因此默认不会自动开放续跑。

验证结果：

```text
checkpoint 输出恢复、完成 Step 不重放、参数变化拒绝、未审批 Step 拒绝、Retry API：15 passed
最终全仓回归：169 passed
compileall：通过
```

后续工作：

1. 按资讯、威胁、漏洞、能力顺序审计每个 Step 的数据库、Artifact、模型和外部副作用。
2. 对可幂等重放 Step 增加唯一键、upsert 或清理补偿后再声明 `resume_safe=true`。
3. 对不可重放 Step 定义失败条目级重试或人工恢复，而不是强行开放整 Step 续跑。
4. 增加 checkpoint 大小、保留周期和敏感字段治理，避免输出快照无限增长或保存不应持久化的数据。

### 2026-07-28：完成 SQLite 顺序迁移与历史校验

背景：

- 原 `init_db()` 在每次启动时执行三个 `ALTER TABLE`，并通过 `except Exception: pass` 吞掉所有异常。
- 该写法无法区分“列已经存在”和磁盘、锁、SQL 或 Schema 损坏等真实失败，也没有数据库版本和升级审计记录。

完成内容：

- 新增 `schema_migrations(version, name, checksum, applied_at)`。
- 将 `last_synced_at`、`queue_source` 和 `cancel_requested` 纳入最新基线 Schema，同时保留版本 1–3 的旧库增量迁移。
- 迁移前显式检查目标表和列；列已存在视为兼容成功，目标表不存在或 SQL 失败则抛出错误。
- 每个版本使用独立 `BEGIN IMMEDIATE` 事务；DDL 或后续逻辑失败时回滚 Schema 变化且不写版本记录。
- 已应用迁移再次启动时验证名称和 checksum，禁止修改历史迁移后静默继续运行。
- 新库直接建立最新表结构并记录 1–3 基线迁移；旧库按顺序补列且保留现有数据。
- `reset_db()` 同时删除迁移历史并重新建立最新 Schema，仍只用于显式初始化 CLI。

验证结果：

```text
迁移专项：10 passed
覆盖新库版本记录、旧库无损升级、幂等执行、历史篡改检测和 DDL 失败回滚
全仓测试：173 passed
compileall：通过
CLI 新库 schema version：3
```

后续边界：

- 当前迁移规模较小，使用代码内顺序迁移；未来复杂表重建需采用新表复制、校验、切换策略，不能直接堆高风险 ALTER。
- 当前只支持单机 SQLite，不提供多节点同时执行迁移；部署顺序必须是备份、停 Worker/API、升级数据库、启动服务、健康检查。

### 2026-07-28：补充 SQLite Readiness 指标与受控 WAL Checkpoint

完成内容：

- 保留 `/api/health` 作为不访问数据库的轻量存活探针。
- 新增 `/api/health/ready`，验证数据库查询并返回数据库文件、WAL、SHM、journal mode、synchronous、busy timeout、页数量、空闲页、分配空间和迁移版本。
- readiness 不执行完整 `PRAGMA integrity_check`，避免每次探针扫描数据库；完整校验仍由备份流程和运维 CLI 执行。
- 新增 `database checkpoint --mode passive|full|restart|truncate`，返回 busy、WAL frame 和已 checkpoint frame。
- 非法 checkpoint 模式在执行 SQL 前拒绝，避免动态 PRAGMA 注入。
- checkpoint 只提供本地 CLI，不暴露到当前尚未认证的 HTTP 运维 API。

验证结果：

```text
SQLite 运维专项：14 passed
全仓测试：177 passed
compileall：通过
PASSIVE checkpoint：busy=0
TRUNCATE checkpoint：busy=0，wal_bytes=0
```

运维建议：

- 普通周期维护使用 PASSIVE，不阻塞活跃读连接。
- TRUNCATE 仅在备份或维护窗口使用，并确认不存在长事务。
- 后续 Prometheus 指标应采集 WAL 增长、数据库容量和 busy/locked 错误累计次数；readiness 只反映当前状态，不替代趋势监控。

### 2026-07-28：切断能力复现模型凭据泄漏链

审计确认：

- 旧实现读取 `REPRO_LLM_API_KEY` 后拼入普通/Web 复现 Prompt。
- Runner 会把完整 Prompt 逐行写入 `capability_repro_tasks.log`，再通过 SSE 和前端返回，形成真实泄漏链。
- OpenCode、Docker、Git、curl、socat 等宿主机子进程默认继承平台进程全部环境变量，可能携带其他 Provider Key。

完成内容：

- Prompt 只包含受管 Gateway Base URL、模型名称和安全使用说明，不包含任何 Key 或 token。
- 新增 `REPRO_MODEL_TOKEN_FILE`，通过 Docker `--mount type=bind,...,readonly` 挂载到 `/run/secrets/repro_model_token`。
- Secret 路径必须是存在的非符号链接普通文件，且权限不得允许 group/other 访问；推荐 `0600`。
- token 内容不出现在 Docker 命令行；容器内只在执行期间读取文件并注入 `OPENAI_API_KEY`/`LLM_API_KEY`。
- 所有 Runner 日志在进入数据库回调前统一脱敏，覆盖已知真实 Secret、`sk-*`、Bearer 和常见 key/token/password 赋值格式。
- 所有宿主机 `subprocess.run/Popen` 通过安全封装执行，删除名称包含 API_KEY、TOKEN、SECRET、PASSWORD、CREDENTIAL 的环境变量。
- 旧能力施工文档中“将 `.env` Key 注入 Prompt”的决策已明确废弃，防止后续恢复不安全实现。

验证结果：

```text
能力专项：37 passed
覆盖 Prompt、日志、Docker mount、命令行与子进程环境不泄漏 token
全仓测试：183 passed
```

剩余风险：

- 当前若未配置任务 token 文件，OpenCode 配置仍兼容读取镜像内 `/root/.local/share/opencode/auth.json`；必须审计并最终移除镜像长期凭据。
- 当前 Secret 文件可能仍是长期 token；目标方案仍是 AI4SEC Model Gateway 签发任务级短期令牌。
- 复现 API 和 ReproManager 当时仍在 API 进程内启动后台线程并持有请求级数据库连接；该问题已在 2026-07-29 的独立持久 Repro Worker 实现中关闭。

### 2026-07-28：补充能力复现资源、日志、超时和端口边界

完成内容：

- 容器启动增加 `--cpus`、`--memory`、`--memory-swap`、`--pids-limit` 和 `no-new-privileges=true`。
- 默认资源为 2 CPU、4 GiB 内存、4 GiB memory+swap 和 1024 PIDs，可通过受控环境变量调整。
- workspace 默认 10 GiB 软上限，Runner 每 5 秒扫描普通非符号链接文件，超限后停止容器并将任务标记失败。
- 数据库/SSE 日志默认 5 MiB 上限；首次超限写一条截断告警，后续日志全部丢弃。
- `_full_output` 同样按字节上限保留尾部，避免虽然数据库日志截断但进程内报告缓冲继续无限增长。
- OpenCode stdout 改为独立读取线程和 Queue；主循环每 0.5 秒检查墙钟超时，因此静默进程不能再通过阻塞 `readline()` 绕过超时。
- 非 Web 任务超时会停止容器并终止 OpenCode 客户端进程；Web 任务保留服务容器，但终止超时的 OpenCode 客户端。
- socat 监听从所有网卡改为 `127.0.0.1`，正式访问需经过后续受认证反向代理。

验证结果：

```text
能力资源与安全专项：42 passed
覆盖资源参数、日志截断、workspace 超限、回环监听和静默进程超时
全仓测试：188 passed
```

剩余边界：

- workspace 周期扫描是软限制，不是文件系统 quota；任务在两个扫描周期之间可能短暂超限。
- sysbox 容器内启动的嵌套 Docker 容器仍需单独验证是否继承/绕过外层资源限制。
- 当前 Docker 命令仍使用宿主机全局 Docker daemon 和 API 内后台线程；独立 rootless Repro Worker 仍是下一阶段 P0。

### 2026-07-29：完成能力复现持久 Worker 第一批实现

- `capability_repro_tasks` 新增 `started_at`、`updated_at`、`worker_id`、`heartbeat_at`、`cancel_requested` 和 `cleanup_requested`，由第 4 版数据库迁移兼容已有 SQLite。
- 能力 API 与 `StartReproTasksStep` 只创建 `queued` 任务，不再持有请求级数据库连接启动 daemon 后台线程，也不直接执行 Docker 清理。
- 新增独立 `repro-worker` CLI 和单机 `flock` 文件锁；Worker 原子认领任务，并使用独立短连接写日志、心跳、状态和报告。
- 停止请求持久化：排队任务直接进入 `stopped`，运行任务设置 `cancel_requested`，Runner 在流式执行阶段终止进程和容器。
- 清理请求持久化：Worker 统一删除容器与 workspace；运行中清理先触发停止，再执行清理。
- Worker 启动对账遗留 `running` 任务。当前不会自动重放不确定是否产生外部副作用的任务，而是标记 `failed`、清理残留资源并由人工重新发起。
- 删除已无调用方的内存 `ReproManager` 及 Runner 异步 `start/stop/cleanup` 接口，数据库成为复现任务唯一状态真相源。
- 专项测试覆盖原子认领、持久停止、异常恢复、Worker 执行、异步清理和 API 只排队，不实际启动 Docker。

当前边界：

- 首期仍使用宿主机 Docker daemon 与 Sysbox Profile，尚未完成 rootless Docker 验收。
- 取消检查主要发生在 OpenCode 流式执行阶段；clone、容器启动和 dockerd 等待阶段的更细粒度取消仍需后续补齐。
- 单机部署必须同时托管 API、Pipeline Worker 和 Repro Worker；能力复现已有实际验收的 `v4` 镜像定义，API、Pipeline Worker、Repro Worker 和前端的正式镜像及 Compose 编排仍待后续实现。

### 2026-07-29：关闭复现镜像长期凭据回退

审计结论：

- 本机 `repro-runner:v3` 的 `/root/.local/share/opencode/auth.json` 确实存在，是 93 字节、权限 `0600` 的 root 文件；此前代码在未配置任务 Secret 时会读取其中 `alibaba-cn` 凭据。
- `v3` 顶层来自手工 commit，仓库中没有可信 Dockerfile，无法证明从镜像历史层删除认证数据。
- 当前仍有 `repro-5-1785207583` 和 `repro-6-1785211000` 两个 `v3` 容器运行。为避免中断现有 Web 复现，本次未强制停止或删除。

完成内容：

- 删除所有 `auth.json` 读取和 fallback；未配置 `REPRO_MODEL_TOKEN_FILE` 或 `REPRO_LLM_BASE_URL` 时 Repro Worker 启动预检失败，不领取任务。
- OpenCode `1.15.12` 官方支持 `{file:path}`，受管 provider 配置改为直接引用 `/run/secrets/repro_model_token`，不再把 token 复制到 `opencode.json`。
- 容器启动使用 `tmpfs` 覆盖 `/root/.local/share/opencode`，即使错误选择旧镜像，运行时认证目录也不可见。
- 新增镜像预检：Worker 会启动一次性检查容器，镜像不存在或 root/repro 用户目录含 OpenCode auth 文件时拒绝运行。
- 新增 `configs/repro-runner/Dockerfile`，固定 Ubuntu digest、Node、Docker、containerd 和 OpenCode 版本，不复制任何认证文件；默认镜像升级为 `repro-runner:v4`。
- 新增 `.env.example` 和 `repro-worker --check-config`，明确 Secret 文件必须同时对 Worker 和宿主机 Docker daemon 使用同一绝对路径可见。

实际验收：

```text
repro-runner:v4 image id: sha256:0acb4041177c879293f75e9a660c76c5cda884370a5252e957d2fad58844b8d4
OpenCode: 1.15.12
Node.js: 20.20.2
containerd: 2.2.6
Docker client/server: 29.6.2 / 29.6.2
Sysbox nested Docker: ready
root/repro auth.json: absent
tmpfs runtime auth hiding: verified
Python full test suite: 199 passed
```

仍需用户/运维完成：

1. 立即在原凭据提供方轮换 `v3` 镜像中的旧 token；代码无法替代凭据提供方执行吊销。
2. 将新 token 写入宿主机 `0600` Secret 文件，并配置 `REPRO_MODEL_TOKEN_FILE`、`REPRO_LLM_BASE_URL`、`REPRO_IMAGE=repro-runner:v4`。
3. 确认两个旧 Web 复现容器是否仍需保留；迁移或验收结束后停止容器，并删除 `repro-runner:v3`。

### 2026-07-29：关闭全开放 CORS

- 删除 `allow_origins=["*"]`、全方法和全请求头配置。
- 平台默认同源部署且不挂 CORS 中间件；FastAPI 正式前端和 Vite `/api` 开发代理均不需要跨域。
- 新增 `AI4SEC_CORS_ALLOWED_ORIGINS`，支持逗号分隔的可信 `http/https` Origin，并进行规范化、去重和严格校验。
- 禁止通配符、路径、查询、fragment、URL 用户名密码和 `file://`，非法配置直接阻止启动。
- 白名单开启时只允许 `GET`、`POST`、`OPTIONS` 与 `Accept`、`Content-Type`，并保留后续 Session Cookie 所需的 credentials 支持。
- `load_settings()` 统一加载项目 `.env`，按文件绝对路径幂等，且不覆盖部署环境已注入的变量；移除此前依赖模型模块导入顺序的偶然行为。
- 专项测试覆盖默认无 CORS、可信 Origin、非可信预检拒绝、非法配置和 `.env`/进程环境优先级。
- 全仓 Python 测试：210 passed。

### 2026-07-29：增加 SQLite 隔离写 readiness

- `/api/health/ready` 不再只执行 `SELECT 1`，新增真实 SQLite 写入能力验证。
- 探测使用 `SAVEPOINT readiness_write_probe` 向 `schema_migrations` 写入保留的负版本记录，随后 `ROLLBACK TO` 并校验不存在残留，不提交任何探测业务数据。
- 使用独立数据库连接，并将锁等待临时缩短为 `AI4SEC_READINESS_WRITE_TIMEOUT_MS`（默认 1000 ms）；探测后恢复原连接 busy timeout。
- 数据库写锁、只读文件、普通 SQLite 错误和迁移历史 RuntimeError 都返回 HTTP 503；响应只暴露 `database_locked`、`database_read_only`、`database_schema_error` 或 `database_error` 稳定错误码。
- 专项测试覆盖成功写入回滚、零残留、busy timeout 恢复和持有 `BEGIN IMMEDIATE` 写锁时的 503 降级。
- 全仓 Python 测试：212 passed。

### 2026-07-29：固定 Pipeline Step 事务边界

- 所有 Step 默认 `transaction_mode=atomic`，Runner 在 Step 前创建 `SAVEPOINT pipeline_step`，成功后释放并统一提交。
- atomic Step 获得受控 connection wrapper；调用 `commit()` 或 `rollback()` 会立即失败，防止业务代码绕过 Runner 提交半成品。
- atomic Step 失败时回滚本步骤全部数据库写入，并删除本步骤通过 ArtifactStore 新建但尚未提交的文件，避免数据库记录回滚后留下孤儿制品。
- 资讯模型门控/深评、漏洞逐条抓取/抽取/审核和漏洞批次编排显式声明 `checkpointed`，允许保留已提交的模型调用、逐条结果和批次进度；失败时回滚最后一个未提交尾部事务。
- 事务模式写入每个 Step 的 Run summary，并纳入 Pipeline checkpoint 输入 checksum；事务模式改变后旧 checkpoint 不可恢复。
- 新增回归测试覆盖 atomic 业务写回滚、违规 commit 阻断、失败 Artifact 清理，以及 checkpointed 已提交检查点保留/尾部回滚。
- 全仓 Python 测试：216 passed。

### 2026-07-29：增强 SQLite 备份、校验和恢复保护

- 继续使用 SQLite Online Backup API，不复制活动 `.db`/WAL 文件，允许 API 和 Worker 在线运行时生成一致性数据库备份。
- 每个备份原子生成 `.db.manifest.json`，记录 UTC 创建时间、源数据库文件名、文件大小、SHA-256 和 schema 版本；`verify` 与 `restore` 自动验证清单。
- 备份文件默认禁止覆盖，并在文件与清单落盘后执行 `fsync`；不支持目录 `fsync` 的文件系统按兼容模式降级。
- CLI 成功备份后执行 D10 已确认的分层保留：最近 7 天保留全部日备、之后 4 周每周一份、再之后 6 个月每月一份，且始终保留最新受管备份。
- 新增 `AI4SEC_BACKUP_DAILY_RETENTION_DAYS`、`AI4SEC_BACKUP_WEEKLY_RETENTION_WEEKS`、`AI4SEC_BACKUP_MONTHLY_RETENTION_MONTHS`，非法非正值回退到安全默认值。
- 恢复工具禁止直接覆盖当前 `AI4SEC_DATABASE_PATH`；只能先恢复到旁路文件并校验，停止所有服务后由运维执行离线切换。覆盖旁路文件时会清理其旧 WAL/SHM sidecar，防止旧日志帧污染恢复库。
- 仍未完成：Compose/宿主机每日调度、独立备份磁盘位置、Artifact 备份、实际部署环境首次计时恢复演练；因此 D10 的 RPO/RTO 目标尚不能仅凭代码视为验收通过。
- 数据库专项测试：21 passed；全仓 Python 测试：221 passed；CLI 实际备份、清单校验和旁路恢复通过。

### 2026-07-29：增加平台公共记录身份约束

- 新增 schema migration v5；升级旧库时先按最大 `id` 保留最新记录，再建立 `TaskRun(run_id, step_name)`、`Artifact(run_id, path)` 和 `DataSource(domain, name)` 唯一索引。
- `create_task_run`、`create_artifact` 和 `create_data_source` 改为基于上述身份的 upsert，重复执行同一平台写入时更新当前状态，不再无限追加重复记录。
- 增加 PipelineRun 域/状态查询、QualityAudit 域类型查询和 HumanQueue 状态优先级查询索引；没有给 QualityAudit 增加错误唯一键，因为当前表尚缺显式 `run_id`。
- v5 不使用 `executescript`，确保去重、索引创建和迁移历史写入仍位于同一个 `BEGIN IMMEDIATE` 事务；旧库升级失败可以整体回滚。
- 回归覆盖旧重复数据迁移、唯一约束生效和 Repository 重复写更新；四域领域对象的幂等键仍需逐模块依据 CVE、canonical key、repo 身份等业务语义设计。
- 数据库专项测试：23 passed；全仓 Python 测试：223 passed。

### 2026-07-29：实现 Pipeline Worker 注册和任务租约

- 新增 migration v6：`pipeline_workers` 持久记录 Worker 的 hostname、PID、启动/心跳/停止时间、当前 Run 和状态；`pipeline_jobs` 新增 `lease_expires_at` 及失联扫描索引。
- Worker 在持有单机文件锁后注册，空闲时续 Worker heartbeat，执行任务时同时续 Worker heartbeat 和 Job 租约，正常退出记录 `stopped`。
- Job 领取写入租约截止时间；只有持有相同 `worker_id` 的 Worker 才能续租和完成任务，避免旧 Worker 在租约所有权丢失后覆盖新状态。
- 恢复逻辑不再把所有 `running` 任务立即判失败，只处理租约已经过期的任务，并将对应 Worker 标记为 `lost`；未过期任务保持运行状态。
- v6 会把升级时遗留且没有租约的 `running` Job 按最后 heartbeat/更新时间回填为已到期候选，避免历史中断任务永久卡住。
- 默认 heartbeat 10 秒、租约 45 秒，配置强制租约不少于三个 heartbeat 周期；回归覆盖活租约不误杀、过期恢复、非 Owner 续租失败和 Worker 正常停止登记。
- Worker/数据库定向测试：36 passed；全仓 Python 测试：226 passed。

### 2026-07-29：实现默认禁用的统一 Scheduler

- 新增 `configs/schedules.yaml` 和独立 Scheduler CLI；Scheduler 只向 `pipeline_jobs` 入队，不执行 Pipeline，执行仍由单 Pipeline Worker 串行负责。
- 时区固定使用 `Asia/Shanghai`；计划支持每日时刻、可选周几、参数、reset 标记和 `grace_minutes` 单次补跑窗口。
- 每个时隙的 Run ID 由计划 ID 哈希和北京时间时隙确定；重启或重复 tick 会识别既有 Run，避免重复入队和重复模型调用。
- 同 Pipeline 已有 queued/running Job 时，Scheduler 返回 `blocked` 并在宽限窗口内重试；超过窗口不会无限补跑。
- Scheduler 使用独立单机文件锁；默认配置没有任何 enabled 计划，避免在资讯/漏洞/威胁真实日更验收前擅自触发采集。
- Scheduler 专项测试：5 passed；全仓 Python 测试：231 passed；默认空配置 CLI `--once` 实测返回 `[]`。

### 2026-07-29：统一 Pipeline partial 和 timeout 状态

- `StepResult` 新增显式 `status` 与 `message`；模块只有明确返回 `partial` 时平台才传播部分成功，不根据错误数量或产出数量擅自推断。
- Step 抛出 `TimeoutError` 时 Runner 将 TaskRun 和 PipelineRun 标记为 `timeout`，普通异常仍标记为 `failed`。
- Pipeline Worker 将 `partial`、`timeout` 作为正式 Job 终态保存，不再折叠成 `failed`；超时 Run 可以进入现有受控 checkpoint 重试入口。
- `partial` Step 可以继续执行后续 Step，最终 Run 保持 `partial`；任何后续失败、超时或取消会按更强终态覆盖。
- 当前只统一“已发生超时”的状态表达，不使用 Python daemon Thread 强制终止任意 Step；外部 HTTP、模型、浏览器和子进程仍须各自在可中断边界实现真实 deadline/kill。
- 回归覆盖 Run、TaskRun、PipelineJob 三层 partial/timeout 一致性。
- 状态传播定向测试：24 passed；全仓 Python 测试：233 passed。

### 2026-07-29：删除 API 同步执行 Worker 入口

- 删除 `/api/runs` 请求模型中的 `wait` 字段和请求进程内 `PipelineWorker.run_once()` 分支；API 现在只验证 Pipeline、持久化 queued Job 并返回轮询 URL。
- Run 与 retry 请求模型禁止额外字段；旧客户端继续发送 `wait=true/false` 会得到 HTTP 422，而不是被静默忽略或意外同步执行。
- retry API 仍只创建新的 queued 恢复任务，不在 API 进程执行 checkpoint 恢复。
- 前端本来就使用异步提交，无需兼容改动；旧 API 业务测试改为“API 入队 → 显式测试 Worker 领取 → API 查询结果”，与生产架构一致。
- 保留 Pipeline CLI 和 Worker `--once` 作为本地同步调试方式，不把开发便利入口重新放回 HTTP API。
- 异步 API/业务定向测试：29 passed；全仓 Python 测试：234 passed。

### 2026-07-29：增加持久平台 kill switch

- 新增 migration v7 和 `platform_controls`；kill switch 状态、原因和更新时间持久化，API、Worker、Scheduler 重启后仍保持停止状态。
- 新增本机 `pipeline-control status/stop/resume` CLI；未将高风险操作暴露到当前未完成认证/RBAC 的 HTTP API。
- `stop` 原子取消 queued Pipeline Job、向 running Job 写入取消请求、停止 queued 复现任务并向 running 复现任务写入取消请求；新 Pipeline API 返回 503，Scheduler 返回 `disabled`。
- Pipeline Worker 在 Step 边界读取全局开关；能力复现 Runner 在运行循环内读取全局开关，并沿用已有 `docker stop`、端口代理停止和宿主进程 `terminate` 强制回收路径。
- `resume` 只重新开放任务领取，不自动重放被取消任务；需要运营人员依据 checkpoint 和业务重跑语义显式重试。
- 普通 Pipeline 当前没有直接 `Popen` 子进程，主要长资源是 crawl4ai 浏览器和线程池；Python 无法安全强杀运行中线程，因此仍须完善 Connector deadline、浏览器 context 关闭和可取消批次提交，不能声称所有 Step 已即时强停。
- kill switch/Worker/Scheduler/Repro/数据库定向测试：54 passed；全仓 Python 测试：238 passed；CLI status/stop/resume 实测通过。

### 2026-07-29：让 crawl4ai 批处理响应 Pipeline 取消

- `PipelineContext` 新增统一 `should_cancel` 回调，Runner 将 Job 取消和平台 kill switch 信号注入 Step，不要求业务 Step 自行访问任务表。
- 公共 `bounded_map` 改为最多只维持 `max_workers` 个在途 Future，不再一次性提交全部输入；取消后停止补充新任务并取消尚未开始的 Future。
- `bounded_map` 保持已完成结果的输入顺序，并提供 completion callback，供 Connector 在每项完成后持久化进度。
- crawl4ai Connector 接入取消回调；每个 URL 完成后写入现有进度 checkpoint，取消后不再抓取剩余 URL，并在 metadata 记录 `cancelled` 和 `unsubmitted`。
- 已经运行的 Python 线程不会被强杀，最多等待当前并发槽位按 URL timeout 和 crawl4ai context manager 正常关闭；这是为避免浏览器、SQLite 和文件状态损坏的明确安全边界。
- 回归覆盖 Step Context 取消信号和 crawl 并发停止提交；取消/抓取/Worker 定向测试：36 passed；全仓 Python 测试：240 passed。

### 2026-07-29：阻止陈旧检查点跨步骤重放

- 审计发现旧检查点可能仍指向较早的安全 Step，而实际 Run 已在更晚的不安全 Step 失败；原重试入口只检查检查点声明的 `resume_safe`，存在重放中间模型调用或外部副作用的风险。
- Runner 与 retry API 现在共用检查点位置校验：失败或超时 Run 的检查点必须紧邻实际失败 Step；取消 Run 的检查点必须紧邻第一个未完成 Step，历史更早的检查点一律拒绝。
- Runner 将 `timeout` 纳入可恢复终态，但仍要求输入 checksum、Step 顺序、实现契约、Artifact checksum 和实际 Step 白名单全部通过。
- 首个生产恢复白名单仅开放 `SelectVulnerabilityKnowledgeCandidatesStep`；该步骤是原子事务内的确定性数据库选择，只恢复 `vulnerability_material_ids`。抓取、模型调用、事件聚合和复杂写入步骤暂不开放自动恢复。
- 新增 Runner 与 API 两层陈旧检查点回归，确认更晚的不安全 Step 不会因旧检查点而被再次调用。
- 恢复相关聚焦测试：38 passed；全仓 Python 测试：242 passed；`compileall` 通过。

### 2026-07-29：固定 SQLite 文件权限契约

- 每次数据库连接前创建并收紧数据库父目录为 `0750`；SQLite 建库并启用 WAL 后收紧数据库以及当时已存在的 WAL/SHM 文件为 `0640`。
- 权限收紧失败不再带着不确定的共享权限继续运行，而是关闭连接并抛出明确启动错误。
- `.env.example` 增加生产绝对路径示例，明确核心 Compose 服务必须共享同一非 root UID/GID，活动 WAL 数据库必须位于本机 Linux 文件系统，禁止放在 NFS。
- 当前完成的是应用层权限契约；仓库尚无核心平台 Dockerfile/Compose 清单，因此宿主持久目录创建、卷挂载和容器 UID/GID 固定仍保留为部署阶段任务，不能提前标记整项完成。
- 数据库专项测试：25 passed；全仓 Python 测试：244 passed；`compileall` 与 `git diff --check` 通过。

### 2026-07-29：同步能力洞察最终业务实现

- 发现能力洞察最终提交此前未进入 master；新 master 合并提交 `e4ebd95` 包含完整能力前端、运营页、评估字段、复现报告验收和 Runner 业务增强。
- 未直接 merge 或覆盖生产分支。同步策略是接收最终业务实现，同时保留现有持久 Repro Worker、任务对账、kill switch、Secret 文件、镜像认证检查、日志脱敏、资源上限和 `127.0.0.1` 端口边界。
- 接入能力首页、能力库、复现工作台、能力转化和运营页面；保持平台原默认首页与全局状态文案，不接收旧分支生成的 dist，而是在当前生产分支重新构建前端。
- 能力 API 新增 stats、运营概览、复现失败和缺失字段端点；start、stop、cleanup 仍只操作持久任务状态，不允许 API 请求线程直接创建、停止或删除容器。
- 能力评估补齐 overview、安全价值、复现评估、代码质量、应用建议和评分理由；仍保留单批默认 100 条上限，拒绝最终分支中默认 100000 条的不受控执行规模。
- Web 复现 success 必须具备真实核心业务闭环、实测步骤、证据和结果；首页 200、mock 或缺少证据会降级为 partial/failed。退出码 0 但没有结构化报告不再判 success。
- 新增 10 分钟可配置报告收尾窗口、GitHub codeload archive fallback、非法模型评分降级和 `partial` 可重试但不可进入能力转化的语义。
- 能力最终分支的报告验收测试与生产分支的 Worker/Secret/资源/取消测试合并；能力/API 聚焦测试 76 passed，前端生产构建通过，全仓 Python 测试 255 passed。
- 前端将 Vite 从 `5.4.11` 补丁升级到 `5.4.21` 并重新构建；`npm audit` 仍报告开发服务器相关的 1 个 moderate 和 1 个 high 风险，自动修复会跨到 Vite 8。生产只发布静态构建产物，当前不使用 `--force` 跨主版本，后续以独立依赖升级批次处理。

### 2026-07-30：自动化 SQLite WAL 与完整性维护

- 新增 migration v8 和 `database_maintenance_runs`，记录维护状态、checkpoint/integrity 模式、锁等待、阶段耗时、WAL 前后大小和执行时间。
- SQLite 连接显式配置 `wal_autocheckpoint`，默认每 1000 WAL 页触发 passive checkpoint，可通过环境变量调整，不再依赖 SQLite 隐式默认值。
- `database maintain` one-shot CLI 依次执行单机互斥、写锁等待采样、quick/full integrity 和 passive/full/restart/truncate checkpoint；success/partial/failed 分别返回退出码 0/2/1。
- 维护任务不执行迁移，避免在持锁期间绕过维护超时；迁移仍由正常服务启动和 `init_db` 流程负责。
- 成功和可记录失败进入历史表；数据库被锁或不可写时仍生成本地 JSON 报告。报告目录权限为 `0750`、文件为 `0640`，历史默认保留 30 天。
- readiness 增加维护次数、失败数、锁等待累计值/峰值和最近状态，后续监控系统可直接采集；维护 CLI 不暴露到当前未认证 HTTP API。
- 数据库专项测试 30 passed；CLI 临时数据库实测成功；全仓 Python 测试 260 passed；`compileall` 与 `git diff --check` 通过。

### 2026-07-30：威胁连接器 TLS 策略显式化

- 威胁在线 JSON 和正文连接器显式创建默认 `SSLContext`，不依赖调用方或 urllib 的隐式行为，不允许通过连接器关闭证书校验。
- 增加 `AI4SEC_THREAT_CA_BUNDLE` 受控 PEM CA 配置入口，仅用于部署环境的额外信任根；路径无效时明确失败，不降级为跳过验证。
- 覆盖默认系统信任根和非法 CA 配置测试；威胁安全专项测试 17 passed。

### 2026-07-30：漏洞抓取统一 URL 安全策略

- 新增公共 `PublicUrlPolicy`，统一校验 HTTP(S) 协议、禁止 URL 用户名/密码、执行域名 allowlist/blocklist，并阻断 localhost 和全部非公网 IPv4/IPv6。
- 漏洞抓取在发起请求前解析目标域名；任一 DNS 结果指向回环、私网、链路本地、保留地址或云 metadata 地址即拒绝，DNS 解析失败也不继续抓取。
- urllib fallback 使用自定义 Redirect Handler，对每一跳重定向目标重新执行 DNS 与公网地址校验；crawl4ai 浏览器路径校验入口和最终 URL。
- 应用层校验无法完全消除 DNS 查询与实际连接之间的重绑定竞态，生产 Compose 仍必须阻断平台管理网、Docker 网桥、宿主机和云 metadata 的网络出口。
- SSRF 与漏洞抓取聚焦测试 26 passed。

### 2026-07-30：资讯 legacy raw 正式退场

- 删除 `news.legacy_raw_pipeline` 定义及 Registry、API 默认值、普通 Pipeline CLI 默认值和 `configs/pipelines.yaml` 注册，旧名称经 HTTP 提交返回 404。
- 新增 `import_news_legacy_raw` 一次性迁移 CLI，必须显式提供源目录、日期和确认参数；不允许重置资讯域，通过单机文件锁防止并发导入，同一日期与文件内容 checksum 成功后禁止重复导入。
- 历史文件读取物理隔离到 `domains/news/migrations.py`，删除旧 `adapters/ai_for_sec_raw.py`；迁移源绝对路径不写入可查询 Run 参数。
- arXiv、GitHub、RSS、X、ASIS 和 Awesome 在线连接器不再继承 `JsonFileConnector`，正式 source adapter 不再接受 `legacy_raw`/`fixture` 模式。
- RSS 在本批次先停止回退旧系统 `state_rss.json`；后续 migration v10 已进一步删除平台 JSON 状态文件并迁移到 SQLite 水位线。
- 资讯迁移、API、架构、在线连接器和资讯模块聚焦测试 39 passed；全仓 Python 测试 267 passed，`compileall` 与 `git diff --check` 通过。

### 2026-07-30：X 数据源正式禁用

- 当前环境不存在 `GETXAPI_KEY`，原 GetXAPI 方案此前存在不可用/额度类失败风险；继续启用会让每次资讯日更产生确定性失败，因此 `configs/news.yaml` 将 X 显式设为 disabled 并记录中文原因。
- 禁用源仍作为六源之一写入数据源状态，但不发起网络请求、不计入来源失败；在全新数据库尚无运行记录时，运营 API 也会从配置返回 disabled 状态和原因。
- 资讯运营页显示“已禁用”和具体原因，禁用重跑按钮；按单源重跑 X 也只刷新 disabled 状态，不会绕过配置访问网络。
- X 连接器健康检查区分 disabled、missing 和 configured；configured 仅表示凭据存在，重新启用前仍需补充真实连通性、认证、额度和最近成功时间探测。
- 重新启用门槛：确定替换 Provider，完成真实健康探测、分页/限流/402 类错误分类、增量 ID 状态和至少一个完整日更样本验收。
- X/资讯聚焦测试通过；全仓 Python 测试 272 passed，前端生产构建、`compileall` 与 `git diff --check` 通过。前端构建仍有既有的动态/静态 import 和大 chunk 警告，本次未扩大依赖升级范围。

### 2026-07-30：资讯真实数据源健康探测

- 新增 `news_health` 独立 CLI，默认对六源执行最小真实请求；禁用源只返回 disabled，不发起网络请求。
- 探测结果写入 `data_sources`，记录健康状态、消息、检查时间、延迟、返回条数和原始错误；不把探测入口暴露到未认证 HTTP API。
- 统一分类 `auth_failed`、`quota_exhausted`、`rate_limited`、`upstream_failed`、`timeout` 和 `unhealthy`，避免 HTTP 402/401 等错误被显示为健康。
- arXiv/GitHub/RSS/Awesome 使用最小探测请求；ASIS 探测沿用登录与最小数据请求并遵守 CLI timeout；X 维持 disabled 语义。
- 新增 migration v9 `source_health_checks` 独立历史表，避免日常 Pipeline 覆盖健康证据；每次探测滚动计算最近成功时间和连续失败次数，成功后清零，disabled 不计失败。
- 运营接口按时间叠加最新健康记录，保留原采集摘要；页面展示最近探测、最近成功、连续失败和探测延迟。
- 健康探测专项测试覆盖禁用持久化、成功探测、错误分类、连续失败累加和成功清零；额度具体剩余量仍取决于替换 Provider 是否提供可读取的 quota 字段。
- 数据库/健康/资讯聚焦测试 51 passed；全仓 Python 测试 273 passed，前端生产构建、`compileall` 与 `git diff --check` 通过。

### 2026-07-30：RSS 与 ASIS 正式增量水位线

- 新增 migration v10 `source_incremental_states`，按 `domain + source + state_key` 唯一保存连接器当前水位线；当前资讯域使用 `default` 状态键。
- RSS 删除本地 `output/source_state/rss.json` 读写，只接收 Pipeline 注入的 `incremental_state.scanned_ids`；ASIS 同样按稳定来源 ID 过滤已扫描条目，低于评分阈值的有效条目也会标记为已扫描，避免每日重复扫描。
- `CollectNewsSourcesStep` 在步骤开始时读取全部资讯来源状态，在连接器无错误时 upsert 下一状态；水位线、采集 Artifact 和步骤状态受同一 savepoint 保护，步骤失败会共同回滚。
- 连接器出现任一错误时不推进该来源水位线，防止部分分页失败造成漏采；独立健康探测不持久化连接器返回的下一状态，因此不会消耗正式日更数据。
- 每个来源默认最多保留 20,000 个已扫描 ID，可通过连接器 `state_max_ids` 调整但下限为 100，避免状态无限增长。
- 普通 `reset_domain(news)` 有意保留增量水位线，避免运维重置导致历史数据和模型调用大规模回放；确需全量重采时必须先备份，再显式删除目标来源状态，不能把该行为混入日常 reset。
- X 继续保持 disabled；未来替换 Provider 除真实健康、认证和额度验收外，还必须返回同一 `next_incremental_state` 契约。
- RSS/ASIS/数据库增量专项测试 50 passed；全仓 Python 测试 276 passed，`compileall` 与 `git diff --check` 通过。

### 2026-07-30：资讯、日报与模型调用幂等

- 复核确认资讯条目已有 `news_item_index.canonical_key` 主键和跨运行 update 语义；同一论文或项目再次出现时更新原 `domain_items`，不创建重复资讯。
- 同日日报继续使用 `report_date` 主键，并在 metrics 中保存当日完整条目 ID 快照；生成前先合并既有日报条目和本次增量条目，水位线导致重跑无新数据时不会再把已有日报覆盖为空或丢失未进入 Top N 的低排名条目。
- 新增 migration v11，为 `model_calls` 增加 `request_key`、`prompt_version` 和 `attempt_no`；请求键由 agent、model profile、prompt 版本和规范化业务输入共同生成。
- 对非空 `request_key` 建立成功记录部分唯一索引。同一成功请求跨 PipelineRun 只保存和复用一份结果；失败及 retryable failure 仍按 attempt 保留，且不阻止人工或自动重跑。
- 门控和深度评审缓存改为按稳定请求键查询，不再依赖未绑定 prompt 版本的原始 `input_json` 字符串比较；prompt 版本或模型身份变化会自然失效旧缓存。
- 删除仅被单元测试调用的旧 `_call_model` 串行入口，重试与模型调用审计测试改为覆盖正式 `_call_model_api + _record_attempts` 路径，避免继续维护历史兼容实现。
- 聚焦测试覆盖请求键字段顺序稳定性、prompt 版本隔离、成功调用唯一约束、资讯跨运行 upsert 和同日日报空重跑保留；资讯/数据库聚焦测试 51 passed，全仓 Python 测试 279 passed，`compileall` 与 `git diff --check` 通过。

### 2026-07-30：资讯分阶段失败重跑

- 不为资讯模块另造任务队列，复用平台持久 `pipeline_jobs`、checkpoint 校验、恢复参数 checksum 和单机 Worker；资讯模块只声明各步骤恢复所需的业务输出。
- 在线来源返回错误时采集步骤标记为 `partial`，成功来源仍进入后续流程；失败来源不推进 SQLite 水位线。历史一次性迁移的允许缺源提示不改变为在线采集失败语义。
- 新增单源重跑 API。它从最近来源记录关联原 PipelineRun，继承原 `date`、模型 profile、评审限额等参数，移除 reset/resume 控制参数后只设置目标 `sources`，避免补跑进入错误日报日期。
- 技术地图门控或深度评审在内置瞬时错误重试耗尽后，不再把失败候选静默当作 reject 并继续发布，而是让当前 checkpointed 步骤失败。步骤已提交的成功模型调用保留，恢复时按稳定 `request_key` 命中缓存，仅失败候选重新调用。
- Extract、Normalize、Dedupe、Resolve、Gate、Deep Review、Build、Daily Report 和 Audit 均声明 `resume_safe` 与最小 `resume_input_keys`。日报恢复同时携带 `news_item_ids` 和 `news_items`，保证恢复后质量审计仍使用原业务输入。
- 日报及后续原子步骤抛出异常时由 Runner 回滚未完成写入，并从前一步校验过的 checkpoint 恢复；成功运行不允许任意阶段重跑，禁用来源也拒绝单源重跑。
- 资讯运行详情返回 `retry.allowed/stage/mode`；前端只在存在可恢复 checkpoint 时展示“从失败阶段重跑”，来源页继续提供独立的来源补跑入口。
- 专项测试使用真实 `PipelineRunner` 验证两个候选中一个成功、一个连续失败后，恢复运行只再次调用失败候选；同时覆盖恢复契约、来源 partial、来源参数继承和资讯运行详情 API。聚焦测试 44 passed，全仓 Python 测试 284 passed，前端生产构建、`compileall` 与 `git diff --check` 通过。前端仍有既有动态/静态 import 和大 chunk 警告，本批次未扩大依赖或拆包范围。

### 2026-07-30：模型 Schema 降级与人工复核

- 门控严格校验完整字段、decision 枚举、0–100 分值、0–1 置信度、证据列表和技术地图路径；深评严格校验七个固定评分字段、合法非空路径、内容字段和置信度。
- 模型 HTTP 调用成功但 Schema 不合格时，将最后一次调用改记为 `schema_invalid`，不进入成功唯一缓存。候选生成明确规则降级结果用于人工理解，但当前模型步骤失败，因此降级内容不会直接进入正式资讯和日报。
- gate prompt 升级为 v2，deep review prompt 升级为 v4；缓存读取也再次执行 Schema 校验，历史宽松“成功”结果不能绕过新规则。
- 新增 migration v12，为公共 `human_queue_items` 增加 `dedupe_key` 和 pending 部分唯一索引。同一模型请求反复结构失败只更新一条待办，不持续制造重复队列。
- 队列记录阶段、item key、标题、URL、原 Run、prompt 版本、Schema 错误和降级结果。模型恢复后返回合格结果时自动将 pending 项标记为 resolved。
- 人工可以选择重试失败 Run，或将候选标记 rejected。checkpoint 恢复时 rejected 请求不再调用模型并按业务拒绝处理，使坏样本不会永久阻塞整个日更；队列支持 reopen API 以便重新评估。
- 修复平台重复恢复缺口：从 checkpoint 创建的新 Run 会立即复制一份经过校验的恢复点；如果同一阶段再次失败，仍可以从新 Run 继续恢复，而不是丢失重跑入口。
- 补充资讯专用本地规则门控和深评实现，离线/测试模式输出与真实 Provider 相同的正式 Schema，不再依赖宽松 fallback 掩盖缺字段。
- 运营质量接口和运行详情展示 `schema_invalid` 数量及待处理队列，前端提供“重试模型阶段”和“忽略该候选”操作。
- 聚焦测试覆盖严格校验、Schema 异常调用状态、队列去重、重复 checkpoint 恢复、人工忽略后零模型调用完成恢复，以及队列查询/操作 API；聚焦测试 89 passed，全仓 Python 测试 287 passed，前端生产构建、`compileall` 与 `git diff --check` 通过。前端仍有既有动态/静态 import 和大 chunk 警告，本批次未扩大拆包范围。

### 2026-07-31：资讯连接器分页与统一重试

- 启用的在线资讯连接器统一读取采集级重试配置，默认最多三次尝试，使用指数退避、随机抖动和最大等待上限；HTTP `429`、`5xx`、网络超时和连接错误可重试，认证及请求参数类 `4xx` 不重试。
- HTTP `429/503` 的数字型 `Retry-After` 会优先于指数退避，并受全局最大等待时间约束，避免服务端限流时立即重试或无限阻塞 Worker。
- arXiv 查询 API 增加 `start/max_results` 有界分页，ASIS 增加 `limit/offset` 有界分页；GitHub 和 WeRSS 保留既有分页并接入统一重试，Awesome 明确采用最多四个近期研究子页的业务有界遍历而非伪造 API 分页。
- ASIS 后续页失败时保留已采集条目并返回来源错误，使采集步骤进入 `partial`；由于失败来源不提交 `next_incremental_state`，下次补跑不会跳过未完成页面。
- X 没有恢复历史 GetXAPI 兼容代码，继续以明确原因显示禁用；未来替换 Provider 必须重新完成认证、额度、分页、来源 ID 水位线和真实样本质量验收。
- 新增专项测试覆盖瞬时超时恢复、`Retry-After` 上限、认证失败不重试、显式关闭抖动、arXiv/GitHub/ASIS 分页、arXiv/ASIS 部分页失败；与既有 WeRSS、Awesome、增量状态和禁用 X 测试合并运行共 36 passed。
- 本批次完成的是连接器代码契约和离线回归，不替代真实来源验收；资讯聚焦测试 36 passed，全仓 Python 测试 296 passed，`compileall` 与 `git diff --check` 通过。3A 仍需在凭据和依赖服务齐备后连续运行三个真实日更周期，并记录各源采集量、重复率、失败率和最终入选质量。

### 2026-07-31：资讯连续三周期验收工具与首次前置检查

- 新增 `news-acceptance` CLI 和资讯域验收聚合器，可默认读取最近最多九个日更 Run，也可显式传入 Run ID；报告同时输出 JSON 和 Markdown 到 `output/acceptance/news/`。
- 合格周期严格要求：`news.daily_pipeline` 最终成功、所有启用源记录齐全且无错误、日报成功、门控和深评实际执行、Schema/模型无失败、ModelCall 使用真实 Provider。`local_rules` 运行仅可用于开发回归，不能计入生产验收。
- 合格周期按 `summary.params.date` 的业务日期去重；同日失败重跑不会虚增周期数量，默认扩大历史 Run 查询窗口以保留更早的不同日期。
- 报告聚合来源采集量、来源失败、标准化数量、重复率、最终入选率、Schema 通过率、模型 Provider、模型调用状态和人工队列处置数量。人工内容纠错率仍需运营人员抽样并形成业务记录，当前不以队列状态冒充纠错率。
- 已执行首次真实健康探针：arXiv、GitHub、WeRSS、Awesome 健康，X 按既定决策禁用；ASIS 缺少 `ASIS_USERNAME` 和 `ASIS_PASSWORD`。健康检查提示已与实际采集规则统一，配置文件已有 Base URL 时不再错误提示缺少 `ASIS_BASE_URL`。
- 当前仓库和进程环境没有配置真实模型 Provider，因此 `news-acceptance` 正确返回 `ready_to_start_cycle=false`、`remaining_cycles=3`。在 ASIS 凭据和 GLM OpenAI-compatible 环境变量配置完成前，不启动完整日更，避免生成不能计入验收的本地规则数据。
- 回归覆盖三个不同日期通过、同日补跑去重、较旧有效日期保留、显式 Run 缺失、来源失败和 `local_rules` 拒绝；资讯聚焦测试 42 passed，全仓 Python 测试 302 passed，`compileall`、`git diff --check` 和本次变更文件敏感信息扫描通过。

### 2026-07-31：资讯第一个真实日更周期与生产缺陷修复

- 本地密钥没有复制到 Windows 挂载盘的普通文件，而是迁移到 WSL `0600` 受限文件并由仓库中被 Git 忽略的 `.env` 符号链接加载；真实 DashScope `glm-5.2` 最小 JSON 请求和 ASIS 登录探针均成功，六源状态为五个启用源健康、X 按决策禁用。
- 首次全量尝试暴露 WeRSS 无界分页：`max_pages=0` 会遍历全部历史并逐篇加载完整正文，进程增长到约 13GB 后被 OOM Killer 终止。正式配置改为最多 10 页、每篇正文最多 100,000 字符；连接器遇到整页来源 ID 均已扫描时立即停止。
- WeRSS 修复后真实单源验证采集 10 页、300 条、正文约 2465 万字符，峰值 RSS 约 145MB。完整日更后续实测峰值约 4GB，主要来自 3200 条规范化数据及多个 checkpoint 上下文副本，后续仍可继续优化 Artifact/上下文体积，但已不再无界增长。
- 长采集 Step 原先在网络请求前打开 SQLite SAVEPOINT，Worker heartbeat 写入后导致读事务升级失败并报 `database is locked`。采集现声明为 `checkpointed`，网络期间不持有原子事务；来源记录、水位线和 Artifact 在采集完成后统一提交。
- 资讯规范化原子事务实测约 53 秒，会临时阻塞 SQLite heartbeat。默认 Job 租约从 45 秒提高到 300 秒，heartbeat 遇到临时 `database is locked` 时继续下一轮，不再永久退出线程。
- arXiv/GitHub 多请求采集元数据原先返回 list，持久化层按 mapping 展开而失败。Adapter 现统一返回 `request_count/requests` 对象，持久化层同时防御历史 list 元数据。
- GitHub 旧配置每天执行约 120 个搜索请求，单页模式仍耗时约 25 分钟。新增确定性 `daily` 轮换 Profile：每天轮换 18 个基础查询、3 个 creation 查询和 2 个 high-star 查询，共约 41 次请求，连续三天覆盖完整基础查询集合；`full_legacy` 保留全量深扫能力。
- `news.daily_pipeline` 默认应用 `daily` Profile、每查询 1 页/30 条、论文和项目各评审 20 条，避免普通 CLI 或调度任务意外触发全量深分页和全部候选模型调用。
- 首次深评在 45 秒超时下失败；真实返回还包含 reasoning/代码块包裹 JSON 和空 final content。模型超时调整为 180 秒、输出上限调整为 8192，并补充从 reasoning/Markdown 包裹中提取最大合法 JSON 对象的确定性解析。
- 最终恢复链 `run_20260731073453_fa194cb9d9 → run_20260731075643_e6773c7d12 → run_20260731080354_ac04d4bc9c` 成功完成。验收工具现沿 checkpoint 父链聚合来源 Artifact、模型调用和人工队列，失败尝试不会冒充额外周期。
- 第 1 个合格周期指标：arXiv 1678、GitHub 843、WeRSS 300、ASIS 100、Awesome 5，共采集 2926 条；引用/规范化 3200 条，去重后 2807 条，重复率 12.28%；门控 40 条，通过 4、待观察 1；深评 5 条，selected 4、watch 1；Schema 通过率 100%，最终 4 条入库并生成日报，质量审计得分 1.0。
- 当前验收状态为 `in_progress`，合格业务日期 `1/3`，`ready_to_start_cycle=true`。前面因 OOM、租约、元数据和模型输出失败的 Run 保留审计，但不计入合格周期。
- 新增回归覆盖 WeRSS 已扫描整页早停、正文上限、日更查询轮换、日更默认边界、多请求元数据、采集事务模式、heartbeat 锁恢复、恢复链验收聚合和 reasoning 包裹 JSON；全仓 Python 测试 310 passed，`compileall` 与 `git diff --check` 通过。

### 2026-07-31：能力复现状态机与启动对账

- 明确定义能力复现任务状态集合 `queued/running/success/partial/failed/timeout/stopped/cleaned` 及合法转换；重复写入当前状态保持幂等，跳过运行态直接成功、终态回到运行态和未知状态均被拒绝。
- Worker 的 Runner 回调、异常收尾和资源清理统一经过状态转换契约，不再通过通用字段更新任意改写状态；Runner 崩溃仍可靠收尾为 `failed` 并清空 Worker 与 heartbeat 占用。
- Worker 启动时对所有遗留 `running` 任务执行报告、容器和任务三方对账。日志中已有通过正式验收规则的结构化报告时，恢复为报告对应的 `success` 或 `partial` 并回写能力卡；没有合格报告时安全标记 `failed`，不自动重放可能产生副作用的复现任务。
- 启动对账会通过 Docker inspect 区分仍存活的孤儿容器与已消失容器，并将两者都纳入持久清理队列；恢复策略明确选择“安全失败、人工重试”，因为 Worker 重启后无法可靠重新附着原 OpenCode 子进程及完整 stdout，盲目续接会造成双重执行。
- SSE 日志流改为绑定本次 API 请求实际使用的 SQLite 数据库，而不是在生成器内重新加载默认配置；终态任务会依次发送历史日志、status 和 end，损坏的历史 `report_json` 降级为 `null`，不再中断整个流。
- 新增状态非法转换、完整报告恢复、停止 API、清理 API、终态 SSE 和错误报告 JSON 回归；能力专项测试 69 passed，全仓 Python 测试 314 passed，`compileall` 与 `git diff --check` 通过。

### 2026-07-31：能力复现资源、队列与重试配额

- 将能力复现配额集中为正式策略：单机 Worker 固定单并发、全局最多 20 个排队任务、同一能力条目 24 小时最多尝试 3 次、自动重试固定为 0。自动重试暂不开放，因为任意项目安装和运行可能产生外部副作用，当前只允许用户在查看失败证据后显式重试。
- API 手动启动和能力 Pipeline 自动启动统一使用 SQLite 单条条件插入，同时检查同条目活跃任务、全局队列深度和 24 小时尝试次数；并发请求不能通过“先查询、后插入”的竞态绕过配额。
- 超限响应区分 `item_active`、`queue_full` 和 `item_attempt_limit`。条目已有任务时返回 HTTP 409，队列或尝试次数超限返回 HTTP 429；自动 Pipeline 不因此中断整批任务，而是将拒绝条目及原因写入 Artifact 和指标。
- Repro Worker 继续通过单机排他文件锁确保实际并发为 1；配置若把 `REPRO_MAX_CONCURRENT_TASKS` 改为其他值会在启动校验阶段失败，不制造名义配额与实际执行模型不一致的假象。
- 运行时校验 CPU、内存、swap、PIDs、普通/Web 墙钟超时、报告宽限、workspace 和日志上限的格式及安全范围；错误配置在任务启动前失败，不交给 Docker 静默解释。
- `.env.example` 已完整声明上述资源和队列参数；新增只读 `/api/capabilities/repro-limits`，返回当前队列使用量、重试/并发策略及容器资源上限，供运营页面和部署验收读取。
- 新增资源非法值、配额查询、全局队列满和条目尝试次数超限回归；能力专项测试 74 passed，全仓 Python 测试 319 passed，`compileall` 与 `git diff --check` 通过。workspace 仍是周期扫描软上限，Sysbox 嵌套 Docker 的资源继承与硬 quota 继续由后续双 Profile 隔离任务处理。

### 2026-07-31：独立 Repro Worker 服务接入

- 新增 migration v13 `capability_repro_workers`，独立保存 Worker 注册、进程状态、启动时间、心跳、停止时间和当前任务，不再通过是否存在 `running` 任务反推 Worker 是否存活。
- 长驻 Worker 启动后注册，空闲和执行阶段均持续心跳，领取任务时原子关联当前 `task_id`，任务结束后清空；正常退出在 `finally` 中写入 `stopped`，异常退出则由心跳年龄判定 stale。
- 空闲轮询不再每秒写 SQLite：Worker 心跳默认 10 秒节流，默认 30 秒未更新视为不可用；配置校验要求 stale 窗口至少是心跳间隔的两倍。
- `run_once` 和 `recover_only` 同样执行注册与停止生命周期，便于运维检查和测试，不会遗留一个看似健康的伪 Worker 记录。
- 新增只读 `/api/capabilities/repro-worker-status`，返回 `ready/unavailable`、健康 Worker 数、心跳年龄、当前任务和停止状态；不暴露宿主机 PID、主机名或 Worker metadata。
- 复现执行仍由独立 CLI 进程完成，API/Uvicorn 不启动 Worker，不接触 Docker；单机文件锁、镜像认证审计、只读模型 Secret、容器资源边界和持久任务配额共同构成当前受限服务契约。
- 当前条目完成的是独立进程及平台生命周期接入。标准 rootless 与 nested_docker Sysbox 双 Profile、细粒度网络出口和最小 OpenCode 权限仍按后续独立条目验收，不能因 Worker 已可观测而提前视为完成。

### 2026-07-31：能力复现任务级 Model Gateway

- 新增平台内 OpenAI-compatible `POST /api/model-gateway/v1/chat/completions`。复现容器只访问该端点，平台 API 使用自身受控环境中的 Provider 配置转发请求，真实 Provider Key 不进入 Worker 或任务容器。
- 新增 migration v14 `repro_model_tokens`。每个复现任务领取后签发独立 `rmt_` 随机令牌，数据库只保存 SHA-256 哈希，并绑定任务、声明模型、有效期、最大调用次数和预留 Token 总量。
- Worker 在 Linux 运行目录以原子 `0600` 文件创建短令牌，Docker 只读挂载到 `/run/secrets/repro_model_token`，OpenCode 继续使用 `{file:...}`。任务成功、失败、取消、超时或 Runner 异常都会在 `finally` 中撤销数据库令牌并删除明文文件；文件创建失败同样立即撤销。
- Model Gateway 用单条条件 UPDATE 原子预留调用次数和 Token 预算，错误模型、过期、撤销、调用耗尽或 Token 超限统一拒绝；上游模型名由平台映射，任务不能借令牌切换其他模型。
- `REPRO_LLM_BASE_URL` 现在必须明确指向 `/api/model-gateway/v1`，容器增加 `host.docker.internal:host-gateway` 解析；原长期 `REPRO_MODEL_TOKEN_FILE` 不再是 Worker 启动依赖。默认任务令牌 TTL 4200 秒、最多 200 次调用、预留 1,000,000 Token，均可通过受控环境变量收紧。
- 回归覆盖令牌模型绑定、调用/Token 配额、撤销、哈希存储、网关 Provider Key 隔离、无效 Bearer 拒绝、临时文件权限和 Worker 收尾删除；能力及网关聚焦测试 107 passed，全仓 Python 测试 322 passed，`compileall`、`git diff --check` 与敏感信息扫描通过。
- 本项只完成模型流量的凭据隔离与逻辑配额。代码仓/软件包仓出口白名单、RFC1918/metadata/Docker 网桥阻断和强制网络层审计仍是后续 3B 项，不能仅依赖该 HTTP 网关替代网络隔离。

### 2026-07-31：能力复现强制出口与私网阻断

- 新增能力域 `ReproEgressPolicy`，仓库 URL 只接受不含凭据的 GitHub HTTP(S) 地址，并在容器启动前解析 DNS；任一批准域名解析到非公网 IPv4/IPv6 时任务失败关闭，不继续运行未知代码。
- 基础允许列表覆盖任务 GitHub 仓库、GitHub 内容域、PyPI、npm、Maven、Cargo、Go Proxy、Hugging Face 和当前配置镜像；管理员可以通过 `REPRO_EGRESS_EXTRA_DOMAINS` 增加固定依赖域名，但任务输入不能自行扩大允许范围。
- 容器显式使用 Docker `bridge`、关闭 IPv6，并将 DNS 指向不可用的容器本地地址；只有启动时审核并固定的域名/IP 通过 `--add-host` 写入 `/etc/hosts`，未知域名不能通过 DNS 查询绕过 IP 白名单。
- 容器启动后、clone 和依赖安装前，Worker 根据容器 IP 创建任务专用 iptables chain，并从 `DOCKER-USER` 跳转。只允许审核公网 IP 的 TCP 80/443 与 bridge gateway 上的 Model Gateway 端口，最后无条件 REJECT 其他出口。
- 防火墙规则在 Runner `finally` 中读取包/字节计数并写入任务日志，然后删除跳转和任务 chain。安装任一规则失败会回滚已创建规则并终止任务，不允许降级为自由出网。
- Worker `--check-config` 增加 Docker bridge 和 `DOCKER-USER` 可操作性预检；宿主机未提供强制隔离能力时不领取任务。rootless Docker/nftables 环境必须实现等价执行器，不能通过关闭检查上线。
- 回归覆盖私网 DNS 拒绝、公开仓库策略、Model Gateway 单端口例外、默认 REJECT、规则撤销与计数、外部 DNS/IPv6 禁用和启动预检失败关闭；能力网络聚焦测试 81 passed，全仓 Python 测试 326 passed，`compileall` 与 `git diff --check` 通过。
- 本批次完成回环、私网、链路本地、metadata、Docker 网桥和平台管理端口的默认阻断。任务声明外部业务 API 的审批记录、按任务持久允许列表和完整域名连接日志仍保留为下一项，因此 3B 的总出口策略条目没有提前勾选完成。
- 当前宿主机实测 Docker bridge 可用，gateway 为 `172.20.0.1`；当前开发用户直接执行和 `sudo -n` 执行 iptables 均无权限。按 fail-closed 契约，此环境在管理员配置 AI4SEC 专用最小防火墙权限前不会领取真实复现任务，不能为了继续运行而回退自由出网。

### 2026-07-31：能力复现任务级外部域名审批

- 新增 migration v15 `capability_repro_egress_domains`，按任务持久保存精确域名、用途、申请人、审批状态、复核人、理由和时间；`UNIQUE(task_id, domain)` 防止同一任务重复申请。
- 手动启动复现可提交最多 20 个外部域名。只接受不带协议、路径、端口、凭据或通配符的完整域名；IP、localhost、格式错误和重复项在任务入队前被拒绝或归一化。
- 含外部域名的任务从 `awaiting_egress_approval` 开始，Worker 的领取查询只接受 `queued`，不存在“先运行后审批”的竞态。全部域名批准后才转为 `queued`，任一拒绝立即转为 `stopped`。
- 批准时重新执行公网 URL/DNS 安全校验，解析到回环、私网、链路本地或其他非公网地址时拒绝批准；运行前 `ReproEgressPolicy` 再次解析并失败关闭，防止审批后 DNS 漂移绕过。
- 新增查询、批准和拒绝 API。审批记录构成持久策略与人工审计；Worker 只从数据库加载该任务已批准域名，并将运行时域名到 IP 映射写入任务日志，防火墙收尾继续记录拒绝包数和字节数。
- 当前简单认证尚未进入阶段 4，`requested_by/reviewer` 暂由调用方提交，只能作为内部运营记录；认证上线后必须改为从统一 `CurrentUser` 注入，不能继续信任请求体身份字段。
- 自动 Pipeline 不声明额外业务域名，保持原 `queued` 行为；固定软件生态域名仍是平台级白名单，不借任务输入隐式扩大。
- 回归覆盖域名格式归一化、重复去除、待审批任务不可领取、多域名全批准后入队、拒绝停止、私网 DNS 拒绝、API 审计字段和 Worker 只传递已批准域名；全仓 Python 测试 336 passed，`compileall` 与 `git diff --check` 通过。

### 2026-07-31：能力复现双 Profile 第一阶段

- 新增 migration v16，为复现任务持久保存 `execution_profile`、审批状态、复核人、风险理由和复核时间。迁移期间遗留的 `queued/running` 任务统一停止并要求显式重新提交，避免旧 Sysbox 任务被无审批地解释为 standard。
- 启动 API 支持 `standard` 与 `nested_docker`，默认 standard。nested 任务先进入 `awaiting_profile_approval`，批准必须填写风险接受理由；若还申请外部域名，则按“Profile 审批 → 域名审批 → queued”顺序执行，任一拒绝转为 `stopped`。
- standard 与 nested 使用 Profile 专用 Worker、文件锁、恢复和清理范围；Worker 只能领取自身 Profile。数据库领取语句同时验证 nested 已批准，并用原子 `NOT EXISTS running` 条件保证两个 Worker 合计最多一个运行任务。
- 新增无 Docker daemon/systemd 的 `Dockerfile.standard`。standard 命令使用只读根文件系统、`cap-drop ALL` 和 rootless daemon；容器内 root 映射到宿主普通用户，不等同宿主 root，并继续只读挂载任务级 `0600` 模型令牌。
- nested 继续使用 Sysbox，但仅在人工批准后可领取；默认资源收紧为 1.5 CPU、3 GiB 内存/交换和 768 PIDs，全机并发固定为 1。Worker 启动检查必须确认 `sysbox-runc` 存在。
- 当前宿主机实测只有 rootful Docker、`runc` 与 `sysbox-runc`，没有 rootless Docker/Podman。更重要的是，rootless 网络尚无与当前 `DOCKER-USER` 等价的强制出口执行器；standard 预检因此显式失败关闭。不能用 rootful runc 或自由出网冒充完成，3B 的双 Profile 总条目继续保持未勾选。
- `repro-runner-standard:v1` 已在当前宿主机从 `Dockerfile.standard` 真实构建成功；无网络烟测确认 Python 3.10.12、Node 20.20.2、OpenCode 1.15.12 可用，镜像内无 Docker 命令和 OpenCode auth 文件，只读根文件系统下启动成功且 `/proc/self/status` 的 `CapEff=0`。
- Profile、迁移、API、领取隔离、审批顺序、rootful 拒绝、rootless 出口适配器缺失时失败关闭及两类 Docker 命令均有回归覆盖；全仓 Python 测试 342 passed，`compileall` 与 `git diff --check` 通过。

### 2026-08-03：能力复现 OpenCode 最小权限

- 按 OpenCode 1.15.12 官方 `config.json` Schema 实现 Profile 权限生成和启动前自校验。规则使用官方“最后匹配者生效”语义，catch-all 放在前、具体 deny 放在后；非交互 Worker 不使用会等待人工输入的 `ask`。
- 两类 Profile 均将未知工具设为 deny，并拒绝外部目录、子代理、Skill、交互提问、WebFetch、WebSearch 和 doom loop；读取额外拒绝 `.env` 与 `/run/secrets`，外部路径只放行 `/workspace/**` 和 `/tmp/**`。
- standard 明确拒绝 Docker、dockerd 和 Podman。nested 允许项目使用 Docker/Compose，但拒绝命令行中明显的 privileged、host network、host PID/IPC/UTS namespace，并继续依赖 nested 人工审批和容器网络边界。
- sudo、su、mount、umount、nsenter、unshare、iptables、ip6tables、nft、systemctl、service 和递归 OpenCode 命令在两类 Profile 中统一拒绝；Prompt 同步声明这些限制，减少模型反复尝试被阻断操作。
- 平台权限不再只写入可被项目配置覆盖的用户级配置。Worker 为每个任务创建独立 `0600` managed config，只读挂载到 Linux 最高优先级 `/etc/opencode/opencode.json`，并在任务结束时与短令牌一起删除；Runner 缺少该文件或权限过宽时拒绝执行。
- managed config 同时固定全局和 `build` agent 权限、清空插件列表；实际命令使用 `opencode run --pure --agent build`。在项目目录放置符合 Schema 的恶意 `opencode.json`，尝试把全局/build 权限改回 allow 并加载插件后，OpenCode 1.15.12 解析结果仍保持两级 deny 且插件为空。
- 任意项目复现仍需要广泛 shell 命令，因此 bash 保留显式 allow fallback。OpenCode 权限只能降低代理误操作，无法约束恶意仓库通过解释器或 Compose 文件绕过命令字符串规则；安全结论仍以容器隔离、强制出口、资源配额和短令牌为准，不能把该配置宣称为沙箱。
- standard 与 nested 生成配置均使用真实 `repro-runner-standard:v1` 中的 OpenCode 1.15.12 在无网络容器内执行 `opencode debug config --pure`，完整解析成功；standard 的 `docker *`、nested 的 `docker run *--privileged*`、两类默认工具和外部目录 deny 均在解析结果中生效。
- 回归覆盖默认 deny、无 `ask`、危险命令、Profile 差异、令牌文件引用、managed config 权限与收尾删除、配置注入和过度宽松策略拒绝；全仓 Python 测试 347 passed，`compileall` 与 `git diff --check` 通过。
- 镜像复核期间发现宿主机仍有两个旧 `repro-*` 容器已连续运行约 6 天。本批次未在缺少任务归属和数据库对账证据时擅自停止；该事实作为下一项“静默超时、孤儿容器与容器信息持久化”真实样本处理。

### 2026-08-03：能力复现运行资源对账与安全回收

- 复核确认 Runner 已使用独立 stdout 读取线程和带超时的队列轮询；即使 OpenCode 子进程完全静默，主循环仍每 0.5 秒执行心跳、停止请求、墙钟超时和 workspace 检查。静默进程超时回归继续通过，不再使用阻塞式 `for stdout` 作为生命周期时钟。
- migration v17 为复现任务增加 `container_id`、`runtime_owner_id` 和 `proxy_pid`。容器名与 workspace 在执行前持久化，Docker 成功创建后立即持久化容器 ID，Web loopback 代理启动后立即持久化宿主 PID；因此 Worker 重启不再只依赖内存中的 Runner 对象。
- 每个新容器写入 `com.ai4sec.resource`、`com.ai4sec.runtime-owner`、`com.ai4sec.task-id` 和 `com.ai4sec.execution-profile` 标签。实例归属 ID 由当前数据库绝对路径的 SHA-256 摘要派生，使同机不同 clone/数据库的 Worker 不会互相回收资源。
- Worker 恢复时只扫描“资源类型、当前实例归属和当前 Profile”三项标签均匹配的容器。与数据库任务、容器名和已持久化容器 ID一致的资源保留；任务不存在、身份不一致或任务已 cleaned 的同实例资源才按容器 ID强制回收。
- 显式清理同样先验证容器四项标签和任务归属，不再仅凭数据库中的容器名执行 `docker rm -f`；旧无标签容器默认拒绝自动删除。workspace 只有在规范化路径严格位于配置的 `REPRO_WORKSPACE_ROOT` 下时才允许递归删除。
- Web 代理继续固定为 `127.0.0.1` 的 `socat + nsenter`。清理恢复只在 `/proc/<pid>/cmdline` 仍匹配任务端口对应的 loopback socat 监听器时发送 SIGTERM，避免 PID 复用后误杀其他进程；失败、停止和超时任务在 Runner finally 中统一停止代理和容器，只有 Web `success/partial` 保留运行环境供人工验收。
- 宿主机实测当前生产硬化数据库实例标签过滤结果为空；两个连续运行约 6 天的 `repro-runner:v3` 容器来自旧 `/home/liuqi777/repro_workspaces`，没有 AI4SEC 归属标签且当前数据库没有任务 5/6。本批次按安全规则保持不动，后续只能在人工确认旧任务和报告后迁移或删除。
- 回归覆盖静默超时、标签完整性、容器 ID/实例归属/PID 持久化、当前实例孤儿回收、无标签容器拒绝、workspace 越界拒绝、代理命令身份校验和 migration v17；全仓 Python 测试 350 passed，`compileall` 与 `git diff --check` 通过。

### 2026-08-03：能力复现项目类型策略

- 新增统一策略决策模块，将项目明确分为 `official_demo`、`local_web`、`cli` 和 `unsupported`。前端不再根据 `is_web` 自行传布尔值，API 的 `strategy=auto` 是唯一默认决策入口；操作者仍可显式选择 local_web 或 cli 覆盖自动分类。
- 官方 Demo 只有同时存在 URL 和分类阶段真实探测后持久化的 `demo_verified=true` 才允许跳过本地部署。仅有未验证 demo URL 不会跳过，仍按 Web/CLI 本地策略执行；跳过响应返回策略、原因和 Demo URL，详情页及能力卡均可直接打开。
- local_web 任务必须在入队前成功保留 `127.0.0.1` 端口，端口耗尽返回 503，不允许静默降级为 CLI；cli 任务禁止携带 Web 端口。Worker 再次校验该不变量，防止数据库被错误修改后以错误 Prompt 执行。
- 明确配置为 unsupported 或 `implementation_depth.has_real_code=false` 的项目不创建昂贵复现任务，返回可解释跳过原因；操作者显式选择本地策略时仍可覆盖，覆盖后若没有仓库 URL 则按输入错误拒绝。
- migration v18 为任务增加 `repro_strategy`，本地 Web/CLI 决策与任务一起持久化并通过任务详情和列表返回。分类批处理同步写回 Demo 验证结果、策略和理由；无法解析有效仓库的条目标记为 unsupported。
- 删除旧 `web: true/false` 请求字段并设置额外字段拒绝，旧调用返回 422，避免继续维护已经与后端任务语义脱节的 Beta 兼容契约。
- 回归覆盖已验证/未验证 Demo、无真实代码、操作者覆盖、官方 Demo 不建任务、无仓库 unsupported、local_web 策略与端口持久化及旧字段拒绝；能力/数据库专项测试 125 passed，全仓 Python 测试 356 passed，前端生产构建、`compileall` 与 `git diff --check` 通过。前端仍只有既有的动态/静态 import 与大 chunk 警告。

### 2026-08-03：能力复现成功判定与证据门槛

- `enforce_report_acceptance` 从只校验 Web 报告扩展为同时校验 CLI/普通项目。非 Web 报告声称 `success` 时必须有摘要、项目类型、至少一个真实步骤且全部 `ok=true`，并提供 `run_result.ran=true`、实际命令、真实输出摘要和结果说明。
- Web 报告继续要求服务真实启动、核心闭环 `verified=true`、`mode=real`、实测步骤、真实证据和结果说明；首页 200、服务启动或普通 CRUD 不再单独构成成功证据。
- `level=L3` 的项目即使完成 import 或环境准备，也自动降级为 `partial`，因为尚未验证完整可用能力。所有自动降级原因同时进入 `acceptance_issues` 和 `blockers`，保留模型原始报告供人工复核。
- 失败或部分成功报告保留其原始状态，不强行伪造成功；没有结构化报告仍由 Runner 按失败收尾。能力卡回写沿用降级后的最终状态，避免前端显示 success 而领域对象实际不可用。
- Prompt 与校验规则同步，明确 CLI 成功所需的真实命令、输出和结果字段；新增回归覆盖缺证据 success、完整 CLI success、L3 降级和已有 Web 规则，专项测试 117 passed。

### 2026-08-03：能力复现结构化报告与能力卡回写

- 报告契约增加 `schema_version`、`evidence` 和 `limitations`，普通 CLI 与 Web Prompt 均输出同一组基础字段；未知字段仍保留在任务原始 `report_json` 中，API 结构化响应只暴露已声明字段。
- Runner 在接受报告时补齐默认版本；能力卡回写保存完整 `repro_report`、版本、摘要、最终状态、usage、evidence、limitations、blockers、gotchas 和环境信息，不再丢失证据与限制字段。
- 回写状态严格使用验收后的报告状态：`success`、`partial`、`failed` 分别映射为“已复现”“部分复现”“复现失败”，模型原始 success 被自动降级时能力卡不会继续显示成功。
- 新增真实 SQLite 回写测试，验证报告版本、证据、限制、摘要和领域状态均持久化；结构化报告与回写专项测试 112 passed。
