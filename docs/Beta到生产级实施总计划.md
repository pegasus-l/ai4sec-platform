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
| 资讯洞察 | 六源采集、本地 raw 导入、分类评分、两阶段评审、日报、专题 | 在线链路收口、增量幂等、X 数据源、真实健康检查、连续日更验收 |
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
- [ ] 固定任务租约、heartbeat、超时、取消和恢复语义。
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
- [ ] 明确 Pipeline/Step 事务边界和失败回滚规则。
- [ ] 为关键业务对象增加唯一约束和幂等键设计。
- [ ] 建立最小备份、校验和恢复流程。
- [ ] CORS 改为环境化白名单。
- [ ] 健康检查增加数据库写入隔离后的连通性检查。

#### 模块任务

- [x] 威胁连接器恢复系统默认 TLS 验证；特殊证书后续使用受控 CA，不允许全局跳过验证。
- [ ] 能力复现已增加 CPU、内存、swap、PIDs、墙钟超时、日志和 workspace 软上限；文件系统硬 quota 与嵌套容器资源治理仍待完成。
- [x] 能力复现停止将模型 Key 写入 Prompt，并在日志回调进入 SQLite/SSE 前统一脱敏；任务 token 改为只读 Secret 文件挂载。
- [ ] 已确认 `repro-runner:v3` 镜像含长期认证文件，并构建通过 Sysbox 验收的干净 `v4`；旧凭据轮换、两个运行中 `v3` 容器迁移及旧镜像删除仍需人工完成。
- [x] 能力复现 Web 端口代理默认只绑定 `127.0.0.1`；受认证反向代理将在部署阶段接入。
- [x] 能力 API/Pipeline 只写持久任务，独立 Repro Worker 使用短连接写日志与状态，不再复用请求级 SQLite connection。
- [ ] 漏洞抓取 URL 增加统一安全策略接入点。
- [ ] 资讯明确 legacy raw 仅用于迁移，不进入正式运行菜单。

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

- [ ] 固定 SQLite 本机持久卷和文件权限。
- [x] 配置并验证 WAL 和 busy timeout；WAL checkpoint 自动化策略仍待补充。
- [x] 建立 `schema_migrations` 表、顺序迁移执行器、checksum 校验和单版本失败回滚。
- [ ] 为 PipelineRun、TaskRun、Worker、Artifact、SourceHealth 和 Audit 表补齐约束与索引。
- [ ] 为四域关键业务对象补齐幂等键和唯一约束。
- [ ] 已增加 busy timeout、数据库大小、WAL/SHM 大小、页使用量和迁移版本 readiness 指标；锁等待累计指标与定期完整性任务仍待补充。
- [x] 建立 SQLite Backup API、一致性校验和恢复到指定文件流程。

#### 任务系统任务

- [ ] API 只创建 queued 任务，不直接启动线程。
- [x] 实现单实例 Pipeline Worker 进程和独立 CLI。
- [x] 实现原子任务领取和运行中周期 heartbeat；租约过期判定与 Worker 注册仍待补充。
- [x] 实现任务条件领取、同 Pipeline/全局 reset 冲突检查和单机 Worker 文件锁。
- [ ] 已实现 queued/running/success/failed/cancelled；partial 和 timeout 尚未统一。
- [ ] 已实现排队立即取消和运行中 Step 边界协作取消；系统级 kill switch 与子进程强杀尚未完成。
- [ ] 已实现严格 JSON Step checkpoint、输入/实现 checksum 和恢复框架；四域 Step 的 `resume_safe` 审核仍待完成。
- [ ] 已实现失败 Run 的白名单续跑入口；失败条目重跑与完整 Run 重跑策略仍待补充。
- [x] 实现 Worker 启动对账；在 checkpoint 完成前将中断的 running 任务标记失败，不做不安全的自动重放。
- [ ] 实现统一 Scheduler 和漏跑补偿。

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

- [ ] 从正式菜单移除 `news.legacy_raw_pipeline`。
- [ ] 将历史导入改为受控一次性迁移命令。
- [ ] 在线连接器与本地 JSON 基类解耦。
- [ ] 明确 X 修复、更换或禁用方案。
- [ ] 完成六源分页、超时、重试、增量和真实健康检查。
- [ ] 建立 RSS/X/ASIS 等正式水位线。
- [ ] 完成资讯、日报、ModelCall 幂等。
- [ ] 定义采集、门控、评审、日报失败重跑语义。
- [ ] 建立模型 Schema 失败降级和人工队列。
- [ ] 连续运行至少三个真实日更周期。

验收指标至少包含：各源采集量、筛选率、重复率、失败率、最终入选率、Schema 通过率、人工纠错率和日报准时率。

#### 3B. 能力洞察

- [ ] 固定复现状态转换和所有异常收尾路径。
- [ ] 实现启动时容器、任务、报告状态对账。
- [ ] 声明任务资源、日志、重试和并发配额。
- [ ] 完成独立受限复现 Worker 接入。
- [ ] 建立 Model Gateway 短期任务令牌，不向复现容器注入真实 Provider Key。
- [ ] 建立代码仓、软件包仓、模型仓和声明外部 API 的出口策略与审计日志。
- [ ] 阻断回环、私网、链路本地、云 metadata、Docker 网桥和平台管理网段。
- [ ] 实现 standard rootless 与 nested_docker Sysbox 双 Profile。
- [ ] nested_docker 必须人工批准、单并发并使用更严格的资源与网络限制。
- [ ] 将 OpenCode 权限从全量 allow 收敛为 Profile 对应的最小权限。
- [ ] 修复静默子进程超时、孤儿容器、容器信息持久化和 Web 端口暴露。
- [ ] 完善 Web、CLI、官方 Demo 和不可复现项目策略。
- [ ] 加强成功判定和证据要求。
- [ ] 完成结构化报告与能力卡回写。
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
