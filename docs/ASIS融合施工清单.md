# ASIS × ai4sec-platform 融合施工清单

> 范围：把 ASIS 作为前端宿主 + 反代网关 + 资讯生产者，ai4sec-platform 作为独立后端子服务接入，实现"一个入口、两个系统、松耦合联邦"。
> 约束：不共享代码仓、不共享数据库、不共享进程；ai4sec 宿主机裸跑不 docker 化；只通过 4 个契约连接。
> 本文是施工清单，不是实现。每个改动点标了文件路径、接口签名、className 映射、验证点。确认后按"施工顺序"分批做。

---

## 0. 总原则与边界

### 0.1 不做的事

- 不把两个代码仓合并
- 不让 ai4sec import ASIS 的包，反之亦然
- 不共享数据库（ASIS 用 SQLite/PG，ai4sec 用自己的 SQLite）
- 不让 ai4sec docker 化（repro_runner 的 sysbox 设计依赖宿主机 docker daemon，见 §6.1）
- 不照搬 ASIS 的 FetchSchedulerState 到 ai4sec（设计目标不同，见 §6.2）
- 不动 ASIS 的业务代码（只加菜单项、rewrites、1 个导出 API、信源登记字段）
- 不动 ai4sec 的威胁/漏洞域业务逻辑（只改前端样式和 API client baseURL）

### 0.2 四个连接契约（全部松耦合）

| # | 方向 | 契约 | 用途 |
|---|---|---|---|
| C1 | ASIS → ai4sec | HTTP 反代 `/insights/*` → ai4sec:8100 | 前端入口整合 |
| C2 | ai4sec → ASIS | `GET /api/items/export?since=` | 能力洞察消费资讯 |
| C3 | ASIS → ai4sec | 共享 `SEC_AI_SESSION_SECRET` | 登录态同源共享 |
| C4 | ASIS → ai4sec | `/admin/sources` 登记 ai4sec 信源（只读） | 信源统一视图 |

### 0.3 部署拓扑

```
宿主机
├─ Docker
│   └─ ai-security-radar 容器（ASIS）
│       ├─ next :8090（公网入口，rewrites /insights/* → 127.0.0.1:8100）
│       ├─ uvicorn :8000（ASIS FastAPI）
│       └─ worker（抓取 + 日报 + timeline 缓存）
├─ systemd: ai4sec-api.service（宿主机 venv，uvicorn :8100，serve frontend/dist）
├─ systemd timers: ai4sec-news-sync / threats / vulns（定时触发 pipeline）
└─ Docker daemon（宿主机）
    └─ repro-runner:v3（sysbox-runc，能力洞察复现时起）
```

---

## 1. ASIS 侧改动（宿主端，最小化）

ASIS 侧总改动量：约 80 行代码 + 配置。全部是边界扩展，不动业务逻辑。

### 1.1 Nav 加"洞察"分组（C1）

**文件**：`apps/web/components/Nav.tsx`

**改动**：在 `groups` 数组的"阅读"组之后，新增"洞察"分组（或合并进"阅读"组，建议独立分组以区分来源）。

**结构示例**：
```ts
{
  label: "洞察",
  links: [
    { href: "/insights/capabilities", label: "能力洞察", icon: FlaskConical, external: true },
    { href: "/insights/threats", label: "威胁洞察", icon: ShieldAlert, external: true },
    { href: "/insights/vulnerabilities", label: "漏洞洞察", icon: Bug, external: true }
  ]
}
```

**关键点**：
- 新增 `external: true` 标记，Nav 渲染时用 `<a>` 而非 `<Link>`（避免 Next.js 客户端路由拦截，让浏览器走 rewrites 反代）
- 图标从 `lucide-react` 选 `FlaskConical` / `ShieldAlert` / `Bug`
- 放在"阅读"组下方、"运营"组上方
- 角色可见性：复用 ASIS 现有 viewer 角色逻辑（viewer 能看阅读+系统，运营只读）——"洞察"组对 viewer 可见即可，不需要 adminOnly

**验证点**：登录后左侧 sidebar 出现"洞察"分组，3 个菜单项点击跳转到 `/insights/*`。

### 1.2 next.config.mjs rewrites 扩展（C1）

**文件**：`apps/web/next.config.mjs`

**改动**：在现有 `rewrites()` 里新增 `/insights/*` 反代规则。**顺序敏感**——`/insights/api/*` 必须在 `/insights/*` 之前匹配。

**规则示例**：
```js
async rewrites() {
  const backend = process.env.BACKEND_API_URL || "http://127.0.0.1:8000";
  const ai4sec = process.env.AI4SEC_API_URL || "http://127.0.0.1:8100";
  return [
    { source: "/insights/api/:path*", destination: `${ai4sec}/api/:path*` },
    { source: "/insights/:path*", destination: `${ai4sec}/:path*` },
    // ... 现有的 /api/* /public/* 规则保持不变
  ];
}
```

**关键点**：
- `/insights/api/*` → ai4sec 后端 API（ai4sec 后端路由仍是 `/api/threats` 等，不改）
- `/insights/*` → ai4sec FastAPI serve 的 frontend/dist（ai4sec `app/main.py` 已有 frontend serve 逻辑）
- 新增环境变量 `AI4SEC_API_URL`，构建时注入（同 ASIS 现有 `BACKEND_API_URL` 模式）
- 构建命令：`AI4SEC_API_URL=http://127.0.0.1:8100 BACKEND_API_URL=http://127.0.0.1:8000 npm run build`

**验证点**：浏览器访问 `/insights/threats`，返回 ai4sec 的 ThreatPage（先看 200 状态，再看内容渲染）。

### 1.3 /api/items/export 导出 API（C2）

**文件**：`apps/api/app/api/routes.py`

**改动**：基于现有 `/api/items` 逻辑，新增 `/api/items/export` 增量导出接口。

**接口签名**：
```
GET /api/items/export
  Query:
    since: ISO8601（必填，UTC，如 2026-07-31T00:00:00Z）
    min_score: float（默认 60）
    category: str（可选，如 "Sec for AI"）
    limit: int（默认 500，上限 1000）
  Header: Authorization: Bearer <ADMIN_TOKEN>  或共享 token
  Response: { "items": [ItemView...], "next_since": "ISO8601", "count": N }
```

**实现要点**：
- 复用 `timeline_cache._query_day_items` 或 `routes._build_item_view` 的字段构造逻辑
- `since` 对 `Item.first_seen_at` 做增量过滤（不是 `published_at`，因为 ASIS 用 first_seen_at 表示"系统首次看到"）
- `next_since` 返回本次结果中最大的 `first_seen_at`，供 ai4sec 下次拉取做游标
- 鉴权：用 ASIS 现有 `ADMIN_TOKEN`，或新增独立的 `AI4SEC_PULL_TOKEN`（建议独立，便于后续权限分离）
- 不走 LLM 重新加工，只读已加工好的 Item

**字段格式**（复用 timeline_cache 的 item view，见 `apps/api/app/services/timeline_cache.py` `_item_view`）：
- id, title, title_zh, summary, canonical_url, recommendation_reason
- primary_category, sub_category, score_total, confidence
- first_seen_at, published_at, source_id, item_type
- entities, paper_url, reader_url

**验证点**：`curl -H "Authorization: Bearer xxx" "http://localhost:8000/api/items/export?since=2026-07-31T00:00:00Z&min_score=60&limit=10"` 返回 JSON。

### 1.4 Source 表加 owner 字段 + 信源登记（C4）

**文件 1**：`apps/api/app/models.py`（`Source` 类）
**改动**：新增字段
```python
owner: str = Field(default="asis", index=True)  # asis | ai4sec
```
- 默认 `asis`，登记 ai4sec 信源时设 `owner="ai4sec"`

**文件 2**：`config/sources.yml`
**改动**：在现有信源后新增 ai4sec 域信源登记（type 用 ai4sec 自有类型，ASIS fetcher registry 不认识这些 type 会自动跳过）：
```yaml
# ---- ai4sec 域信源（ASIS 只登记不抓取，owner=ai4sec）----
- id: huawei-repos
  name: 华为开源仓库
  type: huawei_repo          # ASIS fetcher 不认识，自动 skip
  url: ""
  enabled: true
  authority_weight: 0.6
  fetch_interval_minutes: 360
  owner: ai4sec
  config:
    ai4sec_pipeline: threats.huawei_full_migration_pipeline

- id: cve-recent
  name: CVE 近期漏洞
  type: cve
  url: ""
  owner: ai4sec
  config:
    ai4sec_pipeline: threats.cve_scout

- id: anysearch-vuln
  name: AnySearch 漏洞检索
  type: anysearch
  url: ""
  owner: ai4sec
  config:
    ai4sec_pipeline: vulnerabilities.full_knowledge_discovery_pipeline
```

**文件 3**：`apps/api/app/services/seed_data.py`
**改动**：`seed_defaults()` 同步时把 `owner` 字段写入。

**文件 4**：`apps/api/app/services/ingestion.py`
**改动**：`fetch_sources` 选 due sources 时，加 `where Source.owner == "asis"` 过滤（防止 ASIS worker 去抓 ai4sec 的信源）。

**验证点**：
- ASIS `/admin/sources` 页面能看到 huawei-repos/cve-recent/anysearch-vuln 等信源，标记"ai4sec 管理"
- ASIS worker 不会尝试抓取 type=huawei_repo 的信源（FetchLog 里无相关记录）

### 1.5 /admin/sources 页面显示 owner（C4）

**文件**：`apps/web/app/admin/sources/page.tsx`

**改动**：
- 信源列表加"归属"列，显示 `owner`（asis/ai4sec）
- ai4sec 信源的"立即抓取"按钮禁用或改为"由 ai4sec 管理"提示
- 可选：加筛选器按 owner 过滤

**验证点**：页面正确显示归属列，ai4sec 信源的抓取按钮不可点。

### 1.6 session 共享配置（C3）

**文件**：ASIS `.env` + ai4sec `.env`

**改动**：两边 `.env` 配置同一个 secret：
```env
SEC_AI_SESSION_SECRET=<同一个随机字符串>
```
ASIS 已在用这个 secret（见 `auth.ts` 第 179 行 `sessionSecret()` 读 `SEC_AI_SESSION_SECRET`），从 ASIS `.env` 复制到 ai4sec `.env` 即可。ai4sec 第一版用方案 B（自验 cookie），所以 ai4sec `.env` 必须有这个 secret。

**探查结果**：见 §3.3（cookie 名 `sec_ai_hot_session`、HMAC-SHA256 签名、payload `{username, role, expiresAt, nonce}` 已全部确认，含完整验证代码）。

**验证点**：ASIS 登录后，访问 `/insights/threats`，ai4sec 后端能从 `sec_ai_hot_session` cookie 验签解出 username/role，不返回 401。

---

## 2. ai4sec 侧改动

ai4sec 侧总改动量：约 200 行 + 4 个 features 页面样式重写（主要工作量）。

### 2.1 引入 Tailwind + 复制 ASIS 设计系统

**文件 1**：`frontend/package.json`
**改动**：devDependencies 加
```json
"tailwindcss": "3.4.17",
"postcss": "8.4.49",
"autoprefixer": "10.4.20"
```

**文件 2**：`frontend/tailwind.config.ts`（新增，复制 ASIS）
**内容**：直接复制 ASIS `apps/web/tailwind.config.ts`，content 路径改为 `./src/**/*.{ts,tsx}`。

**文件 3**：`frontend/postcss.config.js`（新增）
```js
export default { plugins: { tailwindcss: {}, autoprefixer: {} } };
```

**文件 4**：`frontend/src/styles/globals.css`（新增，复制 ASIS）
**内容**：直接复制 ASIS `apps/web/app/globals.css`（2364 行，含全部 CSS 变量 + 组件类）。

**文件 5**：`frontend/src/main.tsx`
**改动**：import `./styles/globals.css`，删除原 `tokens.css` 和分域 css 的 import。

**文件 6**：删除 `frontend/src/styles/` 下的 `tokens.css` / `shell.css` / `news.css` / `capability.css` / `threat.css` / `vulnerability.css` / `global.css`（被 ASIS globals.css 取代）。

**验证点**：`npm run build` 成功，dist 里能看到 Tailwind 生成的 utility 类。

### 2.2 删 Shell + 改 App.tsx 路由

**文件 1**：`frontend/src/layouts/Shell.tsx`（删除）
**理由**：被 ASIS 反代后，ASIS 的 Nav + layout 已包裹，ai4sec 不需要自己的顶部 tab。

**文件 2**：`frontend/src/app/App.tsx`（重写）
**改动**：
- 去掉 `<Shell>` 包裹
- 域切换从 `?domain=` query 改为读 path（`/insights/threats` → threat 域）
- 简化为：
```tsx
import { ThreatPage } from '../features/threats/ThreatPage';
import { CapabilityPage } from '../features/capabilities/CapabilityPage';
import { VulnerabilityPage } from '../features/vulnerabilities/VulnerabilityPage';
import { NewsPage } from '../features/news/NewsPage';

const ROUTES: Record<string, () => JSX.Element> = {
  threats: ThreatPage,
  capabilities: CapabilityPage,
  vulnerabilities: VulnerabilityPage,
  news: NewsPage,
};

export function App() {
  const path = window.location.pathname.replace(/^\/insights\/?/, '').split('/')[0] || 'capabilities';
  const Page = ROUTES[path] ?? CapabilityPage;
  return <Page />;
}
```

**验证点**：访问 `/insights/threats` 渲染 ThreatPage，访问 `/insights/capabilities` 渲染 CapabilityPage。

### 2.3 Vite base path

**文件**：`frontend/vite.config.ts`
**改动**：
```ts
export default defineConfig({
  base: '/insights/',
  // ... 其余不变
});
```

**关键点**：base path 让构建产物的资源路径变成 `/insights/assets/*.js`，被 ASIS 反代到 ai4sec 时能正确加载。

**验证点**：`npm run build` 后 dist/index.html 里的资源引用都是 `/insights/assets/...` 开头。

### 2.4 API client baseURL

**文件**：`frontend/src/api/client.ts` + `frontend/src/api/opsClient.ts` + `frontend/src/api/vulnerabilities.ts`
**改动**：所有 API client 的 baseURL 从相对路径或 localhost 改为 `/insights/api`：
```ts
const BASE = '/insights/api';
```

**验证点**：浏览器 DevTools Network 里 API 请求都走 `/insights/api/*`。

### 2.5 ASIS session 验证中间件

**文件**：`src/ai4sec_platform/app/middleware.py`（新增，**完整实现代码见 §3.3**）

**方案**：第一版用方案 B（自验 `sec_ai_hot_session` cookie）。理由：cookie 必透传（浏览器发的，rewrites 转发 HTTP 请求必带），而 ASIS middleware 注入的 `x-user` header 透传不确定。约 35 行 Python（`hmac`+`hashlib`+`base64`）。

**位置**：`app/main.py` 的 `create_app()` 里挂载，CORS 之后、路由之前：
```python
import os
from .middleware import ASISSessionMiddleware
app.add_middleware(ASISSessionMiddleware, secret=os.environ["SEC_AI_SESSION_SECRET"])
```

**前置配置**：ai4sec `.env` 加 `SEC_AI_SESSION_SECRET=<和 ASIS 同一个值>`（ASIS 已在用，从 ASIS `.env` 复制即可）。

**放行路径**：`/api/health`、`/health` 不需要登录（见 §3.3 代码的 `PUBLIC_PATHS`）。

**注入**：`request.state.user = {username, role}`，ai4sec 路由用 `request.state.user.username` 读取。

**验证点**：未登录访问 `/insights/api/threats/today` 返回 401 `{"error":"auth_required","login":"/login"}`；ASIS 登录后访问返回数据，`request.state.user.username` 为 `sec4ai`。

**降级到方案 A 的时机**（优化，非必须）：实测确认 ai4sec 能收到 ASIS middleware 注入的 `x-user` header 后，可在 cookie 验签前加快读路径（header 有就直接用），省掉 HMAC 计算。第一版不优化，先求可靠。

### 2.6 能力洞察 ASIS items adapter（C2 核心）

**文件**：`src/ai4sec_platform/domains/capabilities/adapters/asis_items_source.py`（新增）

**职责**：实现 ai4sec 的 `SourceConnector` 接口，调 ASIS `/api/items/export`，把 ASIS Item 转成 ai4sec `normalized_item`。

**接口签名**：
```python
class ASISItemsSource:
    """从 ASIS 拉取资讯 Item，作为能力洞察的上游数据源"""
    def __init__(self, asis_base_url: str, token: str): ...
    def fetch_since(self, since: datetime | None) -> list[NormalizedItem]:
        """调 GET {asis_base_url}/api/items/export?since={since}&min_score=60
        返回映射后的 normalized_item 列表"""
    def last_cursor(self) -> datetime | None:
        """从 ai4sec DB 读上次拉取的 next_since 游标"""
    def save_cursor(self, cursor: datetime) -> None:
        """持久化游标，下次拉取用"""
```

**字段映射表**（见 §5.1）。

**验证点**：单元测试 mock ASIS API，验证字段映射正确；集成测试拉真实 ASIS 数据。

### 2.7 capabilities pipeline 改数据源

**文件 1**：`src/ai4sec_platform/domains/capabilities/pipelines.py`
**改动**：`from_news_pipeline` 的第一个 step 从"读本地 normalized_items"改为"调 ASISItemsSource.fetch_since()"。

**文件 2**：`src/ai4sec_platform/pipelines/steps/capability.py`
**改动**：`collect` step 的数据源从 `domains/news/repository.py` 改为 `ASISItemsSource`。

**文件 3**：`configs/pipelines.yaml`
**改动**：`capabilities.from_news_pipeline` 描述更新为"从 ASIS 资讯拉取候选生成能力候选"。

**验证点**：跑 `python -m ai4sec_platform.cli.run_pipeline --pipeline capabilities.from_news_pipeline`，从 ASIS 拉到 Item 并生成能力候选。

### 2.8 4 个 features 页面 className 重写（主要工作量）

**文件**：
- `frontend/src/features/news/NewsPage.tsx`（224 行）
- `frontend/src/features/capabilities/CapabilityPage.tsx`（595 行）
- `frontend/src/features/threats/ThreatPage.tsx`（579 行）
- `frontend/src/features/vulnerabilities/VulnerabilityPage.tsx`（696 行）

**改动**：全部 className 按 §4 映射表替换为 ASIS 组件类。业务逻辑、状态管理、数据流不动，只改样式类名。

**验证点**：4 个页面在 ASIS layout 包裹下，视觉与 ASIS 首页/日报页一致（卡片圆角 8px、配色 #24d3ce 青、背景 #080b12、字体 Inter）。

### 2.9 ThreatGraphView 颜色 token 适配

**文件**：
- `frontend/src/features/threats/graph/ThreatGraphView.tsx`（394 行）
- `frontend/src/features/threats/graph/buildDualTreeGraph.ts`（275 行）
- `frontend/src/features/threats/graph/GraphNodeTypes.tsx`

**改动**：节点颜色从 `--sky/--green/--violet/--red` 改为 ASIS 的 `--accent/--accent-2/--warning/--danger`，融入深色主题。图布局逻辑不动。

**验证点**：威胁图节点配色和 ASIS 卡片色系协调，不再出现突兀的紫色/天蓝。

### 2.10 systemd 服务单元

**文件**（新建 `deploy/systemd/` 目录）：

**文件 1**：`deploy/systemd/ai4sec-api.service`
```ini
[Unit]
Description=ai4sec-platform API (shadow)
After=network.target

[Service]
Type=simple
User=liuqi777
WorkingDirectory=/home/liuqi777/ai4sec-platform
Environment="PATH=/home/liuqi777/ai4sec-platform/venv/bin"
Environment="PYTHONPATH=src"
EnvironmentFile=/home/liuqi777/ai4sec-platform/.env
ExecStart=/home/liuqi777/ai4sec-platform/venv/bin/uvicorn ai4sec_platform.app.main:app --host 127.0.0.1 --port 8100
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**文件 2-4**：3 个 timer + service 对（news-sync / threats / vulns）

`ai4sec-news-sync.timer`：
```ini
[Unit]
Description=ai4sec 拉取 ASIS 资讯喂能力洞察
[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Unit=ai4sec-news-sync.service
[Install]
WantedBy=timers.target
```

`ai4sec-news-sync.service`：
```ini
[Unit]
Description=ai4sec sync news from ASIS
[Service]
Type=oneshot
User=liuqi777
WorkingDirectory=/home/liuqi777/ai4sec-platform
Environment="PATH=/home/liuqi777/ai4sec-platform/venv/bin"
Environment="PYTHONPATH=src"
ExecStart=/home/liuqi777/ai4sec-platform/venv/bin/python -m ai4sec_platform.cli.run_pipeline --pipeline capabilities.from_news_pipeline
```

`ai4sec-threats.timer`：`OnUnitActiveSec=6h`，service 跑 `--pipeline threats.huawei_full_migration_pipeline`

`ai4sec-vulns.timer`：`OnUnitActiveSec=12h`，service 跑 `--pipeline vulnerabilities.full_knowledge_discovery_pipeline`

**验证点**：`systemctl status ai4sec-api` active；`systemctl list-timers | grep ai4sec` 看到 3 个 timer。

---

## 3. 数据契约详细规格

### 3.1 C1：反代契约

| 项 | 规格 |
|---|---|
| ASIS rewrites | `/insights/api/:path*` → `http://127.0.0.1:8100/api/:path*` |
| ASIS rewrites | `/insights/:path*` → `http://127.0.0.1:8100/:path*` |
| ai4sec 后端 | 监听 127.0.0.1:8100，不对外 |
| ai4sec 前端 | Vite base `/insights/`，构建产物由 ai4sec FastAPI serve |
| 登录态 | 同源 cookie，ASIS 登录即生效 |

### 3.2 C2：资讯导出契约

**请求**：
```
GET http://127.0.0.1:8000/api/items/export?since=2026-07-31T00:00:00Z&min_score=60&limit=500
Authorization: Bearer <AI4SEC_PULL_TOKEN>
```

**响应**：
```json
{
  "items": [ { "id": 1, "title": "...", "title_zh": "...", "summary": "...", ... } ],
  "next_since": "2026-07-31T03:15:22Z",
  "count": 42
}
```

**频率**：ai4sec 每 15 分钟拉一次，游标存 `ai4sec DB`（新增表 `asis_pull_cursor`）。

**失败处理**：4xx/5xx 不更新游标，下次重试用旧游标；超时 30 秒。

### 3.3 C3：session 共享契约

**探查结果**（已读 ASIS `apps/web/lib/auth.ts` 205 行 + `middleware.ts` 86 行）：

| 项 | 值 |
|---|---|
| cookie 名 | `sec_ai_hot_session`（`AUTH_COOKIE` 常量） |
| cookie 值格式 | `v1.<base64url(payload)>.<base64url(HMAC-SHA256)>` |
| payload 结构 | `{ "username": str, "role": "admin"\|"viewer"\|"user", "expiresAt": unix秒, "nonce": str }` |
| 签名算法 | HMAC-SHA256（Web Crypto API），签名对象是 `encodedPayload`（不含 `v1.` 前缀和 dot） |
| secret 来源 | `SEC_AI_SESSION_SECRET` || `AUTH_TOKEN` || `"sec-ai-hot-local-session-secret"`（fallback） |
| 有效期 | 24 小时（`SESSION_MAX_AGE_SECONDS = 86400`） |
| cookie path/domain/sameSite | middleware 未显式设，Next.js 默认（path=`/`，同源全路径生效） |
| 角色 | `admin`（全权限）/ `viewer`（阅读+系统，无运营）/ `user`（同 viewer） |
| ASIS middleware 注入 header | `x-user`（username）、`x-role`（role）——验证通过后设到 requestHeaders |
| ASIS middleware 拦截 `/insights/*`？ | **是**，`/insights/*` 不在 `PUBLIC_PREFIXES`，会先验 session 再放行给 rewrites |

**关键发现**：ASIS Next.js middleware 在 rewrites 之前执行，会先验证 `sec_ai_hot_session` cookie，验证通过后注入 `x-user` / `x-role` header，然后 rewrites 把请求转发给 ai4sec。但这里有个**透传可靠性差异**：
- **cookie 一定透传**：浏览器发的 cookie，rewrites 转发 HTTP 请求到 destination 时必带 cookie
- **x-user header 透传不确定**：middleware 注入的 custom header 是 Next.js 内部 request 对象上的，rewrites 转发到外部 URL（`http://127.0.0.1:8100`）时是否作为 HTTP 请求头发出，取决于 Next.js 版本行为，不保证

因此 ai4sec 中间件有两条可选路径，**推荐第一版用 B**：

**方案 A（优化，不推荐第一版）**：ai4sec 中间件直接读 ASIS 注入的 `x-user` header，不自己验 cookie。
- 优点：零加密逻辑
- 风险：header 透传不确定，可能读不到 → 误判未登录
- 适用：先验证 header 确实透传到 ai4sec 后，可作为 B 的快速路径优化

**方案 B（推荐，第一版用）**：ai4sec 中间件自己验 `sec_ai_hot_session` cookie（Python 复现 ASIS 的 HMAC-SHA256 + base64url）。
- 优点：**确定可靠**（cookie 必透传），不依赖 Next.js header 转发行为
- 代价：Python `hmac` + `hashlib` + `base64`，约 35 行代码
- secret：ai4sec `.env` 配 `SEC_AI_SESSION_SECRET`（和 ASIS 同一个值）

**ai4sec 中间件实现（方案 B）**：
```python
# src/ai4sec_platform/app/middleware.py
import hmac, hashlib, base64, json, time, os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

COOKIE_NAME = "sec_ai_hot_session"
PUBLIC_PATHS = {"/api/health", "/health"}


class ASISSessionMiddleware(BaseHTTPMiddleware):
    """验证 ASIS 签名的 sec_ai_hot_session cookie（方案 B：自验，不依赖 header 透传）。
    复现 ASIS apps/web/lib/auth.ts 的 createSessionCookieValue / sessionFromCookieValue：
      格式 v1.<base64url(payload)>.<base64url(HMAC-SHA256(encoded_payload, secret))>
    """

    def __init__(self, app, secret: str):
        super().__init__(app)
        self._secret = secret.encode()

    async def dispatch(self, request, call_next):
        path = request.url.path
        if any(path.endswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)

        cookie_val = request.cookies.get(COOKIE_NAME)
        user = self._verify(cookie_val) if cookie_val else None
        if not user:
            return JSONResponse(
                {"error": "auth_required", "login": "/login"},
                status_code=401,
            )
        request.state.user = user
        return await call_next(request)

    def _verify(self, value: str) -> dict | None:
        parts = value.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            return None
        encoded_payload, signature = parts[1], parts[2]
        # 验签：HMAC-SHA256(encoded_payload, secret) → base64url 去 padding
        expected = base64.urlsafe_b64encode(
            hmac.new(self._secret, encoded_payload.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(signature, expected):
            return None
        # 解 payload
        try:
            padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return None
        exp = payload.get("expiresAt")
        if not isinstance(exp, (int, float)) or exp <= time.time():
            return None
        return {
            "username": str(payload.get("username") or "unknown"),
            "role": str(payload.get("role") or "user"),
        }
```

**挂载**（`app/main.py` 的 `create_app()`）：
```python
import os
from .middleware import ASISSessionMiddleware
app.add_middleware(ASISSessionMiddleware, secret=os.environ["SEC_AI_SESSION_SECRET"])
```

**验证点**：
- 未登录访问 `/insights/api/threats/today` → 401 `{"error":"auth_required","login":"/login"}`
- ASIS 登录后访问 → 200 + 数据，`request.state.user.username` 为 `sec4ai`

**角色处理**：ai4sec 的洞察页面是阅读类，`admin`/`viewer`/`user` 都应能看，中间件只验登录不验角色。ai4sec 自己的运营操作（如触发 pipeline）将来可加 `role == "admin"` 检查。

**降级到方案 A 的时机**：实测确认 ai4sec 能收到 `x-user` header 后，可在 `_verify` 前加快速路径（先读 header，header 有就直接用，没有再验 cookie），省掉 HMAC 计算。但第一版不优化，先求可靠。

### 3.4 C4：信源登记契约

- ASIS `Source` 表加 `owner` 字段（asis/ai4sec）
- ai4sec 信源在 ASIS `sources.yml` 登记，`owner=ai4sec`，type 用 ai4sec 自有类型
- ASIS `ingestion.fetch_sources` 过滤 `owner=asis`
- ASIS `/admin/sources` 显示所有信源 + owner 列
- ai4sec 信源的健康状态由 ai4sec 自己维护（可选：ai4sec 暴露 `/api/operations/sources` 给 ASIS 聚合显示，第一版不做）

---

## 4. className 映射表（ai4sec → ASIS）

### 4.1 容器/布局类

| ai4sec 原样式 | ASIS 类 | 说明 |
|---|---|---|
| 自定义 page 容器 | `page-shell` | 主内容区，max-width 1680px |
| 自定义 page 宽 | `page-shell-wide` | 宽布局 |
| 自定义 page 头 | `page-head` | 带渐变的页头卡 |
| 自定义 page 头扁平 | `page-head-flat` | 无背景的页头 |
| 页面标题 | `page-title` | 24px/900 |
| 页面副标题 | `page-subtitle` | 13px/muted |
| 主区域根 | `app-main` | margin-left: 180px（sidebar 宽） |

### 4.2 卡片/表面类

| ai4sec 原样式 | ASIS 类 | 说明 |
|---|---|---|
| 自定义 card | `surface` | 标准面板，带边框+渐变 |
| 紧凑面板 | `surface-compact` | padding 12px |
| 柔和面板 | `surface-soft` | panel-2 背景 |
| 时间轴卡片 | `timeline-card` | hover 上浮+阴影 |
| 指标卡 | `metric-card` | 数字大显示 |
| 链接卡 | `link-card` | 可点击整块 |
| 空状态 | `empty-state` | 居中 muted 文本 |

### 4.3 按钮/标签类

| ai4sec 原样式 | ASIS 类 | 说明 |
|---|---|---|
| 自定义 btn | `btn` | 34px 高/13px/800 |
| 小按钮 | `btn-sm` | 32px |
| ghost 按钮 | `btn-ghost` | 透明背景 |
| 已读激活 | `btn-read-active` | accent-2 色 |
| 徽章 | `badge` | 圆形边框 |
| 标签 | `tag` | 矩形小标签 |
| 选中徽章 | `badge-selected` | warning 色 |
| 分数徽章 | `score-badge` | accent 色+mono 字体 |
| 图标按钮 | `icon-btn` | 34px 方形 |

### 4.4 表格/表单类

| ai4sec 原样式 | ASIS 类 | 说明 |
|---|---|---|
| 表格外壳 | `table-shell` | 带圆角裁切 |
| 表格滚动 | `table-scroll` | 横向滚动 |
| 数据表 | `data-table` | 完整表样式 |
| 输入框 | `field` | 38px 高 |
| 下拉 | `select` | 同 field |
| 文本域 | `textarea` | 140px 高 |
| 分段控件 | `segmented` | 圆形容器 |
| 分段项 | `seg-item` / `seg-item-active` | 激活态 accent |

### 4.5 颜色 token 映射

| ai4sec 原变量 | ASIS 变量 | 值 |
|---|---|---|
| `--bg #020617` | `--bg` | `#080b12` |
| `--bg-2 #07111f` | `--bg-soft` | `#0d121d` |
| `--panel rgba(15,23,42,0.84)` | `--panel` | `#141925` |
| `--panel-2` | `--panel-2` | `#171d2b` |
| `--line` | `--line` | `rgba(150,164,190,0.18)` |
| `--text #e2e8f0` | `--text` | `#eef5ff` |
| `--muted #94a3b8` | `--muted` | `#8d9bb4` |
| `--sky #38bdf8`（资讯色） | `--accent` | `#24d3ce`（青） |
| `--green #34d399`（能力色） | `--accent-2` | `#35e19d`（绿） |
| `--amber #f59e0b` | `--warning` | `#f6c454` |
| `--red #fb7185` | `--danger` | `#ff6f7d` |
| `--violet #a78bfa`（威胁色） | `--accent` 或保留作图节点专用 | 见 §2.9 |
| `--radius 20px` | `--radius` | `8px` |
| `--radius-sm 12px` | `--radius` | `8px` |
| `--shadow` | `--shadow` | `0 16px 48px rgba(0,0,0,0.32)` |

**关键差异**：ai4sec 原本圆角 20px 偏现代风，ASIS 8px 偏紧凑；ai4sec 多色（每域一色），ASIS 双主色（accent 青 + accent-2 绿）。统一后全部用 ASIS 双主色，威胁图的紫色保留为图节点专用不进通用 token。

---

## 5. 字段映射表

### 5.1 ASIS Item → ai4sec normalized_item

| ASIS Item 字段 | ai4sec normalized_item 字段 | 转换说明 |
|---|---|---|
| `id` | `external_id` | 加前缀 `asis:` 避免和 ai4sec 自增 id 冲突 |
| `title` | `original_title` | 英文原标题 |
| `title_zh` | `title` | 中文标题作主标题 |
| `summary` | `summary` | 直接映射 |
| `recommendation_reason` | `reason` | 推荐理由 |
| `score_total` | `score` | 评分 |
| `primary_category` | `category` | 主分类 |
| `sub_category` | `sub_category` | 子分类 |
| `canonical_url` | `url` | 去重键 |
| `first_seen_at` | `seen_at` | 入库时间 |
| `published_at` | `published_at` | 发布时间 |
| `source_id` | `source_meta.source_id` | 来源 ID |
| `source.name` | `source_meta.source_name` | 来源名 |
| `source.authority_weight` | `source_meta.authority` | 权威度 |
| `entities` | `entities` | 实体列表 |
| `item_type` | `item_type` | news/paper |
| `paper_url` / `reader_url` | `paper_url` / `reader_url` | 论文链接 |
| `confidence` | `confidence` | 置信度 |
| — | `source_system` | 固定 `"asis"` 标记来源 |

### 5.2 游标持久化

新增表 `asis_pull_cursor`（ai4sec DB）：
```python
class ASISPullCursor(SQLModel, table=True):
    id: int = Field(default=1, primary_key=True)  # 单例
    last_since: datetime          # 上次拉取的 next_since
    last_pull_at: datetime       # 上次拉取时间
    last_count: int              # 上次拉取条数
    last_error: str | None       # 上次错误
```

---

## 6. 关键技术决策依据

### 6.1 为什么 ai4sec 不 docker 化（DinD 分析）

**证据**：`repro_runner.py` 前 40 行配置
```python
REPRO_IMAGE = os.environ.get("REPRO_IMAGE", "repro-runner:v3")
REPRO_RUNTIME = os.environ.get("REPRO_RUNTIME", "sysbox-runc")
WORKSPACE_ROOT = Path(os.environ.get("REPRO_WORKSPACE_ROOT", ...))
DOCKERD_WAIT = int(os.environ.get("REPRO_DOCKERD_WAIT", "30"))
# 文件头注释: "sysbox + 端口代理(socat+nsenter)"
# DASHSCOPE_PROXY_URL 注释: "sysbox 容器内直连会卡死,通过宿主机 nginx 反代"
```

**结论**：repro_runner 是宿主机进程，调宿主机 docker daemon，起 sysbox 容器（容器内还能跑 docker）。这套设计依赖宿主机侧基础设施。docker 化 ai4sec 会破坏 sysbox 设计（DinD 三层嵌套）或需挂 docker.sock（DooD，安全风险 + nginx 反代链路重做）。**ai4sec 宿主机裸跑是最优解**。

### 6.2 为什么不照搬 FetchSchedulerState

**证据**：`fetch_control.py` 状态机 + `models.py` FetchSchedulerState 表

**结论**：
1. 设计目标不同：ASIS 是高频小任务循环（每 5 分钟抓信源），需要实时监控 + 暂停恢复；ai4sec 是低频大任务（华为全量扫描几十分钟、漏洞知识发现几小时），shadow 阶段不需要实时盯进度
2. ai4sec 已有任务模型：PipelineRun + TaskRun + Artifact + Manifest + model_calls，和 ASIS FetchJob/FetchJobSource/FetchLog 是两套设计，照搬要改 pipeline 框架
3. 照搬代价 500+ 行 + 前端页面，shadow 阶段用不上
4. ASIS 那套是为信源轮询（interval=300s + source due 检查）设计，和 ai4sec 一次性大批处理模型不匹配

**替代方案**：systemd timer + 现有 PipelineRun 追溯 + `GET /insights/api/runs/{id}` 查进度。零新增框架，复用现有。

### 6.3 为什么前端用反代而非 iframe

**反代（选）**：同源、登录态共享（cookie 天然生效）、无 iframe 沙箱限制、体验无感切换。代价：ai4sec Vite 配 base path、rewrites 顺序敏感。

**iframe（不选）**：跨域登录态要 postMessage 握手、沙箱限制多、样式割裂、跳转受限。虽适配量更小，但体验差且边界坑多。

---

## 7. 施工顺序与验证点

### 阶段 A：打通反代 + 认证（先让 ai4sec 页面能在 ASIS 里看到）

1. ai4sec §2.3 Vite base path + §2.1 引入 Tailwind（不先改样式，先让构建跑通）
2. ai4sec §2.2 删 Shell + 改 App.tsx 路由
3. ai4sec §2.4 API client baseURL
4. ASIS §1.2 next.config.mjs rewrites
5. ASIS §1.6 session 共享配置 + ai4sec §2.5 中间件
6. **验证**：登录 ASIS，访问 `/insights/threats`，看到 ai4sec 的 ThreatPage（样式可能还乱，但能渲染）

### 阶段 B：打通数据流（资讯喂能力洞察）

7. ASIS §1.3 `/api/items/export` API
8. ai4sec §2.6 ASISItemsSource adapter + §5.2 游标表
9. ai4sec §2.7 capabilities pipeline 改数据源
10. **验证**：跑一次 capabilities.from_news_pipeline，从 ASIS 拉到 Item 并生成能力候选

### 阶段 C：信源统一登记

11. ASIS §1.4 Source 表 owner + sources.yml 登记 ai4sec 信源 + ingestion 过滤
12. ASIS §1.5 /admin/sources 显示 owner
13. ai4sec §2.10 systemd timers
14. **验证**：ASIS 信源管理页看到 ai4sec 信源；ai4sec 3 个 timer 生效

### 阶段 D：像素级前端统一（最后做，纯样式）

15. ai4sec §2.1 完成复制 ASIS globals.css + tailwind.config
16. ai4sec §2.8 4 个 features 页面 className 重写（按 §4 映射表）
17. ai4sec §2.9 ThreatGraphView 颜色 token 适配
18. ASIS §1.1 Nav 加"洞察"分组
19. **验证**：4 个页面视觉与 ASIS 一致（圆角 8px、配色青绿、背景深蓝黑、字体 Inter）

**阶段间可独立验证，D 可延后**。A-C 是功能打通，D 是视觉统一。如果时间紧，先上 A-C，D 分批迭代。

---

## 8. 待确认/待探查项

1. ~~ASIS session cookie 机制~~（§3.3）：**已完成探查**。cookie 名 `sec_ai_hot_session`，HMAC-SHA256 签名，payload `{username, role, expiresAt, nonce}`。**ai4sec 第一版用方案 B（自验 cookie）**，因为 cookie 必透传而 ASIS middleware 注入的 `x-user` header 透传不确定。完整实现代码在 §3.3。ai4sec `.env` 需配 `SEC_AI_SESSION_SECRET`（和 ASIS 同值）。
2. **ai4sec 拉取 token**（§1.3）：用 ASIS 现有 `ADMIN_TOKEN` 还是新增 `AI4SEC_PULL_TOKEN`？建议独立 token，权限可分离。
3. **部署路径**（§2.10）：ai4sec 在宿主机的实际路径（示例用 `/home/liuqi777/ai4sec-platform`，实际可能不同）。
4. **AI4SEC_API_URL 构建注入**（§1.2）：ASIS 构建命令要加这个环境变量，确认构建流程能接受。
5. **威胁图紫色保留范围**（§2.9）：`--violet` 是保留给图节点专用，还是完全废弃改用 accent？建议保留作图节点专用，不进通用 token。
6. **Nav 分组位置**（§1.1）："洞察"组放"阅读"下方还是"运营"下方？建议放"阅读"下方，对 viewer 可见。
7. **ai4sec worker 触发是否要 SSE**（未来）：第一版用 systemd timer + 轮询 `/api/runs/{id}` 查进度，不加 SSE。将来 shadow 转生产时再考虑。

---

## 9. 风险与回退

- **风险 1：ASIS session 机制非标准**（如用了 JWT 而非 signed cookie）。应对：探查后再定中间件方案，必要时 ai4sec 中间件调 ASIS 的 `/api/auth/verify` 接口而非本地验签。
- **风险 2：ASIS rewrites 和现有 /api/* 冲突**。应对：`/insights/api/*` 必须在 `/api/*` 之前匹配（rewrites 顺序敏感），验证时测 `/insights/api/threats/today` 不被 ASIS FastAPI 处理。
- **风险 3：ai4sec Vite base path 导致 React Router 失效**。应对：App.tsx 路由改为读 path 而非依赖 router basename，且 ai4sec 不用 react-router（当前 App.tsx 就是手动切换，不依赖 router）。
- **风险 4：像素级统一后业务交互异常**。应对：阶段 D 每改一个页面就回归测试该域的主流程，不批量改。
- **回退**：任一阶段失败，对应改动可独立回退（ASIS 侧改的是配置+1 接口，ai4sec 侧改的是边界+样式），不影响两个系统独立运行。
