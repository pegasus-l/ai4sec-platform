# repro-web — 复现容器多服务总机

`repro` 容器(opencode 复现后端)里的 nginx 总机: 按 `/task/{id}/` 把浏览器经
ASIS(`/insights` 鉴权+rewrite)→ ai4sec(`/repro-web`)转发来的请求分发到各任务独立端口
(`127.0.0.1:8101~8199`), 配合 watchdog 在容器重启/服务挂掉后自动拉起。

## 组成
- `register.py` — 任务注册/生成 nginx 配置/热 reload(`add`/`rm`/`gen`/`status`)
- `watchdog.py` + `watchdog.sh` — 启动看护 v2: 确保 nginx 常驻 + 每 10s 按 tasks.json 探活并拉起任务
- `stop_legacy.py` — 旧单服务机制(current.sh/8080)清理
- `nginx/` — nginx.conf(主配置) + tasks.conf(register.py 自动生成)
- `Dockerfile.repro` / `docker-compose.yml` — 容器可重建资料(规范副本在平台根目录 `/opt/ai-security-fusion-v2/`, 此处为版本化副本, 改动以根目录为准)
- `bootstrap_repo15.sh` — 任务 venv 幂等引导示例(task 脚本在全新 volume 时自愈的写法参考)

## 新鲜容器自举(关键)
重建 repro 容器后以下全部自动恢复, 不需手动操作:
1. **nginx 总机** — `watchdog.sh` 启动时拉起(镜像已固化 `nginx`)
2. **任务服务** — `watchdog.py` 每 10s 按 tasks.json 探活, 端口挂则跑 `task-{id}.sh`
3. **依赖持久性** — 镜像固化 `python3 python3-pip python3-venv libgomp1`; 任务依赖装进项目
   `.venv`(/workspace 是 volume, 重建不丢), `task-{id}.sh` 必须用 `.venv/bin/...` 绝对路径
   + flock 幂等引导守卫(入口缺失时先建 venv 装依赖再启动), 写法参考 `task-15.sh` / `bootstrap_repo15.sh`

> 曾经的坑: 依赖运行时手装进系统(streamlit/libgomp1 等)在容器重建后全丢, 任务服务起不来。
> 现固化进镜像/venv, 已根治。

## 重建 repro 容器
    docker compose -p fusion-v2 build repro
    docker compose -p fusion-v2 up -d --build --no-deps repro

**必须 `-p fusion-v2`**: compose project 名默认由目录名推导(`ai-security-fusion-v2`),
与现有容器 project(`fusion-v2`)不匹配会因端口占用重建失败。

## 浏览器全链
浏览器 → 隧道 `localhost:18092→8091` → ASIS `/insights/repro-web/task/{id}`(需登录态,
无 cookie 会 307 跳 `/login`)→ ai4sec `/repro-web/{path}` → repro nginx `/task/{id}` → 任务端口。
nginx 用精确 `location = /task/{id}` + 前缀 `location /task/{id}/` 兜底 ASIS 剥尾斜杠后的无斜杠路径。
