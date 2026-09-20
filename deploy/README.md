# deploy/ — 119 宿主上的部署件(版本化存档)

这些文件**不是**平台代码,是 119(`119.8.125.117`)**部署现场**的文件。入库目的:有版本、有备份、可查改动。
线上真实位置与构建上下文**仍在 `/opt/ai-security-fusion-v2/`**,本目录是它的版本化快照。

## 对应关系

| 本目录 | 线上路径 | 作用 |
|---|---|---|
| `docker-compose.yml` | `/opt/ai-security-fusion-v2/docker-compose.yml` | fusion-v2 三个服务(asis / ai4sec / repro) |
| `Dockerfile.repro` | `/opt/ai-security-fusion-v2/Dockerfile.repro` | 复现镜像(构建上下文=顶层目录, `COPY repro-web/`) |
| `nginx.conf` | `/opt/ai-security-fusion-v2/nginx.conf` | 入口网关: `/`→asis:8090、`/api/`→asis:8003、`/insights/`→ai4sec:8100、`/repro/`→repro:4096 |
| `repro-model.json` | `/opt/ai-security-fusion-v2/repro-model.json` | 复现容器选用的模型 |
| `repro-web/*` | `/opt/ai-security-fusion-v2/repro-web/*` | 复现容器总机脚本(nginx 分发 / register.py 注册 / watchdog.py 看护),由 `COPY repro-web/ /opt/repro-web/` 打进镜像 |

## 不入库的文件(含密钥)

`.env`(session secret / ASIS token / REPRO_PASSWORD)、`repro-auth.json`(opencode auth key)、`repro-opencode.jsonc`(apiKey)。
后者提供了脱敏示例 `repro-opencode.jsonc.example`。

## 漂移检测与同步

线上文件会被人直接改(改完就生效),所以**本目录可能落后**。用脚本核对:

```bash
./sync-to-host.sh            # 只检查: 比对线上与本目录, 报 OK/DIFF/缺失
./sync-to-host.sh --apply    # 把本目录的"非密钥"文件覆盖回线上(密钥类文件不动)
```

改动线上文件后请**回填本目录并提交**,否则下次重建会用到旧版本。

## 已知坑

- `repro-web/Dockerfile.repro` 与 `repro-web/docker-compose.yml` 这两个 09-01 的历史副本**已于 09-18 删除**:它们早已与线上分叉(线上更新过两轮),留着只会误导。真源见本目录顶层同名文件。
- `Dockerfile.repro` 的 `COPY repro-auth.json` / `COPY repro-model.json` 依赖顶层同名文件存在。
- 重建 repro 镜像:`cd /opt/ai-security-fusion-v2 && docker compose build repro`(注意 compose 项目名是 `fusion-v2`)。
