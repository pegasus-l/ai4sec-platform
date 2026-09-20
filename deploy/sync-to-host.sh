#!/bin/bash
# 比对 deploy/ 与 119 线上文件; 默认只检查, --apply 才回写(密钥类文件永不回写)。
# 比对时把长度 >=20 的 token 掩掉再比, 避免"密钥不同"被误报为漂移。
set -u
REPO_DEP="$(cd "$(dirname "$0")" && pwd)"
HOST_DIR="${HOST_DIR:-/opt/ai-security-fusion-v2}"
MASK='s/[A-Za-z0-9+\/=_-]\{20,\}/<TOKEN>/g'

MAP=(
  "docker-compose.yml:docker-compose.yml"
  "Dockerfile.repro:Dockerfile.repro"
  "nginx.conf:nginx.conf"
  "repro-model.json:repro-model.json"
  "repro-web/register.py:repro-web/register.py"
  "repro-web/watchdog.py:repro-web/watchdog.py"
  "repro-web/watchdog.sh:repro-web/watchdog.sh"
  "repro-web/stop_legacy.py:repro-web/stop_legacy.py"
  "repro-web/bootstrap_repo15.sh:repro-web/bootstrap_repo15.sh"
  "repro-web/README.md:repro-web/README.md"
  "repro-web/nginx/nginx.conf:repro-web/nginx/nginx.conf"
  "repro-web/nginx/tasks.conf:repro-web/nginx/tasks.conf"
)

apply=0
[ "${1:-}" = "--apply" ] && apply=1
drift=0

for pair in "${MAP[@]}"; do
  src="$REPO_DEP/${pair%%:*}"; dst="$HOST_DIR/${pair##*:}"
  if [ ! -e "$dst" ]; then printf '  MISSING  %s\n' "${pair##*:}"; drift=1; continue; fi
  a=$(sed "$MASK" < "$src" | md5sum | cut -d' ' -f1)
  b=$(sed "$MASK" < "$dst" | md5sum | cut -d' ' -f1)
  if [ "$a" = "$b" ]; then
    printf '  OK       %s\n' "${pair##*:}"
  else
    drift=1
    if [ "$apply" = 1 ]; then
      cp -p "$src" "$dst" && printf '  SYNCED   %s\n' "${pair##*:}"
    else
      printf '  DIFF     %s   (线上与本目录不一致)\n' "${pair##*:}"
    fi
  fi
done

for f in .env repro-auth.json repro-opencode.jsonc; do
  [ -e "$HOST_DIR/$f" ] && printf '  SKIP     %s (密钥类, 不比对不回写)\n' "$f"
done

if [ "$apply" = 0 ] && [ "$drift" = 1 ]; then
  echo "  → 有漂移: 用 --apply 回写, 或把线上改动回填本目录后提交"
  exit 1
fi
[ "$drift" = 0 ] && echo "  → 无漂移"
exit 0
