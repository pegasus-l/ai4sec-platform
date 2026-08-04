#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo bash configs/repro-egress-helper/install.sh <worker-user> [gateway-port]" >&2
  exit 2
fi

worker_user=${1:-}
gateway_port=${2:-8000}
if [[ ! ${worker_user} =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || ! id "${worker_user}" >/dev/null 2>&1; then
  echo "A valid non-root worker user is required" >&2
  exit 2
fi
worker_uid=$(id -u "${worker_user}")
if [[ ${worker_uid} -eq 0 ]] || [[ ! ${gateway_port} =~ ^[0-9]+$ ]] || (( gateway_port < 1 || gateway_port > 65535 )); then
  echo "Invalid worker user or gateway port" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -d -o root -g root -m 0755 /usr/local/libexec /etc/ai4sec
install -o root -g root -m 0755 "${script_dir}/ai4sec-repro-egress-helper" /usr/local/libexec/ai4sec-repro-egress-helper
printf '{"allowed_uid":%s,"allowed_gateway_ports":[%s]}\n' "${worker_uid}" "${gateway_port}" \
  > /etc/ai4sec/repro-egress-helper.json
chown root:root /etc/ai4sec/repro-egress-helper.json
chmod 0644 /etc/ai4sec/repro-egress-helper.json
printf '%s ALL=(root) NOPASSWD: /usr/local/libexec/ai4sec-repro-egress-helper ""\n' "${worker_user}" \
  > /etc/sudoers.d/ai4sec-repro-egress-helper
chmod 0440 /etc/sudoers.d/ai4sec-repro-egress-helper
visudo -cf /etc/sudoers.d/ai4sec-repro-egress-helper

echo "Installed restricted AI4SEC repro egress helper for ${worker_user} (uid ${worker_uid}), gateway port ${gateway_port}."
