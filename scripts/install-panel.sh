#!/usr/bin/env bash
set -euo pipefail
umask 027

APP_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="/opt/pve-portfw-manager"
DATA_DIR="/etc/pve-portfw"
PANEL_USER="pve-portfw-panel"
SERVICE_DST="/etc/systemd/system/pve-portfw-manager.service"

prepare_runtime_permissions() {
  local paths=("${APP_DIR}/app" "${APP_DIR}/portfw" "${APP_DIR}/.venv")
  chown -R "root:${PANEL_USER}" "${paths[@]}"
  chmod -R u=rwX,g=rX,o= "${paths[@]}"
}

if [[ "$(id -u)" -ne 0 || "$(systemd-detect-virt --container || true)" != "lxc" ]]; then
  echo "Run as root inside an unprivileged LXC CT." >&2
  exit 1
fi
if awk '$1 == 0 && $2 == 0 {found=1} END {exit !found}' /proc/self/uid_map; then
  echo "Privileged CT detected. Use an unprivileged CT for the panel." >&2
  exit 1
fi
apt-get update
apt-get install -y python3 python3-venv python3-pip openssh-client rsync
if ! id "${PANEL_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/pve-portfw-panel --shell /usr/sbin/nologin "${PANEL_USER}"
fi
install -d -m 755 -o root -g "${PANEL_USER}" "${APP_DIR}"
install -d -m 700 -o "${PANEL_USER}" -g "${PANEL_USER}" "${DATA_DIR}" "${DATA_DIR}/backups" "${DATA_DIR}/ssh"
# Copy runtime files without deleting existing app files or copying .git / development data.
rsync -a --exclude '__pycache__/' --exclude '*.pyc' "${APP_SRC_DIR}/app/" "${APP_DIR}/app/"
rsync -a --exclude '__pycache__/' --exclude '*.pyc' "${APP_SRC_DIR}/portfw/" "${APP_DIR}/portfw/"
install -m 640 -o root -g "${PANEL_USER}" "${APP_SRC_DIR}/requirements.txt" "${APP_DIR}/requirements.txt"
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
prepare_runtime_permissions
if [[ ! -f "${DATA_DIR}/rules.json" ]]; then
  printf '[]\n' > "${DATA_DIR}/rules.json"
fi
chown -R "${PANEL_USER}:${PANEL_USER}" "${DATA_DIR}"
if [[ ! -f /etc/pve-portfw/panel.env ]]; then
  install -m 640 -o root -g "${PANEL_USER}" "${APP_SRC_DIR}/examples/panel.env" /etc/pve-portfw/panel.env
fi
if [[ ! -f "${SERVICE_DST}" ]]; then
  install -m 644 "${APP_SRC_DIR}/examples/pve-portfw-manager.service" "${SERVICE_DST}"
else
  echo "Existing systemd service preserved. Compare it with examples/pve-portfw-manager.service before upgrading."
fi
systemctl daemon-reload
systemctl enable pve-portfw-manager.service
systemctl restart pve-portfw-manager.service

cat <<'EOF'
CT panel installed and started at http://127.0.0.1:8088.
No host connection, nft change, bridge change or routing change was performed.
Next: review /etc/pve-portfw/panel.env, install a dedicated SSH key, verify/pin the host key,
then open the panel through an SSH tunnel and run Environment Preflight.
Existing service files, data and local configuration were preserved.
EOF
