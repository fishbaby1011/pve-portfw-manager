#!/usr/bin/env bash
set -euo pipefail
umask 077

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_USER="pve-portfw-helper"
HELPER_HOME="/var/lib/pve-portfw-helper"
DATA_DIR="/etc/pve-portfw-host-helper"
LIB_DIR="/usr/local/lib/pve-portfw-helper"

if [[ "$(id -u)" -ne 0 || ! -d /etc/pve ]]; then
  echo "Run this installer as root on the Proxmox host." >&2
  exit 1
fi
if [[ $# -ne 1 || "$1" == *$'\n'* || "$1" == *$'\r'* || ! "$1" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
  echo "Usage: bash scripts/install-host-helper.sh 'ssh-ed25519 AAAA... ct-panel-key'" >&2
  exit 1
fi
PANEL_PUBLIC_KEY="$1"
KEY_CHECK="$(mktemp)"
trap 'rm -f "${KEY_CHECK}"' EXIT
printf '%s\n' "${PANEL_PUBLIC_KEY}" > "${KEY_CHECK}"
ssh-keygen -l -f "${KEY_CHECK}" >/dev/null

if ! command -v nft >/dev/null 2>&1; then
  echo "nft is missing. Install nftables manually after reviewing its service configuration, then rerun this installer." >&2
  exit 1
fi
apt-get update
apt-get install -y --no-upgrade python3 sudo
if ! id "${HELPER_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "${HELPER_HOME}" --shell /bin/bash "${HELPER_USER}"
fi
install -d -m 700 "${DATA_DIR}" "${DATA_DIR}/backups"
install -d -m 755 "${LIB_DIR}" "${LIB_DIR}/portfw"
install -m 644 "${SRC_DIR}/portfw/"*.py "${LIB_DIR}/portfw/"
install -m 644 "${SRC_DIR}/scripts/host-entry.py" "${LIB_DIR}/entry.py"
chown -R root:root "${LIB_DIR}" "${DATA_DIR}"
install -m 750 "${SRC_DIR}/scripts/pve-portfw-host-helper" /usr/local/sbin/pve-portfw-host-helper
install -m 755 "${SRC_DIR}/scripts/pve-portfw-restricted-ssh" /usr/local/sbin/pve-portfw-restricted-ssh
if [[ ! -f "${DATA_DIR}/config" ]]; then
  install -m 600 "${SRC_DIR}/examples/host-helper.conf" "${DATA_DIR}/config"
fi
chmod 600 "${DATA_DIR}/config"
SUDO_CHECK="$(mktemp)"
trap 'rm -f "${KEY_CHECK}" "${SUDO_CHECK}"' EXIT
cat > "${SUDO_CHECK}" <<'EOF'
pve-portfw-helper ALL=(root) NOPASSWD: /usr/local/sbin/pve-portfw-host-helper dry-run
pve-portfw-helper ALL=(root) NOPASSWD: /usr/local/sbin/pve-portfw-host-helper apply
pve-portfw-helper ALL=(root) NOPASSWD: /usr/local/sbin/pve-portfw-host-helper confirm
pve-portfw-helper ALL=(root) NOPASSWD: /usr/local/sbin/pve-portfw-host-helper rollback
pve-portfw-helper ALL=(root) NOPASSWD: /usr/local/sbin/pve-portfw-host-helper diagnostics
pve-portfw-helper ALL=(root) NOPASSWD: /usr/local/sbin/pve-portfw-host-helper status
EOF
visudo -cf "${SUDO_CHECK}" >/dev/null
install -m 440 "${SUDO_CHECK}" /etc/sudoers.d/pve-portfw-helper

install -d -m 755 -o root -g root "${HELPER_HOME}"
install -d -m 755 -o root -g root "${HELPER_HOME}/.ssh"
AUTHORIZED="${HELPER_HOME}/.ssh/authorized_keys"
KEY_TYPE_AND_DATA="$(awk '{print $1 " " $2}' "${KEY_CHECK}")"
if [[ ! -f "${AUTHORIZED}" ]] || ! grep -Fq -- "${KEY_TYPE_AND_DATA}" "${AUTHORIZED}"; then
  printf 'restrict,command="/usr/local/sbin/pve-portfw-restricted-ssh" %s\n' "${PANEL_PUBLIC_KEY}" >> "${AUTHORIZED}"
fi
chown root:root "${AUTHORIZED}"
chmod 644 "${AUTHORIZED}"

for unit in pve-portfw-watchdog.service pve-portfw-watchdog.timer pve-portfw-recover.service; do
  install -m 644 "${SRC_DIR}/examples/${unit}" "/etc/systemd/system/${unit}"
done
systemctl daemon-reload

cat <<'EOF'
Host helper v2 installed. No nft command was executed and no table was created.
No recovery service or watchdog was started by this installer.
Review /etc/pve-portfw-host-helper/config and match it to the CT settings.
Legacy snapshots are preserved but are not auto-imported into v2.
After an explicit Apply and Confirm, review the opt-in boot recovery instructions.
EOF
