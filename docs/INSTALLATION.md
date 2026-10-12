# Installation

Use two separate machines/roles: an unprivileged LXC CT for the panel and the PVE host for the restricted helper. Run each command only in its stated CT or host role.

## Prerequisites

- A Proxmox host with Python 3.11+, nftables, SSH and systemd. The host installer requires an existing nft binary; it does not install/activate the nftables service.
- An unprivileged Debian CT with Python 3.11+, a static private IP and working package download access.
- A working internal bridge and IPv4 routing/NAT appropriate to your network.
- Stable VM/CT destination addresses. If DHCP exists, reserve addresses or choose static addresses outside its lease pool.
- Console access for your own first deployment and network verification.

The CT installer downloads Python/venv/pip, OpenSSH client and rsync packages, then installs `requirements.txt` into its virtualenv. The host installer installs Python and sudo without upgrading existing packages and needs the existing OpenSSH server, `ip`/`sysctl`, and standard Debian/PVE administration utilities. Backup instructions additionally use tar and util-linux `flock`. Check package access and interpreter versions on both roles before installation; Python 3.11+ is the documented baseline, not a claim that every PVE release was tested.

This tool does not create bridges, set gateways, enable IP forwarding, install DHCP, or fix guest networking. Network settings here are examples, not commands to rewrite your PVE network.

Example values:

| Item | Example |
| --- | --- |
| PVE external IP / interface | 203.0.113.10 / vmbr0 |
| Internal subnet / interface | 10.42.0.0/24 / vmbr42 |
| Host internal gateway | 10.42.0.1 |
| Panel CT | 10.42.0.10/24, gateway 10.42.0.1 |
| Service VM | 10.42.0.100/24, gateway 10.42.0.1 |
| Panel bind | 127.0.0.1:8088 inside the CT |

Use your actual bridge IP as the gateway. It need not end in .1. All sample public IPs are documentation addresses. The private subnet/bridge are also synthetic. New templates use these values; existing local configs, services and runtime fallback defaults are preserved. Explicitly configure both roles before Preflight; an unset environment may retain older defaults.

Clone/download the reviewed project into both the CT and host. Both installers need the repository's scripts, examples and shared portfw package. Do not transfer your panel data or private SSH key to a public repository.

## CT Panel

Run inside the **unprivileged CT**, not on the PVE host:

```bash
cd /root/pve-portfw-manager
bash scripts/install-panel.sh
```

The installer checks the LXC UID mapping, creates the pve-portfw-panel service user, installs the runtime into /opt/pve-portfw-manager, and starts the loopback Web Panel. It preserves existing data, panel.env and systemd service files. It does not connect to the host.

Application and virtualenv files are root-owned, panel-group readable/traversable and not panel-writable. This avoids root's umask 027 making a fresh venv inaccessible to the dedicated service account. The permission block is tested in an isolated Linux user namespace; a complete fresh-CT installation and service startup still require the disposable-PVE acceptance procedure. Preserving a legacy root-running service during upgrade is not evidence that fresh dedicated-user installation has been verified.

Review /etc/pve-portfw/panel.env against examples/panel.env. Set the external address/interface, internal interface/subnet/gateway, protected external ports and helper SSH target. The PVE_PORTFW_PANEL_LISTEN setting is descriptive; changing the bind requires an explicit ExecStart override. Keep the default bind.

Generate a dedicated key **only if it does not already exist**:

```bash
ssh-keygen -t ed25519 -f /etc/pve-portfw/ssh/host-helper -N '' -C pve-portfw-ct
chown pve-portfw-panel:pve-portfw-panel /etc/pve-portfw/ssh/host-helper /etc/pve-portfw/ssh/host-helper.pub
chmod 600 /etc/pve-portfw/ssh/host-helper
cat /etc/pve-portfw/ssh/host-helper.pub
```

Only the .pub contents go to the host. Keep the private key in the CT.

## Host Helper

Run on the **PVE host**:

```bash
cd /root/pve-portfw-manager
bash scripts/install-host-helper.sh 'ssh-ed25519 AAAA... ct-panel-key'
```

The installer creates a dedicated helper account, installs the root-owned wrapper/Python policy, adds the forced SSH command and sudo allow-list, and installs systemd unit examples. It replaces the installed helper/library, sudo allow-list and three supplied host units; back up and review local customizations before an upgrade. Preservation of existing CT service files does not mean the host units are preserved. It does not run any nft command or start/enable the host recovery service or watchdog.

Set /etc/pve-portfw-host-helper/config using examples/host-helper.conf. It must contain the same network values as the CT. It is a root-owned KEY=value file, not an executable shell script.

The installed sudo/SSH actions are exactly:

```text
dry-run
apply
confirm
rollback
diagnostics
status
```

recover and expire are local root/systemd actions. They cannot be called through the CT's SSH key.

Existing helper keys are retained, not replaced. Check that every accepted key for this dedicated account has a forced command and restrict options. Do not use this account for interactive login.

## Pin the Host SSH Key

On the trusted PVE console, read the host's fingerprint:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Inside the CT, collect a candidate key and compare its fingerprint with the trusted console output:

```bash
ssh-keyscan -t ed25519 -p 22 10.42.0.1 > /etc/pve-portfw/ssh/known_hosts.candidate
ssh-keygen -lf /etc/pve-portfw/ssh/known_hosts.candidate
```

Use your configured SSH address/port. **ssh-keyscan alone does not authenticate the host.** Only after the fingerprints match, install the candidate:

```bash
install -m 600 -o pve-portfw-panel -g pve-portfw-panel /etc/pve-portfw/ssh/known_hosts.candidate /etc/pve-portfw/ssh/known_hosts
```

The client uses StrictHostKeyChecking=yes and the explicit known_hosts file. For an already pinned host, review any change before replacing the key.

Check the fixed, read-only action as the panel user:

```bash
sudo -u pve-portfw-panel ssh -i /etc/pve-portfw/ssh/host-helper \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/pve-portfw/ssh/known_hosts \
  pve-portfw-helper@10.42.0.1 /usr/local/sbin/pve-portfw-host-helper status
```

Expect a JSON object with version: 2. A never-used helper should report no pending apply and no confirmed snapshot. A legacy helper's plain-text response is not accepted.

## Start and Open

After reviewing the CT environment:

```bash
systemctl restart pve-portfw-manager
systemctl status pve-portfw-manager --no-pager
curl --fail http://127.0.0.1:8088/api/preflight
```

From your workstation, make an SSH tunnel to the CT using your usual administrative SSH account/key:

```bash
ssh -N -L 8088:127.0.0.1:8088 root@10.42.0.10
```

Open http://127.0.0.1:8088. If the CT's SSH access is only reachable through your VPN, use its reachable private/VPN address. Do not use a host port forward to expose the panel publicly.

The Dashboard preflight shows configuration mismatch, helper connectivity, external/internal interface/address checks, and IPv4 forwarding. Failed checks do not rewrite networking.

See [Basic Workflow](../README.md#basic-workflow) before the first Apply.

## Boot Recovery (Opt-In)

**Do this manually only after a tested Apply and Confirm.** Installation and confirmation do not enable recovery. A running watchdog with `No expired apply.` is not proof of boot restoration: without a pending transaction, it does not restore a missing table.

### Back Up and Review

On the **PVE host**, first read helper status and the effective unit. Check that no transaction is pending, a confirmed snapshot exists, and the live table is verified before using the no-change test below. If a table is present but unverified, investigate rather than overwrite it.

Create a root-private backup before changing service activation:

```bash
(
  set -euo pipefail
  umask 077
  B="$(mktemp -d /root/pve-portfw-recovery.XXXXXX)"
  flock -w 15 /etc/pve-portfw-host-helper/helper.lock bash -s -- "$B" <<'BACKUP'
set -euo pipefail
B="$1"
tar -C / -czf "$B/host-files.tar.gz" \
  etc/pve-portfw-host-helper usr/local/lib/pve-portfw-helper \
  usr/local/sbin/pve-portfw-host-helper usr/local/sbin/pve-portfw-restricted-ssh \
  etc/systemd/system
tar -tzf "$B/host-files.tar.gz" >/dev/null
nft --stateless list ruleset > "$B/ruleset-before.nft"
systemctl cat pve-portfw-recover.service > "$B/recover-unit.txt"
BACKUP
  printf 'Backup directory: %s\n' "$B"
)
```

This only writes backup files and reads nftables. The dump is for inspection/comparison, not a script to blindly replay the entire ruleset. Keep the archive private; it includes host configuration and systemd files. Do not click Apply while making this backup or running the verification steps.

### Enable Future Boot Recovery

```bash
/usr/local/sbin/pve-portfw-host-helper status
systemctl cat pve-portfw-recover.service
systemctl enable pve-portfw-recover.service &&
systemctl is-enabled pve-portfw-recover.service
```

Expect `enabled` and `recoveryEnabled: true`. There is deliberately no `--now`: enabling does not replay nft immediately. Do not enable the global `nftables.service` or restart networking/firewall services as part of this procedure.

On a later host boot, the recovery unit is ordered after network-online, networking and the declared nft/PVE firewall services if they are in the startup transaction. `After=` alone does not enable those services, and network-online does not guarantee a particular bridge is ready. The helper separately checks configured bridge addresses and IPv4 forwarding; systemd retries failures every 10 seconds. No startup sleep is used. Recovery does not provide an Apply-style 120-second confirmation window.

The first explicit Apply starts/enables the separate host watchdog timer. Pending state is durable: if the host reboots before confirmation, the watchdog sees a new boot ID and restores the previous snapshot. Confirmation/rollback stops the idle timer; it remains available on future boots and exits without nft changes when no apply is pending.

With no pending transaction, recovery restores only an absent project table from the last confirmed host snapshot, even if the previous phase was `rolled_back`. That phase records the previous operation, not whether the kernel table currently exists. If the confirmed table already exists, recovery makes no change; if a different project table exists, it refuses to overwrite it. It never manages other tables, bridge configuration or routes. The restored snapshot includes outbound masquerade for the entire configured internal subnet, not only the DNAT rules.

### Test Without Rebooting

First confirm status still reports `tableVerified: true` and `rollbackArmed: false`. Only then manually start the service:

```bash
systemctl start pve-portfw-recover.service
systemctl show pve-portfw-recover.service -p Result -p ExecMainStatus -p ActiveState
journalctl -u pve-portfw-recover.service -n 20 --no-pager
/usr/local/sbin/pve-portfw-host-helper status
```

Expect `Confirmed table already present; no change.`, `Result=success`, `ExecMainStatus=0`, and an unchanged table. `ActiveState=inactive` is normal: this is a oneshot service without `RemainAfterExit`. Do not delete a production table to simulate a reboot. If the table disappears between your check and service execution, recovery may restore the confirmed snapshot instead of taking the no-change path.

### Verify an Actual Boot

The administrator must choose and perform any reboot in a maintenance window, with console access and the impact on **all** hosted VMs/CTs understood. Before pressing Apply or Recover after boot, collect:

```bash
/usr/local/sbin/pve-portfw-host-helper status
nft list table ip pve_portfw
systemctl show pve-portfw-recover.service \
  -p UnitFileState -p ActiveState -p Result -p ExecMainStatus
journalctl -b -u pve-portfw-recover.service -n 40 --no-pager
```

Expect a verified table matching the confirmed rules, `recoveryEnabled: true`, no pending rollback, successful service exit, and a **current-boot** log showing `Restored verified last confirmed table.` if the table was absent. A later missing table despite that success needs investigation of other firewall reloads, not repeated blind Apply.

Separately verify PVE management access and the public TCP/UDP services from an external network. `Test-NetConnection` tests TCP, not UDP; UDP requires its actual application protocol. See [manual acceptance](TROUBLESHOOTING.md#manual-acceptance) for the remaining deployment checks.

### Reversal and Failure Handling

**Reversal only, not part of activation:** manually running `systemctl disable pve-portfw-recover.service` cancels future boot restoration. Do not run it after enabling as a verification step. It does not delete the current table or undo a recovery already performed.

If recovery fails, capture status and current-boot logs before making changes. A continuously retrying recovery service can be stopped with `systemctl stop pve-portfw-recover.service` while investigating; stopping it does not remove the live table or disable future boots. Preserve the backup and the confirmed journal. Do not extract the whole systemd backup over a running installation or load the full ruleset dump as a generic repair. Review the specific failed configuration/snapshot with the administrator before restoring selected files or performing another explicit Apply/Confirm.

## Upgrading From v1

Protocol v2 is deliberately incompatible with arbitrary v1 nft payloads. Upgrade both ends in a reviewed maintenance window:

1. Confirm or roll back any pending apply with the existing version. Do not upgrade while a rollback window is active.
2. Back up /etc/pve-portfw in the CT and /etc/pve-portfw-host-helper on the host.
3. Record the existing CT systemd overrides and current host table. Keep legacy files; the new installer does not delete them.
4. Run the host helper installer and extend its preserved config with all values in examples/host-helper.conf.
5. Run the CT installer. Compare the preserved systemd service with the new service example.
6. Before adopting the new service user/EnvironmentFile, move your actual values into panel.env, set key/known_hosts ownership for the panel user, and check existing overrides. EnvironmentFile values can override Environment entries; do not leave conflicting configuration sources.
7. Pin the host key, restart the CT panel, and run preflight.
8. Review the saved draft, Dry Run, explicitly Apply and Confirm. This creates a v2 host confirmed snapshot.
9. Review and enable optional recovery. Old last-confirmed.nft is not silently imported or replayed.

Before step 8, an existing table may be shown as **unverified**. It is not assumed to match saved JSON. On the first v2 apply, the actual previous project table is backed up so rollback can preserve it.

## Uninstall Without Deleting Data

First finish any pending confirmation/rollback window. Stop/disable the CT panel:

```bash
systemctl disable --now pve-portfw-manager.service
```

On the host, when no transaction is pending:

```bash
systemctl disable --now pve-portfw-recover.service pve-portfw-watchdog.timer
```

Remove the dedicated forced key/sudo allow-list manually if you no longer need them. Keep the data directories and backups until you have chosen another forwarding method. Stopping/uninstalling the panel does not remove the live nft table. Removing a live project table, helper data or network configuration is a separate administrator decision; no destructive uninstall script is provided.
