# Troubleshooting

Start with Environment Preflight and scoped Diagnostics. Read-only checks do not repair networking automatically.

| Symptom | Check |
| --- | --- |
| Panel inaccessible | CT service, loopback bind and authenticated SSH tunnel. |
| Helper unverified | SSH target/port, service-user key permissions, trusted host-key fingerprint, forced command and sudo policy. |
| Protocol v2 required | Upgrade the CT and helper together; never fall back to arbitrary nft payloads. |
| Settings mismatch | Compare `panel.env` and host `config`, including bridge, gateway, subnet and protected ports. |
| Interface/forwarding failure | Review host addresses and `net.ipv4.ip_forward`; do not restart networking as a generic fix. |
| CT reaches guest but Internet does not | Check the independent external path, upstream/PVE/guest firewall and guest routing. |
| Dry Run passes but Apply fails | Inspect host readiness, transaction state and helper audit; syntax is not every prerequisite. |
| Apply response lost/timed out | Refresh authoritative host status before retrying; do not replay a new Apply blindly. |
| Draft changed in another session | Export your draft, reload saved rules and review the ETag/revision conflict. |
| Copy fails | Use localhost/HTTPS and review clipboard permission. No network fallback is used. |
| Rules saved but table absent after boot | Check confirmed host snapshot and opt-in recovery, not just CT JSON or an idle watchdog. |
| Recovery refuses existing table | Investigate out-of-band changes; do not overwrite a different table blindly. |

## Read-Only Diagnosis

Inside the CT:

```bash
systemctl status pve-portfw-manager --no-pager
journalctl -u pve-portfw-manager -n 100 --no-pager
curl --fail http://127.0.0.1:8088/api/preflight
curl --fail http://127.0.0.1:8088/api/apply-status
ip -br addr
ip route
```

On the PVE host, as its administrator:

```bash
/usr/local/sbin/pve-portfw-host-helper status
journalctl -b -u pve-portfw-recover.service -u pve-portfw-watchdog.service -n 100 --no-pager
systemctl show pve-portfw-recover.service -p UnitFileState -p ActiveState -p Result -p ExecMainStatus
ip -br addr
sysctl net.ipv4.ip_forward
nft list table ip pve_portfw
```

`ActiveState=inactive` can be normal for the recovery oneshot service. Inspect its exit result, current-boot journal and actual `tableVerified` state. A historical restore message does not prove the table still exists.

Host state is under `/etc/pve-portfw-host-helper`: root-owned `config`, durable `state.json`, operation backups, `audit.log` and `helper.lock`. CT `/etc/pve-portfw` contains the saved draft, observed apply state, confirmed copies, backups/audit and SSH files. Saved CT `generated.nft` is not a trusted host Apply input. Legacy v1 files are preserved but never replayed automatically.

## Emergency Recovery

1. Keep trusted host console access. Capture status/current-boot logs and back up the private host journal/config before changes.
2. If Apply is pending, use its existing Confirm/Rollback workflow. A failed rollback retains pending state for retry; do not delete the journal to clear the warning. Host operation IDs are idempotent only for the same operation/snapshot.
3. For a missing confirmed table, use [Boot Recovery](INSTALLATION.md#boot-recovery-opt-in) after validating the root-owned snapshot against current settings. It has no new 120-second confirmation window. `No expired apply.` from an idle watchdog is not a restore result.
4. A verified matching table is a no-op recovery path. A different table is deliberately refused. Investigate other firewall services/reloads before another explicit Apply.
5. While investigating repeated recovery failures, `systemctl stop pve-portfw-recover.service` stops current retries without deleting the live table or disabling future boots. Disabling the service is a separate, deliberate reversal.

Do not flush the ruleset, delete a live table as a diagnostic, blindly replay a full dump, extract a systemd backup over a running installation or restart networking/firewalls as a generic repair. A new Apply must follow reviewed Dry Run and external verification.

## Installation and API Issues

Use the panel virtualenv, not system pip. Review preserved service overrides and EnvironmentFile precedence on upgrades; moving to the dedicated service user requires key/data ownership checks. Compare new templates with existing configs instead of copying over them. See [Installation](INSTALLATION.md#upgrading-from-v1).

The default runtime network values remain compatible with older installs, while new templates/documentation use a different synthetic subnet. Explicitly configure both ends and run Preflight. Do not assume missing environment values agree with a freshly copied template.

Restoring a panel backup restores a saved draft, not the host table or its trusted confirmed journal. Review the restored rules, Dry Run and explicitly Apply before expecting live forwarding to change. After a pending Apply is rolled back, later saved draft edits are retained rather than overwritten.

HTTP errors: 400 = disallowed host, 403 = CSRF/origin, 413 = body too large, 422 = invalid input, 409 = revision/lock/confirmation conflict, 503 = helper or transaction failure. Obtain the session cookie/token through `/api/session`, send `X-CSRF-Token` for mutations, and use ETag/If-Match plus the saved revision. A null active rule count means unknown, not zero. The current API schema is `/openapi.json`.

## Development Checks

Run `python -m pytest -q` with development dependencies. Syntax-only checks do not execute installers:

```bash
node --check app/static/app.js
node --check app/static/theme.js
for script in scripts/install-panel.sh scripts/install-host-helper.sh scripts/pve-portfw-host-helper scripts/pve-portfw-restricted-ssh; do
  bash -n "$script" || exit 1
done
```

Run the browser workflow only against `scripts/preview.py`; screenshots go to ignored `.artifacts/browser/`. It covers draft CRUD/import/export, review, Dry Run, Apply, Confirm, manual/clock-expiry rollback, filters, clipboard failures, light/dark layouts and helper disconnection. Mock endpoints are not production routes.

Optional `python tests/nft_namespace.py` requires Linux, nft and unprivileged user/network namespaces. It checks real parser/kernel atomic replacement, confirmed-table recovery and preservation of an unrelated table. It refuses an inherited/nonempty namespace; timer calls and interface readiness are mocked. Environments that prohibit namespaces cannot run it.

The installer permission test exercises only its permission function in a temporary Linux user namespace. It does not install services. Windows skips that test. Framework TestClient deprecation warnings are distinct from a test failure and should be investigated during dependency maintenance.

## Manual Acceptance

Use a disposable PVE environment with console access and backups. Automated tests do not establish these results:

- Fresh unprivileged-CT installation and dedicated-user service startup; coordinated upgrade with preserved overrides/keys.
- Apply/Confirm/manual rollback and actual host-watchdog timeout under lock/transport failures.
- Reboot after Confirm, reboot while confirmation is pending, CT startup withheld and delayed bridge readiness.
- Controlled later firewall reload and preservation of unrelated PVE tables.
- PVE management access and new external TCP connections; UDP via its actual application protocol. A TCP check does not test UDP.
- Supported PVE/Python versions and current CI results, independently of mock test success.

Do not delete a production table or reboot a real host to imitate namespace tests. See [Installation](INSTALLATION.md#boot-recovery-opt-in) for activation, no-change verification, current-boot evidence and reversal.
