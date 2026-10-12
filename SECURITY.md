# Security

This is a private administrative control plane. Its checks and confirmation window reduce specific risks; they do not guarantee network availability or replace a firewall.

## Access Boundary

- Use an unprivileged CT and keep the panel on `127.0.0.1`. Access it through an authenticated SSH tunnel or separately secured private gateway.
- There is no application login/RBAC. Anyone who reaches the panel can obtain a session and change rules. CSRF/origin checks are not authorization.
- Trusted HTTP hosts default to localhost/loopback. Explicitly allow only the private hosts you need; avoid wildcards.
- Mutations require signed, session-bound CSRF tokens and reject foreign/cross-site origins. Session cookies are HttpOnly and SameSite=Strict, and Secure over HTTPS.
- A restrictive same-origin Content Security Policy is enforced; UI assets and icons are served locally at runtime. Installers still require trusted package download access.
- Run one Uvicorn worker. Signing keys are process-local; reload after a restart.

## Host Boundary

The CT has no host CAP_NET_ADMIN. The dedicated panel account can write its data, not the root-owned runtime/virtualenv. Existing CT service files and overrides are preserved; migrating a legacy root-running service requires explicit ownership and configuration review.

A dedicated SSH key has a forced command and `restrict` options. The helper account cannot edit its root-owned `authorized_keys` or SSH directory; retain this ownership boundary. Host subprocesses use fixed absolute executable paths and argument arrays rather than shell interpolation. The root-owned helper and library run Python in isolated mode. Sudo allows exactly `status`, `diagnostics`, `dry-run`, `apply`, `confirm` and `rollback`, with no arbitrary arguments or shell paths. `recover` and `expire` are local root/systemd actions. Audit retained authorized keys and old sudo entries when upgrading.

Pin the SSH host key using a fingerprint verified through the trusted host console. Keep `StrictHostKeyChecking=yes`; a mismatch requires investigation.

Protocol v2 independently validates bounded JSON rules/settings on the host. Both ends must use matching network settings. Arbitrary nft text, paths, shell fragments and caller-owned rollback snapshots are rejected. Rule limits include 500 rules, strict types, usable-subnet/gateway exclusions, duplicate mappings and protected ports; HTTP mutation bodies are capped at 2 MiB.

Only `table ip pve_portfw` is atomically replaced. There are no input/output hooks, whole-ruleset flushes or drop policies. Protected external ports apply to this tool's mappings, including disabled rules; they do not secure services exposed by another table or the host itself. An accept cannot override a drop in another base chain. Existing conntrack entries can retain earlier translations.

## Transactions and Recovery

Save/Import affect only the draft. Dry Run does not prove packet delivery. Apply starts a host-owned watchdog and durably records the previous snapshot before replacing the table. Confirm verifies the operation, deadline/boot ID and running fingerprint, then records the applied snapshot, not later edits.

Rollback survives a disconnected browser or CT but depends on host scheduling, locks, storage and successful nft operations. A failed restore remains pending and visible; no hard real-time guarantee is made. Keep console access during initial testing.

Boot recovery is opt-in. It restores only a missing table and refuses a different existing table. Installation and Confirm do not enable it. Recovery trusts the root-owned confirmed nft snapshot and verifies the result; it does not rerender that snapshot from changed settings or start an Apply confirmation window. Validate/back up snapshots after configuration changes. Never promote an arbitrary backup into the host journal. An unrelated later firewall reload can remove the table again.

The table includes outbound masquerade for the entire configured internal subnet. Disable All is not an outbound traffic kill switch. Read the [activation and reversal procedure](docs/INSTALLATION.md#boot-recovery-opt-in) and [emergency recovery guidance](docs/TROUBLESHOOTING.md#emergency-recovery).

## Private Data

Keep `/etc/pve-portfw` and `/etc/pve-portfw-host-helper` private, including keys, pinned host identities, configs, state, backups, audit logs and diagnostics. Retention is administrator-managed; local backups and audit logs are not tamper-proof. Use synthetic addresses and mock screenshots for public reports.

Ignore rules cannot remove tracked or historical exposure. Review proposed files and reachable history before publishing. Revoke/rotate an exposed credential first; deleting a file or rewriting history does not revoke it or erase external clones/caches.

The software is a Beta candidate without production certification or an independent security audit. Consult [README limits](README.md#security-and-limits) and [manual acceptance checks](docs/TROUBLESHOOTING.md#manual-acceptance).

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting when the repository enables it, or an established private channel with the maintainer. Availability must be checked; do not assume a public issue is private. Do not publish credentials, host access details or exploit information in public issues.
