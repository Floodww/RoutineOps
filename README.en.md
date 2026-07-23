<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/routineops-lockup-dark-256.png">
    <img alt="RoutineOps" src="brand/logo/routineops-lockup-light-256.png" width="360">
  </picture>
</p>

# RoutineOps

RoutineOps — self-hosted MDM/RMM for Windows, macOS and Linux devices. Agents keep a
persistent gRPC/mTLS channel to your own server and work over the internet —
no VPN required. Version: see [`VERSION`](./VERSION).

> Detailed documentation is in Russian — see [README.md](./README.md) and the links below.

## Features

- **Inventory** — hostname, OS, CPU/RAM/disk, IP, serial number, agent version, installed software, process events.
- **Scripts** — one-off runs on a device or group; scheduled (cron), on-connect and event-triggered policies; script library with results.
- **Device groups** — membership, per-group policies, run a script on a whole group.
- **Software policies** — allowed/forbidden rules per device, group or platform.
- **Device lock** — full-screen overlay with a password (Windows and macOS), unlock works offline.
- **Events & alerts** — `agent_unreachable`, forbidden software, unauthorized changes; Telegram notifications.
- **Audit log** — all admin actions, configurable retention.
- **RBAC** — `it_admin` and read-only `viewer` roles; email invites.
- **Agent self-update** — ed25519-signed releases, sha256 + manifest signature verification, anti-rollback.
- **mTLS** — agents authenticate with client certificates issued at enrollment.

## Quick start

1. **Server:** Linux (Ubuntu 22.04+ / Debian 12+), Docker + Compose v2, open ports 80/443 and 50051. A static IP is enough — no domain needed. See [`docs/install.md`](./docs/install.md).
2. **Install.** Copy the config template, fill it in, then run — this way every parameter reaches the install up front:
   ```bash
   cp install.env.example install.env
   nano install.env      # PUBLIC_ADDR (external IP/domain) + ADMIN_EMAIL / ADMIN_PASSWORD
   ./install.sh
   ```
   Generates TLS certs, secrets, a release-signing key, starts the compose stack (migrations run automatically) and builds + publishes agents for Windows/Linux/macOS. **`PUBLIC_ADDR`** is the address agents and browsers reach the server on from outside (external IP or domain): behind NAT/VPN set it explicitly, otherwise enrollment over the external address fails TLS (it must be in the cert SAN; the host's internal IP is added automatically). See [`docs/self-hosted-deploy.md`](./docs/self-hosted-deploy.md).
3. **First login:** `https://<IP-or-domain>` with the `ADMIN_EMAIL`/`ADMIN_PASSWORD` credentials. The password must pass the complexity policy (8+ chars, 3 of 4 character classes), otherwise the admin account is not created.
4. **Agents are already published** by step 2; to roll out a new version later, run `./update.sh` — it pulls the new release, rebuilds the server and republishes the agents; agents then self-update (every 6 hours by default). See [`docs/self-update.md`](./docs/self-update.md).

   > **The "Download MSI/PKG" buttons** in the UI serve `releases/RoutineOps-agent.{msi,pkg}` (over `/downloads/`). These installers are refreshed by **both `install.sh` and `update.sh`** — each copies them from `build/msi/RoutineOps-agent.msi` and `build/pkg/RoutineOps-agent.pkg` (inside the build container, so the files end up server-readable). So to publish a new installer, just place the freshly built file at `build/msi/RoutineOps-agent.msi` / `build/pkg/RoutineOps-agent.pkg` (MSI is built on Windows via `build/msi/build-msi.ps1`, PKG on macOS) and commit/pull it into the repo on the server: the next `./update.sh` (or `./install.sh`) copies it into `releases/` for you. A manual `sudo cp … releases/` is only needed on servers running the old scripts (before July 2026, when `update.sh` did not refresh the installers).
5. **Enroll a device:** in the web UI, "Devices" → "Add device" — you get a single-use token (24 h TTL) and the exact install command (Windows: MSI via `msiexec`; Linux/macOS: generated `install-mdm.sh`). See [`docs/enrollment.md`](./docs/enrollment.md).

## Documentation (Russian)

[`ARCHITECTURE.md`](./ARCHITECTURE.md) ·
[`docs/install.md`](./docs/install.md) ·
[`docs/self-hosted-deploy.md`](./docs/self-hosted-deploy.md) ·
[`docs/enrollment.md`](./docs/enrollment.md) ·
[`docs/agent-cli.md`](./docs/agent-cli.md) ·
[`docs/config-as-code.md`](./docs/config-as-code.md) ·
[`docs/self-update.md`](./docs/self-update.md) ·
[`docs/operations.md`](./docs/operations.md) ·
[`docs/field-troubleshooting.md`](./docs/field-troubleshooting.md) ·
[`docs/tamper-protection.md`](./docs/tamper-protection.md) ·
[`docs/jwt-secret-rotation.md`](./docs/jwt-secret-rotation.md) ·
[`SECURITY.md`](./SECURITY.md) (English)

## Stack

Go (agent + server monolith) · gRPC/Protobuf + mTLS · PostgreSQL 16 ·
Redis + Asynq (task delivery queue) · React + TypeScript web UI.

## Enterprise

Enterprise adds on top of the features above:

| Feature | Status |
|---|---|
| FileVault recovery-key escrow (macOS) | ✅ |
| Enforced FileVault device lock | ✅ |
| Software removal from the UI | in development |
| Multi-tenancy | in development |
| SSO/OIDC, MFA, SCIM, SIEM export | in development |
| Remote desktop | planned |

This build ships without enterprise code (e.g. `lock_mode=filevault` returns 409).
Full list — [`docs/ROADMAP.md`](./docs/ROADMAP.md).

**Enterprise licensing, bug reports & suggestions** — email
[charmander020104@gmail.com](mailto:charmander020104@gmail.com) or Telegram
[@flood_j](https://t.me/flood_j), or open an
[Issue](https://github.com/Floodww/RoutineOps/issues) in this repository.
