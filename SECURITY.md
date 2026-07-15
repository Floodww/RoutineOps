# Security Model & Operator Hardening Guide

RoutineOps is **self-hosted**. This document states the security trust model
explicitly and hands the operator (whoever deploys it) the responsibilities that
live outside the application code.

## Trust model (read this first)

An MDM is, by design, **god-mode over its managed fleet**: the server dispatches
commands and scripts that agents execute as **root / SYSTEM**. That is the product,
not a bug. Concretely:

- The **script channel** (`Task.script_content`, `FetchScriptPolicies` with
  `cron` / `on_connect`) runs arbitrary `bash -c` / `powershell -Command` as root
  on every enrolled endpoint. It is **intentional remote code execution**. There is
  no cryptographic signature on this channel and there will not be one — whoever
  controls the server controls the fleet.
- The **ed25519 signature on agent self-update** protects *only* the update channel
  (anti-tamper / anti-downgrade of the binary). It does **not** bound the script
  channel. Do not read it as "a compromised server cannot run code on the fleet" —
  it can.
- The **admin JWT secret** (`JWT_SECRET`, symmetric HS256) is the single root of
  trust for the panel. Anyone who can read it can mint unlimited admin tokens.

**Therefore the real security perimeter is the host that runs the server.** Making
that host hard to compromise is the operator's job (checklist below). The
application does everything it can to be secure-by-default; the rest is yours.

## What the application does for you (secure-by-default)

- Refuses to start on an empty / default / low-entropy `JWT_SECRET`
  (requires ≥32 bytes and ≥16 distinct bytes).
- Admin JWT TTL 8h; logout revokes the token (`jti` blocklist); password change or
  reset invalidates all previously issued tokens of that user (token-epoch,
  migration 024); per-IP **and** per-account login lockout; bcrypt cost 12; login
  does not leak which accounts exist.
- Two panel roles: `it_admin` and `viewer`. Every mutating API route except
  self-service password change (`POST /me/password`) requires `it_admin`
  (a viewer gets 403); the UI additionally hides admin actions.
- Password complexity policy (≥8 chars, ≥3 of 4 character classes) applies to every
  account, including the seed admin.
- mTLS (TLS 1.3) + private-CA pinning between agent and server after enrollment;
  the server requires and verifies client certificates.
- Enrollment tokens are single-use (race-safe guarded redeem).
- Agent self-update is fail-closed, verifies a signature over the **full** release
  manifest (version + os + arch + sha256), and enforces an anti-rollback version
  floor. The public key that verifies that manifest signature is the release key the
  agent receives in the enrollment response, delivered over the pinned-CA enroll
  channel — the default build is universal and ships **no** embedded key. Embedding
  the key at build time (`-ldflags -X main.releasePubKey=`) is an opt-in for
  legacy/dev builds; when a build does embed it, that key is authoritative and is not
  overridable via env/flag (SEC-2). Either way `-update-pubkey`/`ROUTINEOPS_UPDATE_PUBKEY`
  is only a dev-override for keyless builds and never bypasses an embedded key. The
  agent refuses to fetch a CA over the network (`-ca-url`) without a pinned SHA-256
  (`-ca-sha256`). CA distribution is pinned on every channel: the Windows MSI and the
  macOS `.pkg` both ship the CA inside the (signed) installer payload, and the
  server-generated install script (`GET /api/v1/installer`) passes `-ca-url` with a
  `-ca-sha256` pin rather than an unpinned download.
- Every privileged panel action (script dispatch, lock/unlock, enroll/reenroll,
  policy and admin-access changes) is written to the audit log.
- Security response headers (HSTS/CSP/X-Frame-Options/nosniff), request-size cap,
  rate limits.

## What YOU must do (operator responsibility)

The server host is the crown jewel — harden it:

1. **SSH** — key-only auth, disable password login, disable direct root login,
   restrict source IPs.
2. **sudo** — least privilege; dedicated deploy user; avoid passwordless sudo for
   humans.
3. **Firewall** — expose only what is needed (panel/enroll `443`, the gRPC port).
   Bind Postgres and Redis to localhost / a private network — never the public
   interface.
4. **TLS** — serve the panel only over HTTPS with a real certificate (the server's
   own TLS or a reverse proxy). Enable the secure-cookie setting. Never plain HTTP.
5. **Secrets** — generate strong random values, keep them out of git and away from
   shared readers:
   - `JWT_SECRET`: `openssl rand -base64 48`; file mode `600`; rotate on any
     suspicion of exposure (see `docs/jwt-secret-rotation.md`).
   - Release signing key and CA private key: mode `600`, offline backup, never
     committed.
   - Database / Redis passwords: strong, not defaults.
   - `.env.prod`: mode `600`, not group/world readable.
6. **Panel access** — limit who holds admin accounts; put the panel behind a VPN or
   IP allowlist where possible; consider an authenticating proxy with 2FA in front.
7. **Backups** — regular encrypted database backups, and test the restore.
8. **Updates** — keep the server, its base image, and the OS patched.
9. **Monitoring** — ship the audit log to append-only storage; alert on new admin
   users and on unusual mass script dispatch.

## Reporting a vulnerability

If you find a code-level issue — something the application itself should enforce
but does not — report it **privately** through
[GitHub Security Advisories](https://github.com/Floodww/RoutineOps/security/advisories/new)
(Private Vulnerability Reporting is enabled on this repository) rather than opening
a public issue. Please allow up to 7 days for an initial response.
