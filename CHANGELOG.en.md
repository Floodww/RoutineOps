# Changelog

> Русская версия: [CHANGELOG.md](./CHANGELOG.md)

Kept from version 2.4.6 onward. Earlier versions shipped without a changelog and were
not reconstructed retroactively.

Format: one section per release, grouped by area, listing changes an operator would
notice. Entries marked **[Enterprise]** cover capabilities absent from the free edition.

The product (server + web) and the agent are versioned separately: the product uses
the `VERSION` file, the agent uses `AGENT_VERSION`. A release may touch only one side
(e.g. an agent fix does not move the server version, and vice versa).

---

## Unreleased (in main after 2.5.0)

### Devices

- Device owner on the device page: manual assignment to a panel user
  (`PUT /devices/{id}/owner`); a manual owner takes precedence over the automatic one.
- **[Enterprise]** User directory (LDAP / Active Directory): a "Directory" page —
  connection (ldaps), test, scheduled and manual sync; automatic device-owner
  assignment by exact console-user SID match with a login fallback; disabled
  accounts never match; the binding survives account renames (canonical key —
  objectGUID). The free edition ships without the directory code entirely
  (`/directory/*` → 501).

---

## 2.5.0 — 24 July 2026

A server-and-web release: panel and server changes accumulated since 2.4.8 —
decommissioning from the device page, pagination, config-as-code, API tokens — plus
exact identity matching in the macOS keystore.

### Devices

- Decommission a device straight from its page: a button gated by typing the
  hostname; the server queues a full agent self-removal and flips the status to
  "decommissioned" once the agent confirms.
- "Console user" on the device page — who is at the machine now (Windows:
  `DOMAIN\user`; macOS/Linux — the active session login).
- Device and audit-log lists are paginated (`X-Total-Count` header); audit-log
  filters are evaluated on the server.

### Security

- Deleting a device from the inventory revokes its certificate: a deleted device with
  a live agent no longer "resurrects" as an empty record on its next connection.
  "Delete from inventory" on the device page is now available only for
  already-decommissioned devices.
- macOS keystore: the agent's identity is resolved by an exact certificate-name
  match. Previously, on a shared System keychain (holding third-party VPN/Wi-Fi
  identities), the agent could pick up a certificate that was not its own; key
  removal on teardown is now targeted as well.

### Management

- Issue and revoke API tokens from the panel (role, lifetime; the token is shown
  once). Previously tokens were issued only by a manual API call.
- Config-as-code: export and apply scripts, policies and groups via YAML and the
  `routineops` CLI. A resource's identity is its name (script and policy names are
  now unique).
- Bulk enrollment tokens: revocation and listing; a "not connected" section in the
  enrollment queue.

### Compatibility

- Database migrations are applied automatically on server upgrade.
- The product (server+web) and the agent are now versioned separately (`VERSION` and
  `AGENT_VERSION` files) — a release may move only one component.

---

## 2.4.9 — 24 July 2026

An agent release: decommissioning is now carried through to the end on macOS and
Linux — a decommissioned device is left with no files, no keys and no way back
into the fleet.

> This release covers the agent only. Server and web changes accumulated since
> 2.4.8 (including the decommission button on the device page) will ship with
> 2.5.0.

### Devices

- Decommissioning on macOS is now complete. Previously the removal aborted right
  at the start: deregistering the service instantly terminated the agent process
  that was performing the removal — a "decommissioned" machine kept the agent
  binary, keys, data, autostart entries and the installer record, while the
  console reported success. The service is now deregistered as the last step,
  after the files are gone; Windows and Linux behaviour is unchanged.
- The macOS installer record (.pkg receipt) no longer survives decommissioning:
  the package is forgotten by the system along with the other traces of the
  installation.
- Decommissioning on Linux also revokes the installation itself: the enrollment
  file with its multi-use token and the bootstrap certificate are removed, and
  the package is deregistered from dpkg/rpm. Previously reinstalling the package
  with standard system tools silently brought a decommissioned machine back into
  the fleet.
- The agent's key material is also removed when the system key store is in use:
  the certificate and private key pair is purged from the macOS Keychain and
  from the Windows certificate store (together with the private CNG key).
  Previously it stayed in the system indefinitely in this mode. On Windows the
  certificate name is matched exactly before anything is deleted, so unrelated
  entries are not touched.

### Compatibility

- Upgrading the agent from 2.4.8 requires no manual steps.
- The server side is not rolled out by this release: production servers stay on
  2.4.8, and the accumulated server and web changes will ship with 2.5.0. Note
  that the v2.4.9 tag is cut from the shared development branch and does
  physically contain those changes together with migration 033 (unique script
  and policy names; duplicates get renamed). The standard `update.sh` upgrades
  the server as a whole and would apply it — to upgrade agents only, publish the
  agent artifacts (publish-release / the releases directory) without rebuilding
  the server.

---

## 2.4.8 — 23 July 2026

A follow-up release: complete agent removal on Windows, and visibility when a lock fails
to apply.

> Version 2.4.7 was prepared but never shipped: it carried the decommissioning bug
> described below. All of its changes are included in 2.4.8.

### Devices

- Decommissioning on Windows is now complete: the tray icon holding the agent file is
  terminated, tray autostart is removed, the installation directory is deleted in full,
  and the package itself is uninstalled properly — along with its entry in Add or Remove
  Programs. Previously a decommissioned device kept files, an installation record and a
  tray icon that came back at the next sign-in.
- Directory removal during decommissioning is limited to the agent's own installation
  directory. If the agent was running from somewhere else (a manual placement next to
  unrelated files), that directory is no longer deleted as a whole — only the agent
  file itself is removed. A regular package installation behaves as before.
- The agent service is deregistered before processes are force-terminated. Otherwise the
  system's configured service recovery could bring the agent back mid-removal, leaving it
  holding its own file.

### Security

- A failed lock is now visible to the operator: a device where the lock did not come up
  is flagged in its device page, the event is written to the audit log and sent as a
  notification. Previously the console showed "locked" while the device stayed fully
  usable, and the discrepancy was visible nowhere. The assigned lock is preserved — the
  agent keeps retrying.
- The device page now shows the actual lock state reported by the agent next to the
  assigned one. Intermediate FileVault states (key revoked but reboot not yet done;
  revoke not completed) became visible too — they were recorded in the database but
  never displayed.

### Known limitations

- **Windows, decommissioning during a system update.** If Windows Installer is busy with
  another installation while the agent is being removed, package removal is retried six
  times at roughly ten-second intervals. If the system stays busy longer, files are
  removed by a fallback path, but the Add or Remove Programs entry remains — it does not
  clear itself and has to be removed manually or by reimaging.

### Compatibility

- Upgrading from 2.4.6 requires no manual steps: the release contains no database
  migrations.

---

## 2.4.6 — 22 July 2026

A large release: two rounds of adversarial review of the agent, bulk enrollment,
device decommissioning and extended inventory.

### Security

- Device lock: a stale lock confirmation delivered by the agent after an unlock no
  longer resurrects the desired "locked" state without a password. Previously a device
  could be shown as locked in the panel while remaining fully usable, and the
  divergence was invisible to the operator.
- Device lock: the record of a local unlock moved to the protected state directory.
  Kept in a user-writable directory, it allowed re-locking to be suppressed
  indefinitely.
- Device lock: a command carrying an invalid password hash is now rejected by the
  agent — previously such a command produced a lock that could not be lifted offline.
- The service state directory on Windows is protected by an admin-only access list,
  with a check against directory substitution through a reparse point (junction).
- Device lock: a stale unlock report delivered by the agent from its queue after a NEW
  lock had been issued no longer cancels it. Previously a device returning from being
  offline silently disarmed a freshly issued lock.
- Device lock: a failure to apply a lock no longer goes unnoticed by the agent — the
  state is rolled back, the attempt is retried, and the failure is logged. Previously
  a single disk write failure suppressed the lock indefinitely.
- Console-user detection on Linux no longer mistakes a seatless session (ssh, cron)
  for a local login.
- A task result delivered outside the durable queue is no longer lost silently: the
  agent now checks the server acknowledgement.
- Closed 16 findings from the agent readiness audit for fleets of 1000+ machines, and
  17 findings from three rounds of adversarial review on top of it.

### Known limitations

- **Windows, device lock.** A local user with access to the lock state file can clear
  the lock without the password and suppress re-locking until an operator intervenes.
  That file's directory is deliberately user-writable — the lock screen and the tray
  icon rely on it. The fix requires reworking that channel on Windows and is planned
  for 2.4.7.
- **Lock application failures are not visible everywhere.** If the agent could not
  raise the lock, it retries and logs the failure, but the panel does not yet reflect
  this as a distinct state — planned for 2.4.7.
- **Upgrading from 2.4.5 while a lock is active.** If an employee cleared the lock
  locally, the server has not yet received that report, and the upgrade arrives at
  exactly that moment, the device may be locked again. The window is narrow and the
  state self-heals once the server receives the report. This is deliberate: an extra
  lock is preferable to a lost one.

### Enrollment

- Bulk enrollment: one token per batch of devices instead of one token per device.
- Approval queue: a device requesting enrollment waits for an operator decision.
  Re-enrollment no longer promotes a rejected or blocked device into a managed state
  bypassing approval.
- Enrollment screen in the web interface: approval queue, bulk token issuance and a
  single map of device statuses.

### Devices

- Decommissioning: a server-side command for complete agent removal — service
  uninstall, tamper protection disarm, deletion of state and binary. The status
  becomes terminal only after the agent confirms.
- Extended inventory: CPU model, serial number, boot time, free disk space, console
  user and other fields.
- Inventory fields are now sticky: a single probe failure no longer overwrites a
  previously collected value with an empty one.
- Agent self-removal on operator command.

### Tasks and scripts

- Results of ad-hoc tasks survive agent restarts and connection loss (durable on-disk
  queue).
- Tasks stuck in the "acknowledged" state are closed by timeout, and a late result no
  longer silently replaces an already closed task.
- A cap on the number of scripts executing concurrently on a device.
- A script leaving a background process behind no longer stalls the task channel.

### Integrations and API

- Service API tokens for automation (issuance and revocation by a human only).
- Resilient connection to Telegram under partial ISP blocking.

### Web interface

- Interface redesigned: a dark liquid-glass theme across every page and every control —
  panels, forms, tables, dialogs.
- Navigation grouped: overview, alerts, audit log, then hosts, management, settings.
- Compliance policies: pass/fail breakdown per device, and a truthful rule creation
  form.
- Dashboard: event taxonomy, distribution by operating system, text contrast raised to
  AA level, and a correct count of acknowledged alerts.

### Installation and packages

- `.deb` and `.rpm` packages for the Linux agent.
- Environment files with Windows line endings no longer break installation on Unix.

### Enterprise

- **[Enterprise]** Licensing: validation core, server-side entitlements, a "License"
  page in the web interface, and an offline vendor CLI for issuing licenses. Expiry is
  checked at the moment of the operation rather than by a background tick.
- **[Enterprise]** FileVault: closed review findings on the revocation mechanism and
  recovery key escrow.

### Compatibility

- Upgrading from 2.4.5 requires no manual steps: database migrations are applied at
  startup and agent state is migrated automatically.
