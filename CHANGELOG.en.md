# Changelog

> Русская версия: [CHANGELOG.md](./CHANGELOG.md)

Kept from version 2.4.6 onward. Earlier versions shipped without a changelog and were
not reconstructed retroactively.

Format: one section per release, grouped by area, listing changes an operator would
notice. Entries marked **[Enterprise]** cover capabilities absent from the free edition.

The version number is shared by the server, the web interface and the agent.

---

## 2.4.6 — upcoming

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

- Dark theme across all pages.
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
