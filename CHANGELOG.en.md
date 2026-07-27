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
- **Remote device reboot.** An operator can reboot a machine from the panel — to finish
  installing updates, for instance, or to bring a stuck device back. The employee gets a
  grace period (one minute by default) to save their work; once it expires the reboot is
  forced — otherwise a single window with an unsaved file would silently cancel the
  operator's command and leave the device unchanged without a trace. On Windows the
  employee sees a system warning carrying the stated reason; on macOS and Linux the
  warning only reaches terminal sessions, not the graphical one (a tray notification is
  a separate step). The grace period is counted by the operating system, not by the
  agent: a timer inside the agent would vanish when it self-updates or the service
  restarts, and the reboot would silently not happen while the task reported "done". If
  the OS scheduler refuses the command (no privilege, another reboot already scheduled),
  the task fails with the reason rather than reporting a false success. In the panel this
  is the "Reboot" item on the device page: pick a grace period and a reason, which on
  Windows ends up in the warning the employee sees. "Immediately" in the list means ten
  seconds, not zero — the grace period *is* the protection for unsaved work, so it cannot
  be set to zero. Clicking again on the same machine lands in the same task and never
  causes a second reboot. The panel says "scheduled", not "rebooted": the machine goes
  down on the operating system's timer, and the confirmation arrives before that moment.
- **Group-wide reboot** for maintenance windows. Only machines that are in service are
  rebooted; the panel shows their count and confirms exactly that number, and if the
  group changed in the meantime the command does not go out. No more than 50 machines at
  a time: this is the heaviest button after decommissioning, and a misclick on the wrong
  group must not take the fleet down during working hours.
- **[Enterprise] Export of the escrowed FileVault recovery key.** The device page now
  lists the escrowed secrets (when they were escrowed, by which agent, who exported them
  and when), and the current one can be downloaded. The server hands it over **still
  encrypted** — it cannot decrypt it by design; the file is opened offline with
  `routineops-unseal` using shares of the private key, and the panel shows the exact
  command with the right arguments: nobody should be recalling it from memory during an
  incident. Exporting requires a separate `can_reveal_escrow` grant (issued by a database
  administrator by hand — there is no role for it) and is closed to service tokens: this
  is the key to an encrypted disk. Both the export and every refusal land in the audit
  log — an attempt to obtain a recovery key is a security event even when it fails. The
  newest record is always the one served: a re-issue rotates the key, and a stale one
  will decrypt fine yet no longer unlock the machine.
- **[Enterprise]** User directory (LDAP / Active Directory): a "Directory" page —
  connection (ldaps), test, scheduled and manual sync; automatic device-owner
  assignment by exact console-user SID match with a login fallback; disabled
  accounts never match; the binding survives account renames (canonical key —
  objectGUID). The free edition ships without the directory code entirely
  (`/directory/*` → 501).

### Inventory

- **Windows: software installed into a user profile is now visible.** Only the
  machine-wide part of the registry was read before, so applications that install into
  a profile (browsers, messengers) never reached the inventory at all — and the
  forbidden-software policy did not see them either, meaning a per-user install bypassed
  the ban. Such entries are now listed and marked as per-user. The service cannot remove
  them (the install lives in someone else's profile), which is stated honestly: no
  "remove" action is offered for them.
- **Service noise removed from the software list.** Entries the installer itself marks
  as hidden from "Programs and Features" (runtimes, driver packages) and updates that
  declare themselves children of a product (patches, language packs) are no longer shown
  as separate software. The parent product stays in the list. If a forbidden-software
  rule was written against such a service entry, it will stop matching — point the rule
  at the product itself.
- **More data is collected per application:** publisher, install path, architecture, a
  machine-readable removal identifier and a machine-vs-profile marker. This is the
  groundwork for removing software from the interface and for vulnerability scanning: a
  single human-readable name cannot tell apart same-named products from different
  vendors. Install date is deliberately not collected — its format diverges between
  sources, and an unstable value would make the whole fleet re-send its inventory every
  five minutes. Publisher and architecture are shown on the device page; architecture
  appears exactly as the source reports it (`amd64` from one package manager, `x86_64`
  from another) — collapsing it into a single vocabulary would drop data needed for
  future vulnerability scanning.
- **A per-profile install now counts as a policy violation.** In a forbidden-software
  rule breakdown such machines land in "Fail", and the match is tagged "installed in
  user profile": there is nothing to remove it with, but the operator must know about
  it — that is precisely how the ban was being bypassed. When forbidden software is
  found both machine-wide and in a profile, the example shows the machine-wide install:
  that one can actually be acted upon.
- After the agents update, the fleet re-sends its full inventory once (the snapshot
  composition changed); after that, sending resumes happening only on real changes.

### Security

- **Windows device lock: password-free release closed** (a known limitation of the
  2.4.6 release). The lock screen no longer marks the device unlocked itself — it
  hands the typed password to the service, which re-checks it and releases the lock
  authoritatively, exactly as macOS already does. Any "unlocked" that appears in the
  state file behind the service's back is now treated as tampering: the lock is
  written back, the screen is raised again, and no re-lock suppression is recorded —
  so a reboot no longer leaves the device open. For the employee a single change is
  visible: after the correct password the screen closes once the service confirms
  (a fraction of a second), and if the service is stopped it says so instead of
  releasing silently.
- **Attempts to release the lock behind the service's back are now visible in
  security.** Previously such tampering only restored the lock and went to the agent
  log — nothing reached the console, and the security team never learned an attempt
  had been made. The agent now sends a security event. The event reports an ATTEMPT,
  not a success: the lock stays in force. Repeats are deliberately damped — at most
  one event per device per 15 minutes: the watchdog checks the file every second, and
  an event per check would push reports that cannot be reconstructed out of the
  delivery queue. Every attempt still lands in the agent log. In the console such an
  event appears as its own type, "Lock bypass attempt", and sorts first: it is the only
  alert type that means a live intruder on the device right now, rather than a policy
  violation noticed after the fact.
- **Telegram notifications: an undelivered message is no longer counted as sent.** The
  server did not check Telegram's response at all — any refusal (a bot blocked by the
  employee, rate limiting, a rejected message) looked like a successful send, and the
  alert vanished without a trace in the log. Refusals now reach the server log with a
  reason. Along with it, one way to suppress delivery using the device's own data is
  closed: hostname and detail text come from the agent and were interpolated into the
  formatted message as-is, so a single markup character in them broke parsing on
  Telegram's side — and the alert about a device was silenced by that same device's data.
- **[Enterprise] FileVault lock: secrets now travel over a separate arming channel.**
  The recovery key and the service administrator password are no longer meant to ride
  inside the lock command itself: the command is stored in the database, and a secret
  does not belong there for a single second. Instead the operator "arms" an already
  issued lock as a separate action (`POST /devices/{id}/lock/arm`) — the secret reaches
  only the server's memory, lives for a bounded time (15 minutes by default) and is
  handed to the agent exactly once. Only a device with an already issued FileVault lock
  can be armed, and only by a human: automation and service tokens are refused. A server
  restart clears the arming — the lock will not apply until the operator arms it again;
  this is deliberate, because the alternative is keeping the administrator password on
  disk. The audit log records the fact of arming, never the secret values.
- **[Enterprise] FileVault lock: the key is matched against escrow before the
  irreversible step.** Before stripping disk-decryption rights, the agent now verifies
  that the recovery key (and service administrator password) supplied by the operator
  is the one held in this device's escrow. Previously only two things were confirmed —
  that "some key reached the server" and that "the key unlocks the volume" — but not
  that they were the SAME key: after a rotation the operator could supply a key from a
  stale record, leaving the disk sealed with a key that escrow does not hold. A
  mismatch, or the absence of anything to match against, stops the operation BEFORE the
  first irreversible action. Devices escrowed before this release have nothing to match
  against — for them the operation stops until provisioning is run again.
- **[Enterprise] FileVault lock: the disk-owner list was being read past.** Before
  stripping rights, the agent enumerates everyone able to decrypt the disk and strips
  rights from all but the service administrator. The second, backstop source of that
  list was parsed incorrectly — it looked for a label the system does not print, and so
  never contributed a single owner. The check effectively rested on one source instead
  of two. Parsing now matches the real output format and has been verified against a
  live machine. It also accounts for the recovery key being listed alongside user
  accounts: it is not an owner to be evicted — it is precisely what support uses to
  open the disk after a lock. An unrecognised entry type (for example Apple ID
  recovery, which an employee can enable themselves and which defeats the lock) now
  stops the operation instead of being skipped silently.
- **[Enterprise] FileVault lock: a refusal before the irreversible step no longer
  stays silent.** When the lock cannot be applied (the key does not match, the service
  password is rejected, the owner list cannot be read), the device is left untouched —
  but until now the server was not told either: the console showed an issued task while
  the laptop kept working. The agent now reports an unapplied lock the same way it
  reports a partial failure — with an audit entry and a security alert. Repeats are
  damped to one message per hour per command: the agent re-checks desired state every
  thirty seconds, and a persistent misconfiguration would otherwise flood the inbox.
- **[Enterprise] FileVault lock: the service password is no longer visible in the
  process list.** On macOS the command-line arguments of any process — including ones
  running as root — are readable by every user of the machine. While the agent stripped
  decryption rights, the service password was briefly visible to the very employee it
  was being stripped from: reading it in time would let them grant themselves access
  right back. Both lock operations now pass the password to the system utilities over a
  hidden channel, using the built-in mode Apple itself calls preferable. For the
  one-off device setup operations the previous method is deliberately kept: two
  passwords take part in a single command there, the hidden channel carries one, and
  switching would protect the less valuable of the two at the cost of breaking a
  working setup flow.

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
