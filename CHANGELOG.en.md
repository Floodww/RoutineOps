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

## 2.11.0 — 18 August 2026

Product release (server + web). The agent does not move — stable 2.6.9. Minor rather than
patch: a capability that used to stop at a licence check is now available to the free edition.

### Software removal

- 🔴 **Removing installed software works in the free edition.** The button was present on
  every device card, but on a free installation the server answered "licence required" (402) —
  in practice the capability only existed on an enterprise installation. The endpoint is now
  mounted in the open-source build with no licence gate: removal is available under the same
  permissions it had on a paid installation, and the agent still verifies the target and
  removes the package by the method it determined itself.

### Agent releases and updates

- 🔴 **A published agent version is now immutable.** Publishing the same number (OS,
  architecture, version) again with different bytes is rejected with an explanation instead of
  silently overwriting the filename, sha256 and signatures of a row that has already been
  handed out — which is exactly how the Windows 2.6.8 build changed both its bytes and its
  channel under one number on 12 August. The only legitimate mutation of a published row is
  the channel change that promotes a canary, and it requires a matching sha256. Re-running the
  publication of the same commit still succeeds: the build is reproducible.
- **A failed agent publication no longer rolls back a server hotfix.** The server and web
  come up before the publication step, so a failure there stops `./update.sh` loudly without
  taking the product update that already shipped down with it.

## 2.6.12 — 17 August 2026

Canary agent release (**beta** channel). The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] Maintenance mode is now continuous: one live session follows the
  machine everywhere.** Previously the secure desktop (UAC, Ctrl+Alt+Del) paused the picture
  and the lock screen ended the session — you could not walk a machine through an elevation
  prompt or unlock it without starting over. The session now runs continuously across the
  employee desktop, UAC, and the lock screen in both directions: the operator types the admin
  password right in the UAC prompt or on the lock screen and unlocks the machine without
  interrupting the session.
- **[Enterprise] The employee is notified through the audit log only.** A notice banner
  cannot be drawn on secure desktops, and in this mode it is not shown on any desktop; the
  operator's connection is recorded by the `screen_session_maintenance_granted` audit entry.

## 2.6.11 — 15 August 2026

Canary agent release (**beta** channel). The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- **[Enterprise] The Windows agent advertises maintenance-mode support.** The
  `screen_maintenance` capability is now declared, and the server stops rejecting a maintenance
  invitation (409) on such agents. The behaviour is turned on by the invitation flag; non-Windows
  and older builds do not advertise the capability, and such a request is refused honestly rather
  than silently downgraded to a regular session.

## 2.6.10 — 13 August 2026

Canary agent release (**beta** channel). The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- **[Enterprise] Frame delivery pause is a distinct session state.** The pause on the secure
  desktop (§9.11) is separated from a disconnect and reaches the operator as its own signal:
  the operator sees "frame delivery paused" instead of a frozen, unexplained screen.

## 2.6.9 — 13 August 2026

Agent release (**stable** channel). The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] On the secure desktop, frames pause instead of ending the session.** On a
  UAC or Ctrl+Alt+Del prompt during a live session, frame delivery pauses (60-second ceiling)
  while the session itself continues — previously the secure desktop looked like a frozen or
  dropped remote session. The lock screen still ends the session.
- **[Enterprise] Agent release selection is by highest version, not publish time.** Devices in
  the beta group no longer accidentally receive a fleet stable build published after the canary.
- **[Enterprise] Maintenance-mode groundwork laid (not yet active).** The `screen_maintenance`
  capability and its server gate (409) appear; a maintenance invitation without control is
  refused (400) rather than turned into a silent session.

## 2.6.8 — 11 August 2026

Canary agent release (**beta** channel). The product (server + web) does not move — 2.10.0.

### Self-update

- 🔴 **Rollback protection no longer locks a machine onto a version that never ran.** The
  floor was raised by a SUCCESSFUL FILE REPLACEMENT rather than a successful start: if the
  new binary landed on disk but the process did not come up afterwards (a corrupt build, an
  incompatible library, a startup failure), the machine refused that version forever and
  **silently** — including a fixed rebuild under the same number — while the documented
  recovery from the backup copy never touched the floor. The floor is now raised by the
  first successful start, and a refusal caused by it is logged with every number and the
  file path instead of silence.
- **The previous binary's backup copy is removed on confirmation, not at startup.** An
  agent that came up and died two seconds later used to delete its only recovery path
  before breaking.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] Control now works against windows started as administrator.** The system
  used to silently discard input aimed at a window with higher privileges: the operator saw
  a healthy picture and rising counters while the cursor stood still and clicks went
  nowhere — a Task Manager left in the foreground was enough. The screen capturer now runs
  with system privileges, which also removes the loss of control at the moment of an
  elevation prompt (UAC).
- **[Enterprise] Input follows the desktop the system switches to** — the binding is
  refreshed before every batch of events instead of once per session. Input is deliberately
  not delivered to the secure desktop (lock screen, UAC, Ctrl+Alt+Del): that is the
  territory of the rule "locking the screen ends the session".
- **[Enterprise] Detecting the secure desktop no longer relies on being denied access.**
  With system privileges the secure desktop opens, so the former signal ("access denied,
  therefore we are on the secure desktop") would have answered backwards on the lock screen
  and the rule would have stopped firing exactly where it is the only safeguard. The signal
  is now the desktop's name.

## 2.6.7 — 10 August 2026

Canary agent release (**beta** channel). The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] Control diagnostics now state the cause in words, not by hint.** The
  field run of 2.6.6 reached the cause: input is dropped by UIPI — the foreground window
  sits at a higher integrity level than the agent. The previous reading scheme was
  **actively misleading**: "setting the cursor position directly did not help" was taken to
  mean a foreign desktop, whereas it obeys the very same UIPI and, in the actual field case,
  would have sent the investigation the wrong way. The diagnosis is now printed as its own
  line together with what actually fixes it, instead of being inferred by the reader from
  two flags.
- 🔴 **[Enterprise] The self-check no longer shows green while clicks are dead.** It hung on
  the first mouse move only, so in two field sessions the log reported "input reaches the
  OS" while not a single click went through — an hour and a half of investigation went into
  a green line over a live defect. A first-click check was added, and the counters are now
  split by input kind: moves, buttons, keys, wheel (a single total cannot tell "buttons
  never arrived" from "they arrived and were dropped").
- **[Enterprise] The notice card no longer gets clipped by display scaling.** At 1920×1200
  and 125% it ran off the bottom-right corner: the work area is taken in physical pixels
  while the content is laid out in 96-DPI units — the two agree at 100% and diverge above
  it. Sizes are now derived from the **window's** DPI (scaling differs per monitor) and
  clamped to the work area.
- **[Enterprise] A probe for reaching elevated windows — behind a flag, off by default.** The
  service runs as LocalSystem and can set the UIAccess bit in the capturer's token directly,
  with no certificate purchase and no rollout of an internal certificate authority to every
  machine. The hypothesis is being verified in the field; a refusal is safe — without the
  bit the capturer behaves exactly as before. Enabling it fleet-wide is a separate decision
  and a separate release: it changes the agent's privilege model.

## 2.6.6 — 10 August 2026

Canary agent release (**beta** channel). The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- **[Enterprise] The log now names the foreground owner and both integrity levels.** The
  field run of 2.6.5 ruled out two explanations of three; the third remained — the event is
  accepted and dropped after acceptance. Only a process inside the session at the moment of
  injection can observe that: a process list captured over SSH an hour later answers a
  different question. The foreground window's process, its level and **our own level next to
  it** are logged — the rule is about the relation between levels, so one number without the
  other means nothing. The window title is deliberately not captured: it can carry file
  names and an employee's correspondence.
- **[Enterprise] The two remaining branches are separated by a single probe.** Setting the
  cursor position directly bypasses the synthetic input queue; it runs once per session and
  only after input has already failed — moving an employee's cursor without cause is not
  acceptable.

## 2.6.5 — 10 August 2026

Agent release. The product (server + web) does not move — 2.10.0.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] The mouse pointer now appears in the frame.** It never did: the system
  screen capture on Windows does not include the cursor under any setting, and on macOS it
  had been switched off back during measurements. That was harmless while sessions were
  watch-only; with control it turned out the operator was moving a mouse they could not
  see, with nothing to aim by — the only way to locate the pointer was to bump into
  something visible. Linux still has no cursor: it requires a separate mechanism there, and
  that work is not done.
- **[Enterprise] Control diagnostics now name the whole environment.** The previous log line
  printed the desktop name — not enough: the interactive and the service desktop share a
  name, so "Default" looked identical whether input worked or went into a queue nobody
  reads. The window station, the session number and the desktop that owns input are now
  logged, stating plainly whether it matches the thread's desktop.
- **[Enterprise] The input thread is pinned to the input desktop.** Previously the binding
  depended on which system thread the code happened to run on — that is, it worked
  sometimes, and such a defect reproduces every other time.
- **[Enterprise] The first-move self-check no longer rules instantly.** The system accepts
  an event before it processes it, and the "did the cursor arrive" check ran before there
  was anywhere for it to arrive: it reported a fault on a healthy machine just as
  confidently. It now waits and retries, and the log shows how long the cursor took.

## 2.10.0 — 10 August 2026

Product release (server + web). The agent does not move — 2.6.4. Minor rather than patch:
a migration, a new endpoint, a new interface section and **a changed default for existing
installations**.

Deliberately its own number rather than an addition to 2.9.0: that release is about owner
records and the compliance report, and folding a fleet-wide doubling of the frame rate
into its section would misstate the very text an operator reads before upgrading. It also
keeps "roll back to 2.9.0" a working answer for a tenant whose link could not take it — a
bandwidth rollback then does not drag along the compliance fix, which has nothing to do
with bandwidth.

### Remote desktop (Enterprise)

- **[Enterprise] Session quality is no longer a constant; it is a tenant setting.** Until
  now every session ran the "1 frame per second, up to 1280 px" profile — not by decision,
  but because the bandwidth budget had been computed from the worst case (a full frame
  refresh every frame). Field measurement showed the worst case does not occur: a session
  with control takes 1.6–1.7% of the allotted bandwidth. A new section, **"Screen access" →
  "Quality and frame rate"**, offers two values: `medium` (2 fps, up to 1920 px) and `low`
  (1 fps, up to 1280 px).
- **[Enterprise] This is a tenant ceiling, not an operator's choice.** The server still
  assigns the profile when issuing the invitation; the setting defines the upper bound a
  session cannot exceed. Changing the ceiling is recorded in the audit log as its own
  action.
- 🔴 **[Enterprise] Control no longer continues after the recording breaks.** The rule "no
  recording, no control" existed from the start but never took effect: the "session with
  control" flag never reached the frame loop, so a broken recording terminated nothing. The
  operator kept working on the employee's machine while no trace of those actions was being
  kept. Such a session is now closed on the very frame where the recording broke; a
  watch-only session continues, as before, marked "recording incomplete".

### 🔴 Read before upgrading

- **The default changes for existing tenants, not only new ones.** The migration sets
  `medium` across the fleet at apply time. This is deliberate: the measurement was taken on
  a live machine, and keeping working installations on a knowingly worse profile out of a
  caution that same measurement refuted would mean not using the result. To restore the
  previous behaviour: "Screen access" → "Quality and frame rate" → `low`, per tenant, with
  no restart and no agent rebuild.
- **Session recordings take noticeably more space.** On `medium` frames arrive twice as
  often and each is heavier (2.25× the area, higher quality), so the same day of
  observation weighs several times more — modest on quiet work, a multiple on busy work
  (window dragging, scrolling, video). Per-tenant capacity is expressed in bytes (20 GiB by
  default), not hours, so more volume means less time before the cap. The consequence is
  not about disk but about evidence: a recording is marked truncated sooner, and a session
  WITH CONTROL is terminated when its recording breaks — controlling a machine without
  evidence is not permitted by contract.
- **The per-session recording ceiling now scales with the profile.** 512 MiB was chosen as
  a duration (≈ 47 minutes at the `low` bandwidth ceiling), not as a volume: on `medium`
  the same byte count would mean ≈ 22 minutes, silently halving the longest possible
  support session. The ceiling now scales with bandwidth, preserving that duration.
- **Both capacities are now configurable:** `ROUTINEOPS_SCREEN_SESSION_MAX_BYTES` and
  `ROUTINEOPS_SCREEN_TENANT_MAX_BYTES` (e.g. `40GiB`). Previously "raise the quota" meant
  rebuilding the server.
- Usual order: apply migrations before starting the new server.

## 2.9.0 — 7 August 2026

Product release (server + web). The agent does not move and ships under its own number,
2.6.4. Minor rather than patch: deleting owner records is a new capability.

### Devices and owners

- **Owner records can now be deleted.** Creating one was possible from the start, removing
  one was not: the list filled up with test entries, and picking an owner in a device card
  lost its meaning. Deletion lives on the separate "Owners" page rather than in the device
  card: it removes the owner from ALL of their machines, and inside a single device card
  such an action would read as "remove the owner here". The confirmation says so plainly.
  Records synchronised from a directory have no button — those are removed in the
  directory itself.

### Compliance

- 🔴 **The Compliance section no longer accumulates unused enrollment tokens.** A device
  row is created when a token is issued, not when an agent connects, and until now every
  unused row appeared in the report as a permanently non-compliant machine that "has not
  been seen". The report answered "how many tokens were issued" rather than "what state is
  the fleet in", and the clutter grew on its own. Unenrolled devices are excluded from the
  report — they remain visible in the enrollment queue, where they belong.

### Audit log

- **Server action codes no longer reach the interface raw.** Some entries were shown as a
  technical string such as `screen_recording_view_denied` instead of a human description.

### Remote desktop (Enterprise)

- **[Enterprise] The recording button is no longer offered without the grant to view
  recordings.** The grant is revocable and issued separately, yet the button was shown to
  everyone: an administrator without it clicked and received a bare refusal code for an
  action the interface itself had offered. The journal row now shows that a recording
  exists, and explains who issues access, with a link to the page where it is granted.
- **[Enterprise] Early input no longer costs the operator control for the rest of the
  session.**
- **[Enterprise] Session quality (dropped frames and bandwidth stalls) is now stored in
  the session journal** — "the picture stutters" and "the picture lags" became
  distinguishable.

## 2.6.4 — 7 August 2026

Agent release. The product (server + web) does not move. Diagnostics only: no new
capabilities, session behaviour is unchanged.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] Input in a control session now leaves traces in the agent log.** The
  field showed a failure with no symptoms at all: the operator clicks, the server records
  event after event, nothing happens on the employee's screen, and neither the agent nor
  the service writes a single line about it. "No errors" meant three different things at
  once — the events never arrived, they arrived and were applied in the wrong place, or
  they were applied and discarded by the operating system itself — and there was nothing
  to tell them apart.

  The session heartbeat now carries counters of accepted, applied and rejected events, the
  first batch of input is printed together with the full coordinate mapping, and input
  skipped because the desktop changed is no longer silent. Windows adds two checks for the
  same question: the name of the desktop the injecting thread is bound to, and a
  comparison of the first move against the cursor's actual position — the system accepts
  an event even when it lands nowhere.

- **[Enterprise] Session quality is visible in the session journal.** The agent has been
  counting dropped frames and bandwidth stalls since telemetry first appeared — and the
  server discarded both numbers. "The picture stutters" and "the picture lags" are
  different faults with different causes, and there was no way to tell them apart.

## 2.6.3 — 7 August 2026

Agent release. The product (server + web) does not move. A patch on top of 2.6.2: a
transport defect and diagnostics, no new capabilities.

### Remote desktop (Enterprise)

- 🔴 **[Enterprise] Observation sessions on Windows finally show a picture.** Until this
  release they never did, on any machine: the session opened, the screen geometry reached
  the panel, and not a single frame arrived — with a live capture process and no error in
  any log. The channel between the service and the capture process was opened in a mode
  where Windows performs reads and writes one after another rather than simultaneously,
  and both sides always have a read outstanding, so the very first frame could never leave.
  Operator input failed to reach the device for the same reason — it was one defect, not two.
- **[Enterprise] The frame-loop heartbeat names its phase.** Alongside the number of frames
  handed off and the time since the last iteration, it now reports what the loop is actually
  doing: waiting for the pacer, grabbing, encoding, assembling a frame, or writing to the
  channel. Diagnosing "no frames" now starts from one log line instead of a list of suspects.

## 2.6.2 — 6 August 2026

Agent release. The product (server + web) does not move. A patch on top of 2.6.1:
diagnostics and output, no new capabilities.

### Remote desktop (Enterprise)

- **[Enterprise] Screen capture now keeps its own log.** A session could open, hold for a
  minute and close without showing a single frame — and there was nothing to explain it
  with: capture runs as a separate process inside the employee's session, and its output
  went nowhere. It now writes `screen-worker.log` next to the service log, and if that
  file cannot be opened it reports the actual path and the reason back to the service, so
  the failure shows up in the agent log instead of dying with the process.
- **[Enterprise] A stalled capture is no longer silent.** "No frames" looked identical
  whether the capture loop was stuck inside a system call, spinning without producing
  anything, or losing frames on the way to the service. The agent now prints a line every
  few seconds with the number of frames handed off and the time since the last iteration,
  and entering the loop, the first frame and a failed grab are logged separately.

### Windows

- **Agent command output reaches redirection again.** `RoutineOps-agent version >
  out.txt` and launching via `Start-Process -RedirectStandardOutput` produced an empty
  file with a successful exit code: the agent is built as a GUI-subsystem binary and, when
  attaching to the parent console, reopened its output onto that console over the handles
  the parent had deliberately supplied. Files and pipes are no longer overridden — a
  console still is. The `screen-probe` diagnostic command gained an `-out` flag for the
  case where there is no console at all.

## 2.6.1 — 6 August 2026

Agent release. The product (server + web) does not move. This section was added
retroactively — the release shipped without one.

### Remote desktop (Enterprise)

- **[Enterprise] Keyboard and mouse in an interactive session.** Viewing from 2.6.0 is
  joined by control: an operator holding an explicitly granted right works on the device
  directly. The employee sees the same observation badge, and every control session lands
  in the audit log as its own event.
- 🔴 **[Enterprise] Observation sessions finally start.** Before this release they never
  started on any platform: the agent opened the frame stream on the context of the task
  that carried the invitation, and the stream died as soon as that task was answered. The
  operator saw a blank screen and not a single error.

### Windows

- 🔴 **Manual removal of the agent also removes the installer registration.**
  `uninstall.bat` removed the service, the files and the registry keys but never called
  `msiexec /x` — the product stayed registered as installed over an empty disk. The next
  installation of the same package went into maintenance mode and exited 0 without
  installing either the service or the certificates: silent success with a zero result.
  The registration is now removed, and a package handed enrollment parameters where
  enrollment will not run aborts the installation with a hint instead of a quiet "done".

## 2.8.0 — 3 August 2026

Product (server + web) **2.8.0** and agent **2.6.0** — both move: the agent binary changed
too (capability advertisement in the inventory, accepting an interactive-session
invitation, a self-update hold while a session is running). Product and agent numbers
diverging is normal since 2.5.0.

Minor, not a patch: the batch is additive — new endpoints, fields and columns, no breaking
API changes. The upgrade applies **six migrations** (`062`…`067`); there are no down
migrations, so a rollback means restoring the backup `update.sh` takes automatically.

**What to check when upgrading.** 🔴 If your installation predates this release, verify
that the server connects to the database as `mdm_app` and not as the owner: `install.sh`
used to write a single DSN under the owner, and row-level security does not apply to the
owner — tenant isolation existed on paper only. Fresh installs fix themselves, existing
ones — see [`docs/self-hosted-deploy.md`](./docs/self-hosted-deploy.md). Also: if you
enable the remote desktop, decide up front where session recordings live — there is no
volume for `SCREEN_DIR` in `docker-compose.prod.yml`, so recreating the container wipes
them.

### User interface

- **English UI.** The panel is fully translated — screens, dialogs, device status labels,
  audit action names, relative time and the non-compliance reasons in the report. The
  switch lives in the sidebar and the choice is remembered; on first visit the language
  comes from the browser. The compliance report export and the screen use the exact same
  wording — otherwise there is nothing to reconcile the export against.
- **Page language attribute.** `<html lang>` was pinned to `en` and never changed even
  though the default UI is Russian: screen readers read Russian text with English rules
  and dates were formatted for the wrong locale. The page language now follows the switch.
- **Translation completeness is guarded by the build, not by eye.** Two gates: the `ru`
  and `en` dictionaries are compared by key set and for empty values (they drift
  silently — i18next falls back to Russian, so an English-speaking operator sees a
  Russian string with no console error), and a second gate hunts for leftover Russian
  text in sources, separating it from comments. Both were verified by a failing run.

### Agent updates

- **Update channels and canary rollout.** A device group now carries a channel —
  `stable` (default) or `beta` — and so does a release. A canary group is just a group on
  `beta`: soak the new version there, then move the release to `stable` and the whole
  fleet picks it up. Previously a publish went out to the ENTIRE fleet at once, with no
  way back per device: self-update does not roll back, anti-rollback forbids going
  backwards, and a bad build could only be fixed by a new version forward — i.e. by
  rolling out to an already broken fleet.
- Two rules worth knowing: `beta` is a superset of `stable` (a canary is never older than
  the fleet), and a device in several groups resolves by maximum — one beta group is
  enough.
- **The "Rollout" screen** shows which versions run where, broken down by channel and
  group; before it, "did it land?" was answered by eyeballing the device list.

### Identity (Enterprise)

- **[Enterprise] SAML providers are configured from the panel.** The SAML login
  endpoints existed before, but a provider could only be created by inserting a row into
  the database — so from the outside the capability did not exist. Now: list, create,
  edit, delete, export of our own SP metadata and a check of the IdP metadata **before**
  enabling.
- **[Enterprise] Service tokens gained a scope.** SCIM provisioning is a machine
  protocol, so the "humans only" gate cannot apply to it — and without a scope any
  service token with the admin role could create and delete console users, including a
  token issued for builds or monitoring. SCIM now requires a token issued specifically
  for SCIM, and such a token goes nowhere else.

### Compliance (Enterprise)

- **[Enterprise] SIEM export is configured and verified from the panel.** A receiver is
  created in the UI (syslog/CEF or webhook) with a signing secret and an event filter,
  next to a test-send button and the last delivery status with counters. Previously a
  wrong address only showed up as events silently not arriving, and silence is
  indistinguishable from "nothing happened".
- **[Enterprise] Vulnerabilities are matched by version, not by substring.** The old
  matcher compared a version to a pattern with "contains", which produced both false
  positives and misses on any non-standard versioning scheme. Versions are now compared
  properly, and "could not compare" became a **separate status**: it used to look like
  "clean", i.e. the report was green where no check happened at all. The card shows whose
  side it is on: the software version came from the device (fixed by inventory) or the
  pattern came from the dictionary (fixed by the feed provider).

### Remote desktop (Enterprise, first stage)

- **[Enterprise] Viewing a device screen from the panel.** An operator requests a session
  from the device page, **stating a reason (mandatory)**, and sees a live picture in the
  browser. The stream goes agent → server → browser: no new outbound network path, the
  employee's NAT and firewall are untouched, and the recording is made by the server —
  the party with no interest in forging it.
- **Viewing only.** No keyboard, mouse or file transfer in this stage. The Windows secure
  desktop (login screen, UAC, Ctrl+Alt+Del), Wayland on Linux and a machine with nobody
  logged in are operating-system ceilings, not missing work; each such refusal is shown
  to the operator as a distinct reason rather than a blank screen.
- **A session that leaves no trace is impossible.** The audit record is written in the
  same transaction as the session: if it fails, there is no session. Every endpoint is
  restricted to a live human with the admin role — a service token cannot watch an
  employee. Viewing a recording is a separate revocable grant, and the act of viewing is
  itself audited.
- **A session does not survive what should end it:** screen lock, logoff, user switch,
  the operator closing the tab, revocation of their rights, the device being blocked or
  decommissioned, an agent self-update, or the duration ceiling — each outcome has its own
  reason on the session card. A self-update waits for the session to finish (up to half an
  hour) instead of killing the capture mid-observation.
- **Recordings are kept for 30 days** and are deleted along with the tenant or when a
  device is moved — personal data does not travel to a different controller. This is the
  first unrecoverable artifact in the product: plan disk space, a 20-minute session is
  tens to hundreds of megabytes.
- **Field acceptance has not been done on any platform.** The code builds for all three
  operating systems and is covered by tests, but acceptance on live machines (Windows,
  Linux/X11, a Mac with screen-recording permission granted) is a separate item, and
  until then no platform counts as accepted.

### Agent (2.6.0)

- **The agent advertises its capabilities, not just its version.** The server used to
  infer what a device can do from the version number — but a free build of the same
  version physically does not contain the remote desktop (files are stripped at build
  time, not disabled by a flag), so a session would have been dispatched to a machine
  that cannot run it. The agent now sends a capability list in the inventory, and a task
  is not created until the device advertises it.
- **An unknown task still ends in an error, not in silence.** A session invitation
  arriving at an agent without that capability reports a refusal with a reason code: an
  operator waiting for frames must see the refusal, not a blank screen.
- **Self-update no longer interrupts a running session** — the check happens before the
  download, the hold is capped at half an hour, and the shutdown is graceful.
- 🔴 **Installers lag one train behind:** the MSI and the macOS package in this release
  are built as 2.5.9. They are bootstrappers — the agent pulls 2.6.0 itself at the first
  update check. Version skew across platforms is normal.

### Install and operations

- 🔴 **A fresh install no longer ships with decorative tenant isolation.** `install.sh`
  wrote a single DSN under the database owner and knew nothing about the application
  role — and row-level security does not apply to the owner. Which means every new
  install had tenant isolation on paper only. The installer now sets up two roles: the
  server connects with a role that cannot bypass RLS, migrations run as the owner.
  Verified against a live Postgres by a dedicated script.
- **An invitation now places the person into the tenant they were invited to.** Accepting
  an invitation created the user in the default tenant regardless of where they were
  invited.
- **A device-bound enrollment token enrolls into that device's tenant**, not the default
  one.
- **The API specification caught up with reality:** the guard comparing
  `docs/openapi.yaml` against the routes did not see the whole picture, and 12 endpoints
  were living undocumented. The spec is complete now, and drift is caught in both
  directions.
- **Gates run on push, not on trust:** the enterprise test set and the image build are
  executed automatically.

## 2.5.9 — 31 July 2026

Agent release. The product (server + web) is unchanged.

### FileVault (Enterprise)

- **[Enterprise] Disk-encryption setup can now be finished from the admin panel
  without visiting the machine.** The agent needs the employee's password, and a silent
  install has no terminal to ask from, so setup was quietly skipped and the only way
  left was walking up to every Mac. An operator now presses a button on the device
  card, the employee gets a dialog with the stated reason and types the password, and
  the service finishes the setup. The password stays on the machine: only the encrypted
  recovery key and service password leave it.
- **[Enterprise] The task can no longer end in a silent skip.** If the employee
  cancelled, did not answer within ten minutes, nobody is at the machine, or encryption
  is off — the operator sees exactly that reason instead of "completed".

### Deployment

- **[Enterprise] The escrow-recipient publishing command no longer takes the
  fingerprint on faith.** A typo produced a signed record that agents silently
  rejected: the rotation never happened while the publication looked successful. The
  fingerprint is now derived from the key itself, and a mismatch with a manually passed
  one cancels the publication.

- **[Enterprise] The self-update channel can no longer hand out an agent of the wrong
  edition.** On an enterprise installation, publishing the macOS agent from the
  repository is now rejected: the binary there is the free build, where FileVault is not
  disabled but absent, and a Mac that updated to it would refuse encryption commands
  forever. The enterprise binary comes from the private delivery channel
  (`DARWIN_AGENT`), and Windows/Linux builds inherit the installation's edition. The
  reverse case — a free installation with an enterprise build — is rejected too.

## 2.5.8 — 30 July 2026

Agent release. The product (server + web) is unchanged.

### Tasks

- **A task of an unknown type is no longer reported as done.** When the server sent a
  task type this agent version does not know, the agent ran an empty script and
  reported success — the operator saw "completed" while nothing happened on the
  device. Such a task now fails with "task type is not supported by this agent version
  (version) — the task was NOT executed", so a lagging agent is visible immediately
  instead of looking like finished work.

### FileVault (Enterprise)

- **[Enterprise] The escrow recipient can now be rotated without rebuilding the agent.** The
  recipient used to be baked in at build time, so changing it meant a release and a
  fleet-wide rollout. The agent now takes the recipient from the server, verifying the
  release-key signature and rejecting rollbacks to an older publication; the baked-in
  recipient remains the fallback, and the accepted record is cached so escrow keeps
  working offline.

## 2.5.7 — 30 July 2026

Agent release. The product (server + web) is unchanged.

On macOS this release is also the first to carry the 2.5.6 changes: the mac build lags
a version behind because it is produced on the maintainer's Mac, not on the server.

### Updates

- **The agent checks for updates right after the service starts, not six hours
  later.** The first check used to wait a full interval
  (`ROUTINEOPS_UPDATE_INTERVAL`, 6h by default), so a fresh release reached a machine
  up to six hours after a service restart or reboot: the agent was alive, the link was
  up, the version simply did not move. The check now runs shortly after start, with a
  random delay of up to `min(interval/10, 5 min)` so a large fleet powering on at once
  does not fetch the update simultaneously. The service log line is `selfupdate:
  первая проверка после старта`.

## 2.5.6 — 30 July 2026

Agent release. The product (server + web) is unchanged. Published for Windows and
Linux; on macOS these changes arrive with 2.5.7 (the mac build lagged a version).

### Linux

- **Lock screen on Linux.** Previously "Lock" on Linux only persisted the state: the
  device counted as locked while nothing happened on the employee's screen. The
  service now raises a full-screen lock with a password field in the active graphical
  session, following the same model as Windows and macOS (only the service may
  unlock; the window merely hands it the password). The window covers the screen,
  grabs keyboard and pointer, re-raises itself every second and disables screen
  blanking.
- **Wayland sessions are honestly unsupported.** Only the compositor can cover the
  screen and grab input under Wayland, so the agent skips the overlay and says so in
  the log instead of faking protection. Details and limits:
  [docs/lock-linux.md](docs/lock-linux.md).

## 2.5.5 — 29 July 2026

Agent release. The product (server + web) is unchanged.

### Security

- **Hardening the Windows certs directory now also covers files already on disk.**
  In 2.5.4 the protected DACL was applied only to the directory. Ordinary users
  have bypass-traverse privilege by default, so denying access to the directory
  did not stop them opening `agent.key` by full path while the file itself still
  carried an inherited Users RX ACE. Confirmed on a test bench after the
  2.5.4 update: `icacls` on the directory failed, but a normal user could still
  read the key. Service start now applies the same admin-only DACL to existing
  files inside certs.

## 2.5.4 — 29 July 2026

Agent release. The product (server + web) is unchanged.

### Security

- **The mTLS private key on Windows is no longer readable by ordinary local users.**
  With `cert-source=file` (the MSI default) the key is a file under the install
  directory. Nobody set permissions on it: the installer inherited the ACL from
  `C:\Program Files`, and mode `0600` on Windows only sets the read-only flag. Any
  local user could copy the key+certificate pair — and per ADR-1 that pair *is* the
  device identity.

  The agent now hardens the certs directory with an admin-only DACL (SYSTEM +
  Administrators) before enrollment writes the key, and again on every service
  start. Outside Windows the directory mode is `0700`. Failure during enroll
  aborts installation; on service start it logs ERROR and continues, so a bad ACL
  on one machine does not leave the fleet unmanaged.

## 2.5.3 — 28 July 2026

Agent release. The product (server + web) is unchanged.

### Temporary administrator rights

- **A request for a user who is already an administrator no longer stalls.** When asked
  to add someone who is already in the group, Windows answers with an error — and the
  agent read that as a failed grant: the request stayed unmarked and no session evidence
  was collected at all. That answer now means "the rights are already in place": the
  request closes normally and the session is accounted for like any other.

  The decision is made on the fact — the agent checks actual group membership instead of
  parsing the error message. The wording differs per system language, and on Russian
  Windows text parsing has failed us before.

---

## 2.5.2 — 28 July 2026

Agent release. The product (server + web) is unchanged.

### Temporary administrator rights

- **A temporary grant no longer becomes permanent after an agent restart.** The state of
  granted rights lived only in the service's memory. After a restart — an agent update, a
  reboot, a crash — the agent forgot about the request, saw the user already in the
  administrators group and recorded that as "they were an administrator all along". The
  request then expired without the rights ever being revoked: as far as the agent was
  concerned, there was nothing to revoke. The only way to notice was to log into the
  machine and look.

  The session trace now survives both a service restart and a reboot. A second change
  follows from that: **if the trace cannot be written, the rights are not granted at
  all.** Refusing the grant is better than leaving rights on a machine that nobody will
  know about after a restart.

- **Rights no longer drop because a probe failed.** To know who the rights belong to, the
  agent determines the logged-in user. That probe sometimes does not answer — the OS
  service is busy, the session is switching. An empty answer used to read as "nobody is at
  the machine", and the rights were revoked with the reason "user logged out": someone in
  the middle of their work lost administrator, and the log kept a false reason. "Unknown"
  and "nobody" are now distinguished: on a failed probe the rights are held, while the
  request's expiry is checked independently and still revokes them exactly as before.

  On Windows the same place fixes a hidden defect: when the probe failed, the account the
  service runs under was substituted — a non-empty but knowingly wrong answer.

### Under the hood

- Administrator-session accountability is now complete on the device side: the agent
  captures a snapshot of installed software and service definitions at the moment rights
  are granted, computes the session delta against it and reports that delta to the
  server — periodically, and always when the rights are revoked. Collection and
  reporting are **off** until the server enables them, so device behaviour is unchanged
  for now. Whether to collect is decided once, when rights are granted: flipping the
  server setting does not change sessions already in flight, in either direction —
  otherwise turning it off mid-session would look like missing evidence, and turning it
  on like evidence with nothing to compare against.

  Evidence reports never crowd out anything else: in the delivery queue they yield to
  security signals and lock statuses rather than displacing them. Reports are
  cumulative, so a dropped intermediate one is caught up by the next; the session's
  final report, if the queue will not take it, is sent directly — it gets no second
  chance.

---

## 2.7.0 — 27 July 2026

### Devices

- **[Enterprise] Uninstalling software from the device page.** Every entry the agent can
  remove now has a delete action in the software list. Entries that cannot be removed
  (installed into a user profile on Windows, protected by the system on macOS) get no
  button — it would only return a refusal.

  The server does not send the agent an operating-system command. It sends a **target
  description**, and the agent re-collects its inventory, finds that entry locally and
  runs whichever removal method it determined itself. Otherwise the task channel would
  become a second path to arbitrary execution on the device — bypassing the signing,
  auditing and limits that scripts have.

  A consequence worth knowing up front: server-side inventory lags by a few minutes. If
  the program was updated or its key changed in the meantime, the removal will **not**
  happen — you will see "target changed" and can retry after refreshing the inventory.
  By construction the system cannot remove the wrong version, or a same-named product
  from a different vendor.

  The outcome is shown separately from the task status, because different outcomes call
  for different actions: "target changed" — refresh the inventory, "ambiguous target" —
  narrow it down, "not removable" — nothing to do. **"Still present"** deserves its own
  mention: it is not the same as an error. An uninstaller can report success while the
  program remains — for instance when removal is deferred until reboot. That is why the
  agent verifies with a second inventory snapshot rather than trusting the exit code.

  The agent will not remove itself: such an attempt returns "this is the agent". Removing
  the agent is done by decommissioning the device.


- **You can now see when an agent has gone blind.** The agent has a queue that carries
  task results, lock statuses and security events to the server. When that queue fails
  (disk error, broken permissions on the state directory) the device stays connected and
  looks perfectly healthy in the console — it simply stops reporting anything. That is
  exactly how the 2.5.1 field failure on Windows presented itself: the only outward sign
  was a frozen lock status, spotted by eye.

  The agent now reports the queue being unavailable in its heartbeat — the one channel
  that does not depend on it. An "Agent blind" marker with the cause and the time it
  started appears in the device list and on the device page, and an entry requiring
  acknowledgement appears under alerts. While the marker is up, the absence of events
  from that machine does not mean nothing is happening on it: it means events are not
  getting through. The marker clears itself as soon as the queue recovers; the alert
  entry stays — a human closes it after checking that nothing happened during the
  blind period.

  Requires an agent of this version or newer. An older agent does not send the signal and
  its device is shown as before.

### Notifications

- **Alerts now have severity levels, and notifications have a threshold.** Every alert used
  to be equal: "a destructive action is happening right now" and "an agent has not checked
  in for two hours" looked the same and were pushed to Telegram to every administrator
  alike. The knowledge of what matters more lived in the frontend only, so neither the
  server, nor notifications, nor exports could see it.

  Each alert now carries one of four levels. It is stamped when the alert is created and
  then lives with the row: editing the severity map does not rewrite history, and an
  incident triaged six months ago as medium stays medium. The order reflects urgency of
  intervention rather than "seriousness in general". The list shows the level as a badge
  and sorts unacknowledged first, by level second: an acknowledged critical alert has
  already been handled by a human and must not push unacknowledged ones out of view.

  Each recipient has their own delivery threshold — the selector next to the Telegram
  binding. The default delivers everything, exactly as before: any higher default would
  **silently** unsubscribe administrators from part of what they received yesterday. It
  only gets quieter by an explicit operator action. Local-admin requests are not subject to
  the threshold — they carry no severity; they are either reviewed or they expire.

  An unacknowledged critical alert reminds after 30 minutes and then hourly until it is
  acknowledged (`ALERT_ESCALATE_AFTER_MINUTES`, `ALERT_ESCALATE_REPEAT_MINUTES`,
  `ALERT_ESCALATE_MIN_SEVERITY`; a zero interval disables escalation). An alert type the
  server does not know is treated as high rather than low: an unknown type means an agent
  newer than the server, and such an event must not silently fall below the threshold.

### Users

- **Accounts can now be deleted.** There was no delete endpoint at all: an employee who
  left could only be left in the system. The only way to take access away was changing
  their password — that drops live sessions, but the account keeps existing.

  Every row under "Users" now has a delete action. It takes access away immediately and
  completely: active sessions stop being accepted on the very next request, and service
  tokens issued by that person are removed along with them — otherwise automation acting
  in their name would outlive their departure, invisibly, because nobody would be left to
  look at it.

  What deletion does not touch: the audit log, issued invitations, recovery-key reveals
  and local-privilege requests. All of it stays, losing its reference to the deleted
  account — a security journal must not be cleared along with a person.

  Two refusals: deleting yourself (the operator would instantly lose their own session,
  and any other administrator can remove a colleague) and deleting the last IT
  administrator (the console would be left without a single account able to change
  anything, fixable only with database access).

### Security

- **The login attempt limit is counted per client address again.** The "10 login attempts
  per minute per address" limit relied on the address the server sees on the connection —
  and behind nginx that address is the same for every request. The limit was therefore not
  per-address but **one shared counter for everyone**: a brute-force from a single machine
  consumed it entirely and locked everyone else out, with no per-address isolation at all.
  The same applied to password recovery, password reset and invitation acceptance.

  The server now recovers the client address from the header the proxy sets — but trusts
  that header **only** when the request comes from the proxy's address. A request from
  anywhere else carrying its own header changes nothing: otherwise the limit could be
  bypassed by supplying a fresh value on every attempt, which is worse than the original
  problem.

  Private and loopback ranges are trusted by default, which covers the standard
  installation where nginx sits alongside the server. If your proxy is on a public
  address, list it in `TRUSTED_PROXIES`, or the counter becomes shared again. A typo in
  that variable stops the server from starting: silently falling back to the default would
  leave the operator with a limit they believe is configured.

  nginx was fixed alongside: it now overwrites the client-address header on all routes,
  not only under `/api/`. Previously a client-supplied header passed straight through on
  the other routes; that did not affect the login limits (they live under `/api/`) but was
  a trap for any future address-based check.


- **[Enterprise] Directory: StartTLS and a custom root certificate.** The server
  previously supported only `ldaps://` verified against system roots — so a directory
  whose Active Directory is issued by the organisation's own certificate authority could
  not be connected at all, and the only alternative was a plaintext channel, which a
  production AD generally refuses to accept a service-account bind over. The directory
  settings now offer a StartTLS switch (raises encryption on an already-open connection,
  before the password is sent) and a field for the root certificate.

  The certificate **replaces** the system roots rather than extending them: trust is
  addressed to the organisation's own authority. Otherwise a certificate from any public
  authority, issued for the name of your domain controller, would be accepted. There is
  no "skip certificate verification" option and there will not be one — it turns the
  channel into a plaintext one while looking like encryption is on in the interface.

  The certificate is parsed on save: a PEM mangled while pasting is rejected by the form
  instead of surfacing as a sync failure an hour later. Like the password, it is never
  returned — the interface only shows whether one is set.


- **The audit log can now be checked for tampering.** It used to be an ordinary table:
  anyone who reached the database could edit a row or delete it without leaving a trace. A
  log that cannot be verified is not evidence in an incident review, it is an opinion.

  Every entry now carries a chain number and a hash linking it to the previous one. The
  check (`GET /audit-log/verify`) catches an edited field, a deletion from the middle, a
  reordering and an insertion. Routine retention cleanup does not count as tampering —
  otherwise the nightly cleanup would raise a forgery alarm every time and the check would
  be switched off within a week. There is no button in the panel yet; the check is
  available through the API.

  **An honest boundary.** The chain does not stop someone who is allowed to write to the
  database and knows about it: they will recompute the whole thing. What makes it
  meaningful is keeping the head outside the database, so the server prints the chain head
  to the log on every start and once a day — that line is not diagnostics, it is part of
  the mechanism, and must not be filtered out as noise. That is what you compare against.

  Entries written before the upgrade are not part of the chain and never will be:
  recomputing over data that may already have been tampered with would produce a valid
  chain over a forgery. The check reports their count separately, so that "the check
  passed" is not read as "the whole log is intact". It also returns 200 when tampering is
  found: "the check ran, the result is that the log was tampered with" is a successful
  response, whereas an error code would be indistinguishable from the server being down.

## 2.6.0 — 27 July 2026

Product release (server + web). The agent stays at **2.5.1** — its Free-edition code has
not changed since the previous release, so there is nothing to rebuild.

⚠️ **Breaking API change.** A device owner is no longer a console account: the body of
`PUT /devices/{id}/owner` changed (`owner_user_id` → `person_id`) and the owner fields on
the device object were renamed (`owner_user_*`, `owner_directory_name` →
`owner_person_*`). Integrations built on these endpoints need updating. Existing data is
migrated automatically on upgrade — nothing is lost.

### Devices

- **A device owner no longer needs a console invitation.** Previously only someone with a
  login could be an owner — to record that a laptop belongs to an employee you had to
  invite that employee and make them set a password, even though they have no business in
  the console. The owner is now created right on the device page: full name, e-mail
  (optional), "Create and assign". No e-mail, no account.

  Invitations stay what they always were — a way to grant access TO the console: for
  administrators, technical support, interns.

  "Owner" now has a single meaning. In Enterprise the person cards are brought in by the
  Active Directory sync, in Free the operator creates them — the field on the device page
  is the same one, and moving between editions breaks nothing: turn the directory on and
  employees start arriving on their own, while manually created cards stay put and are not
  disabled by the sync. Owners already assigned as accounts are migrated to person cards
  automatically on upgrade.

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

  Two new lock states appear on the device page. "Awaiting arming" — the lock is issued
  but there is no secret: the machine is untouched, and IT keeps getting a reminder until
  it arms. "Secret does not match escrow" — the supplied key is not the one escrowed for
  this machine: the operation stops before the first irreversible step, and the event is
  raised as its own alert in the console, because it means the key custody has drifted
  rather than a workflow hiccup.

  An unfinished rights-removal operation ("revoke not completed") now also reaches the
  alerts console, not just the notification and the log: it is the only state in which
  the machine is left half-processed and will not recover on its own. Repeat reminders do
  not create new rows. That state is no longer overwritten on the device page by later
  "not armed" reports — previously a half-processed machine could show up as merely
  unarmed.
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
