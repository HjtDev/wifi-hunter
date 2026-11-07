# Roadmap

Current version: **0.9.0** (shipped, see the bottom of this file). Next: **1.0.0**, planned in two phases.

## v1.0 - solid, fast, and on Windows

**What we care about:** stability, performance and the speed of finding a good IP. Every item below is judged by that.

**In scope**
- Windows support, through a platform backend interface.
- Auto-login that works reliably (needs your details, see phase 1.3).
- Stability and performance work, measured instead of guessed.

**Not in scope**
- Android, any GUI, any TUI. The tool stays a command line.
- MAC randomization (the MAC is still stored with every result; nothing more is planned).
- Shorter or fewer tests per candidate, and second-wifi-adapter support (decided against earlier; evidence per accepted IP
  stays exactly as it is today).
- macOS and non-NetworkManager Linux (iwd, systemd-networkd). Not planned, but the new interface makes them possible later.

**Principle carried over:** an IP is only accepted after the same full evidence as today. Speed comes from less waiting,
skipping likely-bad IPs, stopping *failing* tests early, and filtering in parallel. It never comes from weaker proof.

| Phase | Theme | Ships |
|---|---|---|
| 1 | Solid and fast on Linux | backend interface, simulator + benchmarks, auto-login overhaul, stability pack, speed pack |
| 2 | Windows and the 1.0 release | Windows backend, portable probes and scanning, platform layer, Windows setup and CI, 1.0.0 |

---

## Design decisions (my choices, with the reason)

| Topic | Decision | Why |
|---|---|---|
| Backend shape | One small interface per concern (network control, probes, scanning, notifications, platform paths and secrets, shell setup), chosen by platform at start-up. The current Linux code moves behind it with no behavior change. | Windows then plugs in without touching the hunt, triage, watchdog, scoring or history code, which stay platform-free. |
| Windows network control | PowerShell NetTCPIP cmdlets through one long-lived PowerShell worker, talking JSON. Hot paths may move to the native IP Helper API later, only if measured slow. | Cmdlets are stable and give locale-independent JSON (`netsh` text is translated per language). A warm worker avoids paying PowerShell's start-up cost on every call. |
| Windows live switching | Expected to be natural on Windows (address changes need no wifi reconnect; the active-store option should keep candidates temporary and only the winner persistent, like `nmcli device modify`). | Mirrors what we do on Linux. **Not assumed**: it must be verified on real Windows with the same read-back-and-fall-back rule and a `live-check` equivalent. |
| Probing | A probe interface with structured results. Linux keeps the system `ping` (forced to the C locale). Windows uses the ICMP echo API from the standard library, which supports a source address and needs no admin rights; TCP-connect timing is the fallback. | Windows `ping` output is localized and cannot be parsed safely. |
| Scanning | Two scan backends: `arp-scan` where installed, and a portable "neighbor sweep" (touch every candidate from many threads, then read the OS neighbor table). | Windows has no arp-scan. On Linux the sweep also removes the sudo prompt and the setcap step. The kernel ARP-resolves each address first, so hosts that block ICMP still show up. |
| Privileges | Detect elevation up front. Windows needs an Administrator terminal to change IPs; `dorm-ip` says so clearly instead of failing half-way. No self-elevation, no helper service. | Simple and honest; a service is a security and maintenance burden for a personal tool. |
| Config, data, secrets | Platform directories (config, data, state) instead of hard-coded XDG paths. On Windows the password lives in Credential Manager by default (via the optional keyring support), or in a file restricted to your user account. | `chmod 600` has no meaning on Windows. |
| Notifications | A notifier interface: `notify-send` on Linux, a Windows toast through the built-in API with a console line as fallback. | No extra packages. |
| Shell command | Add PowerShell (profile function) next to bash/zsh/fish. Setup checks move from the Makefile into `dorm-ip init` and a new `dorm-ip doctor`, so Windows needs no `make`. | The Makefile becomes a thin wrapper. |
| Distribution | `uv` on both platforms (`winget install astral-sh.uv` on Windows). No packaged .exe for 1.0. | One install path; fewer things to break. |

---

## Phase 1 - Solid and fast on Linux

### 1.1 Backend interface (Linux refactor, no behavior change)
Everything OS-specific moves behind interfaces. Today that surface is: `nmcli` and `ip route` calls, `ping` and `arp-scan`
output parsing, `/sys` reads for the MAC and traffic counters, `notify-send`, XDG paths, `chmod 600`, SIGTERM handling and
the bash/zsh/fish shell step.

| Interface | Responsibilities |
|---|---|
| Network control | read the profile, back up and restore it, switch to one IP, add several addresses, set DNS, return to DHCP, list live addresses, MAC, traffic counters, find the interface carrying internet traffic (VPN detection), report whether live switching and multi-address are supported |
| Probes | ping (with a source address) returning loss, average and jitter as numbers, never as text to parse |
| Scanning | which candidate IPs are in use |
| Notifier | send a desktop notification |
| Platform | config, data and state directories, secret storage, privilege check, console-close/SIGTERM handling |
| Shell setup | which shells exist, where the command is installed |

Rules: callers never import a concrete backend; the backend is picked automatically (overridable for tests); the existing
unit tests must pass unchanged on the Linux backend before anything else is built on top.

### 1.2 Simulator and benchmarks (measure before optimizing)
- A **simulated network backend**: scripted IPs that are dead, blocked by the portal, slow, lossy, fast-then-dead, or
  good, with realistic delays. It lets the whole hunt, triage, failover and watchdog run end to end in tests and CI, on any OS.
- **Timing instrumentation** in real runs: seconds per stage (switch, wait for gateway, portal, ping, DNS, quick, sustained,
  triage), stored in the history and shown by `history` and the hunt summary.
- **Benchmark scenarios** on the simulator (for example "5% good IPs", "mostly portal-blocked", "everything dead"), reporting
  time to the first accepted IP, IPs tried per minute and how often a good IP was wrongly rejected. We take a **baseline
  first**, then set numeric targets from it.

### 1.3 Auto-login overhaul
**Done in 0.9.1:** diagnostics (`login --debug`), the flow engine (follow the redirect, cookies, form parsing, Kerio fallback), verification by
the connectivity check, and dorm-DNS resolution for `.local` portals. **Still open:** HAR import, learning and refreshing the session
lifetime, and a Windows-friendly flow check. The original description follows.

Blocked on your details (list below), so this runs in parallel with the rest of the phase. We diagnose before changing
anything.

1. **Diagnostics.** `dorm-ip login --debug` records a redacted trace of the whole attempt: every request and redirect, status,
   timing, redacted headers and body snippets, and the portal state before and after. Secrets are masked, so the file is safe
   to send. A matching "inspect the portal" command shows what the portal page contains (forms, hidden fields, scripts).
2. **Better import.** Accept a browser **HAR file** (the whole login flow including redirects, token fetches and cookies),
   not just one copied request. Today the cURL import drops cookies and sees a single request, which breaks portals that
   need a session or a token fetched first.
3. **A small multi-step flow instead of one request.** Steps such as: open the portal page, extract values (hidden fields,
   CSRF tokens, challenge strings) with patterns, apply a transform (for example an MD5/SHA-1 hash of the password, which
   some hotspot portals compute in JavaScript), submit, follow redirects including HTML/JavaScript ones, keep cookies
   between steps.
4. **Verify by result, not by text.** Success means the connectivity check now returns "open", not "the page contains word X".
   Recognize and report the portal's own failure cases: wrong password, already logged in, too many devices, quota
   reached, captcha required (cannot be automated; reported clearly).
5. **Session lifecycle.** Learn how long a login lasts (fixed or idle timeout), refresh it before it expires, handle
   "logging in on a new IP logs out the old one", and keep the existing safety limits (2 failures in a row, a cap per hunt).

**What I need from you (send whatever you can; redact the username and password):**
- What exactly "not working" means. Rejected request? Request accepted but the portal still blocks? Works once and then
  expires quickly? Works for some IPs and not others? Only fails inside a hunt or triage but works with `dorm-ip login`?
- The output of `dorm-ip login --force` and your `[portal]` config section.
- A **HAR export** of a full login from a fresh, not-logged-in IP, starting from opening
  `http://connectivitycheck.gstatic.com/generate_204` until the internet works, plus one of a failed attempt if you can.
- The text of the portal's success and failure responses (wrong password, already logged in, device limit, quota).
- Whether the login page uses JavaScript to hash the password or has hidden fields that change on every load, and whether a
  captcha ever appears.
- Session facts: how long until you are logged out, whether it asks again after an IP change, whether logging in on one IP
  logs out another, whether a logout or "status" page exists.
- Any vendor hint (page footer, URL patterns such as `hotspotlogin`, `fgtauth`, `login.html`).

### 1.4 Stability pack
- **One instance at a time.** A lock so `hunt`, `watch`, `set` and `live-check` can never fight over the interface; a clear
  message says which one is running.
- **Crash-safe journal.** Write a marker before the first network change and remove it on a clean finish. If a run is killed
  (power loss, `kill -9`, suspend mid-hunt), the next command notices and offers to restore. This matters more on Windows,
  where address changes can persist.
- **Locale-proof Linux calls.** Run `nmcli`, `ping` and `arp-scan` in the C locale so a non-English system cannot break parsing.
- **Logging.** A rotating structured log file and `--verbose`, so a problem report (like the first outside user's) comes with
  facts instead of guesses.
- **`dorm-ip doctor`.** Checks the tools, privileges, config, credentials, portal reachability, DNS, database health, and
  whether live switching and parallel triage work here (cached, re-checked when the interface changes). Prints a shareable report.
- **Watchdog hardening.** Detect a real upstream outage (several independent targets fail, or every standby fails at once)
  and wait instead of churning IPs; limit how many switches can happen per hour; a longer post-switch grace period.
- **Database care.** Schema versioning with migrations, pruning of old rows, safe concurrent access (a running `watch` plus
  `history`).
- **Timeouts and cancellation everywhere**, including in parallel triage, so Ctrl+C is always prompt and nothing can hang.
- **Config versioning.** Unknown or deprecated keys are reported helpfully and `init` migrates them.

### 1.5 Speed pack (each item verified against the 1.2 benchmarks)
- **Stop failing tests early.** The moment a collapse or a certain failure is seen, end that test instead of waiting for the
  window. Accepted IPs still get the complete test, so evidence does not shrink.
- **Run independent cheap checks at once** in the full test (ping and DNS use no bandwidth), instead of one after another.
- **Adaptive triage.** Batch size grows when most candidates pass triage cheaply and shrinks when the control IP or loss
  suggests trouble.
- **Fast lane for favorites.** Standby and top-history IPs are tried first, skipping triage, because they already have evidence.
- **Reuse connections and clients** across checks; avoid repeated start-up work.
- **Portable scan option** (the neighbor sweep above), faster to start and no sudo, with arp-scan still preferred when present.
- **Per-stage budget review.** Use the timing data to remove the slowest wasted seconds on dead IPs, the common case.

**Done when:** all existing tests pass on the Linux backend; the simulator runs full hunts in CI; benchmarks show a
measurable improvement over the baseline without more wrongly rejected good IPs; two processes can no longer collide;
`doctor` produces a useful report; auto-login works on your portal on fresh IPs, during hunts and in the watchdog.

---

## Phase 2 - Windows and the 1.0 release

### 2.1 Windows network backend
- Find the wifi adapter and the connected profile (adapter name, index, SSID) from JSON, not translated text.
- Switch IP, add several addresses, set DNS, return to DHCP, and **back up and restore** the original configuration, using
  the warm PowerShell worker. Verify every switch by reading the addresses back, exactly as on Linux.
- Live switching and multi-address triage are expected to work without a reconnect; both are **verified on real hardware**
  and fall back automatically if they do not. A Windows `live-check` and `doctor` section report it.
- Known Windows behavior to measure and handle: the address may stay "tentative" for a moment while the OS checks for
  duplicates (adds seconds; the state also reveals a duplicate); network-location detection may flap after a change; Windows
  may use a per-network random hardware address, so we always read the MAC actually in use.

### 2.2 Probes and scanning without Linux tools
- ICMP via the Windows echo API with a source address; the same structured result as Linux.
- Neighbor sweep for scanning (read the neighbor table with PowerShell).
- Source-bound HTTP, DNS and the portal login work as they are (they use standard sockets).
- VPN detection through the route the OS would use for 1.1.1.1 (the same idea as `ip route get`).

### 2.3 Platform layer
- Directories for config, data and state from the platform; credentials in Credential Manager or a user-only file, with the
  permission check made OS-aware.
- Elevation check with a clear message; console-close and Ctrl+C handling so a closed terminal window still restores the
  profile (Windows has no SIGTERM to catch).
- Toast notifications with a console fallback.

### 2.4 Setup on Windows
- `uv sync` then `uv run dorm-ip init`; the wizard and `doctor` do the checks the Makefile does on Linux (no `make`, no
  arp-scan).
- PowerShell profile function so `dorm-ip` works from any folder (same marked-block, backup-once, uninstall rules as the
  POSIX shells).
- Documentation of the Administrator-terminal requirement and of `winget install astral-sh.uv`.

### 2.5 Testing and CI for Windows
- Recorded real outputs from a Windows machine become fixtures for **contract tests** of the Windows backend.
- A `windows-latest` job in CI runs the unit tests and the contract tests (no wifi on the runner, so no real network changes).
- A written **manual hardware checklist** (live switch, multi-address triage, DNS, restore after Ctrl+C and after closing the
  window, portal login, watchdog with a VPN) that a Windows tester runs before each release. Same workflow as Linux: I write,
  you or a tester run it and report.

### 2.6 Documentation and release
- README with a platform support table, Windows setup, the new commands (`doctor`, `login --debug`) and the new config.
- CHANGELOG, version **1.0.0**, tag `v1.0.0`.
- Windows is labelled **experimental** in the README until at least two people have run the hardware checklist successfully.

**Done when:** a full hunt, `set`, `watch`, restore and portal login work on a real Windows machine; the Linux behavior is
unchanged; CI is green on both operating systems.

**Risks:** I cannot run real Windows hardware, so Windows correctness depends on your tester and on the recorded fixtures;
a locked-down machine may block PowerShell or the profile change; Windows services may re-apply DHCP after a wifi roam.

---

## Open questions for you
1. Do you (or someone you trust) have a Windows 10/11 machine on the dorm wifi to run the hardware checklist?
2. Is "open the terminal as Administrator" acceptable for Windows users?
3. Which number would make you say a hunt is fast enough (for example time to the first good IP)? We will set the target after
   the baseline measurement, but your expectation helps.
4. The auto-login details listed in 1.3.

---

## v0.9.0 (shipped)

Phase 1: live IP switching, readiness polling, smart ordering (cooldown after failures, hour of day, busy and near-good
IPs), timings. Phase 2: parallel triage, `hunt --find N`, standby list and watchdog failover. Phase 3: shell command step,
`hunt --watch`, CI on pull requests, a README that documents every feature (enforced by a test), version 0.9.0.

Decided against, still true: shorter tests per candidate, second wifi adapter support.
