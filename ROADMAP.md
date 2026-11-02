# Roadmap to v0.9

Current version: **0.2.0**. Everything below ships as **v0.9.0** at the end of phase 3. Items that are deliberately
left for **v1.0** are listed at the bottom.

**Principle for all performance work:** a candidate IP is only ever accepted after the *same full evidence* as today
(gateway, portal, ping/loss, DNS, quick speed, sustained test with collapse detection). Speed comes from doing less
*waiting*, skipping IPs that are very likely bad, and filtering in parallel - never from shorter tests.

| Phase | Theme | Ships |
|---|---|---|
| 1 | Faster, smarter hunting on one connection | live IP switching, readiness polling, smart ordering, timings |
| 2 | Parallel triage and standby IPs | multi-IP triage, `--find N`, standby list + watchdog failover |
| 3 | Setup, CI and release | shell alias step in `init`, `hunt --watch`, GitHub Actions CI, a README listing every feature, version 0.9.0 |

---

## Phase 1 - Faster, smarter hunting on one connection

### 1.1 Live IP switching
Change the address of the *running* connection (`nmcli device modify <dev> ipv4.addresses ...`, a runtime-only change)
instead of `con mod` + `con up`, which drops and re-associates the wifi on every candidate.

- **Never trusted blindly.** After each live change the tool reads the address back (`nmcli dev show`) and requires
  exactly the new address. If the change did not take, or `nmcli` rejects it, it falls back to the normal reconnect
  for the rest of the run and says so.
- **Safer by construction.** The saved NetworkManager profile is untouched while candidates are tried. Only the winner
  is persisted (`con mod`, no reconnect). A crash mid-hunt leaves the profile as it was; the live address disappears at
  the next reconnect. Failure/Ctrl+C still runs the normal restore.
- **`dorm-ip live-check [--ip IP] [--compare]`**: measures on *your* wifi how long the address takes to change, to become
  visible and for the gateway to answer, optionally against the reconnect method, then restores your profile. Use a
  known-good IP (e.g. one from `dorm-ip history`); a dead IP makes the timing meaningless.
- `hunt.live_change = "auto" | "off"`. `dorm-ip set` uses the same switch (with the same fallback).
- Not verifiable without real NetworkManager hardware: this is why the runtime read-back and `live-check` exist.

### 1.2 Readiness polling
Replace the fixed `settle_seconds` sleep by polling the gateway until it answers (max wait = `settle_seconds` for live
switching, longer for a reconnect). A live switch that is ready in 300 ms no longer waits 4 s.

### 1.3 Smart ordering
All of it uses the history database and only changes the *order* and which IPs are retried soon:

- **Skip recently failed IPs.** After a failure an IP is not tried again for `hunt.skip_failed_minutes` (default 30),
  doubling per consecutive failure (cap 12 h). IPs that passed in the last 24 h only get the base cooldown (good IPs
  flake). Portal "login required" results never count as failures. `hunt --retry-failed` ignores the cooldown. If skipping
  would leave too few candidates, skipped IPs are appended at the end instead of starving the hunt.
- **Hour-of-day weighting.** Results from around the current hour (+-2 h) count double in an IP's score.
- **Busy history.** Every ARP scan is stored; IPs that were seen in use in many recent scans rank lower.
- **Explore near good IPs.** Unknown IPs within +-3 of a known-good one get a small bonus
  (`hunt.explore_near_good`, default on; `dorm-ip history` will show whether neighbors really correlate).

### 1.4 Measure it
`hunt` shows seconds per candidate and the total hunt time, and says whether live switching was used, so the gain
from 1.1-1.3 is visible rather than assumed.

**Status: implemented** (250 unit tests). Still to confirm on real hardware: that `nmcli device modify` switches the IP on your wifi
(`dorm-ip live-check --compare`).

**Done when:** `live-check` reports sensible timings on real hardware; a hunt with `live_change = auto` falls back cleanly
when live switching is unsupported; a failed IP is skipped on the next hunt; unit tests cover the new paths.

---

## Phase 2 - Parallel triage and standby IPs

### 2.1 Multi-IP triage ("test several IPs at once")
One wifi card has one MAC, but the interface can hold many addresses at once (`nmcli device modify` with a list, same live
layer as 1.1). Add a batch of N candidates (default 12) together, then run the *cheap* checks for all of them in parallel,
each bound to its own source address (`ping -I`, HTTP `local_address`): gateway reachable, portal state (with auto-login
per IP, bound to that IP), packet loss, and a small download that must complete without stalling.

- Parallel flows share the wifi bandwidth, so triage only **filters** (alive / open / not lossy / not stalling). It never
  ranks or accepts.
- **Survivors go through the full serial test** (same as today, one IP at a time, so speeds are measured alone). Evidence
  per accepted IP is unchanged.
- Caveat: if the dorm throttles per MAC rather than per IP, parallel flows from one MAC blur together. Triage thresholds
  stay conservative, and `history` already stores the MAC so this can be analysed.

### 2.2 `hunt --find N`
Collect N IPs that pass the full test instead of stopping at the first. Keep the best (by score) as the active IP; the
rest go to the standby list. `--find 1` is today's behavior.

### 2.3 Standby list
- New table of pre-qualified IPs (ip, score, tested at, MAC, DNS mode).
- The watchdog fails over to a standby IP first: quick re-verification of the candidate (gateway, portal, quick speed),
  then switch live, instead of a full hunt. A full hunt only when no standby verifies.
- Entries expire (`standby.max_age_hours`) and are dropped after a failed verification; `dorm-ip standby` lists them.

**Done when:** a triage hunt of 30 candidates finishes in a small fraction of the serial time on real hardware; survivors
are verified serially; `--find 3` stores two standbys; the watchdog switches to a standby without running a hunt.

---

## Phase 3 - Setup, CI and release 0.9.0

### 3.1 Shell integration step in `init`
- Detects the shells you actually use (bash, zsh, fish; nushell/PowerShell are out of scope) from `$SHELL`, installed
  shells and existing rc files, and offers to add a `dorm-ip` command that works from any directory
  (runs `uv run --project <repo>` so it always uses the project's environment).
- Marker-delimited block in `~/.bashrc`, `~/.zshrc`, `~/.config/fish/conf.d/dorm-ip.fish`; idempotent, backs the file up
  once, `dorm-ip shell uninstall` removes it. `init --no-shell` skips the step.

### 3.2 `hunt --watch`
New flag: start the watchdog right after a successful hunt (same process, same settings as `dorm-ip watch`), so
`dorm-ip hunt --watch` is the whole routine in one command. It does not start when the hunt finds nothing, and Ctrl+C
during the hunt still restores the original profile.

### 3.3 CI
GitHub Actions on every pull request and on pushes to `main`: install with `uv`, run `uv run pytest`, on the supported
Python versions (3.12+). Required check for merging; README badge.

### 3.4 README: every feature, documented
Rewrite the README so that **every** feature of the tool is described with how to use it: hunt (scan, ordering, tests,
scoring, live switching, triage, `--find`, `--watch`), portal auto-login and cURL import, DNS override, watchdog and its
safety rules, standby list, history, smart ordering, `set`/`dns`/`dhcp`/`restore`, `live-check`, `init`, shell step,
Makefile, safety guards, data budget, files and troubleshooting. Add a "Features at a glance" section at the top and
check it against `dorm-ip --help` so nothing is missing.

### 3.5 Release
Bump to **0.9.0** (`pyproject.toml`, `dorm_ip/__init__.py`), update `NOTES.md`, add `CHANGELOG.md`. Tag `v0.9.0`.

## Decided against

- **Shorter / fewer tests per candidate.** Not enough evidence leads to accepting IPs that are not really good.
  Kept as is; speed comes from the items above.
- **Second wifi adapter support.** Most users have one adapter, so the extra checks would be dead weight.

## Later (v1.0)

To be discussed after v0.9. Already known: MAC randomization (`applier.set_mac`; the MAC is stored with every result so
per-MAC behavior can be analysed first) and a TUI on top of the same functions.