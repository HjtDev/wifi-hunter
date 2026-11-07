# Changelog

## [0.9.1] - 2026-11-04

### Added
- **Flow-mode portal login** (`portal.mode = "flow"`, now the default for new setups): follows the portal's own redirect to its
  login page, loads it for the session cookies, submits its form from the right source address and then verifies that the
  internet really opened. Nothing is pasted or goes stale per IP. Recognises Kerio Control portals whose login page has no
  parsable form (`/internal/dologin.php`, `kerio_username` / `kerio_password`); other portals can set `post_path` and the field names.
- `dorm-ip login --debug`: a step-by-step trace (redirects, cookies by name, form fields, result) with no secrets in it.
- Portal and `.local` names are resolved through the dorm DNS (system resolvers often send `.local` to mDNS only).
- `dorm-ip init` asks how to log in (`flow` or `replay`).

### Fixed
- Auto-login failed on portals that put per-client values in the login URL (here: a base64 token containing the client IP),
  need the session cookies from the login page, or answer `302` whether the login worked or not. The old replay import froze
  the token, dropped the cookies and trusted the response code.

## [0.9.0] - 2026-11-02

### Added
- **Parallel triage**: candidates are put on the interface in batches (`hunt.triage_batch`, default 12) and filtered in
  parallel, each probe sent from its own address; only survivors get the full serial test. A control IP and an
  "all extra addresses dead" check fall back to one-by-one testing if it does not work on the network.
- **`hunt --find N`** keeps the best of N passing IPs and stores the rest as **standby** IPs (`dorm-ip standby`);
  the watchdog fails over to a standby IP (quick re-check) before running a full hunt (`[standby]` section).
- **Live IP switching** (`hunt.live_change`): the IP of the running connection is changed without reconnecting the wifi,
  verified by reading the address back, with an automatic fallback. Only the final IP is written to the saved profile.
  `dorm-ip live-check [--compare]` measures it on your machine.
- **Smart ordering**: IPs that failed recently are skipped (`hunt.skip_failed_minutes`, doubling per failure, `--retry-failed`),
  hour-of-day weighting, busy-IP penalty from stored ARP scans, bonus for untested neighbors of good IPs
  (`hunt.explore_near_good`).
- Readiness polling instead of a fixed wait after switching IP; per-candidate timing and total time in the hunt output.
- **`hunt --watch`**: start the watchdog right after a successful hunt.
- **Shell command**: `dorm-ip init` offers to add a `dorm-ip` command to bash, zsh and fish (`dorm-ip shell install|uninstall|status`).
- **`dorm-ip --version`**, `dorm-ip standby`, and a cooldown listing in `dorm-ip history`.
- **CI**: GitHub Actions runs the tests on pull requests and pushes to `main` (Python 3.12-3.14) and builds the wheel.
- A README that documents every command, option and config key, enforced by a test.

### Changed
- `no internet` failures now say why (timed out / DNS lookup failed / could not connect), and fast DNS or connect errors
  right after an IP switch are retried before the IP is marked as failed.
- `set` keeps the current DNS (override stays override) and logs in to the portal when it asks.
- Config lookup: `--config`, then `~/.config/dorm-ip/config.toml`, then `./config.toml`.

## [0.2.0]

First public version: guided setup (`init`, `make init`), hunt with sustained-test collapse detection, DNS override, portal
auto-login from a pasted cURL request, watchdog with VPN / suspend / other-network protection, SQLite history, daily data
budget, backup and restore of the original network profile.
