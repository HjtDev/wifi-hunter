# NOTES

Decisions made where the spec was ambiguous (simplest option chosen).

## Phase 1
- `apply_static`, `apply_dhcp`, `set_dns` take a keyword-only `connection` (the CLI resolves it once);
  `get_profile` takes optional `interface`/`connection`. Spec signatures otherwise unchanged.
- Connection choice: `network.connection` if set, else the active wifi connection on `network.interface`.
  If that interface has no active wifi but exactly one wifi is active, it is used with a note.
  Only that one connection is ever modified.
- Backup (`~/.local/state/dorm-ip/backup.json`, chmod 600) stores the live profile plus the *configured* ipv4
  settings. An existing backup for the same connection is never overwritten, so a second run cannot replace
  the true original with an already-modified state. `restore` deletes the backup after success; the next change
  takes a fresh one. Backup for a different connection replaces the old one.
- Non-network settings (thresholds, tests, ...) have code defaults. Network values (prefix, gateway, ranges,
  dorm DNS) are required in config.toml and have no defaults in code. Gateway is always excluded from candidates.
- Network/broadcast addresses of the subnet are dropped with a warning; out-of-subnet IPs are kept with a warning.
- `info` compares the live prefix/gateway with the config. If the method is manual it says the value comes from
  static config, not a DHCP lease.
- `--dry-run` still reads state (read-only nmcli); if nmcli/wifi is unavailable it falls back to a placeholder
  connection name so the commands can still be previewed.
- Global flags go before the subcommand: `dorm-ip --dry-run set 172.18.40.9`.

## Phase 2
- New optional `[tests]` keys (defaults in code, your config.toml works unchanged): `sustained_url` (empty = repeat
  `speed_url` on one keep-alive connection, which avoids server-side size caps) and `dns_domains`.
- DNS time is measured with a raw UDP/53 query to the first IPv4 DNS server of the live profile, so it times the
  active DNS and not a local cache. `dns_mode` is "default", "override", or "custom" (anything else).
- Fail-fast order: gateway -> portal -> ping -> DNS -> quick speed -> sustained. Any hard fail or threshold miss
  stops the suite, so slow/lossy IPs never spend quota on downloads. A `portal` state stops before downloads.
- Hard fails (score 0): gateway down, no internet, portal, loss > max, collapse, DNS failure, download failure.
  Threshold misses (ping, quick, sustained below limit) keep a non-zero score but `passed = False`.
- Sub-scores: speed 100 at 5x its threshold (linear from 0); ping 100 at <=25% of max, 0 at max; loss 100 at 0,
  0 at max; sustained uses 0.7*avg + 0.3*min. Unmeasured parts (e.g. --no-deep) are dropped and weights renormalised.
- Sustained `min` ignores the first sample interval (TCP slow start) when there are >= 3 intervals.
- Collapse = under `collapse_below_mbps` for >= 2 s, reported as MB downloaded when the low stretch began.
  A stalled stream (2 s read timeout) counts as zero speed until the end of the window.
- `bytes_used` counts HTTP payload only; ping/DNS traffic is ignored. One deep test costs roughly
  speed x sustained_seconds (e.g. 30 Mbps x 8 s = 30 MB) plus the 5 MB quick test.
- `test` does not save to the database yet (phase 4).

## Phase 3
- `scan_used` runs arp-scan only over `network.ranges`. If arp-scan fails with a permission error and we are not
  root, it retries once with `sudo` (password prompt works in the terminal). To avoid the prompt:
  `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/arp-scan`. A missing/failed scan is not fatal for `hunt`:
  every IP is treated as unused and a note is shown. Results are intersected with the candidate list.
- Ordering: `prefer_unused` puts IPs not seen in ARP first; used IPs are kept, just later. Within a group:
  random | sequential | best-history. `best-history` takes a `scores` dict (phase 4 will supply it); with none it is random.
- Hunter never prints; it talks to a `HuntObserver` (the CLI's `LiveHunt` draws the rich table).
  Hooks for phase 4 already exist: `hunt(..., spent=db.daily_bytes, save=db.save, history=db.scores)`.
  Until then the data budget counts only the current run's traffic.
- Restore happens when nothing passes, on any exception, on Ctrl+C and on SIGTERM (mapped to KeyboardInterrupt).
  `restore` consumes the backup, so a later `dorm-ip restore` after a failed hunt says "nothing to restore" (already done).
  After a successful hunt the backup is kept, so `dorm-ip restore` still returns to the original profile.
- Applying an IP can fail (`con up` error): that candidate is skipped; 3 consecutive failures abort the hunt (and restore).
- A candidate that fails with "gateway unreachable" is retried once after another `settle_seconds`, because wifi may
  still be re-associating after `con up`.
- Finalize (dns.final_mode): `default` -> switch to dorm DNS + portal check; `override` -> keep/switch to override;
  `auto` -> override if the portal check is `open`, otherwise dorm DNS and re-check. A test that passed already proved
  `open` under its DNS, so no re-check is done unless the DNS was switched. If still `portal`: `hunter.try_login()`
  (phase 6 stub, returns False), then "Login required" and, with `--open-portal`, `xdg-open <Location header or
  connectivity_url>`.
- `--dry-run hunt`: prints the arp-scan command and the nmcli commands for the first 3 candidates; runs no tests and
  does not touch the backup or the network. `hunt` exits 1 when no IP passes, 130 on Ctrl+C.
- New options: `hunt --range A-B[,C-D] --max N --order ... --open-portal`; new command `scan`.

## Phase 4 (db, history, budget)
- History DB: `~/.local/share/dorm-ip/history.db` (`$XDG_DATA_HOME/dorm-ip/`). Tables: `results` (every TestResult incl. MAC),
  `checks` (watchdog), `daily_usage(day, bytes)`. The day is the *local* calendar day (the dorm quota reset time is unknown).
- `test` and `hunt` save every result. `hunt` and `watch` pass `spent=db.daily_bytes`, so the budget is the real
  daily total (tests + watchdog probes + confirmation tests), not just the current run.
- `best-history` ordering: per IP, mean of its last 5 results where a failed test counts as 0 (reliability x quality).
  IPs without history are neutral (50) and keep their random order; with no history at all it is plain random.
- `history`: top N by that reliability-weighted score, pass %, average score of passing tests, sustained Mbps, good
  hours (hours where the IP passed >= 50% of its tests there), last test, flag (`bad` = 0 passes in >= 3 tests,
  `flaky` = < 50% in >= 3 tests). Also: IPs that often fail, pass rate by hour of day (all IPs), and pass rate for
  IPs seen in use vs unused (to check the shared-IP assumption).

## Phase 5 (watchdog)
- Every `interval_seconds`: 3 pings to the gateway + a `probe_bytes` download on a persistent connection (speed is
  measured after the response headers). A check is bad on: gateway unreachable, loss > max_loss_pct, probe failed
  (HTTP error, timeout, or a body shorter than half the expected size, e.g. a portal page), or probe speed below
  `watchdog.min_probe_mbps`.
- New optional keys: `watchdog.min_probe_mbps` (default 1.0 instead of `thresholds.min_speed_mbps`, because a
  200 KB probe on a ~180 ms link is dominated by TCP slow start and would read far below 5 Mbps on a healthy IP) and
  `watchdog.rehunt_cooldown_seconds` (default 300).
- After `bad_checks_to_rehunt` consecutive bad checks the watchdog: (1) notifies; (2) checks the portal: if it asks
  for login it tries `portal.login()` (session expired is cheaper to fix than a new IP) and stops if that worked;
  (3) otherwise runs a real quick test on the current IP (about 5 MB): if it passes it is a false alarm and the
  watchdog holds off for the cooldown; (4) otherwise re-hunts (skipped if today's budget is spent).
- A failed re-hunt restores the original profile (as `hunt` does) and the next attempt waits cooldown, 2x, 4x ...
  up to 30 minutes. A successful re-hunt checks the portal and notifies "Login required" if needed.
- Wifi disconnected = a bad check. Ctrl+C / SIGTERM stops the watcher and leaves the current IP as it is.
- Watchdog traffic counts toward the daily budget: 200 KB every 10 s is about 1.7 GB/day. Use a longer interval
  (30-60 s) if the daily limit matters.
- `notify-send` is used for notifications; failures (no desktop session, e.g. under sudo) are ignored.

## Phase 6, part 1 (auto-login). MAC randomization and TUI are NOT built yet.
- `[portal]` in config.toml describes the login request (url, method, form/json fields, query, headers). The tokens
  `{username}` `{password}` `{ip}` `{mac}` are replaced at send time; other braces are left alone. Success = HTTP < 400
  after redirects, plus optional `success_contains` / `failure_contains` text checks. `enabled = false` by default.
- Credentials are never in config.toml: `~/.config/dorm-ip/credentials.toml` with `username` and `password`,
  refused unless `chmod 600`. Optional `keyring_service` reads `username`/`password` from the system keyring
  (needs the `keyring` package). Credentials are never printed or included in error messages.
- `dorm-ip login [--force]` tests the setup: shows the portal state, sends the request, shows the state again.
- Used by: `hunter.finalize` (when the final DNS still shows the portal), the watchdog (expired session), and
  optionally during the hunt: `portal.login_during_hunt = true` logs in on every candidate that shows the portal,
  then tests it. Off by default because it creates a portal session per candidate and may log out other sessions.
