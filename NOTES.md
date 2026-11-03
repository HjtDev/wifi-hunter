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

## Phase 6, part 2 + setup (init, Makefile, README)
- `dorm-ip init` writes `~/.config/dorm-ip/config.toml` (XDG) and the credentials file (chmod 600). Config lookup is now:
  `--config`, then `~/.config/dorm-ip/config.toml`, then `./config.toml`. The template and defaults live in
  `dorm_ip/config.example.toml`; the repo no longer needs a real `config.toml` (add `config.toml` and
  `credentials.toml` to `.gitignore`). Re-running init uses the existing values as defaults and keeps a `.bak`.
- Portal login request comes from a pasted "Copy as cURL": username/password/IP/MAC become `{username}` `{password}`
  `{ip}` `{mac}`; cookies, content-length, sec-* and similar headers are dropped. Real portal details therefore live
  only in the user-level config, never in the repository.
- Portal host resolution: the login resolves the portal host by querying `dns.default` directly (UDP/53) and connects
  to that IP with the original Host/SNI, so login works while the system DNS is the override. `portal.host_ip`
  pins it. A failed DNS answer falls back to the system resolver.
- `login_during_hunt` is on in the shipped template (the user asked for it). Safety: after 2 failed logins the hunt stops
  trying; `max_logins_per_hunt` (10) caps successful logins.
- `dorm-ip set` keeps the current DNS (override stays override) unless `--dns` is given, waits for the link, and logs in if
  the portal asks (`--no-login` to skip).
- Safety guards: `set`/`test`/`hunt` refuse when the live gateway differs from `network.gateway` (`--force`);
  `test`/`hunt` refuse while a tunnel device carries the default route (`ip route get 1.1.1.1`, `--ignore-vpn`).
- Watchdog never judges the link when: wifi is down, another network is connected, a VPN carries the traffic (gateway-only
  checks, no re-hunt), the machine just resumed from suspend (wall-clock gap > 3x interval + 10 s -> 60 s grace), or
  a slow probe coincides with your own traffic on the interface (> `busy_mbps`).
- `thresholds.speed_rule = "either"`: pass when the quick OR the sustained speed reaches its limit. Between stages a low
  quick speed does not stop the test (sustained may still pass); collapse is still a hard fail.
- Defaults chosen where the request was cut off: `max_ping_ms = 250` (a good IP measured about 180 ms); "1 MB of speed" is read
  as 1 MB/s = 8 Mbps for both quick and sustained; `order = "best-history"`; `final_mode = "override"`;
  watchdog `interval_seconds = 30`.
- `data_budget_mb = 0` means unlimited.

## Roadmap phase 1 (live switching, readiness polling, smart ordering)
- `applier.switch_static(live=True)`: `nmcli device modify <dev> ipv4.*` (runtime only, saved profile untouched), then
  `nmcli dev show` must list exactly the new address; otherwise (nmcli error, address unchanged, or an extra address next to
  the old one) it falls back to `con mod` + `con up` and returns a note. The hunter turns live switching off for the rest of
  the run after the first fallback. The winner is written to the profile with `persist_static` (`con mod`, no reconnect).
  Restore after a failed/interrupted hunt is still `con mod` (saved values) + `con up`.
- This cannot be tested without real NetworkManager/wifi, hence the read-back check and `dorm-ip live-check`
  (switches to a known-good IP live, optionally by reconnect too, always restores the original profile).
- `_wait_ready` polls the gateway (1 ping, 0.2 s apart) instead of sleeping `settle_seconds`; live: max `settle_seconds`,
  reconnect: max `max(2 x settle_seconds, 8 s)`. `run_all(gateway_ok=...)` reuses that result instead of pinging again, and a
  gateway that never answered is recorded without running any test. The old "retry once if the gateway is unreachable" is gone
  (the longer reconnect wait replaces it).
- New tables `scan_runs`/`scan_hits` (only non-empty scans are stored). `Ranking(scores, skip, busy)` comes from
  `DB.ranking()`. Cooldown: base x 2^(streak-1), max 12 h, base only if the IP passed in the last 24 h; "captive portal"
  failures are ignored. Skipped IPs are appended after all others (shortest cooldown first), so they are only reached when
  `max_candidates` is larger than the number of other candidates.
- Scoring for `best-history`: score (last 5 results, failures = 0, +-2 h of the current hour double) - 20 x busy ratio
  + 10 for an untested IP within 3 addresses of an IP scoring >= 60. Random and sequential order only get the skip rule.
- `hunt` prints the time per candidate and the total.

## Roadmap phase 2 (parallel triage, --find, standby)
- Triage: `applier.switch_many` puts the control IP (the IP the hunt started from) plus a batch of candidates on the running
  connection with one `nmcli device modify ipv4.addresses a/21,b/21,...` (first = primary) and checks the whole set read back.
  There is no reconnect fallback (several addresses only exist live): "unsupported" disables triage for the rest of the hunt and
  the batch goes back to the queue. Each probe is sent from its own address (`ping -I`, httpx `local_address`, portal login
  bound to the source address).
- Triage checks: gateway (2 pings), portal state (+ auto-login hook, `login_during_hunt`), loss (4 pings to ping_target,
  limit 25%), ping (limit 2 x max_ping_ms), small download (300 KB must complete, >= 0.3 Mbps). It never accepts or ranks.
  Survivors go through the unchanged full test one at a time (the first switch drops the extra addresses).
- Safety nets for "multi-IP does not work here": control IP fails the gateway check, or (no control) >= 4 candidates and all
  of them "gateway unreachable". Both disable triage and requeue the batch. Failed triage results are saved as TestResults
  (reason = the triage reason, so "captive portal" stays neutral for the cooldown).
- `--find N`: collect N passing IPs (default `hunt.find` = 1); best = highest score; if the best is not the active IP the hunt
  switches back to it (live, `settle_portal`), then persists and finalizes. Others -> `standby` table (upsert by IP).
- Standby: `standby(ip, ts, score, mac, dns_mode)`, expired after `standby.max_age_hours`. `hunter.failover()` tries up to 3
  entries with a quick re-check (`run_all(deep=False)`), drops failures, persists the winner. The watchdog calls it after the
  false-alarm check and budget check and before a hunt; never during a VPN.
- Connectivity check: fast DNS/connect failures are retried twice (1 s apart) because right after a live switch the resolver
  or routes may still be settling; timeouts are not retried. For "dead" the third tuple element is the cause, which becomes
  `no internet: <cause>` in the result.

## Roadmap phase 3 (shell command, hunt --watch, CI, README, 0.9.0)
- `shellint.py`: a marker-delimited block (`# >>> dorm-ip >>>` ... `# <<< dorm-ip <<<`) with a *function* (not a plain alias, so it
  also works with arguments and quoting) `uv run --quiet --project <repo> dorm-ip "$@"`. bash -> `~/.bashrc`, zsh ->
  `$ZDOTDIR/.zshrc` or `~/.zshrc`, fish -> `conf.d/dorm-ip.fish` (the whole file is ours; fish function with `$argv`).
  Shells offered: binary on PATH and (login shell, or its rc file / fish config dir exists). Install is idempotent (replaces the
  block in place), backs the file up once as `<file>.dorm-ip.bak`, uninstall removes only the block (deletes the fish file).
  The path is quoted with `shlex.quote` / a fish quoter; a test runs the real bash function with a stub `uv`.
  `init --yes` and `--no-shell` never touch dotfiles; the step is a question per shell. When the package is not run from a
  checkout (no `pyproject.toml` next to it) nothing is added: it is already a normal command.
- `hunt --watch` reuses the same `_watch_loop` as `watch` (DB opened by the loop; only after a successful, non-dry-run hunt).
  The watchdog's re-hunt now also passes `on_standby`, so `hunt.find > 1` keeps the extra IPs during automatic re-hunts.
- CI: `.github/workflows/ci.yml` (pull requests and pushes to `main`): `uv sync`, `uv run pytest -q` on 3.12/3.13/3.14, CLI smoke
  checks, and a wheel build that must contain `config.example.toml`. It uses `uv sync` (not `--locked`), so a stale `uv.lock`
  after the version bump does not fail CI; run `uv lock` and commit it.
- `tests/test_readme.py` fails if a command, option or config key is missing from the README, if the version differs between
  `pyproject.toml`, `dorm_ip/__init__.py` and the README/CHANGELOG, or if the CI workflow / Makefile docs go missing.
- Version 0.9.0; `dorm-ip --version` added.
