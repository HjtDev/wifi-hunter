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
