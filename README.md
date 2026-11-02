# dorm-ip

Find and keep a **fast, stable static IP** on a dorm wifi that hides behind a captive portal.

Dorm networks like this one share a bandwidth-limited connection, a daily data quota and a login page. Speed
depends heavily on *which IP* you use: some are fast, some crawl, some work for 2 MB and then die. Trying IPs by
hand is slow, and "ping" scanners cannot tell a good IP from one that collapses after a few megabytes.

`dorm-ip` automates the whole routine on Linux (NetworkManager): it scans for IPs in use, tries candidates one by
one, measures each with a **sustained download test** that catches the "fast, then dead" case, logs in to the portal
for you, keeps the winner, remembers what it learned, and watches the connection so it can switch when the IP goes bad.

- Scans only the configured IP ranges and tries **unused IPs first** (shared IPs are still allowed).
- Tests every candidate: gateway, portal state, ping/loss/jitter, DNS, quick speed and a sustained test with
  **collapse detection**.
- **Auto-login** to the captive portal (replays the browser's login request; credentials stay in a `chmod 600` file).
- **DNS override** support: hunts with a public DNS so the portal's DNS redirect does not get in the way, and keeps it.
- **Live IP switching**: changes the IP of the running connection instead of reconnecting the wifi for every
  candidate (verified after each change, falls back to a normal reconnect if it does not work on your machine).
- **History** in SQLite: best IPs, the hours they were good, IPs that often fail.
- **Smart ordering**: IPs that failed recently are skipped for a while, and `best-history` ranks by past results
  (weighted by the hour of day), busy IPs and neighbors of good IPs.
- **Watchdog** that notices a degraded connection and re-hunts, without being fooled by VPNs, suspend/resume, other
  networks or your own heavy downloads.
- A **daily data budget** for test traffic, and a safe **backup/restore** of your original network profile.

## Requirements

| Needed | Notes |
|---|---|
| Linux with **NetworkManager** (`nmcli`) | Tested on Arch Linux + Hyprland |
| **[uv](https://docs.astral.sh/uv/)** | `sudo pacman -S uv` (installs Python 3.12 deps for you) |
| **arp-scan** | `sudo pacman -S arp-scan`; `make init` installs it if missing |
| `ping` (iputils) | already on most systems |
| `notify-send` | optional, for desktop notifications (libnotify) |

## Quick start

```bash
git clone <your repo url> dorm-ip && cd dorm-ip
make init
```

`make init` installs `arp-scan` if needed, runs `uv sync`, then starts the guided setup, `uv run dorm-ip init`.
Without make: `uv sync && uv run dorm-ip init`.

The setup asks a few questions and writes two files **outside the repository**:

- `~/.config/dorm-ip/config.toml` - network values, thresholds, DNS, watchdog and the portal login request
- `~/.config/dorm-ip/credentials.toml` - your portal username and password (`chmod 600`)

What it asks:

1. **Network**: it detects interface, gateway, prefix and dorm DNS from your current wifi connection and asks you to
   confirm them (and the IP ranges to hunt).
2. **What is a good IP**: prefer unused IPs, override DNS servers, which DNS to keep, minimum speed in MB/s, whether
   quick *or* sustained speed is enough, maximum ping, candidates per hunt, daily data budget.
3. **Portal auto-login**: your username, your password (hidden) and the portal's login request (see below).
4. **Watchdog**: check interval and notifications.

Re-running `init` is safe: your existing values are the defaults and the old config is kept as `config.toml.bak`.
`dorm-ip init --yes` accepts every default without asking.

### Giving it the portal login request

Auto-login replays the request your browser sends when you log in:

1. Open the portal login page in Chrome/Firefox and press **F12** > **Network**.
2. Log in. Right-click the login request (usually a `POST`) > **Copy** > **Copy as cURL (bash)**.
3. Paste it into the setup when asked (end with an empty line), or save it to a file and run
   `uv run dorm-ip init --curl-file login.curl`.

The setup swaps your username/password (and IP/MAC) for `{username}`, `{password}`, `{ip}`, `{mac}` placeholders,
drops cookies and browser-only headers, and writes the rest to `[portal]`. **Your credentials never end up in
`config.toml`.** Then check it works:

```bash
uv run dorm-ip login --force
```

## Everyday use

Use `uv run dorm-ip ...`, or `source .venv/bin/activate` to call `dorm-ip` directly. `make info|scan|hunt|watch|history|login`
are shortcuts.

| Command | What it does |
|---|---|
| `dorm-ip info` | Show the live profile (IP, gateway, DNS, MAC) and warn if it does not match the config |
| `dorm-ip scan` | arp-scan the configured ranges: which candidates are in use, and the order they would be tried |
| `dorm-ip test [--no-deep]` | Run the full test suite on the current IP (`--no-deep` skips the sustained test) |
| `dorm-ip hunt [--range A-B] [--max N] [--order ...] [--open-portal] [--retry-failed]` | Find a good IP and keep it. Shows seconds per candidate; `--retry-failed` also tries IPs that failed recently |
| `dorm-ip live-check [--ip IP] [--compare]` | Check on this machine that switching the IP without a reconnect works, and time it against a reconnect |
| `dorm-ip watch [--notify/--no-notify]` | Watch the connection and re-hunt when it degrades |
| `dorm-ip history [--top N]` | Best IPs, when they were good, IPs that often fail, pass rate by hour |
| `dorm-ip set <ip> [--dns A,B] [--gw X] [--prefix N] [--no-login]` | Apply a static IP. **Keeps your current DNS** unless `--dns` is given; logs in to the portal if it asks |
| `dorm-ip login [--force]` | Test or trigger the portal login |
| `dorm-ip dns override\|default\|set A,B` | Change only the DNS, not the IP |
| `dorm-ip dhcp` | Back to automatic (DHCP) |
| `dorm-ip restore` | Restore the original profile saved before the first change |
| `dorm-ip init [--yes] [--curl-file F]` | Guided setup |
| `dorm-ip path config\|credentials\|db\|backup` | Print where a file lives |

Global flags go **before** the command: `--config PATH`, `--dry-run` (prints the exact `nmcli`/`arp-scan` commands and
changes nothing). `test` and `hunt` also accept `--ignore-vpn` and `--force` (see *Safety*).

A typical day: `dorm-ip hunt`, then leave `dorm-ip watch` running in a terminal.

## How it works

### The hunt

```
arp-scan the ranges  ->  order candidates (unused first, then history)
for each candidate IP:
    apply it (static IP + override DNS)  ->  wait for the link
    gateway reachable?  ->  portal open? (log in if not)  ->  ping/loss  ->  DNS  ->  quick speed  ->  sustained test
    first failure stops the test (cheap tests first, so bad IPs cost almost no data)
    passed?  ->  keep it, finish the DNS/portal state, stop
nothing passed / error / Ctrl+C / SIGTERM  ->  restore the original profile
```

| Test | What it checks |
|---|---|
| Gateway | 2 pings to the gateway. Dead = bad IP (or an IP conflict) |
| Portal | `generate_204`: `204` = open, redirect/HTML = portal, timeout = dead |
| Ping | loss, average and jitter to `ping_target` |
| DNS | resolve time of a few domains, asked directly from the active DNS server |
| Quick speed | one 5 MB download |
| Sustained | downloads for `sustained_seconds`, sampled every `sample_interval`; reports average, minimum and the **collapse point** (speed under `collapse_below_mbps` for 2 s, reported as "after N MB") |

**Faster than one reconnect per candidate.** By default (`hunt.live_change = "auto"`) the tool changes the address of the
*running* connection (`nmcli device modify`) instead of reconnecting. After every switch it reads the address back and
requires exactly the new one; if NetworkManager refuses or the address did not change, it says so, uses full reconnects for the
rest of the hunt and carries on. Instead of a fixed wait it polls the gateway, so a candidate that is ready in half a second
is tested at once, and a dead one is recorded as soon as the wait runs out. While candidates are tried the saved
NetworkManager profile is not touched; only the winner is written to it. Run `dorm-ip live-check --compare` once to see the
real timings on your wifi.

**Smart ordering.** Every result and ARP scan is kept in the history and used to order the next hunt:

| Rule | Effect |
|---|---|
| Recently failed IPs are skipped | cooldown `hunt.skip_failed_minutes` (30), doubling per consecutive failure up to 12 h; an IP that passed in the last 24 h only gets the base cooldown; "login required" never counts as a failure; skipped IPs are still used if there are not enough other candidates; `--retry-failed` ignores it |
| Hour of day | with `order = "best-history"`, results from within 2 hours of now count double, so an IP that is good in the evening ranks higher in the evening |
| Busy IPs | IPs seen in use in many of the last 10 scans rank lower |
| Near good IPs | untested IPs within 3 addresses of a known-good one get a small bonus (`hunt.explore_near_good`) |

**Pass/fail.** Hard fails (score 0): gateway down, no internet, portal blocking, packet loss over the limit, speed
collapse, DNS or download failure. Threshold fails: ping above `max_ping_ms`, or speed below the limit. With
`speed_rule = "either"` the quick **or** the sustained speed reaching its limit is enough; with `"both"` both must.
The score (0-100) is `0.5*sustained + 0.2*quick + 0.2*ping + 0.1*loss`, used to rank IPs.

### DNS override and the portal

The dorm DNS sends every unauthenticated client to the portal, and the portal's name only exists in that DNS. A public
DNS (the *override*) skips the redirect, so most candidates are testable immediately. Two situations remain:

- **A candidate still shows the portal** (its IP is not logged in). `dorm-ip` logs in for you: it resolves the portal
  host by asking the **dorm DNS server directly** (a UDP query, no system change) and connects to that address while
  keeping the real host name for `Host`/TLS. So login works while your system DNS stays on the override, with no DNS
  switching and no extra wifi reconnect. (`portal.host_ip` can pin the address by hand.)
- **`final_mode`** decides which DNS stays after a hunt: `override` (default), `default` (dorm DNS, then portal check)
  or `auto` (override if the portal stays open, otherwise the dorm DNS).

`dorm-ip set` does the same: it keeps whatever DNS is active, then logs in if the portal appears.

### The watchdog

Every `interval_seconds` it pings the gateway and downloads a small probe. After `bad_checks_to_rehunt` bad checks in
a row it: notifies; tries to **log in again** if the portal is asking (an expired session is cheaper than a new IP);
otherwise runs a real quick speed test to rule out a false alarm; and only then re-hunts. After a failed re-hunt it
backs off 5, 10, 20... minutes (max 30). It never judges the link, and never re-hunts, when:

| Situation | Behavior |
|---|---|
| Wifi is disconnected | paused, nothing counted |
| Connected to a **different network** (gateway does not match) | paused: it will never reconfigure your home wifi |
| A **VPN/tunnel carries your traffic** | gateway-only checks, no downloads, no re-hunt (tests would measure the VPN) |
| Just **resumed from suspend** | 60 s grace period while the wifi reconnects |
| A slow probe while **you are using the link** (> `busy_mbps` of your own traffic) | ignored |
| Daily data budget is used up | no re-hunt |

Ctrl+C stops the watcher and leaves your current IP as it is.

### History

Every test and watchdog check is stored in SQLite (`dorm-ip path db`) together with the MAC used, so you can later see
whether the throttle is per IP or per MAC. `hunt_order = "best-history"` ranks IPs by their last 5 results (failures count
as 0) and still explores IPs it has never tried.

## Configuration

`dorm-ip init` writes it and `make edit-config` opens it. The built-in template is
[`dorm_ip/config.example.toml`](dorm_ip/config.example.toml). Network values are never hard-coded: they live only in
the config.

| Section | Key | Meaning |
|---|---|---|
| `[network]` | `interface`, `connection` | wifi device; NetworkManager connection (empty = the active wifi) |
| | `prefix`, `gateway` | subnet; the real prefix is read from the DHCP lease and `info` warns on a mismatch |
| | `ranges`, `exclude` | IPs to hunt (`A-B` ranges) and IPs never to use |
| | `prefer_unused` | try IPs not seen in the ARP scan first |
| `[dns]` | `default`, `override` | dorm DNS; public DNS used to skip the portal redirect |
| | `hunt_with_override`, `final_mode` | hunt with the override; DNS kept afterwards (`override`/`default`/`auto`) |
| `[tests]` | `ping_target`, `ping_count`, `connectivity_url` | ping and portal-check targets |
| | `speed_url`, `sustained_url`, `sustained_seconds`, `sample_interval` | download tests |
| | `data_budget_mb` | daily cap for all test traffic (`0` = unlimited) |
| `[thresholds]` | `max_ping_ms`, `max_loss_pct` | latency and loss limits |
| | `min_speed_mbps`, `min_sustained_mbps` | speed limits (8 Mbps = 1 MB/s) |
| | `speed_rule` | `either` (quick or sustained is enough) or `both` |
| | `collapse_below_mbps` | below this for 2 s counts as a collapse |
| `[hunt]` | `max_candidates`, `order` | candidates per hunt; `random`/`sequential`/`best-history` |
| | `settle_seconds` | longest wait for the gateway after a live switch (a reconnect waits at least twice as long) |
| | `live_change` | `auto` (switch without reconnecting, verified) or `off` |
| | `skip_failed_minutes`, `explore_near_good` | cooldown after a failed IP (0 = off); bonus for untested neighbors of good IPs |
| `[watchdog]` | `interval_seconds`, `probe_bytes`, `bad_checks_to_rehunt`, `notify` | check cadence and trigger |
| | `min_probe_mbps`, `rehunt_cooldown_seconds`, `busy_mbps` | probe limit (slow-start aware), back-off, "link busy" threshold |
| `[portal]` | `enabled`, `url`, `method`, `content_type`, `fields`, `headers` | the login request (`{username}` `{password}` `{ip}` `{mac}` are filled in) |
| | `success_contains`, `failure_contains` | text that marks a successful / rejected login |
| | `credentials_file`, `keyring_service` | where the credentials are read from |
| | `login_during_hunt`, `max_logins_per_hunt` | log in on candidates that show the portal; cap per hunt |
| | `resolve_via_dorm_dns`, `host_ip`, `verify_tls`, `timeout` | how the portal host is reached |

### credentials.toml

```toml
username = "your-portal-username"
password = "your-portal-password"
```

Keep the values in **quotes** (an unquoted number like `03211040300022` is not valid TOML because of the leading
zero). The file must be readable only by you; `dorm-ip` refuses to use it otherwise. `make edit-credentials` creates it
with the right permissions and opens it. Optionally set `portal.keyring_service` to read both values from the system
keyring instead (needs `uv sync --extra keyring`).

## Safety

- **Backup first.** Before the first change `dorm-ip` saves your original NetworkManager settings
  (`dorm-ip path backup`). It is restored when a hunt finds nothing, on errors, Ctrl+C and SIGTERM, or with
  `dorm-ip restore`. Only the configured connection is ever modified.
- **Wrong network.** `set`, `test` and `hunt` refuse to run when the connected network's gateway is not the configured
  one (`--force` overrides), so a hunt cannot reconfigure your home wifi.
- **VPN.** `test` and `hunt` refuse while a tunnel carries your traffic (they would measure the VPN, and changing the IP
  would drop it). Disconnect it or pass `--ignore-vpn`. The watchdog handles this itself (see above).
- **Account.** Auto-login stops after 2 failed attempts per hunt (no lock-outs) and after `max_logins_per_hunt`.
- **Secrets.** Credentials live only in `credentials.toml` (chmod 600); they are never printed, logged or put in the
  config. Do not commit `config.toml` or `credentials.toml`.
- **Network load.** Tests are short and stop at the first failure. The ARP scan sends one frame per candidate
  (about 500). The watchdog probe is 200 KB per check.

### Data usage

A full test of a good IP costs roughly `speed x sustained_seconds` (30 Mbps x 8 s = 30 MB) plus 5 MB. Bad IPs usually
cost under 1 MB. The watchdog probe adds `probe_bytes x 86400 / interval` per day (200 KB every 30 s is about 580 MB;
every 10 s about 1.7 GB), so keep the interval long if your daily limit matters. All of it counts toward
`data_budget_mb`; `dorm-ip history` shows today's total.

## Files

| What | Where |
|---|---|
| Config | `~/.config/dorm-ip/config.toml` (falls back to `./config.toml`) |
| Credentials | `~/.config/dorm-ip/credentials.toml` |
| History database | `~/.local/share/dorm-ip/history.db` |
| Profile backup | `~/.local/state/dorm-ip/backup.json` |

## Make targets

| | |
|---|---|
| `make init` | install `arp-scan` if missing, `uv sync`, run `dorm-ip init` |
| `make edit-config` / `make edit-credentials` | open the files in `$VISUAL`/`$EDITOR` |
| `make arp-cap` | let `arp-scan` run without sudo (`setcap`) |
| `make test` | run the unit tests |
| `make info\|scan\|hunt\|watch\|history\|login` | shortcuts |

## Troubleshooting

- **`arp-scan` asks for a password / "permission"**: it retries with `sudo`. Run `make arp-cap` once to avoid it.
- **"arp-scan saw no hosts"**: the wifi may isolate clients, or the interface is wrong. The hunt still works; every IP
  is treated as unused.
- **Candidates fail with "captive portal: login required"**: auto-login is off or failing. Run
  `dorm-ip login --force`; if it says the request was rejected, set `success_contains`/`failure_contains` or re-run
  `dorm-ip init` and paste the request again.
- **Login works but the portal host does not resolve**: set `portal.host_ip` to the portal's address.
- **"does not look like the dorm wifi"**: the gateway differs from `network.gateway`. Fix the config or use `--force`.
- **"a VPN/tunnel is carrying your traffic"**: disconnect the VPN before `test`/`hunt`.
- **"live IP switching is not working here"**: your driver or NetworkManager version does not apply the change live; the hunt
  continues with reconnects. Run `dorm-ip live-check --compare` to see why, and set `hunt.live_change = "off"` to silence it.
- **A good IP is never tried**: it is probably cooling down after a failure (`dorm-ip history` shows how many are). Use
  `dorm-ip hunt --retry-failed`, or set `hunt.skip_failed_minutes = 0`.
- **Everything is slow after `hunt` gave up**: it restored your original profile (DHCP, dorm DNS); log in to the portal
  or run `dorm-ip hunt` again.

## Development

```bash
uv sync
uv run pytest        # no real network calls; nmcli, ping, arp-scan and httpx are mocked
```

Layout: `cli.py` (thin typer CLI), `config.py`, `models.py`, `netinfo.py` (nmcli/ip), `applier.py` (change/restore),
`scanner.py`, `tests.py` (probes), `scorer.py`, `hunter.py`, `watchdog.py`, `db.py`, `portal.py` (auto-login, cURL
import), `dnsq.py` (DNS packets), `livecheck.py`, `wizard.py` (`init`). Design decisions are in [`NOTES.md`](NOTES.md).

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for the path to v0.9 (parallel triage, `--find N`, standby IPs, shell alias step, CI).
Not built yet: MAC randomization (`applier.set_mac`; the MAC is already stored with every result so you can analyze per-MAC behavior)
and a TUI.
