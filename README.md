# dorm-ip

<!-- CI badge: replace OWNER/REPO and uncomment
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
-->

Find and keep a **fast, stable static IP** on a dorm wifi that hides behind a captive portal. Version 0.9.

Dorm networks like this one share a bandwidth-limited connection, a daily data quota and a login page. Speed depends
heavily on *which IP* you use: some are fast, some crawl, some work for 2 MB and then die. Trying IPs by hand is slow,
and "ping" scanners cannot tell a good IP from one that collapses after a few megabytes.

`dorm-ip` automates the whole routine on Linux (NetworkManager): it scans for IPs in use, filters many candidates in
parallel, measures the survivors with a **sustained download test** that catches the "fast, then dead" case, logs in to
the portal for you, keeps the winner, remembers what it learned, and watches the connection so it can switch when the IP
goes bad.

## Features at a glance

**Finding an IP**
- ARP scan of only your configured ranges; IPs nobody else uses are tried first (shared IPs are still tried).
- **Parallel triage**: a batch of candidates sits on the interface at once and is filtered in parallel, each probe sent
  from its own address (gateway, portal, loss, small download). Survivors get the full serial test.
- **Full test per accepted IP**: gateway, portal state, ping/loss/jitter, DNS time, quick speed, and a sustained test with
  **collapse detection** ("speed died after N MB"). Fails fast: cheap checks first.
- **Live IP switching**: changes the IP of the running connection instead of reconnecting the wifi for each candidate;
  verified after every change, falls back to a normal reconnect if it does not work on your machine.
- **Smart ordering** from the history: recently failed IPs are skipped for a while, IPs are ranked by past results
  (weighted by the hour of day), busy IPs rank lower, untested neighbors of good IPs get a bonus.
- **`--find N`**: collect several passing IPs, keep the best, remember the rest as **standby** IPs.
- Quick-or-sustained speed rule, maximum ping and loss limits, collapse limit, all configurable.
- **Daily data budget** for all test traffic; per-candidate timing in the live table.

**The captive portal**
- **Auto-login that works like a browser** (`portal.mode = "flow"`): follows the portal's own redirect to its login page, loads
  it (session cookies), submits its form and then checks that the internet really opened. Nothing to paste, nothing goes stale
  per IP. Works with Kerio Control portals even when the page is built by JavaScript. The older "replay a pasted request" mode
  is still available. The portal host is resolved through the dorm DNS even while your system DNS is the override.
- Logs in during a hunt, after `dorm-ip set`, when the watchdog sees an expired session, and on demand (`dorm-ip login`).
- **DNS override** to skip the portal's DNS redirect while testing; you choose which DNS stays afterwards.
- Credentials live in a `chmod 600` file (or the system keyring), never in the config.

**Keeping it good**
- **Watchdog** (`watch`): gateway ping + a small download probe; on a degraded link it logs in again, rules out false
  alarms with a real speed test, switches to a **standby IP**, and only then runs a full hunt, with back-off after failures.
- Never fooled by: wifi disconnects, a different network, a **VPN**, suspend/resume, or your own heavy downloads.
- `hunt --watch` does the whole routine in one command; desktop notifications.

**Everyday tools**
- `info`, `set` (keeps your DNS, logs in), `dhcp`, `dns override|default|set`, `restore`, `test`, `scan`.
- **History** in SQLite: best IPs, the hours they were good, IPs that often fail, pass rate by hour, used vs unused
  IPs, IPs on cooldown, today's data use. The MAC of every test is stored.
- `live-check`: measures on your machine whether live switching works and how much faster it is.
- Everything supports `--dry-run`.

**Safe by design**
- Backup of your original network profile before the first change; restored on failure, errors, Ctrl+C and SIGTERM.
- Refuses to touch a network that is not the dorm wifi, and to measure a VPN instead of your wifi.
- Only the configured connection is ever modified.

**Setup**
- `make init` / `dorm-ip init`: a guided setup that detects your network, writes the config and credentials, imports the
  portal login request and adds a `dorm-ip` command to your shell (bash, zsh, fish).
- CI runs the tests on every pull request.

## Requirements

| Needed | Notes |
|---|---|
| Linux with **NetworkManager** (`nmcli`) | Tested on Arch Linux + Hyprland |
| **[uv](https://docs.astral.sh/uv/)** | `sudo pacman -S uv`; installs Python 3.12+ and the dependencies for you |
| **arp-scan** | `sudo pacman -S arp-scan`; `make init` installs it if missing |
| `ping` (iputils), `ip` (iproute2) | already on most systems |
| `notify-send` | optional, for desktop notifications (libnotify) |

## Quick start

```bash
git clone <your repo url> dorm-ip && cd dorm-ip
make init
```

`make init` installs `arp-scan` if needed, runs `uv sync`, then starts the guided setup (`uv run dorm-ip init`).
Without make: `uv sync && uv run dorm-ip init`.

The setup asks a few questions and writes two files **outside the repository**:

- `~/.config/dorm-ip/config.toml`: network values, thresholds, DNS, watchdog and the portal login request
- `~/.config/dorm-ip/credentials.toml`: your portal username and password (`chmod 600`)

What it asks (Enter accepts the default shown; yes/no questions default to Yes):

1. **Network**: interface, gateway, prefix and dorm DNS are detected from your current wifi connection; you confirm them
   (and the IP ranges to hunt).
2. **What is a good IP**: prefer unused IPs, override DNS servers, which DNS to keep, minimum speed in MB/s, whether the
   quick *or* the sustained speed is enough, maximum ping, candidates per hunt, order, daily data budget.
3. **Portal auto-login**: username, password (hidden) and how to log in: `flow` (recommended: nothing to paste) or `replay` (a
   login request you paste, below).
4. **Watchdog**: check interval and notifications.
5. **Shell command**: offers to add `dorm-ip` to bash, zsh and fish so you can run it from any folder (see
   [Shell command](#shell-command)). Skipped with `--no-shell` or `--yes`.

Re-running `init` is safe: your existing values become the defaults and the old config is kept as `config.toml.bak`.
`dorm-ip init --yes` accepts every default without asking (and never touches your shell files).

### How the portal login works

**Flow mode (default, recommended).** `dorm-ip` does what your browser does: it asks for a normal web page, the portal answers
with a redirect to its login page (that address carries values that are specific to your IP, so nothing is ever copied from an
old session), it loads that page (which sets the session cookies), finds the login form, submits it with your credentials from
the right source address, and then checks that the internet is really open. It does **not** trust the portal's reply: some
portals answer `302` whether the login worked or not. If the page has no form that can be parsed (built by JavaScript), Kerio
Control portals are recognised and their login endpoint is used; for other portals set `portal.post_path`,
`portal.form_username_field` and `portal.form_password_field`. Test and inspect it with:

```bash
dorm-ip login --force --debug     # every step, redirect and form field; no secrets in the output
```

**Replay mode.** For portals where flow mode does not fit: `portal.mode = "replay"` sends one request that you captured. Open
the login page, press **F12** > **Network**, log in, right-click the login request > **Copy** > **Copy as cURL (bash)**, and paste
it into `dorm-ip init` (or `dorm-ip init --curl-file login.curl`). Your username/password become `{username}`/`{password}`
placeholders and cookies are dropped, so this only suits portals with a fixed, cookie-less login request.

Either way **your credentials never end up in `config.toml`.**

## Everyday use

Run commands as `dorm-ip ...` once the shell command is installed, otherwise `uv run dorm-ip ...`.
`make info|scan|hunt|watch|history|login` are shortcuts.

| Command | What it does |
|---|---|
| `dorm-ip info` | Show the live profile (IP, gateway, DNS, MAC) and warn if it does not match the config |
| `dorm-ip scan` | arp-scan the configured ranges: which candidates are in use, and the order they would be tried |
| `dorm-ip test [--no-deep] [--ignore-vpn] [--force]` | Full test suite on the current IP (`--no-deep` skips the sustained test) |
| `dorm-ip hunt` | Find a good IP and keep it (options below) |
| `dorm-ip watch [--notify/--no-notify]` | Watch the connection and re-hunt when it degrades |
| `dorm-ip history [--top N]` | Best IPs, when they were good, IPs that often fail, pass rate by hour, cooldowns, data used today |
| `dorm-ip standby [--clear]` | List (or forget) the pre-qualified standby IPs |
| `dorm-ip set <ip> [--dns A,B] [--gw X] [--prefix N] [--no-login] [--force]` | Apply a static IP. **Keeps your current DNS** unless `--dns` is given; logs in to the portal if it asks |
| `dorm-ip dns override` / `dns default` / `dns set A,B` | Change only the DNS, not the IP |
| `dorm-ip dhcp` | Back to automatic (DHCP) |
| `dorm-ip restore` | Restore the original profile saved before the first change |
| `dorm-ip login [--force] [--debug]` | Log in to the portal now; `--debug` shows every step of the login (no secrets) |
| `dorm-ip live-check [--ip IP] [--compare] [--force]` | Check that switching the IP without a reconnect works here, and time it |
| `dorm-ip init [--yes] [--curl-file F] [--no-shell]` | Guided setup (`--curl-file` selects replay mode with that request) |
| `dorm-ip shell install` / `shell uninstall` / `shell status` | Add or remove the `dorm-ip` command in your shell config (`--shell bash\|zsh\|fish\|all`) |
| `dorm-ip path config\|credentials\|db\|backup` | Print where a file lives |

**`hunt` options**

| Option | Meaning |
|---|---|
| `--range A-B[,C-D]` | Hunt these IPs instead of the configured ranges |
| `--max N` | Try at most N candidates |
| `--order random\|sequential\|best-history` | Order within the unused/used groups |
| `--find N` | Stop after N IPs pass the full test; keep the best, the rest become standby |
| `--no-triage` | Test candidates one by one (no parallel filtering) |
| `--retry-failed` | Also try IPs that failed recently |
| `--watch` | Start the watchdog as soon as a good IP is found |
| `--open-portal` | Open the login page in your browser if login is still required |
| `--ignore-vpn`, `--force` | Override the VPN / wrong-network safety checks |

**Global flags** go before the command: `--config PATH`, `--dry-run` (prints the exact `nmcli`/`arp-scan` commands and
changes nothing), `--version`.

**A typical day**

```bash
dorm-ip hunt --watch          # find a good IP, then keep watching it
dorm-ip hunt --find 3         # collect standby IPs for fast failover
dorm-ip history               # what has worked, and when
dorm-ip set 172.18.40.123     # go back to a favorite IP (keeps DNS, logs in)
```

## How it works

### The hunt

```
arp-scan the ranges  ->  order candidates (history, cooldowns, unused first)
batch of candidates  ->  all added to the interface at once  ->  parallel triage (each probe from its own address)
each survivor, one at a time:  live IP switch  ->  gateway answers? -> portal (log in if needed) -> ping/loss
                               -> DNS -> quick speed -> sustained test (first failure stops the test)
passed?  ->  --find N reached?  ->  keep the best, standby for the rest, finish DNS/portal state
nothing passed / error / Ctrl+C / SIGTERM  ->  restore the original profile
```

| Test | What it checks |
|---|---|
| Gateway | the gateway answers from the new address (polled, not a fixed wait) |
| Portal | `generate_204`: `204` = open, redirect/HTML = portal, no answer = dead |
| Ping | loss, average and jitter to `ping_target` |
| DNS | resolve time of a few domains, asked directly from the active DNS server |
| Quick speed | one 5 MB download |
| Sustained | downloads for `sustained_seconds`, sampled every `sample_interval`; reports average, minimum and the **collapse point** (speed under `collapse_below_mbps` for 2 s, reported as "after N MB") |

**Pass/fail.** Hard fails (score 0): gateway down, no internet, portal blocking, packet loss over the limit, speed
collapse, DNS or download failure. Threshold fails: ping above `max_ping_ms`, or speed below the limit. With
`speed_rule = "either"` the quick **or** the sustained speed reaching its limit is enough; with `"both"` both must. The score
(0-100) is `0.5*sustained + 0.2*quick + 0.2*ping + 0.1*loss` and ranks IPs; `--find` keeps the highest.

**Parallel triage.** A wifi card has one MAC but the interface can hold many addresses at once. With live switching
available, `hunt` adds a batch (`triage_batch`, default 12) to the interface together and runs the cheap checks for all of
them in parallel, each sent from its own address: gateway, portal state (with auto-login from that address), packet loss and
a small download that must complete. Parallel flows share the bandwidth, so triage only *filters*: it is deliberately lenient
(up to 25% loss, double the ping limit) and never ranks or accepts. Survivors are then switched to one at a time and get the
normal full test, so every accepted IP has the same evidence as before. Failed triage results are stored in the history like
any failure. Your own current IP stays on the interface as a *control*: if it stops answering when sent from a secondary
address, or none of the extra addresses reach the gateway, the tool decides that triage does not work on this network, says
so, and tests one by one.

**Live IP switching.** By default (`live_change = "auto"`) the tool changes the address of the *running* connection
(`nmcli device modify`) instead of reconnecting. After every switch it reads the address back and requires exactly the new
one; if NetworkManager refuses or the address did not change, it says so and uses full reconnects for the rest of the hunt.
The saved NetworkManager profile is not touched while candidates are tried; only the final IP is written to it. Run
`dorm-ip live-check --compare` once to see the real timings on your wifi.

**Smart ordering.** Every result and ARP scan is kept in the history and used to order the next hunt:

| Rule | Effect |
|---|---|
| Recently failed IPs are skipped | cooldown `skip_failed_minutes` (30), doubling per consecutive failure up to 12 h; an IP that passed in the last 24 h only gets the base cooldown; "login required" never counts; skipped IPs are still used if there are not enough other candidates; `--retry-failed` ignores it |
| Hour of day | with `order = "best-history"`, results from within 2 hours of now count double |
| Busy IPs | IPs seen in use in many of the last 10 scans rank lower |
| Near good IPs | untested IPs within 3 addresses of a known-good one get a small bonus (`explore_near_good`) |

**`--find N` and standby.** `dorm-ip hunt --find 3` keeps going until three IPs pass the full test, keeps the best and stores
the others as *standby* IPs. When the watchdog sees a degraded connection it first tries the standby IPs (a quick re-check of
gateway, portal, ping, DNS and speed, up to 3 of them) and only runs a full hunt if none still works. A standby IP that fails
is removed; they are forgotten after `standby.max_age_hours`.

### DNS override and the portal

The dorm DNS sends every unauthenticated client to the portal, and the portal's name only exists in that DNS. A public DNS
(the *override*) skips the redirect, so most candidates are testable immediately. Two situations remain:

- **A candidate still shows the portal** (its IP is not logged in). `dorm-ip` logs in for you: it resolves the portal host by
  asking the **dorm DNS server directly** (a UDP query, no system change) and connects to that address while keeping the real
  host name for `Host`/TLS, always from the candidate's own address. So login works while your system DNS stays on the
  override, with no DNS switching and no extra reconnect. This also works for portal names ending in `.local`, which many Linux
  systems send to mDNS only (a browser may then fail to open the page while `dorm-ip` logs in fine). `host_ip` pins the address
  by hand if the name cannot be resolved at all.
- **`final_mode`** decides which DNS stays after a hunt: `override` (default), `default` (dorm DNS, then portal check) or
  `auto` (override if the portal stays open, otherwise the dorm DNS).

Auto-login is careful: it stops after 2 failed attempts in a row during a hunt (no account lock-outs) and after `max_logins_per_hunt`
successful logins. `hunt` logs in on candidates only if `login_during_hunt` is on.

### The watchdog

Every `interval_seconds` it pings the gateway and downloads a small probe. After `bad_checks_to_rehunt` bad checks in a row
it: notifies; tries to **log in again** if the portal is asking (an expired session is cheaper than a new IP); otherwise runs
a real quick speed test to rule out a false alarm; then tries the **standby IPs**; and only then re-hunts. After a failed
re-hunt it backs off 5, 10, 20... minutes (max 30). It never judges the link, and never re-hunts, when:

| Situation | Behavior |
|---|---|
| Wifi is disconnected | paused, nothing counted |
| Connected to a **different network** (gateway does not match) | paused: it will never reconfigure your home wifi |
| A **VPN/tunnel carries your traffic** | gateway-only checks, no downloads, no failover, no re-hunt (tests would measure the VPN) |
| Just **resumed from suspend** | 60 s grace period while the wifi reconnects |
| A slow probe while **you are using the link** (more than `busy_mbps` of your own traffic) | ignored |
| Daily data budget is used up | no re-hunt |

Ctrl+C stops the watcher and leaves your current IP as it is.

### History

Every test and watchdog check is stored in SQLite (`dorm-ip path db`) together with the MAC used, so you can later see
whether the throttle is per IP or per MAC. `dorm-ip history` shows the best IPs (reliability-weighted: failures count as 0),
the hours each was good, IPs that often fail (`bad` = never passed in 3+ tests, `flaky` = under half), a pass-rate-by-hour
chart, how unused IPs compare with IPs seen in use, IPs on cooldown, and today's data use.

### What the hunt table says

| Result text | Meaning |
|---|---|
| `gateway unreachable` | the IP did not answer from the gateway (dead, or an IP conflict) |
| `captive portal: login required` | the portal blocks this IP and auto-login is off or failed (`dorm-ip login --debug` shows why) |
| `no internet: no answer within 5 s (connection timed out)` | the gateway answers but the internet path is blocked for this IP |
| `no internet: DNS lookup failed` / `could not connect` | the network was not usable (fast errors are retried twice first) |
| `packet loss N% > M%` | too much loss |
| `ping N ms > M ms` | too slow to answer |
| `quick N / sustained M Mbps: neither reaches ...` | below the speed limit (`speed_rule = "either"`) |
| `quick speed ...` / `sustained ...` | below the limit (`speed_rule = "both"`, or with `--no-deep`) |
| `speed collapsed after N MB` | fast at first, then dead: the pattern this tool exists to catch |
| `DNS lookups failed` / `download failed` | DNS or the download did not work |
| `download stalled`, `packet loss`, ... (during triage) | filtered out by the parallel triage |
| `skipped ...` | the IP could not be applied |

## Configuration

`dorm-ip init` writes the file and `make edit-config` opens it. The built-in template with every key is
[`dorm_ip/config.example.toml`](dorm_ip/config.example.toml). Network values are never hard-coded: they live only in the
config. Lookup order: `--config PATH`, `~/.config/dorm-ip/config.toml`, `./config.toml`.

| Section | Key | Meaning |
|---|---|---|
| `[network]` | `interface`, `connection` | wifi device; NetworkManager connection (empty = the active wifi) |
| | `prefix`, `gateway` | subnet; the real prefix is read from the DHCP lease and `info` warns on a mismatch |
| | `ranges`, `exclude` | IPs to hunt (`A-B` ranges) and IPs never to use |
| | `prefer_unused` | try IPs not seen in the ARP scan first |
| `[dns]` | `default`, `override` | dorm DNS; public DNS used to skip the portal redirect |
| | `hunt_with_override`, `final_mode` | hunt with the override; DNS kept afterwards (`override`/`default`/`auto`) |
| `[tests]` | `ping_target`, `ping_count`, `connectivity_url` | ping and portal-check targets |
| | `speed_url`, `sustained_url`, `sustained_seconds`, `sample_interval` | download tests (empty `sustained_url` repeats `speed_url`) |
| | `dns_domains` | domains used for the DNS timing |
| | `data_budget_mb` | daily cap for all test traffic (`0` = unlimited) |
| `[thresholds]` | `max_ping_ms`, `max_loss_pct` | latency and loss limits |
| | `min_speed_mbps`, `min_sustained_mbps` | speed limits (8 Mbps = 1 MB/s) |
| | `speed_rule` | `either` (quick or sustained is enough) or `both` |
| | `collapse_below_mbps` | below this for 2 s counts as a collapse |
| `[hunt]` | `max_candidates`, `order` | candidates per hunt; `random`/`sequential`/`best-history` |
| | `settle_seconds` | longest wait for the gateway after a live switch (a reconnect waits at least twice as long) |
| | `live_change` | `auto` (switch without reconnecting, verified) or `off` |
| | `skip_failed_minutes`, `explore_near_good` | cooldown after a failed IP (0 = off); bonus for untested neighbors of good IPs |
| | `triage_batch`, `find` | candidates filtered in parallel per batch (0/1 = one by one); IPs that must pass before the hunt stops |
| `[standby]` | `max_age_hours`, `failover` | forget standby IPs after this long; let the watchdog use them before a full hunt |
| `[watchdog]` | `interval_seconds`, `probe_bytes`, `bad_checks_to_rehunt`, `notify` | check cadence, probe size, trigger, notifications |
| | `min_probe_mbps`, `rehunt_cooldown_seconds`, `busy_mbps` | probe limit (slow-start aware), back-off, "link busy" threshold |
| `[portal]` | `enabled`, `mode` | auto-login on/off; `flow` (follow the portal's login page) or `replay` (send the request below) |
| | `url`, `method`, `content_type`, `fields`, `query`, `headers` | replay mode: the login request (`{username}` `{password}` `{ip}` `{mac}` are filled in) |
| | `post_path`, `form_username_field`, `form_password_field`, `post_drop_params` | flow mode, only if the login page has no parsable form: where to submit and the field names; query parameters not to carry over (default `reason`) |
| | `success_contains`, `failure_contains` | replay mode: text that marks a successful / rejected login (flow mode checks the internet instead) |
| | `credentials_file`, `keyring_service` | where the credentials are read from |
| | `login_during_hunt`, `max_logins_per_hunt` | log in on candidates that show the portal; cap per hunt |
| | `resolve_via_dorm_dns`, `host_ip`, `verify_tls`, `timeout` | how the portal host is reached |

**Recipes**

- *Save data*: `data_budget_mb = 3000`, `watchdog.interval_seconds = 60`, `hunt.order = "best-history"`.
- *Stricter*: `speed_rule = "both"`, `max_loss_pct = 1`, `min_speed_mbps = 16`.
- *Keep it simple*: `triage_batch = 0`, `live_change = "off"` (one candidate at a time, with reconnects).
- *Never skip IPs*: `skip_failed_minutes = 0`.

### credentials.toml

```toml
username = "your-portal-username"
password = "your-portal-password"
```

Keep the values in **quotes** (an unquoted number such as `03211040300022` is not valid TOML because of the leading zero).
The file must be readable only by you; `dorm-ip` refuses to use it otherwise. `make edit-credentials` creates it with the
right permissions and opens it. Optionally set `portal.keyring_service` to read both values from the system keyring instead
(needs `uv sync --extra keyring`).

## Shell command

The setup offers to add a `dorm-ip` command to your shell so you can run it from any folder. It is a small function in a
marked block (`# >>> dorm-ip >>>` ... `# <<< dorm-ip <<<`) that runs `uv run --project <this repo> dorm-ip`, so it always
uses the project's own environment.

- Detected shells: bash (`~/.bashrc`), zsh (`~/.zshrc`, or `$ZDOTDIR`), fish (`~/.config/fish/conf.d/dorm-ip.fish`); only the
  shells you actually use are offered.
- Safe: your file is backed up once (`.dorm-ip.bak`), the block is added or refreshed in place, nothing else is touched.
- `dorm-ip shell status` shows where it is installed, `dorm-ip shell install --shell zsh` adds it later,
  `dorm-ip shell uninstall` removes it again.
- If you installed `dorm-ip` as a package (not from the repository) it is already a normal command and nothing is added.

## Safety

- **Backup first.** Before the first change `dorm-ip` saves your original NetworkManager settings
  (`dorm-ip path backup`). It is restored when a hunt finds nothing, on errors, Ctrl+C and SIGTERM, or with `dorm-ip restore`.
  Only the configured connection is ever modified.
- **Wrong network.** `set`, `test`, `hunt` and `live-check` refuse to run when the connected network's gateway is not the
  configured one (`--force` overrides), so a hunt cannot reconfigure your home wifi.
- **VPN.** `test`, `hunt` and `live-check` refuse while a tunnel carries your traffic (they would measure the VPN, and
  changing the IP would drop it). Disconnect it or pass `--ignore-vpn` (`test`, `hunt`). The watchdog handles this itself.
- **Account.** Auto-login stops after 2 failed attempts in a row during a hunt and after `max_logins_per_hunt` logins.
- **Secrets.** Credentials live only in `credentials.toml` (chmod 600); they are never printed, logged or put in the config.
  Do not commit `config.toml` or `credentials.toml`.
- **Network load.** Tests are short and stop at the first failure. The ARP scan sends one frame per candidate (about 500).
  Parallel triage puts up to `triage_batch` extra addresses on your interface for a few seconds and downloads 300 KB per
  candidate; the watchdog probe is 200 KB per check.

### Data usage

A full test of a good IP costs roughly `speed x sustained_seconds` (30 Mbps x 8 s = 30 MB) plus 5 MB. Bad IPs usually cost
under 1 MB, and triage rejects most of them for about 300 KB each. The watchdog probe adds `probe_bytes x 86400 / interval`
per day (200 KB every 30 s is about 580 MB; every 10 s about 1.7 GB). All of it counts toward `data_budget_mb`;
`dorm-ip history` shows today's total.

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
- **"arp-scan saw no hosts"**: the wifi may isolate clients, or the interface is wrong. The hunt still works; every IP is
  treated as unused.
- **Candidates fail with "captive portal: login required"**: auto-login is off or failing. Run `dorm-ip login --force`; if
  it says the request was rejected, set `success_contains`/`failure_contains` or re-run `dorm-ip init` and paste the request
  again.
- **Login fails**: run `dorm-ip login --force --debug`. It shows the redirect, the login page, the form fields and the result.
  `no login form found` means the page is built by JavaScript: set `portal.post_path` and the two field names (Kerio Control is
  recognised automatically). `the portal rejected the login` means the portal sent you back to the login page: check the
  username and password. `no internet afterwards` means the login worked but the IP has no route out.
- **Login works but the portal host does not resolve**: set `portal.host_ip` to the portal's address.
- **"live IP switching is not working here"**: your driver or NetworkManager does not apply the change live; the hunt continues
  with reconnects. Run `dorm-ip live-check --compare` to see why, and set `hunt.live_change = "off"` to silence it.
- **"Parallel triage does not work here"**: the extra addresses did not appear, or sending from a secondary address failed.
  The hunt continues one by one; set `hunt.triage_batch = 0` to stop trying.
- **A good IP is never tried**: it is probably cooling down after a failure (`dorm-ip history` lists them). Use
  `dorm-ip hunt --retry-failed`, or set `hunt.skip_failed_minutes = 0`.
- **"does not look like the dorm wifi"**: the gateway differs from `network.gateway`. Fix the config or use `--force`.
- **"a VPN/tunnel is carrying your traffic"**: disconnect the VPN before `test`/`hunt`/`live-check`.
- **Everything is slow after `hunt` gave up**: it restored your original profile (DHCP, dorm DNS); log in to the portal or run
  `dorm-ip hunt` again.
- **`dorm-ip: command not found`**: run `dorm-ip shell install` (or use `uv run dorm-ip`) and open a new terminal.

## Development

```bash
uv sync
uv run pytest        # no real network calls; nmcli, ping, arp-scan and httpx are mocked
```

Layout: `cli.py` (thin typer CLI), `config.py`, `models.py`, `netinfo.py` (nmcli/ip), `applier.py` (change/restore, live
switching), `scanner.py`, `tests.py` (probes), `triage.py` (parallel filtering), `scorer.py`, `hunter.py`, `watchdog.py`,
`db.py`, `portal.py` (auto-login, cURL import), `dnsq.py` (DNS packets), `livecheck.py`, `shellint.py` (shell command),
`wizard.py` (`init`). Design decisions are in [`NOTES.md`](NOTES.md), the history of releases in
[`CHANGELOG.md`](CHANGELOG.md), the plan in [`ROADMAP.md`](ROADMAP.md).

**CI.** `.github/workflows/ci.yml` runs on every pull request and on pushes to `main`: `uv sync`, the unit tests on
Python 3.12, 3.13 and 3.14, a check that the command line starts, and a wheel build that must contain the config template.
Make the `test` jobs a required check in the repository's branch protection to block merging a failing pull request.

**Releasing.** Bump the version in `pyproject.toml` and `dorm_ip/__init__.py`, run `uv lock`, add a `CHANGELOG.md` entry,
tag `vX.Y.Z`.

## Roadmap

The plan for 1.0 is in [`ROADMAP.md`](ROADMAP.md): Windows support through a platform backend interface, auto-login
reliability, and stability and performance work. Not planned: MAC randomization, a GUI or TUI, Android.
