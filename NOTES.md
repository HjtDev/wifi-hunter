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