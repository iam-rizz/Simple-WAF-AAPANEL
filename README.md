# Simple WAF aaPanel

Simple WAF aaPanel is an aaPanel plugin source for monitoring suspicious web requests from webserver logs and preparing IP bans with safe dry-run defaults.

## Features

- Nginx log monitoring from `/www/wwwlogs/*.log`
- Rule engine for common web attack probes
- Detection categories:
  - sensitive files
  - dotfiles and secrets
  - backup/database dumps
  - path traversal and LFI/RFI
  - SQL injection
  - XSS
  - webshell/RCE probes
  - CMS scanners
  - framework debug endpoints
  - bad bots
- SQLite event storage
- Custom rules via JSON
- IP ban engine with backend auto-detection:
  - `ufw`
  - `firewalld`
  - `iptables`
- Whitelist IP/path support
- Auto-unban by expiry timestamp
- Nginx WAF rule generator
- aaPanel plugin UI entry
- Safe defaults:
  - dry-run enabled
  - auto-ban disabled
  - WAF disabled

## Structure

```text
security_monitor/
  security_monitor_main.py
  index.html
  install.sh
  uninstall.sh
  package.sh
  task.py
  data/
filter.d/
fixtures/
tests/
dist/
sensitive-paths.conf
```

## Build package

```bash
bash security_monitor/package.sh
```

Output:

```text
dist/security_monitor.zip
```

## Install on aaPanel server

Copy source or zip to server, then run:

```bash
bash security_monitor/install.sh
```

Plugin target path:

```text
/www/server/panel/plugin/security_monitor
```

## Run scanner manually

```bash
python3 security_monitor/security_monitor_main.py
```

Default scan result is dry-run only.

## Recommended rollout

1. Install plugin on aaPanel server.
2. Keep `dry_run: true` and `auto_ban: false`.
3. Run for 24 hours.
4. Review false positives in Events.
5. Enable auto-ban for high/critical rules only.
6. Enable generated Nginx WAF rules per-domain only after testing.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Current defaults

```json
{
  "enabled": true,
  "dry_run": true,
  "auto_ban": false,
  "default_ban_seconds": 3600,
  "waf_enabled": false,
  "firewall_backend": "auto"
}
```

## Security note

Do not disable dry-run or enable auto-ban before reviewing false positives. Always whitelist your admin IP before enabling automatic bans.
