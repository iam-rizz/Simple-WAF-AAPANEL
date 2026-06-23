# Simple WAF aaPanel

Simple WAF aaPanel is an aaPanel plugin for monitoring suspicious web requests from webserver logs and preparing IP bans with safe dry-run defaults.

Current version: `0.3.0`

## Features

- Nginx log monitoring from `/www/wwwlogs/*.log`
- aaPanel-style fixed-size dashboard with internal scroll
- Light/dark theme adaptation based on aaPanel theme classes
- Export report for sharing detected events, summary, bans, and settings
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
sensitive-paths.conf
```

## Install on VPS with aaPanel

### 1. Clone repository

Use HTTPS:

```bash
cd /tmp
git clone https://github.com/iam-rizz/Simple-WAF-AAPANEL.git
cd Simple-WAF-AAPANEL
```

Or use SSH if your VPS has deploy key configured:

```bash
cd /tmp
git clone git@github.com-wafaapanel:iam-rizz/Simple-WAF-AAPANEL.git
cd Simple-WAF-AAPANEL
```

### 2. Install plugin

```bash
bash security_monitor/install.sh
```

Plugin target path:

```text
/www/server/panel/plugin/security_monitor
```

Installer uses `python3` first, then falls back to aaPanel Python path when available.

### 3. Restart aaPanel

```bash
bt restart
```

### 4. Test dry-run scanner

```bash
python3 /www/server/panel/plugin/security_monitor/security_monitor_main.py
```

Expected output example:

```json
{
  "status": true,
  "msg": {
    "scanned": 6,
    "matched": 0,
    "banned": 0,
    "dry_run": true
  }
}
```

### 5. Open plugin

Open aaPanel, then open **Security Monitor / Simple WAF** from plugin list.

## Update on VPS

```bash
cd /tmp/Simple-WAF-AAPANEL
git pull
bash security_monitor/install.sh
bt restart
```

## Build package

```bash
bash security_monitor/package.sh
```

Output:

```text
dist/security_monitor.zip
```

## Dashboard pages

- **Home**: overview, total risks, risks in last 24h, blockade count, top attacking IPs
- **Interception**: detected suspicious requests from logs
- **Rules**: detection rules, severity, threshold, ban duration
- **Blockade**: dry-run or active ban records
- **Global**: runtime configuration
- **Logs**: last operation result in table format, with full-size JSON view button

The **Logs** page is not raw webserver logs. It shows the latest plugin operation/API result. Actual detected requests are shown in **Interception**.

## Export report

Click **Export Report** in the dashboard header. The plugin creates a JSON report under:

```text
/www/server/panel/plugin/security_monitor/data/security-monitor-report-YYYYMMDD-HHMMSS.json
```

Report contains:

- generated time
- settings
- summary
- risk counts
- top attacking IPs
- recent events
- ban records

Use this file to share investigation results.

## Recommended rollout

1. Install plugin on aaPanel server.
2. Keep `dry_run: true` and `auto_ban: false`.
3. Run for 24 hours.
4. Review false positives in **Interception**.
5. Whitelist your admin IP.
6. Enable auto-ban for high/critical rules only.
7. Enable generated Nginx WAF rules per-domain only after testing.

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
