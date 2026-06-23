#!/bin/bash
set -e
PLUGIN=security_monitor
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DST_DIR="/www/server/panel/plugin/$PLUGIN"
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v /www/server/panel/pyenv/bin/python >/dev/null 2>&1; then
  PYTHON_BIN="/www/server/panel/pyenv/bin/python"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  printf '%s\n' "python3 not found"
  exit 1
fi
mkdir -p "$DST_DIR"
cp -a "$SRC_DIR"/* "$DST_DIR"/
chown -R www:www "$DST_DIR" 2>/dev/null || true
"$PYTHON_BIN" "$DST_DIR/security_monitor_main.py" >/dev/null
CRON_FILE="/etc/cron.d/simple-waf-aapanel"
CRON_LOG="/www/server/panel/plugin/$PLUGIN/data/cron.log"
if [ -d /etc/cron.d ]; then
  printf '%s\n' "* * * * * root flock -n /tmp/simple-waf-aapanel.lock $PYTHON_BIN $DST_DIR/task.py >> $CRON_LOG 2>&1" > "$CRON_FILE"
  chmod 644 "$CRON_FILE"
fi
printf '%s\n' "installed: $DST_DIR"
printf '%s\n' "python: $PYTHON_BIN"
printf '%s\n' "cron: $CRON_FILE"
