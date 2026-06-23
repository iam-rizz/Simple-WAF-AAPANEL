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
printf '%s\n' "installed: $DST_DIR"
printf '%s\n' "python: $PYTHON_BIN"
