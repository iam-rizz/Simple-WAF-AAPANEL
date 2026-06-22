#!/bin/bash
set -e
PLUGIN=security_monitor
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DST_DIR="/www/server/panel/plugin/$PLUGIN"
mkdir -p "$DST_DIR"
cp -a "$SRC_DIR"/* "$DST_DIR"/
chown -R www:www "$DST_DIR" 2>/dev/null || true
python "$DST_DIR/security_monitor_main.py" >/dev/null
printf '%s\n' "installed: $DST_DIR"
