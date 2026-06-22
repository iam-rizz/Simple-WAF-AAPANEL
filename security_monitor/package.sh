#!/bin/bash
set -e
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PLUGIN="security_monitor"
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR/$PLUGIN.zip"
cd "$ROOT_DIR"
python3 -m zipfile -c "$DIST_DIR/$PLUGIN.zip" "$PLUGIN"
printf '%s\n' "$DIST_DIR/$PLUGIN.zip"
