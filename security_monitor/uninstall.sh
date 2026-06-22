#!/bin/bash
set -e
PLUGIN=security_monitor
rm -rf "/www/server/panel/plugin/$PLUGIN"
printf '%s\n' "uninstalled: $PLUGIN"
