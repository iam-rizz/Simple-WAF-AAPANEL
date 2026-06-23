#!/bin/bash
set -e
PLUGIN=security_monitor
rm -f /etc/cron.d/simple-waf-aapanel
rm -rf "/www/server/panel/plugin/$PLUGIN"
printf '%s\n' "uninstalled: $PLUGIN"
