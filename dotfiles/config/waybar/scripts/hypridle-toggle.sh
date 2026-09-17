#!/bin/bash
# Toggles hypridle on/off and reports status as JSON for waybar's custom module.

ICON_ACTIVE="󰛊"   # outline cup: hypridle running
ICON_INACTIVE="󰅶" # solid cup: hypridle stopped

if [[ "$1" == "--toggle" ]]; then
    if pgrep -x hypridle >/dev/null; then
        pkill -x hypridle
    else
        setsid -f hypridle >/dev/null 2>&1
    fi
    exit 0
fi

if pgrep -x hypridle >/dev/null; then
    echo "{\"text\":\"$ICON_ACTIVE\",\"tooltip\":\"hypridle: active (click to disable)\",\"class\":\"active\"}"
else
    echo "{\"text\":\"$ICON_INACTIVE\",\"tooltip\":\"hypridle: inactive (click to enable)\",\"class\":\"inactive\"}"
fi
