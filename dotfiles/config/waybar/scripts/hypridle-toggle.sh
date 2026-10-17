#!/bin/bash
# Toggles hypridle on/off and reports status as JSON for waybar's custom module.

ICON_ACTIVE="󰛊"   # outline cup: hypridle running
ICON_INACTIVE="󰅶" # solid cup: hypridle stopped

DISABLED_MARKER="$HOME/.cache/hypridle-disabled"

if [[ "$1" == "--toggle" ]]; then
    if pgrep -x hypridle >/dev/null; then
        # Manual disable: mark it so the login retry loop in ~/.config/hypr/autostart
        # doesn't see "not running" and turn it back on behind your back.
        touch "$DISABLED_MARKER"
        pkill -x hypridle
    else
        rm -f "$DISABLED_MARKER"
        setsid -f hypridle >/dev/null 2>&1
    fi
    exit 0
fi

if pgrep -x hypridle >/dev/null; then
    echo "{\"text\":\"$ICON_ACTIVE\",\"tooltip\":\"hypridle: active (click to disable)\",\"class\":\"active\"}"
else
    echo "{\"text\":\"$ICON_INACTIVE\",\"tooltip\":\"hypridle: inactive (click to enable)\",\"class\":\"inactive\"}"
fi
