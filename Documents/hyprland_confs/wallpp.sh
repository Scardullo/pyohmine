#!/bin/bash
# Usage: set-wallpaper /path/to/image

# Check if an argument was provided
if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/wallpaper"
    exit 1
fi

WALLPAPER="$1"

# Apply the wallpaper to both monitors
swaybg -o DP-1 -i "$WALLPAPER" -m fill \
       -o HDMI-A-1 -i "$WALLPAPER" -m fill &
