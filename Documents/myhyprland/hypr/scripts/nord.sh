#!/bin/bash

cat <<EOF | rofi -dmenu -i -p "Hyprland Keybinds" \
-theme ~/.config/rofi/themes/nord.rasi

SUPER + ENTER   Terminal
SUPER + D       Rofi Launcher
SUPER + E       Thunar
SUPER + B       Firefox
SUPER + C       VS Code
SUPER + F       Fullscreen
SUPER + X       Kill Window

SUPER + 1-0     Switch Workspace
SUPER + SHIFT + 1-0 Move Window To Workspace

SUPER + V       Toggle Floating
SUPER + S       Toggle Scratchpad

SUPER + PRINT   Screenshot Monitor
EOF
