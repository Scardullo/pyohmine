#!/usr/bin/env bash
set -e

echo "[*] Starting Hyprland rice setup..."

# -----------------------------

# VARIABLES

# -----------------------------

USER_HOME="$HOME"
CONFIG_DIR="$HOME/.config"
HYPR_DIR="$CONFIG_DIR/hypr"
KITTY_DIR="$CONFIG_DIR/kitty"
WALL_DIR="$HOME/Pictures/wallpaper"

# -----------------------------

# INSTALL PACKAGES

# -----------------------------

echo "[*] Installing required packages..."

sudo pacman -S --needed 
hyprland kitty dolphin rofi swaybg 
brightnessctl playerctl 
pipewire wireplumber 
firefox code 
qt5ct ttf-fantasque-sans-mono 
noto-fonts noto-fonts-emoji

# -----------------------------

# CREATE DIRECTORIES

# -----------------------------

echo "[*] Creating directories..."

mkdir -p "$HYPR_DIR"
mkdir -p "$KITTY_DIR"
mkdir -p "$WALL_DIR"

# -----------------------------

# BACKUP OLD CONFIGS

# -----------------------------

echo "[*] Backing up old configs..."

[ -d "$HYPR_DIR" ] && mv "$HYPR_DIR" "${HYPR_DIR}.bak.$(date +%s)"
[ -d "$KITTY_DIR" ] && mv "$KITTY_DIR" "${KITTY_DIR}.bak.$(date +%s)"

mkdir -p "$HYPR_DIR" "$KITTY_DIR"

# -----------------------------

# HYPRLAND CONFIG (DEFAULT: GRUVBOX)

# -----------------------------

echo "[*] Writing Hyprland config..."

cat <<'EOF' > "$HYPR_DIR/gruvbox"

# (your gruvbox config pasted here EXACTLY)

EOF

cat <<'EOF' > "$HYPR_DIR/catppuccin_blue"

# (your catppuccin config pasted here)

EOF

cat <<'EOF' > "$HYPR_DIR/nord"

# (your nord config pasted here)

EOF

# set default

cp "$HYPR_DIR/gruvbox" "$HYPR_DIR/hyprland.conf"

# -----------------------------

# KITTY THEMES

# -----------------------------

echo "[*] Writing Kitty configs..."

cat <<'EOF' > "$KITTY_DIR/gruvbox"

# (paste your gruvbox kitty config)

EOF

cat <<'EOF' > "$KITTY_DIR/catppuccin"

# (paste your catppuccin kitty config)

EOF

cat <<'EOF' > "$KITTY_DIR/nord"

# (paste your nord kitty config)

EOF

cat <<'EOF' > "$KITTY_DIR/everforest"

# (paste your everforest kitty config)

EOF

cat <<'EOF' > "$KITTY_DIR/tokyo-night"

# (paste your tokyo-night kitty config)

EOF

cat <<'EOF' > "$KITTY_DIR/teal-purple"

# (paste your teal-purple kitty config)

EOF

cat <<'EOF' > "$KITTY_DIR/dracula_cat"

# (paste your dracula kitty config)

EOF

# default kitty theme

cp "$KITTY_DIR/gruvbox" "$KITTY_DIR/kitty.conf"

# -----------------------------

# WALLPAPER SCRIPT

# -----------------------------

echo "[*] Installing wallpaper script..."

sudo tee /usr/local/bin/wallpp > /dev/null <<'EOF'
#!/bin/bash

if [ -z "$1" ]; then
echo "Usage: wallpp /path/to/wallpaper"
exit 1
fi

WALLPAPER="$1"

pkill swaybg 2>/dev/null

swaybg -o DP-1 -i "$WALLPAPER" -m fill 
-o HDMI-A-1 -i "$WALLPAPER" -m fill &
EOF

sudo chmod +x /usr/local/bin/wallpp

# -----------------------------

# THEME SWITCHER SCRIPTS

# -----------------------------

echo "[*] Installing theme switchers..."

install_theme_script () {
NAME=$1
WALL=$2
KITTY=$3
HYPR=$4

```
sudo tee "/usr/local/bin/$NAME" > /dev/null <<EOF
```

wallpp "$WALL"
cp ~/.config/kitty/$KITTY ~/.config/kitty/kitty.conf
cp ~/.config/hypr/$HYPR ~/.config/hypr/hyprland.conf
EOF

```
sudo chmod +x "/usr/local/bin/$NAME"
```

}

install_theme_script "gruvbox" "$WALL_DIR/gruvy_street.png" "gruvbox" "gruvbox"
install_theme_script "catppuccin" "$WALL_DIR/catppuccin.webp" "catppuccin" "catppuccin_blue"
install_theme_script "nord" "$WALL_DIR/darker-space.webp" "nord" "nord"
install_theme_script "everforest" "$WALL_DIR/everforest_steps.webp" "everforest" "gruvbox"
install_theme_script "tokyo-night" "$WALL_DIR/arch-dark-dracula.webp" "tokyo-night" "nord"
install_theme_script "teal-purple" "$WALL_DIR/mountain.jpg" "teal-purple" "catppuccin_blue"
install_theme_script "dracula" "$WALL_DIR/japanese_dracula.webp" "dracula_cat" "catppuccin_blue"


# -----------------------------
# HYPRLAND AUTOSTART
# -----------------------------

echo "[*] Writing Hyprland autostart..."

cat <<'EOF' > "$HYPR_DIR/autostart"
#!/bin/bash

# Set wallpapers with swaybg
sleep 2 && swaybg -o DP-1 -i /home/anthony/Pictures/wallpaper/gruvy_street.png -m fill \
                  -o HDMI-A-1 -i /home/anthony/Pictures/wallpaper/gruvy_street.png -m fill &

# Optional: start apps/services
# waybar &
# dunst &

EOF

chmod +x "$HYPR_DIR/autostart"



# -----------------------------

# DONE

# -----------------------------

echo "[✓] Setup complete!"
echo "Run: Hyprland"
echo "Switch themes with: gruvbox / nord / catppuccin / etc."
