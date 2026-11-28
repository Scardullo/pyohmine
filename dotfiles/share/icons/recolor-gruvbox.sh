#!/usr/bin/env bash
# Make a single-color copy of Gruvbox-Plus-Dark's small (16/22/24px) symbolic icons.
# usage: recolor-gruvbox.sh <name> <bright-hex> [dark-hex]
#   e.g. recolor-gruvbox.sh CRT 33ff33 0a2a0a   ->  icon-theme: "Gruvbox-Plus-CRT";
# Re-run after the gruvbox-plus-icon-theme package updates.
set -euo pipefail
name="Gruvbox-Plus-$1"; bright="$2"; dark="${3:-0a2a0a}"
src=/usr/share/icons/Gruvbox-Plus-Dark
dst="$HOME/.local/share/icons/$name"

# bright/colored Gruvbox shades -> main color; dark shades (cutouts/details) -> dark color
brights="ebdbb2 458588 fb4934 689d6a fe8019 cc241d fabd2f b8bb26 98971a 83a598 8f3f71 b16286 a89984 8ec07c d79921 d65d0e d3869b 928374 fbf1c7 bdae93 7c6f64 427b58 076678 ff6b26 db3c30 d5c4a1 b57614 af3a03 9d0006 79740e"
darks="504945 282828 3c3836 32302f 1d2021 0f0f0f"

expr=()
for c in $brights; do expr+=(-e "s/#$c/#$bright/gI"); done
for c in $darks;   do expr+=(-e "s/#$c/#$dark/gI"); done

rm -rf "$dst"; mkdir -p "$(dirname "$dst")"
cp -a "$src" "$dst"
sed -i "s/^Name=.*/Name=$name/" "$dst/index.theme"

find "$dst" -type f -name '*.svg' \( -path '*/16*' -o -path '*/22*' -o -path '*/24*' \) -print0 |
  xargs -0 -P"$(nproc)" -n 500 sed -i "${expr[@]}"

gtk-update-icon-cache -f "$dst" >/dev/null 2>&1 || true
echo "Installed $dst  ->  icon-theme: \"$name\";"
