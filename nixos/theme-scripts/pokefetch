#!/usr/bin/env bash
# Pipes a random pokemon-colorscripts sprite into fastfetch as the logo,
# sizing the logo to the sprite's real dimensions so the info text never
# overlaps it and stays top-aligned with the sprite.
set -euo pipefail

CONFIG="$HOME/.config/fastfetch/config-pokemon.jsonc"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/pokefetch"
mkdir -p "$CACHE_DIR"
find "$CACHE_DIR" -type f -mmin +60 -delete 2>/dev/null

SPRITE="$(mktemp -p "$CACHE_DIR")"

pokemon-colorscripts --no-title -r > "$SPRITE"

read -r LOGO_LINES LOGO_WIDTH < <(python3 - "$SPRITE" <<'PY'
import re, sys
ansi = re.compile(r'\x1b\[[0-9;]*m')
with open(sys.argv[1], encoding="utf-8") as f:
    lines = [ansi.sub('', l.rstrip('\n')) for l in f]
while lines and lines[-1] == '':
    lines.pop()
print(len(lines), max((len(l) for l in lines), default=0))
PY
)

exec fastfetch -c "$CONFIG" \
    --logo-type raw --logo "$SPRITE" \
    --logo-width "$((LOGO_WIDTH + 2))" --logo-height "$LOGO_LINES"
