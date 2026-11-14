#!/usr/bin/env bash
# Arch Linux + Hyprland setup.
#   1. Installs every package from ../Documents/pacman_Qe (repo) and pacman_Qm (AUR, via yay)
#   2. Copies these dotfiles into place (backing up anything it overwrites)
#   3. Enables sddm / NetworkManager, sets the sddm theme, zram, and zsh as login shell
#   4. If Hyprland is running, writes this PC's monitors (hyprctl monitors) into the hypr configs
#
# Usage: ./install.sh [--packages-only | --dotfiles-only | --monitors-only | --save-packages]
#   --monitors-only  only redo step 4 (run it from inside Hyprland, e.g. after the first login)
#   --save-packages  save explicit repo (-Qqen) and AUR (-Qqem) packages, then exit
# Run as your normal user (not root); sudo is used where needed. Safe to re-run.
set -euo pipefail

DOTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$DOTS")"
PKG_QE="$REPO/Documents/pacman_Qe"
PKG_QM="$REPO/Documents/pacman_Qm"
BACKUP="$HOME/.dotfiles-backup/$(date +%Y%m%d-%H%M%S)"

# Not explicitly installed on the source PC (pulled in as deps), but called directly by the
# configs/scripts: playerctl (waybar/hypr media keys), wpctl (volume keys), brightnessctl
# (brightness keys), curl (weather), python (pokefetch, rofi-name-popup, claude-usage), rsync
# (this script), gtk-layer-shell (built into rofi-name-label, volume-osd and claude-osd below),
# libpulse, json-glib and at-spi2-core (volume-osd / claude-osd: volume events, Hyprland socket
# replies, waybar's module position).
EXTRA_PKGS=(playerctl wireplumber brightnessctl curl python rsync gtk-layer-shell
            libpulse json-glib at-spi2-core)

# Scripts that live in /usr/local/bin so Hyprland can find them without ~/.local/bin on PATH.
SYSTEM_BIN=(wallpp wallp1 wallp2 hypr-outputs)

msg()  { printf '\n\033[1;34m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ->\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

do_packages=1 do_dotfiles=1 do_monitors=1
case "${1:-}" in
  --packages-only) do_dotfiles=0 do_monitors=0 ;;
  --dotfiles-only) do_packages=0 ;;
  --monitors-only) do_packages=0 do_dotfiles=0 ;;
  --save-packages)
    pacman -Qqen > "$PKG_QE" && pacman -Qqem > "$PKG_QM"
    msg "Saved $(wc -l < "$PKG_QE") explicit and $(wc -l < "$PKG_QM") foreign packages to $REPO/Documents"
    exit 0 ;;
  -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) die "unknown option: $1 (try --help)" ;;
esac

[[ $EUID -ne 0 ]] || die "run as your normal user, not root (makepkg refuses to run as root)"
[[ -f /etc/arch-release ]] || die "this script is for Arch Linux"

install_packages() {
  [[ -f $PKG_QE && -f $PKG_QM ]] || die "package lists not found in $REPO/Documents"

  msg "Updating system and installing base-devel + git"
  sudo pacman -Syu --needed base-devel git

  local -a qe qm repo_pkgs=() aur_pkgs=()
  local -A foreign=() in_repos=()
  mapfile -t qe < <(awk 'NF {print $1}' "$PKG_QE")
  mapfile -t qm < <(awk 'NF {print $1}' "$PKG_QM")
  for p in "${qm[@]}"; do foreign[$p]=1; done
  while read -r p; do in_repos[$p]=1; done < <(pacman -Slq)

  for p in "${qe[@]}" "${EXTRA_PKGS[@]}"; do
    [[ -n ${foreign[$p]:-} ]] && continue
    if [[ -n ${in_repos[$p]:-} ]]; then
      repo_pkgs+=("$p")
    else
      warn "$p is no longer in the official repos, trying the AUR"
      aur_pkgs+=("$p")
    fi
  done
  for p in "${qm[@]}"; do [[ $p == yay ]] || aur_pkgs+=("$p"); done

  msg "Installing ${#repo_pkgs[@]} packages from the official repos"
  sudo pacman -S --needed "${repo_pkgs[@]}"

  if ! command -v yay >/dev/null; then
    msg "Bootstrapping yay from the AUR"
    local tmp; tmp="$(mktemp -d)"
    git clone https://aur.archlinux.org/yay-bin.git "$tmp/yay-bin"
    (cd "$tmp/yay-bin" && makepkg -si --noconfirm)
    rm -rf "$tmp"
  fi

  msg "Installing ${#aur_pkgs[@]} AUR packages with yay"
  yay -S --needed "${aur_pkgs[@]}"
}

setup_system() {
  msg "Enabling services"
  sudo systemctl enable sddm.service NetworkManager.service

  msg "Setting sddm theme (sddm-astronaut-theme)"
  sudo mkdir -p /etc/sddm.conf.d
  sudo tee /etc/sddm.conf.d/theme.conf >/dev/null <<'EOF'
[Theme]
Current=sddm-astronaut-theme

[General]
InputMethod=qtvirtualkeyboard
EOF

  if [[ ! -f /etc/systemd/zram-generator.conf ]]; then
    msg "Configuring zram swap"
    printf '[zram0]\ncompression-algorithm = zstd\n' | sudo tee /etc/systemd/zram-generator.conf >/dev/null
  fi

  if [[ "$(getent passwd "$USER" | cut -d: -f7)" != /usr/bin/zsh ]]; then
    msg "Changing login shell to zsh"
    chsh -s /usr/bin/zsh
  fi

  msg "Refreshing font cache"
  fc-cache -f >/dev/null
}

# place SRC/ DEST/ NAME [RSYNC_ARGS] — merge SRC into DEST; files it overwrites go to $BACKUP/NAME
place() {
  mkdir -p "$2"
  rsync -a -c -b --backup-dir="$BACKUP/$3" "${@:4}" "$1" "$2"
}

install_dotfiles() {
  command -v rsync >/dev/null || die "rsync is required (run without --dotfiles-only first)"

  # Stage the text files so hardcoded /home/anthony paths can be rewritten for another user.
  local stage; stage="$(mktemp -d)"
  cp -a "$DOTS/config" "$DOTS/zshrc" "$stage/"
  # claude is the Claude Code binary (gitignored, ~300MB); install it separately
  rsync -a --exclude=claude "$DOTS/theme-scripts" "$stage/"
  # The theme scripts copy fastfetch/starship/zshrc variants out of ~/Documents.
  # starship and zshrc come from $DOTS (placed below); the rest from the repo's Documents.
  mkdir -p "$stage/Documents"
  for d in fastfetch-configs color-themes; do
    [[ -d $REPO/Documents/$d ]] && cp -a "$REPO/Documents/$d" "$stage/Documents/"
  done
  if [[ $HOME != /home/anthony ]]; then
    grep -rlIZ /home/anthony "$stage" | xargs -0 -r sed -i "s#/home/anthony#$HOME#g"
  fi

  # config/starship only goes to ~/Documents/starship (placed below); the active theme is
  # ~/.config/starship.toml, which the theme scripts write.
  msg "Installing ~/.config (hypr, waybar, kitty, rofi, nvim, cava, fastfetch, gtk, qt6ct, btop)"
  place "$stage/config/" "$HOME/.config/" config --exclude=/starship/

  msg "Installing theme scripts"
  local -a sys=() user_excludes=()
  for f in "${SYSTEM_BIN[@]}"; do
    [[ -f $stage/theme-scripts/$f ]] && sys+=("$stage/theme-scripts/$f")
    user_excludes+=(--exclude="$f")
  done
  mkdir -p "$HOME/.local/bin"
  rsync -a -c -b --backup-dir="$BACKUP/local-bin" "${user_excludes[@]}" \
    "$stage/theme-scripts/" "$HOME/.local/bin/"
  sudo install -Dm755 -t /usr/local/bin "${sys[@]}"

  # Older setups put the per-theme scripts in /usr/local/bin too. Those stale copies shadow
  # the current ones in ~/.local/bin wherever /usr/local/bin comes first in PATH, so remove them.
  local name
  for f in "$stage"/theme-scripts/*; do
    name="${f##*/}"
    [[ " ${SYSTEM_BIN[*]} " == *" $name "* ]] && continue
    if [[ -f /usr/local/bin/$name ]]; then
      mkdir -p "$BACKUP/usr-local-bin" && cp -a "/usr/local/bin/$name" "$BACKUP/usr-local-bin/"
      sudo rm -f "/usr/local/bin/$name"
      warn "removed stale /usr/local/bin/$name (now lives in ~/.local/bin)"
    fi
  done

  # Small C programs, built here from ~/.local/src:
  #   rofi-name-label  the theme switchers' name label and color panel
  #   volume-osd       volume bar overlay under waybar's volume module (started by hypr/autostart)
  #   claude-osd       Claude usage overlay under waybar's Claude module (hover / SUPER+U; started
  #                    by hypr/autostart, data from ~/.local/bin/claude-usage)
  msg "Building rofi-name-label, volume-osd and claude-osd into ~/.local/bin"
  place "$DOTS/src/" "$HOME/.local/src/" src
  local -A build_libs=(
    [rofi-name-label]="gtk-layer-shell-0 gtk+-3.0"
    [volume-osd]="gtk-layer-shell-0 gtk+-3.0 atspi-2 json-glib-1.0 libpulse libpulse-mainloop-glib"
    [claude-osd]="gtk-layer-shell-0 gtk+-3.0 atspi-2 json-glib-1.0"
  )
  local prog
  for prog in rofi-name-label volume-osd claude-osd; do
    # shellcheck disable=SC2086
    if command -v gcc >/dev/null && pkg-config --exists ${build_libs[$prog]}; then
      gcc -O2 "$HOME/.local/src/$prog/$prog.c" -o "$HOME/.local/bin/$prog" -lm \
        $(pkg-config --cflags --libs ${build_libs[$prog]}) || warn "building $prog failed"
    else
      warn "gcc or the libraries for $prog are missing (${build_libs[$prog]}): skipping it"
    fi
  done

  # Claude Mascot: the Claude Code mascot at U+E4A0, the icon of waybar's Claude module and
  # claude-osd (source: src/claude-mascot/build.py)
  msg "Installing fonts to ~/.local/share/fonts"
  place "$DOTS/fonts/" "$HOME/.local/share/fonts/" fonts
  fc-cache -f "$HOME/.local/share/fonts" >/dev/null

  msg "Installing wallpapers to ~/Pictures/wallpaper"
  place "$DOTS/wallpaper/" "$HOME/Pictures/wallpaper/" wallpaper
  mkdir -p "$HOME/Pictures/ScreenShots"

  msg "Installing zsh config"
  local src dest
  for pair in "p10k:.zshrc" "p10k.zsh:.p10k.zsh"; do
    src="$stage/zshrc/${pair%%:*}" dest="$HOME/${pair#*:}"
    if [[ -f $dest ]] && ! cmp -s "$src" "$dest"; then
      mkdir -p "$BACKUP" && cp -a "$dest" "$BACKUP/"
    fi
    cp "$src" "$dest"
  done

  msg "Installing theme assets into ~/Documents and ~/Pictures/fastfetch_pics"
  place "$stage/Documents/" "$HOME/Documents/" documents
  place "$stage/zshrc/" "$HOME/Documents/zshrc/" documents
  place "$stage/config/starship/" "$HOME/Documents/starship/" documents
  [[ -d $REPO/Documents/Pictures/fastfetch_pics ]] && \
    place "$REPO/Documents/Pictures/fastfetch_pics/" "$HOME/Pictures/fastfetch_pics/" fastfetch_pics

  mkdir -p "$HOME/.local/state/wallpaper"
  [[ -f $HOME/.local/state/current-theme ]] || echo catppuccin > "$HOME/.local/state/current-theme"
  rm -rf "$stage"

  if [[ -d $BACKUP ]] && [[ -n "$(ls -A "$BACKUP")" ]]; then
    warn "overwritten files were backed up to $BACKUP"
  else
    rm -rf "$BACKUP"
    rmdir "$HOME/.dotfiles-backup" 2>/dev/null || true
  fi
}

# configure_monitors [BACKUP_DIR] — the hypr configs ship with the source PC's two outputs
# (DP-1 main, HDMI-A-1 second). Replace the hl.monitor blocks in ~/.config/hypr/hyprland.lua and
# every theme template (*.lua) with what `hyprctl monitors` reports on this PC, and point the
# workspace rules and the screenshot bind at the detected outputs. The main monitor is the one
# with the most pixels; the next one from the left gets workspace 2 (the same order as
# theme-scripts/hypr-outputs, which the wallpaper scripts use). If BACKUP_DIR is given,
# files that change are copied there first.
configure_monitors() {
  msg "Detecting monitors with hyprctl"
  local json
  if ! command -v hyprctl >/dev/null || ! json="$(hyprctl monitors -j 2>/dev/null)" \
     || [[ $json != \[* ]]; then
    warn "Hyprland isn't running here, so the hypr configs keep the source PC's DP-1/HDMI-A-1 layout."
    warn "After logging in to Hyprland, run: $DOTS/install.sh --monitors-only"
    return 0
  fi
  command -v python3 >/dev/null || { warn "python3 is missing: skipping monitor setup"; return 0; }

  local -a files=("$HOME"/.config/hypr/*.lua)
  [[ -e ${files[0]} ]] || { warn "no ~/.config/hypr/*.lua configs found"; return 0; }

  MONITORS_JSON="$json" python3 - "${1:-}" "${files[@]}" <<'PY' || warn "monitor setup failed"
import datetime, json, os, re, shutil, socket, sys

backup, files = sys.argv[1], sys.argv[2:]
mons = [m for m in json.loads(os.environ["MONITORS_JSON"]) if not m.get("disabled")]
if not mons:
    sys.exit("hyprctl reported no monitors")

by_area = sorted(mons, key=lambda m: (-m["width"] * m["height"], m["x"], m["y"]))
main = by_area[0]
others = sorted(by_area[1:], key=lambda m: (m["x"], m["y"]))
second = others[0] if others else main

def num(v, places):
    return f"{v:.{places}f}".rstrip("0").rstrip(".")

def desc(m):
    return f'{m.get("make", "")} {m.get("model", "")}'.strip() or m["name"]

def label(m):
    return m["name"] if desc(m) == m["name"] else f'{desc(m)}, {m["name"]}'

def role(m):
    if len(mons) == 1:
        return "main, all workspaces"
    if m is main:
        return "main: workspaces 1, 3-10"
    if m is second:
        return "workspace 2 only"
    return "no pinned workspaces"

stamp = datetime.date.today().isoformat()
out = [f"-- Detected by install.sh from `hyprctl monitors` on {socket.gethostname()}, {stamp}.",
       "-- Re-run `install.sh --monitors-only` from inside Hyprland after changing monitors.",
       ""]
for m in [main] + others:
    out += [f"-- {desc(m)} ({role(m)})",
            "hl.monitor({",
            f'    output   = "{m["name"]}",',
            f'    mode     = "{m["width"]}x{m["height"]}@{num(m["refreshRate"], 2)}",',
            f'    position = "{m["x"]}x{m["y"]}",',
            f'    scale    = "{num(m["scale"], 6)}",',
            "})", ""]
section = "\n".join(out).rstrip("\n") + "\n"

BLOCK = re.compile(r"(?:^--[^\n]*\n)?^hl\.monitor\(\{.*?^\}\)\n", re.M | re.S)
HEADER = re.compile(r"-- Detected by install\.sh[^\n]*\n-- Re-run[^\n]*\n\n\Z")

changed = 0
for path in files:
    with open(path) as f:
        text = f.read()
    blocks = list(BLOCK.finditer(text))
    if not blocks:
        continue
    if any(text[a.end():b.start()].strip() for a, b in zip(blocks, blocks[1:])):
        print(f"  -> {path}: hl.monitor blocks aren't next to each other, skipped")
        continue
    start, end = blocks[0].start(), blocks[-1].end()
    h = HEADER.search(text[:start])
    if h:
        start = h.start()

    # The outputs this file used before (first block = main, second = workspace 2) become
    # the detected ones everywhere else in the file: workspace rules, grim -o, comments.
    old = re.findall(r'output\s*=\s*"([^"]+)"', text[blocks[0].start():end])
    rename = {old[0]: main["name"]}
    if len(old) > 1:
        rename[old[1]] = second["name"]
    rest = text[end:]
    rest = re.sub(r"(?<![\w-])(" + "|".join(map(re.escape, rename)) + r")(?![\w-])",
                  lambda mt: rename[mt[1]], rest)
    rest = re.sub(r'(workspace_rule\(\{\s*workspace\s*=\s*"2",\s*monitor\s*=\s*")[^"]*"',
                  lambda mt: mt[1] + second["name"] + '"', rest)
    rest = re.sub(r"-- (?:RIGHT|SECOND) MONITOR \(.*\) ONLY workspace 2",
                  f"-- SECOND MONITOR ({label(second)}) ONLY workspace 2", rest)
    rest = re.sub(r"-- (?:LEFT|MAIN) MONITOR \(.*\) main workspaces",
                  f"-- MAIN MONITOR ({label(main)}) main workspaces", rest)

    new = text[:start] + section + rest
    if new != text:
        if backup:
            os.makedirs(backup, exist_ok=True)
            shutil.copy2(path, backup)
        with open(path, "w") as f:
            f.write(new)
        changed += 1

for m in [main] + others:
    print(f'  -> {m["name"]}: {desc(m)}, {m["width"]}x{m["height"]}@{num(m["refreshRate"], 2)}'
          f' at {m["x"]}x{m["y"]}, scale {num(m["scale"], 6)} ({role(m)})')
print(f"  -> updated {changed} of {len(files)} hypr configs")
PY
}

(( do_packages )) && install_packages && setup_system
(( do_dotfiles )) && install_dotfiles
if (( do_monitors && do_dotfiles )); then
  configure_monitors   # the configs were just installed, so there's nothing of yours to back up
elif (( do_monitors )); then
  configure_monitors "$BACKUP/hypr-monitors"
  [[ -d $BACKUP ]] && warn "overwritten files were backed up to $BACKUP"
  exit 0
fi

msg "Done. Reboot, log in through sddm, and pick a theme with ALT+SPACE."
echo "     SUPER+ALT+SPACE switches wallpaper, SUPER+/ lists all keybinds."
echo "     The Claude usage module on waybar needs a Claude login: run claude once and sign in."
