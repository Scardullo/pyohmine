#!/usr/bin/env bash
# Arch Linux + Hyprland setup.
#   1. Installs every package from ../Documents/pacman_Qe (repo) and pacman_Qm (AUR, via yay)
#   2. Copies these dotfiles into place (backing up anything it overwrites)
#   3. Enables sddm / NetworkManager, sets the sddm theme, zram, and zsh as login shell
#
# Usage: ./install.sh [--packages-only | --dotfiles-only | --save-packages]
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
# (brightness keys), curl (weather), python (pokefetch), rsync (this script).
EXTRA_PKGS=(playerctl wireplumber brightnessctl curl python rsync)

# Theme scripts that live in /usr/local/bin so Hyprland can find them without ~/.local/bin on PATH.
SYSTEM_BIN=(wallpp wallp1 wallp2 catppuccin_star dracula_star everforest_star gruvbox_star
            nord_star purple-daze_star tokyo-night_star)

msg()  { printf '\n\033[1;34m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ->\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

do_packages=1 do_dotfiles=1
case "${1:-}" in
  --packages-only) do_dotfiles=0 ;;
  --dotfiles-only) do_packages=0 ;;
  --save-packages)
    pacman -Qqen > "$PKG_QE" && pacman -Qqem > "$PKG_QM"
    msg "Saved $(wc -l < "$PKG_QE") explicit and $(wc -l < "$PKG_QM") foreign packages to $REPO/Documents"
    exit 0 ;;
  -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) die "unknown option: $1 (try --help)" ;;
esac

[[ $EUID -ne 0 ]] || die "run as your normal user, not root (makepkg refuses to run as root)"
[[ -f /etc/arch-release ]] || die "this script is for Arch Linux"
[[ "$DOTS" == "$HOME/pyohmine/dotfiles" ]] || \
  warn "repo is not at ~/pyohmine — the p10k theme scripts copy from ~/pyohmine/dotfiles/zshrc/p10k"

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

# place SRC/ DEST/ NAME — merge SRC into DEST; files it overwrites go to $BACKUP/NAME
place() {
  mkdir -p "$2"
  rsync -a -c -b --backup-dir="$BACKUP/$3" "$1" "$2"
}

install_dotfiles() {
  command -v rsync >/dev/null || die "rsync is required (run without --dotfiles-only first)"

  # Stage the text files so hardcoded /home/anthony paths can be rewritten for another user.
  local stage; stage="$(mktemp -d)"
  cp -a "$DOTS/config" "$DOTS/zshrc" "$stage/"
  # claude is the Claude Code binary (gitignored, ~300MB); install it separately
  rsync -a --exclude=claude "$DOTS/theme-scripts" "$stage/"
  # The theme scripts copy fastfetch/starship/zshrc variants out of ~/Documents.
  mkdir -p "$stage/Documents"
  for d in fastfetch-configs color-themes bash_zsh_rc; do
    [[ -d $REPO/Documents/$d ]] && cp -a "$REPO/Documents/$d" "$stage/Documents/"
  done
  if [[ $HOME != /home/anthony ]]; then
    grep -rlIZ /home/anthony "$stage" | xargs -0 -r sed -i "s#/home/anthony#$HOME#g"
  fi

  msg "Installing ~/.config (hypr, waybar, kitty, rofi, nvim, cava, fastfetch, starship)"
  place "$stage/config/" "$HOME/.config/" config

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
  place "$stage/zshrc/" "$HOME/Documents/bash_zsh_rc/myhypr/" documents
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

(( do_packages )) && install_packages && setup_system
(( do_dotfiles )) && install_dotfiles

msg "Done. Reboot, log in through sddm, and pick a theme with ALT+SPACE."
echo "     SUPER+ALT+SPACE switches wallpaper, SUPER+/ lists all keybinds."
