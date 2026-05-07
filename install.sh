#!/bin/bash

set -e

echo " Arch Hyprland Setup Installer ..."

PACMAN_PKGS=(
    alacritty
    autofs
    base
    base-devel
    bat
    bpytop
    breeze
    breeze-gtk
    cbonsai
    cmatrix
    dolphin
    dunst
    efibootmgr
    eza
    fastfetch
    ffmpegthumbnailer
    firefox
    gdm
    git
    gnome-themes-extra
    grim
    grub
    htop
    hyprland
    imagemagick
    intel-media-driver
    intel-ucode
    iwd
    kde-cli-tools
    kitty
    libva-intel-driver
    linux
    linux-firmware
    man-db
    nano
    ncdu
    neovim
    net-tools
    network-manager-applet
    networkmanager
    nfs-utils
    nwg-look
    pipewire-alsa
    plasma-integration
    polkit-kde-agent
    pycharm
    qt5-wayland
    qt5ct
    qt6-wayland
    qt6ct
    rofi
    rsync
    slurp
    smartmontools
    starship
    sudo
    swaybg
    thunar
    thunar-archive-plugin
    thunar-volman
    tk
    tumbler
    usbutils
    uwsm
    vim
    vulkan-intel
    wget
    which
    wireless_tools
    wofi
    wpa_supplicant
    xdg-desktop-portal-hyprland
    xdg-utils
    xorg-server
    xorg-xinit
    zram-generator
    zsh
    zsh-autosuggestions
    zsh-syntax-highlighting
    zsh-theme-powerlevel10k
)

AUR_PKGS=(
    candy-icons-git
    colloid-icon-theme-git
    gruvbox-plus-icon-theme
    nerdfetch-git
    pokemon-colorscripts-git
    tela-icon-theme
    visual-studio-code-bin
)

NERD_FONTS=(
    ttf-jetbrains-mono-nerd
    ttf-firacode-nerd
    ttf-hack-nerd
    ttf-iosevka-nerd
    ttf-meslo-nerd
    ttf-ubuntu-mono-nerd
    ttf-cascadia-code-nerd
    ttf-nerd-fonts-symbols
    ttf-nerd-fonts-symbols-mono
)

echo "Installing pacman packages..."

sudo pacman -Syu --needed --noconfirm "${PACMAN_PKGS[@]}"

if ! command -v yay &>/dev/null; then
    echo "Installing yay..."

    cd /tmp
    git clone https://aur.archlinux.org/yay.git
    cd yay
    makepkg -si --noconfirm
fi

echo "Installing AUR packages..."

yay -S --needed --noconfirm "${AUR_PKGS[@]}"

echo "Installing Nerd Fonts..."

sudo pacman -S --needed --noconfirm "${NERD_FONTS[@]}"

echo "Enabling services..."

sudo systemctl enable NetworkManager
sudo systemctl enable gdm
sudo systemctl enable autofs

mkdir -p ~/.config/kitty
mkdir -p ~/.config/hypr
mkdir -p ~/.config/fastfetch
mkdir -p ~/.config/starship
mkdir -p ~/Pictures/wallpaper

echo "Copying configs..."

cp -r ./config/kitty/* ~/.config/kitty/
cp -r ./config/hypr/* ~/.config/hypr/
cp -r ./config/fastfetch/* ~/.config/fastfetch/
cp -r ./config/starship/* ~/.config/starship/

cp ./zshrc/.zshrc ~/.zshrc

echo "Copying wallpapers..."

cp -r ./wallpapers/* ~/Pictures/wallpaper/

echo "Installing theme scripts..."

sudo mkdir -p /usr/local/bin

sudo cp ./theme-scripts/* /usr/local/bin/

sudo chmod +x /usr/local/bin/*

echo "Setting zsh as default shell..."

chsh -s /bin/zsh

gsettings set org.gnome.desktop.interface color-scheme prefer-dark || true

echo " INSTALLATION COMPLETE"
echo ""
echo "Reboot recommended."
