{ config, lib, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
  ];

  # -------------------------
  # BOOT
  # -------------------------
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  boot.kernelPackages = pkgs.linuxPackages_latest;

  # -------------------------
  # NETWORK
  # -------------------------
  networking.hostName = "nixos";
  networking.networkmanager.enable = true;

  environment.localBinInPath = true;

  # -------------------------
  # TIME / LOCALE
  # -------------------------
  time.timeZone = "America/Chicago";
  i18n.defaultLocale = "en_US.UTF-8";

  # -------------------------
  # NIX FEATURES
  # -------------------------
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  nixpkgs.config.allowUnfree = true;

  # -------------------------
  # USER
  # -------------------------
  users.users.anthony = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" ];
    shell = pkgs.zsh;
    initialPassword = "nixos";
  };

  # -------------------------
  # ZSH
  # -------------------------
  programs.zsh = {
    enable = true;
    autosuggestions.enable = true;
    syntax-highlighting.enable = true;
  };

  # -------------------------
  # HYPRLAND
  # -------------------------
  programs.hyprland = {
    enable = true;
    xwayland.enable = true;
  };

  xdg.portal = {
    enable = true;
    extraPortals = [
      pkgs.xdg-desktop-portal-hyprland
    ];
  };

  # -------------------------
  # AUDIO
  # -------------------------
  services.pipewire = {
    enable = true;
    pulse.enable = true;
  };

  # -------------------------
  # SSH
  # -------------------------
  services.openssh.enable = true;

  # -------------------------
  # FONTS
  # -------------------------
  fonts.packages = with pkgs; [
    nerd-fonts.jetbrains-mono
    nerd-fonts.fira-code

    noto-fonts
    noto-fonts-cjk-sans
    noto-fonts-color-emoji
    nerd-fonts.agave
  ];

  # -------------------------
  # THEMING (THIS IS WHAT YOU WANTED)
  # -------------------------
  environment.systemPackages = with pkgs; [
    # WM
    hyprland
    waybar
    kitty
    rofi
    swaybg

    # file manager
    xfce.thunar

    # GTK / GNOME THEMING SUPPORT (IMPORTANT FOR DARK MODE)
    gnome-themes-extra
    adwaita-qt
    glib
    dconf

    # screenshots / clipboard
    grim
    slurp
    wl-clipboard

    # dev tools
    git
    wget
    curl
    nano
    vim
    neovim
    gcc
    ripgrep
    fd

    # system tools
    fastfetch
    eza
    starship

    # audio / media
    playerctl
    pavucontrol
    brightnessctl

    # apps
    firefox
    vscode

    # network
    networkmanagerapplet

    # zsh plugins
    zsh-autosuggestions
    zsh-syntax-highlighting

  ];

  # -------------------------
  # STATE VERSION
  # -------------------------
  system.stateVersion = "25.05";
}
