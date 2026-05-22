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

  # let nix manage ~/.local/bin properly
  environment.localBinInPath = true;

  # ❌ REMOVE custom PATH override (not needed on NixOS)
  # environment.sessionVariables = {
  #   PATH = "$HOME/.local/bin:$PATH";
  # };

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

  programs.zsh = {
    enable = true;
  };

  # FIXED WAY (THIS IS WHY YOUR AUTOSUGGESTIONS BROKE BEFORE)
  programs.zsh.autosuggestions.enable = true;
  programs.zsh.syntaxHighlighting.enable = true;

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
  # FONTS (FIXED NERD FONTS)
  # -------------------------
  fonts.packages = with pkgs; [
    nerd-fonts.jetbrains-mono
    nerd-fonts.fira-code

    noto-fonts
    noto-fonts-cjk-sans
    noto-fonts-color-emoji
  ];

  # -------------------------
  # SYSTEM PACKAGES
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

    # screenshots
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

    # zsh plugins (OK to keep here too)
    zsh-autosuggestions
    zsh-syntax-highlighting

    zsh-powerlevel10k
    meslo-lgs-nf
  ];

  # -------------------------
  # STATE VERSION
  # -------------------------
  system.stateVersion = "25.05";
}
