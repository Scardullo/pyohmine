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

  environment.sessionVariables = {
    XCURSOR_THEME = "Bibata-Modern-Classic";
    XCURSOR_SIZE = "24";
  };

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

  services.accounts-daemon.enable = true;

  environment.etc."AccountsService/users/anthony".text = ''
    [User]
    Icon=/etc/user-icons/anthony.png
  '';

  # -------------------------
  # ZSH
  # -------------------------
  programs.zsh = {
    enable = true;
    autosuggestions.enable = true;
    syntaxHighlighting.enable = true;
  };

  # -------------------------
  # HYPRLAND
  # -------------------------
  programs.hyprland = {
    enable = true;
    xwayland.enable = true;
  };
  
  # -------------------------
  # DISPLAY MANAGER (GDM)
  # -------------------------
  services.xserver.enable = true;

  services.displayManager.gdm = {
    enable = true;
    wayland = true;
  };

  services.desktopManager.gnome.enable = false;

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

  # thumbnail support
  services.tumbler.enable = true;

  # -------------------------
  # NFS AUTOMOUNT (SYSTEMD)
  # -------------------------

  services.rpcbind.enable = true;

  fileSystems."/mnt/nfs/Documents" = {
    device = "10.0.0.75:/home/anthony/Documents";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/mediaplex" = {
    device = "10.0.0.75:/home/anthony/mediaplex";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/python" = {
    device = "10.0.0.75:/home/anthony/python";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/bashscripts" = {
    device = "10.0.0.75:/home/anthony/bashscripts";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/postgres" = {
    device = "10.0.0.75:/home/anthony/postgres";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/vmisos" = {
    device = "10.0.0.75:/home/anthony/vmisos";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  # -------------------------
  # SSH
  # -------------------------
  services.openssh.enable = true;

  # -------------------------
  # LOCATE (plocate)
  # -------------------------
  services.locate = {
    enable = true;
    package = pkgs.plocate;

    prunePaths = [
      "/tmp"
      "/var/tmp"
      "/nix/store"
    ];
  };
  
  # SUDO NOPASSWD
  security.sudo.extraRules = [
    {
      users = [ "anthony" ];
      commands = [
        {
          command = "ALL";
          options = [ "NOPASSWD" ];
        }
      ];
    }
  ];  
 
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
    alacritty    

    # file manager
    xfce.thunar

    # GTK / GNOME THEMING SUPPORT (IMPORTANT FOR DARK MODE)
    gnome-themes-extra
    adwaita-qt
    glib
    dconf
    bibata-cursors

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
    
    # miscellaneous
    imagemagick
    ffmpegthumbnailer
    poppler-utils
    gdk-pixbuf
    webp-pixbuf-loader
    librsvg
    htop
    bat
    lsof
    psmisc
    ncdu
    cmatrix
    hyprshot
    python3
  ];

  # -------------------------
  # STATE VERSION
  # -------------------------
  system.stateVersion = "25.05";
}
