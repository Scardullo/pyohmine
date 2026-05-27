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
    NIXOS_OZONE_WL = "1";

    # Qt theming (needed for qt5ct)
    QT_QPA_PLATFORMTHEME = "qt5ct";
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
    extraGroups = [ "wheel" "networkmanager" "wireshark" ];
    shell = pkgs.zsh;
    initialPassword = "nixos";
  };

  services.accounts-daemon.enable = true;
  services.tor = {
    enable = true;
    settings = {
      SocksPort = "0.0.0.0:9050";
    };
  };

  programs.wireshark.enable = true;

  environment.etc."AccountsService/users/anthony".text = ''
    [User]
    Icon=/etc/user-icons/anthony.png
  '';
  
  environment.etc."proxychains.conf".source = pkgs.writeText "proxychains.conf" ''
    dynamic_chain
    proxy_dns
    tcp_read_time_out 15000
    tcp_connect_time_out 8000

    [ProxyList]
    socks5 127.0.0.1 9050
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
  # DISPLAY MANAGER (SDDM)
  # -------------------------
  services.xserver.enable = true;

  services.displayManager.sddm = {
    enable = true;
    wayland.enable = true;
  };

  services.desktopManager.gnome.enable = false;

  services.displayManager.sessionPackages = [
    pkgs.hyprland
  ];

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

  # -------------------------
  # SUDO NOPASSWD
  # -------------------------
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
  # QT (FIXED)
  # -------------------------
  qt = {
    enable = true;
    platformTheme = "qt5ct";
    style = "adwaita-dark";
  };


  # -------------------------
  # PACKAGES
  # -------------------------
  environment.systemPackages = with pkgs; [
  
    # -------------------------
    # WAYLAND / HYPRLAND
    # -------------------------
    hyprland
    waybar
    kitty
    rofi
    swaybg
    alacritty

    # -------------------------
    # FILE MANAGER
    # -------------------------
    xfce.thunar

    # -------------------------
    # THEMING / GTK / QT
    # -------------------------
    gnome-themes-extra
    adwaita-qt
    glib
    dconf
    bibata-cursors

    qt6.qtwayland
    qt5.qtwayland
    libsForQt5.qt5ct

    # -------------------------
    # SCREENSHOT / WAYLAND TOOLS
    # -------------------------
    grim
    slurp
    wl-clipboard
    hyprshot

    # -------------------------
    # DEVELOPMENT / CLI TOOLS
    # -------------------------
    git
    wget
    curl
    nano
    vim
    neovim
    gcc
    python3

    ripgrep
    fd
    bat
    eza

    # -------------------------
    # SYSTEM MONITORING / UTILITIES
    # -------------------------
    fastfetch
    htop
    lsof
    psmisc
    ncdu

    # -------------------------
    # SHELL / TERMINAL ENHANCEMENTS
    # -------------------------
    starship
    zsh-autosuggestions
    zsh-syntax-highlighting
    cbonsai
    cmatrix

    # -------------------------
    # AUDIO / MEDIA
    # -------------------------
    playerctl
    pavucontrol
    brightnessctl

    # -------------------------
    # WEB / EDITORS
    # -------------------------
    firefox
    vscode

    # -------------------------
    # NETWORKING
    # -------------------------
    networkmanagerapplet

    dnsutils
    ipcalc
    nettools
    nmap
    speedtest-cli

    proxychains-ng
    tor
    wireshark

    # -------------------------
    # IMAGE / THUMBNAIL SUPPORT
    # -------------------------
    imagemagick
    ffmpegthumbnailer
    poppler-utils
    gdk-pixbuf
    webp-pixbuf-loader
    librsvg
  ];

  # -------------------------
  # STATE VERSION
  # -------------------------
  system.stateVersion = "25.05";
}
