{ config, lib, pkgs, ... }:

let
  # -------------------------
  # SDDM THEME (sddm-astronaut, custom background + glass UI)
  # -------------------------
  sddmAstronautTheme =
    let
      baseTheme = pkgs.sddm-astronaut.override {
        embeddedTheme = "astronaut";
        themeConfig = {
          # Background
          Background = "Backgrounds/space.png";
          CropBackground = "true";

          # Clock
          HourFormat = "h:mm AP";
          DateFormat = "dddd, MMMM d";
          TimeTextColor = "#ffffff";
          DateTextColor = "#e6e6e6";

          # Fully transparent login form (no blur, no tint box) - only text/icons are opaque
          PartialBlur = "false";
          FullBlur = "false";
          HaveFormBackground = "false";
          FormPosition = "center";
          RoundCorners = "24";
          DimBackground = "0";

          LoginFieldBackgroundColor = "#00ffffff";
          PasswordFieldBackgroundColor = "#00ffffff";
          LoginFieldTextColor = "#ffffff";
          PasswordFieldTextColor = "#ffffff";
          PlaceholderTextColor = "#cccccc";

          LoginButtonTextColor = "#ffffff";
          LoginButtonBackgroundColor = "#00ffffff";

          # Behavior
          ForceLastUser = "true";
          PasswordFocus = "true";
          HideCompletePassword = "true";
          HideVirtualKeyboard = "true";
        };
      };
    in
    pkgs.runCommand "sddm-astronaut-theme-custom" { } ''
      mkdir -p $out/share/sddm/themes
      cp -r ${baseTheme}/share/sddm/themes/sddm-astronaut-theme $out/share/sddm/themes/sddm-astronaut-theme
      chmod -R u+w $out/share/sddm/themes/sddm-astronaut-theme
      cp ${./wallpapers/space.png} $out/share/sddm/themes/sddm-astronaut-theme/Backgrounds/space.png
    '';

  # -------------------------
  # POKEMON-COLORSCRIPTS (not in nixpkgs, packaged from upstream)
  # -------------------------
  pokemon-colorscripts = pkgs.stdenv.mkDerivation rec {
    pname = "pokemon-colorscripts";
    version = "unstable-2024-10-19";

    src = pkgs.fetchFromGitLab {
      owner = "phoneybadger";
      repo = "pokemon-colorscripts";
      rev = "5802ff67520be2ff6117a0abc78a08501f6252ad";
      hash = "sha256-gKVmpHKt7S2XhSxLDzbIHTjJMoiIk69Fch202FZffqU=";
    };

    nativeBuildInputs = [ pkgs.makeWrapper ];

    dontBuild = true;

    installPhase = ''
      runHook preInstall

      mkdir -p $out/share/pokemon-colorscripts
      cp -r colorscripts $out/share/pokemon-colorscripts/
      cp pokemon.json $out/share/pokemon-colorscripts/
      cp pokemon-colorscripts.py $out/share/pokemon-colorscripts/

      mkdir -p $out/bin
      makeWrapper ${pkgs.python3}/bin/python3 $out/bin/pokemon-colorscripts \
        --add-flags "$out/share/pokemon-colorscripts/pokemon-colorscripts.py"

      runHook postInstall
    '';

    meta = with pkgs.lib; {
      description = "CLI tool that prints out colorscripts of pokemon to the terminal";
      homepage = "https://gitlab.com/phoneybadger/pokemon-colorscripts";
      license = licenses.mit;
      mainProgram = "pokemon-colorscripts";
      platforms = platforms.all;
    };
  };
in

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
  # NIX-LD (run generic dynamically-linked Linux binaries)
  # -------------------------
  programs.nix-ld.enable = true;
  programs.nix-ld.libraries = with pkgs; [
    sqlite
  ];

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
    client = {
      enable = true;
      socksListenAddress = {
        addr = "0.0.0.0";
        port = 9050;
      };
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
  # ZSH / POWERLEVEL10K
  # -------------------------

  programs.zsh = {
    enable = true;

    autosuggestions.enable = true;
    syntaxHighlighting.enable = true;

    ohMyZsh = {
      enable = true;

      plugins = [
        "git"
      ];

      theme = "";
    };

    promptInit = ''
      source ${pkgs.zsh-powerlevel10k}/share/zsh-powerlevel10k/powerlevel10k.zsh-theme
    '';
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
    theme = "sddm-astronaut-theme";
    extraPackages = with pkgs.kdePackages; [
      qtmultimedia
      qtsvg
      qtvirtualkeyboard
    ];
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
  nerd-fonts.agave
  nerd-fonts.meslo-lg

  noto-fonts
  noto-fonts-cjk-sans
  noto-fonts-color-emoji
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
    # SDDM THEME
    # -------------------------
    sddmAstronautTheme

    # -------------------------
    # WAYLAND / HYPRLAND
    # -------------------------
    hyprland
    hypridle
    waybar
    kitty
    rofi
    swaybg
    alacritty
    cava

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
    candy-icons
    gruvbox-plus-icons   
    
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
    file

    # -------------------------
    # SYSTEM MONITORING / UTILITIES
    # -------------------------
    fastfetch
    htop
    lsof
    psmisc
    ncdu
    smartmontools
    btop

    # -------------------------
    # SHELL / TERMINAL ENHANCEMENTS
    # -------------------------
    starship
    zsh-autosuggestions
    zsh-syntax-highlighting
    cbonsai
    cmatrix
    tty-clock
    mc
    pokemon-colorscripts

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
