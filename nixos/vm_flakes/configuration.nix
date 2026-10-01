# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).

{ config, lib, pkgs, ... }:

let
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
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  # -------------------------
  # BOOT
  # -------------------------
  # Use the GRUB 2 boot loader.
  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
  boot.loader.grub.useOSProber = true;

  boot.kernelPackages = pkgs.linuxPackages_latest;

  networking.hostName = "nixos-vm"; # Define your hostname.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Enable networking
  networking.networkmanager.enable = true;

  environment.localBinInPath = true;

  environment.sessionVariables = {
    XCURSOR_THEME = "Bibata-Modern-Classic";
    XCURSOR_SIZE = "24";
    NIXOS_OZONE_WL = "1";
  };

  # Set your time zone.
  time.timeZone = "America/Chicago";

  # Select internationalisation properties.
  i18n.defaultLocale = "en_US.UTF-8";

  i18n.extraLocaleSettings = {
    LC_ADDRESS = "en_US.UTF-8";
    LC_IDENTIFICATION = "en_US.UTF-8";
    LC_MEASUREMENT = "en_US.UTF-8";
    LC_MONETARY = "en_US.UTF-8";
    LC_NAME = "en_US.UTF-8";
    LC_NUMERIC = "en_US.UTF-8";
    LC_PAPER = "en_US.UTF-8";
    LC_TELEPHONE = "en_US.UTF-8";
    LC_TIME = "en_US.UTF-8";
  };

  # -------------------------
  # NIX FEATURES
  # -------------------------
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # -------------------------
  # NIX-LD (run generic dynamically-linked Linux binaries)
  # -------------------------
  programs.nix-ld.enable = true;
  programs.nix-ld.libraries = with pkgs; [
    sqlite
  ];

  # Enable the X11 windowing system.
  services.xserver.enable = true;

  # Enable the Pantheon Desktop Environment.
  services.xserver.displayManager.lightdm.enable = true;
  services.desktopManager.pantheon.enable = true;

  services.accounts-daemon.enable = true;

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "us";
    variant = "";
  };

  # Enable CUPS to print documents.
  services.printing.enable = true;

  # Enable sound with pipewire.
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    # jack.enable = true;
  };

  # thumbnail support
  services.tumbler.enable = true;

  # Enable touchpad support (enabled default in most desktopManager).
  # services.libinput.enable = true;

  # -------------------------
  # NFS AUTOMOUNT (SYSTEMD)
  # -------------------------
  services.rpcbind.enable = true;

  fileSystems."/mnt/nfs/Documents" = {
    device = "10.0.0.139:/home/anthony/Documents";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/mediaplex" = {
    device = "10.0.0.139:/home/anthony/mediaplex";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/python" = {
    device = "10.0.0.139:/home/anthony/python";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/bashscripts" = {
    device = "10.0.0.139:/home/anthony/bashscripts";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/postgres" = {
    device = "10.0.0.139:/home/anthony/postgres";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  fileSystems."/mnt/nfs/vmisos" = {
    device = "10.0.0.139:/home/anthony/vmisos";
    fsType = "nfs4";
    options = [
      "x-systemd.automount"
      "x-systemd.idle-timeout=60"
      "noatime"
    ];
  };

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users."anthony" = {
    isNormalUser = true;
    description = "anthony";
    extraGroups = [ "networkmanager" "wheel" "wireshark" ];
    shell = pkgs.zsh;
    packages = with pkgs; [
    #  thunderbird
    ];
  };

  programs.wireshark.enable = true;

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


  environment.systemPackages = with pkgs; [
   claude-code
   git

   kitty
   alacritty

    # -------------------------
    # THEMING / ICONS / CURSORS
    # -------------------------
    pokemon-colorscripts
    gnome-themes-extra
    adwaita-qt
    glib
    dconf
    bibata-cursors
    nwg-look
    qt6.qtwayland
    qt5.qtwayland
    libsForQt5.qt5ct
    candy-icons
    gruvbox-plus-icons

    # -------------------------
    # FILE MANAGER
    # -------------------------
    xfce.thunar

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
    cava

    # -------------------------
    # AUDIO / MEDIA
    # -------------------------
    playerctl
    pavucontrol
    brightnessctl

    # -------------------------
    # WEB / EDITORS
    # -------------------------
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

  # Install firefox.
  programs.firefox.enable = true;

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # List packages installed in system profile.
  # You can use https://search.nixos.org/ to find more packages (and options).
  # environment.systemPackages = with pkgs; [
  #   vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  #   wget
  # ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;

  # This option defines the first version of NixOS you have installed on this particular machine,
  # and is used to maintain compatibility with application data (e.g. databases) created on older NixOS versions.
  #
  # Most users should NEVER change this value after the initial install, for any reason,
  # even if you've upgraded your system to a new NixOS release.
  #
  # This value does NOT affect the Nixpkgs version your packages and OS are pulled from,
  # so changing it will NOT upgrade your system - see https://nixos.org/manual/nixos/stable/#sec-upgrading for how
  # to actually do that.
  #
  # This value being lower than the current NixOS release does NOT mean your system is
  # out of date, out of support, or vulnerable.
  #
  # Do NOT change this value unless you have manually inspected all the changes it would make to your configuration,
  # and migrated your data accordingly.
  #
  # For more information, see `man configuration.nix` or https://nixos.org/manual/nixos/stable/options#opt-system.stateVersion .
  system.stateVersion = "26.05"; # Did you read the comment?

}
