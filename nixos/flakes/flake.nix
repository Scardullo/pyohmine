{
  description = "Combined NixOS configurations for 'nixos' (Hyprland PC) and 'nixos-vm' (KDE Plasma VM)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
    in
    {
      nixosConfigurations = {
        nixos = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ./hosts/nixos/configuration.nix
          ];
        };

        "nixos-vm" = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ./hosts/nixos-vm/configuration.nix
          ];
        };
      };
    };
}
