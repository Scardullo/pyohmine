{
  description = "Combined NixOS configurations for 'nixos' (Hyprland PC) and 'vm_nixos' (Proxmox VM)";

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

        vm_nixos = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ./hosts/vm_nixos/configuration.nix
          ];
        };
      };
    };
}
