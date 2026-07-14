{ config, pkgs, lib, modulesPath, ... }: {
  boot.uki.name = "trusted-hash-server";
  networking.hostName = "trusted-hash-server";
  networking.firewall.allowedTCPPorts = [ 31337 ];

  # Challenge-intentional: players control machine A as root. The trusted
  # boundary is Secure Boot + lockdown + TPM-bound kernel code, not Unix user
  # separation inside A.
  users.users.root.initialPassword = "root";

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "yes";
    };
  };

  environment.systemPackages = with pkgs; [
    coreutils
    tpm2-tools
    python3
    openssl
    parted
  ];

  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  system.stateVersion = "25.11";
}
