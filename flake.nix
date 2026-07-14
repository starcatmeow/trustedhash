{
  description = "Trusted Hash CTF operator workspace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/95ca1e203c0750115fd4a6f17d5a245dfe6b1edd";
    challenge = {
      url = "path:./challenge";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, challenge }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      buildOperatorRust = package: pkgs.rustPlatform.buildRustPackage {
        pname = package;
        version = "0.1.0";
        src = ./.;
        cargoRoot = "operator";
        buildAndTestSubdir = "operator";
        cargoLock.lockFile = ./operator/Cargo.lock;
        cargoBuildFlags = [ "-p" package ];
        doCheck = false;
      };
      trustedHashPortal = buildOperatorRust "trusted_hash_portal";
      trustedHashPortalRuntimeEnv = pkgs.buildEnv {
        name = "trusted-hash-portal-runtime-env";
        paths = [
          trustedHashPortal
          challenge.packages.${system}.trusted_hash_attester
          pkgs.bash
          pkgs.coreutils
          pkgs.novnc
          pkgs.iproute2
          pkgs.openssh
          pkgs.openssl
          pkgs.procps
          pkgs.python313Packages.virt-firmware
          pkgs.qemu_kvm
          pkgs.qemu-utils
          pkgs.socat
          pkgs.swtpm
          pkgs.tpm2-tools
          pkgs.util-linux
        ];
      };
    in {
      packages.${system} = challenge.packages.${system} // {
        trusted_hash_portal = trustedHashPortal;
        trusted_hash_portal_runtime_env = trustedHashPortalRuntimeEnv;
      };

      devShells.${system} = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            qemu
            swtpm
            openssl
            tpm2-tools
            sbctl
            nixos-rebuild
            python313Packages.virt-firmware
            cargo
            rustc
            rustfmt
          ];
          QEMU_PATH = "${pkgs.qemu}";
        };

        kernel = challenge.devShells.${system}.kernel;
      };
    };
}
