{
  description = "Dev shell with qemu, swtpm, and openssl";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/95ca1e203c0750115fd4a6f17d5a245dfe6b1edd";
  };

  outputs = { self, nixpkgs }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      lib = nixpkgs.lib;
      linuxPkg = pkgs.linuxPackages_7_0;
      kernel = linuxPkg.kernel;
      inherit (linuxPkg) kernelModuleMakeFlags;
      llvm = pkgs.llvmPackages;
      clangKernel = kernel.override {
        stdenv = pkgs.clangStdenv;
      };
      buildTrustedHashRust = package: pkgs.rustPlatform.buildRustPackage {
        pname = package;
        version = "0.1.0";
        src = lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" package ];
        doCheck = false;
      };
      trustedHashKmod =
        kernel.stdenv.mkDerivation {
          pname = "trusted_hash_kmod";
          version = "0-unstable-2026-05-04";

          src = ./trusted_hash_kmod;

          nativeBuildInputs = kernel.moduleBuildDependencies;
          makeFlags = kernelModuleMakeFlags ++ [
            "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
          ];

          installFlags = [ "INSTALL_MOD_PATH=${placeholder "out"}" ];
          installTargets = [ "modules_install" ];

          meta = {
            platforms = [ "x86_64-linux" ] ++ lib.optional (kernel.kernelAtLeast "6.9") "aarch64-linux";
          };
        };
    in {
      packages.x86_64-linux = {
        trusted_hash_agent = buildTrustedHashRust "trusted_hash_agent";
        trusted_hash_attester = buildTrustedHashRust "trusted_hash_attester";
        trusted_hash_kmod = trustedHashKmod;
      };
      devShells.x86_64-linux.default = pkgs.mkShell {
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
      devShells.x86_64-linux.kernel = pkgs.mkShell {
        inputsFrom = [
          clangKernel
        ];
        nativeBuildInputs = clangKernel.moduleBuildDependencies ++ (with pkgs; [
          llvmPackages.lld
          llvmPackages.llvm
          rustc rust-bindgen rustfmt clippy
        ]);
        shellHook = ''
          export MAKEFLAGS="${pkgs.lib.concatStringsSep " " clangKernel.commonMakeFlags} $MAKEFLAGS"
          export RUST_LIB_SRC="${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
          export LLVM=1
        '';
      };
    };
}
