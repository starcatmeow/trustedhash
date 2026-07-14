{
  inputs = {
    nixpkgs.follows = "trusted_hash_workspace/nixpkgs";
    trusted_hash_kmod = {
      url = "path:../trusted_hash_kmod";
      flake = false;
    };
    trusted_hash_workspace = {
      url = "path:..";
    };
    secureBootKeys = {
      url = "path:/tmp/tobefilled";
      flake = false;
    };
    moduleSigningKeys = {
      url = "path:/tmp/tobefilled";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, secureBootKeys, moduleSigningKeys, trusted_hash_kmod, trusted_hash_workspace, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = nixpkgs.lib;
      challengeKernel = pkgs.linux_7_0.override {
        autoModules = false;
        ignoreConfigErrors = true;
        preferBuiltin = true;
      };
      challengeKernelPackages = pkgs.linuxPackagesFor challengeKernel;

      mkNixos = lib.nixosSystem {
        inherit system;
        modules = [
          ./configuration.nix
          ({ config, pkgs, lib, modulesPath, ... }:
            let
              signEfi = source:
                pkgs.runCommand "sign-efi"
                  { nativeBuildInputs = [ pkgs.sbctl ]; }
                  ''
                    cat > "$TMPDIR/sbctl.conf" <<EOF
                    ---
                    landlock: false
                    keydir: ${secureBootKeys}
                    guid: ${secureBootKeys}/GUID
                    files_db: $TMPDIR/sbctl-files.json
                    bundles_db: $TMPDIR/sbctl-bundles.json
                    EOF

                    printf '{}\n' > "$TMPDIR/sbctl-files.json"
                    printf '{}\n' > "$TMPDIR/sbctl-bundles.json"
                    
                    mkdir -p $out

                    ${pkgs.sbctl}/bin/sbctl \
                      --config "$TMPDIR/sbctl.conf" \
                      --disable-landlock \
                      sign \
                      --output "$out/bootx64.efi" \
                      "${source}"
                  '';
              signedUki = signEfi "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
              trustedHashKmod =
                config.boot.kernelPackages.kernel.stdenv.mkDerivation {
                  pname = "trusted_hash_kmod";
                  version = "0-unstable-2026-05-04";

                  src = trusted_hash_kmod;

                  moduleSigningCertHash = builtins.hashFile "sha256" "${moduleSigningKeys}/module-signing.pem";
                  moduleSigningKeyHash = builtins.hashFile "sha256" "${moduleSigningKeys}/module-signing.key";

                  nativeBuildInputs = config.boot.kernelPackages.kernel.moduleBuildDependencies;
                  makeFlags = config.boot.kernelPackages.kernelModuleMakeFlags ++ [
                    "KDIR=${config.boot.kernelPackages.kernel.dev}/lib/modules/${config.boot.kernelPackages.kernel.modDirVersion}/build"
                  ];
                  installFlags = [ "INSTALL_MOD_PATH=${placeholder "out"}" ];
                  installTargets = [ "modules_install" ];
                  postFixup = ''
                    find "$out/lib/modules/${config.boot.kernelPackages.kernel.modDirVersion}" \
                      -name '*.ko.xz' \
                      -exec ${pkgs.xz}/bin/unxz {} \;
                    find "$out/lib/modules/${config.boot.kernelPackages.kernel.modDirVersion}" \
                      -name '*.ko' \
                      -exec \
                        ${config.boot.kernelPackages.kernel.dev}/lib/modules/${config.boot.kernelPackages.kernel.modDirVersion}/build/scripts/sign-file \
                          sha512 \
                          ${moduleSigningKeys}/module-signing.key \
                          ${moduleSigningKeys}/module-signing.pem \
                          {} \;
                    find "$out/lib/modules/${config.boot.kernelPackages.kernel.modDirVersion}" \
                      -name '*.ko' \
                      -exec ${pkgs.xz}/bin/xz -f {} \;
                  '';
                };
            in {
              imports = [
                "${modulesPath}/image/repart.nix"
              ];

              boot = {
                loader = {
                  grub.enable = false;
                  systemd-boot.enable = false;
                  efi.canTouchEfiVariables = false;
                };
                initrd = {
                  systemd.enable = true;
                  includeDefaultModules = false;
                  availableKernelModules = [
                    "virtio_pci"
                    "virtio_blk"
                    "ext4"
                    "vfat"
                  ];
                  kernelModules = [ "trusted_hash" ];
                  systemd.suppressedUnits = [
                    "sys-kernel-debug.mount"
                    "sys-kernel-tracing.mount"
                  ];
                };
                extraModulePackages = [ trustedHashKmod ];
                kernelPackages = challengeKernelPackages;
                kernelModules = lib.mkForce [];
                kernelParams = [
                  "console=ttyS0"
                  "debugfs=off"
                  "lockdown=confidentiality"
                ];
                kernel.sysctl = {
                  "dev.tty.ldisc_autoload" = 0;
                  "fs.protected_fifos" = 2;
                  "fs.protected_hardlinks" = 1;
                  "fs.protected_regular" = 2;
                  "fs.protected_symlinks" = 1;
                  "fs.suid_dumpable" = 0;
                  "kernel.core_pattern" = "|/bin/false";
                  "kernel.dmesg_restrict" = 1;
                  "kernel.kexec_load_disabled" = 1;
                  "kernel.kptr_restrict" = 2;
                  "kernel.perf_event_paranoid" = 3;
                  "kernel.unprivileged_bpf_disabled" = 1;
                  "kernel.yama.ptrace_scope" = 3;
                };
                kernelPatches = [
                  {
                    name = "enable-lockdown-lsm";
                    patch = null;
                    structuredExtraConfig = with lib.kernel; {
                      # Keep the challenge's QEMU boot/TPM path built in so
                      # per-VM Secure Boot keys only sign the UKI.
                      VIRTIO_BLK = yes;
                      VIRTIO_NET = yes;
                      VIRTIO_PCI = yes;
                      VIRTIO_PCI_LIB = yes;
                      VIRTIO_PCI_LIB_LEGACY = yes;
                      EXT4_FS = yes;
                      JBD2 = yes;
                      CRC16 = yes;
                      FAT_FS = yes;
                      MSDOS_FS = yes;
                      VFAT_FS = yes;
                      NLS = yes;
                      NLS_CODEPAGE_437 = lib.mkForce yes;
                      NLS_ISO8859_1 = lib.mkForce yes;
                      NLS_UTF8 = lib.mkForce yes;
                      FAT_DEFAULT_CODEPAGE = freeform "437";
                      FAT_DEFAULT_IOCHARSET = freeform "iso8859-1";
                      TCG_TPM = yes;
                      TCG_CRB = yes;
                      TCG_TIS_CORE = yes;
                      TCG_TIS = yes;

                      # NixOS firewall uses iptables 1.8 with the nft backend.
                      # Keep the small compat surface built in because autoload
                      # is a poor fit once lockdown and module signing are on.
                      NF_TABLES = yes;
                      NF_TABLES_INET = yes;
                      NFT_COMPAT = yes;
                      NFT_CT = yes;
                      NFT_LOG = yes;
                      NFT_NAT = yes;
                      NF_NAT = yes;
                      NF_CONNTRACK = yes;
                      NF_CONNTRACK_MARK = yes;
                      NETFILTER_XT_MATCH_CONNTRACK = yes;
                      NETFILTER_XT_MATCH_PKTTYPE = yes;
                      NETFILTER_XT_TARGET_LOG = yes;
                      IP_NF_IPTABLES = yes;
                      IP_NF_MATCH_RPFILTER = yes;
                      IP6_NF_IPTABLES = yes;
                      IP6_NF_MATCH_RPFILTER = yes;

                      MODULE_SIG = lib.mkForce yes;
                      MODULE_SIG_ALL = no;
                      MODULE_SIG_FORCE = no;
                      MODULE_SIG_KEY = freeform "certs/signing_key.pem";
                      SECONDARY_TRUSTED_KEYRING = yes;
                      SYSTEM_TRUSTED_KEYS = freeform "${moduleSigningKeys}/module-signing.pem";
                      INTEGRITY_PLATFORM_KEYRING = yes;
                      INTEGRITY_ASYMMETRIC_KEYS = yes;
                      INTEGRITY_SIGNATURE = yes;
                      INTEGRITY_MACHINE_KEYRING = yes;
                      LOAD_UEFI_KEYS = yes;
                      SYSTEM_BLACKLIST_KEYRING = yes;
                      SECURITY_LOCKDOWN_LSM = lib.mkForce yes;
                      SECURITY_LOCKDOWN_LSM_EARLY = yes;
                    };
                  }
                ];
              };

              environment.systemPackages = [
                trusted_hash_workspace.packages.${system}.trusted_hash_agent
              ];

              security.lsm = lib.mkForce [
                "landlock"
                "lockdown"
                "yama"
                "bpf"
              ];

              systemd.coredump.enable = false;
              systemd.suppressedSystemUnits = [
                "sys-kernel-debug.mount"
                "sys-kernel-tracing.mount"
              ];

              systemd.services.trusted-hash-agent = {
                description = "Trusted Hash userspace proxy";
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" "dev-trusted_hash.device" ];
                serviceConfig = {
                  ExecStart = "${trusted_hash_workspace.packages.${system}.trusted_hash_agent}/bin/trusted-hash-agent 0.0.0.0:31337";
                  AmbientCapabilities = [
                    "CAP_CHOWN"
                    "CAP_DAC_OVERRIDE"
                    "CAP_FOWNER"
                  ];
                  CapabilityBoundingSet = [
                    "CAP_CHOWN"
                    "CAP_DAC_OVERRIDE"
                    "CAP_FOWNER"
                  ];
                  LimitCORE = 0;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  NoNewPrivileges = true;
                  ProtectClock = true;
                  ProtectControlGroups = true;
                  PrivateTmp = true;
                  ProtectHome = true;
                  ProtectKernelLogs = true;
                  ProtectKernelModules = true;
                  ProtectKernelTunables = true;
                  ProtectSystem = "strict";
                  ReadWritePaths = [
                    "/etc"
                    "/var/lib/trusted-hash-agent"
                  ];
                  RemoveIPC = true;
                  RestrictAddressFamilies = [
                    "AF_INET"
                    "AF_INET6"
                    "AF_UNIX"
                  ];
                  RestrictNamespaces = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  Restart = "on-failure";
                  RestartSec = "1s";
                  StateDirectory = "trusted-hash-agent";
                  SystemCallArchitectures = "native";
                  UMask = "0077";
                };
              };

              fileSystems."/" = {
                device = "/dev/disk/by-label/nixos";
                fsType = "ext4";
              };

              image.repart = {
                name = config.boot.uki.name;
                mkfsOptions = {
                  ext4 = [
                    "-i" "4096"
                  ];
                };
                partitions = {
                  esp = {
                    contents = {
                      "/EFI/BOOT/BOOTX64.EFI".source = "${signedUki}/bootx64.efi";
                    };

                    repartConfig = {
                      Type = "esp";
                      Format = "vfat";
                      SizeMinBytes = "128M";
                    };
                  };

                  root = {
                    storePaths = [ config.system.build.toplevel ];
                    repartConfig = {
                      Type = "root";
                      Format = "ext4";
                      Label = "nixos";
                      Minimize = "guess";
                    };
                  };
                };
              };
            })
        ];
      };
      nixos = mkNixos;
    in {
      nixosConfigurations.vm = nixos;

      packages.${system} = {
        qcow2 = pkgs.runCommand "disk.qcow2"
          { nativeBuildInputs = [ pkgs.qemu ]; }
          ''
            mkdir -p $out
            qemu-img convert -f raw -O qcow2 \
              ${nixos.config.system.build.image}/${nixos.config.boot.uki.name}.raw \
              $out/disk.qcow2
          '';

        secureBootPublic = pkgs.runCommand "secure-boot-public" {} ''
          mkdir -p $out/PK $out/KEK $out/db
          cp ${secureBootKeys}/GUID $out/GUID
          cp ${secureBootKeys}/PK/PK.pem $out/PK/PK.pem
          cp ${secureBootKeys}/KEK/KEK.pem $out/KEK/KEK.pem
          cp ${secureBootKeys}/db/db.pem $out/db/db.pem
        '';

        release = pkgs.runCommand "trusted-hash-release" {} ''
          mkdir -p $out/os $out/secure-boot-public
          cp ${self.packages.${system}.qcow2}/disk.qcow2 $out/os/disk.qcow2
          cp -a ${self.packages.${system}.secureBootPublic}/. $out/secure-boot-public/
          printf '%s\n' \
            trusted_hash_release_version=1 \
            qcow2=os/disk.qcow2 \
            secure_boot_public=secure-boot-public \
            > $out/manifest.env
        '';
      };
    };
}
