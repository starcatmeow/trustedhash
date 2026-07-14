# Trusted Hash Challenge Source

This directory is the player-facing source bundle for the Trusted Hash
challenge.

## Challenge Background

The hosted challenge has two roles:

- The **player VM** is the Linux VM you control. You can log in over SSH,
  inspect it through VNC, and do whatever you want.
- The **checker**, also called the **attester**, is the remote service that
  periodically verifies your player VM and sends the current CTF flag through
  the attested flow.

## Development Environment

All build and runtime tools needed by players are provided by the Nix dev shell:
Rust, QEMU, swtpm, tpm2-tools, OpenSSL, sbctl, virt-firmware helpers, and the
kernel module build toolchain. You do not need to install Nix yourself if you
use the provided Docker image.

The official Docker image is:

```sh
dongruixuan/trustedhash-devenv:latest
```

It contains Nix with flakes enabled, the challenge dev shells, pre-generated
local reproduction Secure Boot and module-signing keys (for development only),
and a warmed Nix store from a full release build. That cache is included so
you do not spend your first local run recompiling Linux.

From this `challenge` directory:

```sh
docker pull dongruixuan/trustedhash-devenv:latest

docker run --rm -it --privileged \
  -v "$PWD:/work" \
  -w /work \
  -p 31337:31337 \
  -p 5900:5900 \
  -p 5700:5700 \
  -p 2222:2222 \
  dongruixuan/trustedhash-devenv:latest
```

The container starts in `nix develop .#default`. `--privileged` is used for the
local VM workflow because QEMU needs KVM access.

## Image Build Details

The player image is built from `docker/nix-builder.Dockerfile`:

```sh
docker buildx create --driver-opt image=moby/buildkit:master  \
                     --use --name insecure-builder \
                     --buildkitd-flags '--allow-insecure-entitlement security.insecure'
docker buildx use insecure-builder
docker buildx build --allow security.insecure -f docker/nix-builder.Dockerfile -t <image>:<tag> . --load
```

The Dockerfile intentionally performs one `./scripts/build-release` during
image creation. The release output is discarded, but the generated dev keys
and expensive Nix store paths remain in the image for players to reuse.
