# syntax=docker/dockerfile:1.3-labs
# Build context: challenge directory.
#
# Maintainer build for the player-facing development image:
#
#   docker build -f docker/nix-builder.Dockerfile \
#     -t <image>:<tag> .
#
# The image preloads the Nix dev shells, creates local reproduction signing
# keys, and performs one release build so the Nix store contains the expensive
# kernel/NixOS build products before the image is pushed.
FROM nixos/nix:2.28.3

RUN mkdir -p /etc/nix \
  && printf '%s\n' \
    'experimental-features = nix-command flakes' \
    'accept-flake-config = true' \
    > /etc/nix/nix.conf

WORKDIR /tmp/trusted-hash/challenge
COPY . .

RUN nix develop .#default --command true \
  && nix develop .#kernel --command true

ENV TRUSTED_HASH_SECURE_BOOT_DIR=/opt/trusted-hash-dev-keys/secure-boot-signing
ENV TRUSTED_HASH_MODULE_SIGNING_DIR=/opt/trusted-hash-dev-keys/module-signing
ENV XDG_CACHE_HOME=/tmp/nix-cache

RUN --security=insecure nix develop .#default --command bash -euo pipefail -c '\
    ./scripts/secure-boot-signing-init; \
    ./scripts/module-signing-init; \
    ./scripts/build-release /tmp/trusted-hash-prebuilt-release; \
  ' \
  && rm -rf /tmp/trusted-hash-prebuilt-release \
  && chmod -R u+rwX,go-rwx /opt/trusted-hash-dev-keys

WORKDIR /work

CMD ["nix", "develop", ".#default", "--command", "bash"]
