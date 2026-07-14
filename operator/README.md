# Operator Deployment Materials

This directory contains operator-side deployment services and runtime helpers.
Author-only notes, private regression tools, and source-review audits live under
`../author/`.

Player releases may exclude this directory as a whole.

Contents:

- `Cargo.toml`: Rust workspace for operator-side deployment services.
- `trusted_hash_portal/`: the per-player service
  that owns the web UI, QEMU lifecycle, noVNC proxy, and attester loop.
- `docker/`: Dockerfiles and compose examples.
- `docs/deployment-services.md`: build and runtime notes for the portal
  deployment.

## Build the OS Image in Docker

Use a privileged Nix container for the release build. This avoids maintaining a
separate host-side insecure Nix builder just to produce the qcow2 release
artifact.

Run from the repository root:

```sh
./challenge/scripts/build-release-docker challenge/release/current
```

The release output is written back to the mounted checkout at
`challenge/release/current/`. The shared Secure Boot and module signing private
keys are created under `challenge/.secrets/`; keep that directory operator-only.

The wrapper runs `nixos/nix:2.28.3` with `docker run --privileged`, mounts the
repository at `/work`, writes a container-local `nix.conf` with flakes enabled
and `sandbox = false`, enters `challenge`'s default dev shell, then calls
`challenge/scripts/build-release` inside the container. The dev shell provides
the Secure Boot and firmware tools used by release initialization.

The named Docker volume `trusted-hash-nix` keeps `/nix` between builds so repeat
builds can reuse the expensive kernel/NixOS outputs. Override it with
`NIX_DOCKER_VOLUME=...` if needed. Override the base image with
`NIX_DOCKER_IMAGE=...`.

After the release exists, build the portal image from the repository root:

```sh
docker build -f operator/docker/player-portal.Dockerfile \
  --build-arg RELEASE_DIR=challenge/release/current \
  -t trusted-hash-portal:local .
```
