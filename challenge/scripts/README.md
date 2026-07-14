# Challenge Scripts

These scripts are player-facing helpers for reproducing the challenge flow.

- `build-release <release-dir>` builds a reusable `os/disk.qcow2` and exports
  Secure Boot public material.
- `create-vm <release-dir> <vm-dir>` creates per-VM TPM state, NVRAM, and a
  writable qcow2 overlay.
- `start-vm <vm-dir>` starts a prepared VM with QEMU and swtpm.

Generated signing material defaults to `challenge/.secrets/`, and generated
release artifacts commonly live under `challenge/release/`. Both are ignored by
git.
