# trustedhash

trustedhash is a challenge from
[R3CTF 2026](https://ctftime.org/event/3149). It explores whether TPM 2.0,
Secure Boot, measured boot, and Linux Lockdown can be combined
to approximate a Trusted Execution Environment (TEE) on a machine controlled
by the player. The challenge asks players to recover a dynamically supplied
flag from an attested hashing workflow without breaking the underlying
cryptographic primitives.

For the challenge design, intended solution, unintended solutions, and
postmortem, see the [writeup](./writeup.md).

## Repository Structure

- [`challenge/`](./challenge/) contains the player-facing attachment distributed
  during the competition, including the source code and local build and runtime
  tooling.
- [`operator/`](./operator/) contains the operator-side deployment materials,
  including the player portal, container configuration, and deployment notes.
- [`writeup.md`](./writeup.md) contains the full challenge writeup and
  postmortem.
- `flake.nix` and `flake.lock` define the top-level Nix workspace used to build
  and develop the challenge and operator components.
