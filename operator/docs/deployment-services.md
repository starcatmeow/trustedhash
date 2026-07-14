# Deployment Services

The deployment shape is one `trusted_hash_portal` instance per player
environment. The portal serves the player UI, starts QEMU directly with KVM
access, proxies noVNC's websocket, and runs the checker/attester loop against
`127.0.0.1`.

## Build the OS image

Build a no-secret release artifact first:

```sh
./challenge/scripts/build-release challenge/release/current
```

The release contains the player disk image and public Secure Boot material. It
must not contain operator private keys.

## Build the portal image

```sh
docker build -f operator/docker/player-portal.Dockerfile \
  --build-arg RELEASE_DIR=challenge/release/current \
  -t trusted-hash-portal:local .
```

## Run the portal

Local compose run:

```sh
FLAG=flag{local-test} \
  docker compose -f operator/docker/player-portal.compose.yml up --build
```

Equivalent direct container shape:

```sh
docker run --rm --privileged --network host \
  -e FLAG=flag{local-test} \
  -v trusted-hash-state:/var/lib/trusted-hash \
  trusted-hash-portal:local
```

The container needs KVM access. The compose file uses `privileged: true` and
host networking for the local operator run; production can replace that with
the platform's pod security and service exposure model.

## Runtime environment

Required:

- `FLAG`: dynamic per-team flag. The portal passes this to the internal
  attester as `CTF_FLAG`.

Optional:

- `TH_PORTAL_ADDR`: portal HTTP listen address, default `0.0.0.0:8080`.
- `TH_RELEASE_DIR`: release directory inside the image, default
  `/opt/trusted-hash-release`.
- `TH_TEST_INTERVAL_SECONDS`: attester interval, default `30`.

Persistent state is fixed under `/var/lib/trusted-hash`: VM disk/TPM/NVRAM live
in `/var/lib/trusted-hash/vm`, and portal metadata/PCR captures live in
`/var/lib/trusted-hash/portal`. Each deployed portal is expected to run in its
own player pod and owns exactly one VM.

VM exposure is fixed: SSH `2222`, trusted-hash agent `31337`, raw VNC `5900`,
QEMU VNC websocket `127.0.0.1:5700`, and VNC display `0`.

## VM flow

1. The portal starts without a VM.
2. The player clicks Create VM.
3. The portal creates the VM directory and starts QEMU with
   `TRUSTED_HASH_VM_MODE=provision`, where all exposed services bind to
   `127.0.0.1`.
4. It captures PCR/module baselines and provisions a one-time root password
   through the guest agent.
5. Only after that setup completes, it restarts QEMU with
   `TRUSTED_HASH_VM_MODE=public`, where SSH, agent, and raw VNC bind to
   `0.0.0.0`; the websocket remains loopback-only for portal noVNC proxying.
6. Root and VNC passwords are returned only in that create response. `/api/state`
   does not expose them.
7. Restart requires the root password as confirmation.

The CTF platform is responsible for exposing SSH/VNC/agent addresses to the
player. The portal UI only tells the player to use those platform addresses and
the passwords returned at VM creation time.
