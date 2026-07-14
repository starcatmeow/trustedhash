# Build context: repository root.
#
#   ./challenge/scripts/build-release challenge/release/current
#   docker build -f operator/docker/player-portal.Dockerfile \
#     --build-arg RELEASE_DIR=challenge/release/current \
#     -t trusted-hash-portal:local .
FROM nixos/nix:2.28.3 AS runtime-builder

ARG RELEASE_DIR=challenge/release/current

WORKDIR /src
COPY . /src

RUN nix --extra-experimental-features "nix-command flakes" build \
    .#trusted_hash_portal_runtime_env \
    -o /tmp/trusted-hash-runtime-env

RUN mkdir -p \
    /runtime/nix/store \
    /runtime/bin \
    /runtime/etc \
    /runtime/root \
    /runtime/usr/bin \
    /runtime/usr/local/bin \
    /runtime/usr/share \
    /runtime/opt/trusted-hash/challenge \
    /runtime/tmp \
    /runtime/var/lib/trusted-hash \
    /runtime/var/tmp \
  && cp -a $(nix-store --query --requisites /tmp/trusted-hash-runtime-env) /runtime/nix/store/ \
  && cp -a /tmp/trusted-hash-runtime-env/bin/. /runtime/bin/ \
  && cp -a /tmp/trusted-hash-runtime-env/share /runtime/share \
  && ln -s /bin/env /runtime/usr/bin/env \
  && ln -s /bin/trusted-hash-portal /runtime/usr/local/bin/trusted-hash-portal \
  && ln -s /bin/trusted-hash-attester /runtime/usr/local/bin/trusted-hash-attester \
  && ln -s /share/webapps/novnc /runtime/usr/share/novnc \
  && cp -a challenge/scripts /runtime/opt/trusted-hash/challenge/scripts \
  && cp -a "${RELEASE_DIR}" /runtime/opt/trusted-hash-release \
  && printf 'root:x:0:0:root:/root:/bin/bash\n' > /runtime/etc/passwd \
  && printf 'root:x:0:\n' > /runtime/etc/group \
  && chmod 1777 /runtime/tmp /runtime/var/tmp

FROM scratch

COPY --from=runtime-builder /runtime /

ENV TH_PORTAL_ADDR=0.0.0.0:8080
ENV TH_RELEASE_DIR=/opt/trusted-hash-release
ENV TH_SCRIPTS_DIR=/opt/trusted-hash/challenge/scripts
ENV TH_ATTESTER_BIN=/usr/local/bin/trusted-hash-attester
ENV TH_NOVNC_ROOT=/share/webapps/novnc
ENV PATH=/usr/local/bin:/bin

VOLUME ["/var/lib/trusted-hash"]
EXPOSE 8080 2222 31337 5900 5700

ENTRYPOINT ["/usr/local/bin/trusted-hash-portal"]
