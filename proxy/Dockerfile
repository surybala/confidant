# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible image for confidant-proxy, targeting GCP Confidential Space.
# The image DIGEST is the attestation anchor (broker-core.md §5): Workload
# Identity Federation releases the KMS key only to a workload whose measured
# image_digest matches the pinned value, so keep this build deterministic and
# pin every version.

# ---- build the broker (static, CGO-off) ----
FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -ldflags="-s -w" -o /out/confidant-proxy .

# ---- fetch a pinned Tailscale (userspace daemon + CLI) ----
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS tailscale
ARG TS_VERSION=1.78.1
ARG TARGETARCH=amd64
ADD https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_${TARGETARCH}.tgz /tmp/ts.tgz
RUN tar -xzf /tmp/ts.tgz -C /tmp && \
    mkdir -p /ts && \
    cp /tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscaled /ts/tailscaled && \
    cp /tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscale  /ts/tailscale

# ---- final image ----
FROM debian:bookworm-slim
LABEL "tee.launch_policy.allow_env_override"="KMS_KEY,WIF_AUDIENCE,KMS_SERVICE_ACCOUNT,EGRESS_ALLOW,SECRET_STORE,TLS_CERT,TLS_KEY,CLIENT_CA,TS_AUTHKEY,TS_HOSTNAME,TS_TAGS" \
      "tee.launch_policy.log_redirect"="always"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/confidant-proxy /usr/local/bin/confidant-proxy
COPY --from=tailscale /ts/tailscaled /usr/local/bin/tailscaled
COPY --from=tailscale /ts/tailscale /usr/local/bin/tailscale
# The whole deploy/ dir is baked in. Drop an enrolled store.json into proxy/deploy/
# before building to ship it at /deploy/store.json (it holds only KMS ciphertext);
# then set tee-env-SECRET_STORE=/deploy/store.json. Or mount the store another way.
COPY deploy/ /deploy/
ENTRYPOINT ["/deploy/entrypoint.sh"]
