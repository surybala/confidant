#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Confidential Space container entrypoint for confidant-proxy.
#
# Confidential Space runs a single, non-interactive workload container with no TUN
# device, so Tailscale runs in userspace-networking mode. Inbound tailnet TCP is
# forwarded to the broker's loopback listener, preserving the broker's own mTLS
# end to end (Tailscale is the transport + network-identity gate; mTLS is the
# app-level device-identity gate — invariant I-B14). The broker itself binds only
# to 127.0.0.1, so it has no public listener (invariant I-B13).
#
# Required env (set as Confidential Space metadata / tee-env):
#   TS_AUTHKEY   ephemeral, pre-approved, tagged tailnet auth key
#   KMS_KEY      KEK resource name  (projects/.../cryptoKeys/K)
#   WIF_AUDIENCE //iam.googleapis.com/projects/NUM/.../providers/PROV
#   EGRESS_ALLOW comma-separated upstream allowlist
#   SECRET_STORE path to the mounted envelope store (ciphertext only)
# Optional: KMS_SERVICE_ACCOUNT, TS_HOSTNAME, TS_TAGS, AUDIT_SINK, TLS_CERT, ...
set -eu

PORT="${BROKER_PORT:-8443}"
TS_SOCK=/tmp/tailscaled.sock

echo "[entrypoint] starting tailscaled (userspace-networking)"
/usr/local/bin/tailscaled \
	--tun=userspace-networking \
	--socket="${TS_SOCK}" \
	--state=mem: &

echo "[entrypoint] joining tailnet as ${TS_HOSTNAME:-confidant-broker}"
/usr/local/bin/tailscale --socket="${TS_SOCK}" up \
	--authkey="${TS_AUTHKEY}" \
	--hostname="${TS_HOSTNAME:-confidant-broker}" \
	--advertise-tags="${TS_TAGS:-tag:confidant-broker}"

echo "[entrypoint] forwarding inbound tailnet tcp/${PORT} -> 127.0.0.1:${PORT}"
# NOTE: `tailscale serve` flag syntax varies by version; check `tailscale serve
# --help` for your pinned version. This forwards raw TCP so the broker's mTLS is
# terminated by the broker, not by Tailscale.
/usr/local/bin/tailscale --socket="${TS_SOCK}" serve --bg --tcp="${PORT}" "tcp://127.0.0.1:${PORT}"

echo "[entrypoint] starting confidant-proxy on 127.0.0.1:${PORT}"
export BROKER_LISTEN="127.0.0.1:${PORT}"
export CONFIDANT_MODE=enclave
exec /usr/local/bin/confidant-proxy serve
