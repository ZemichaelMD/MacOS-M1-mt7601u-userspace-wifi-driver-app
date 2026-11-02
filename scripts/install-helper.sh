#!/usr/bin/env bash
#
# Install (or remove) the privileged helper LaunchDaemon.
#
# The helper lets the GUI create and drive the `utun` interface without the
# whole app running as root. It is a small root LaunchDaemon that listens on a
# Unix socket (`/var/run/mt7601u-helper.sock`) and does only the privileged
# plumbing: `utun` creation, `ifconfig`, `route` and `scutil`.
#
# Usage:
#   sudo bash scripts/install-helper.sh              # install
#   sudo bash scripts/install-helper.sh --uninstall  # remove
#
# Environment overrides:
#   PROFILE=release|debug   build profile to install (default: release)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROFILE="${PROFILE:-release}"
CARGO_FLAGS=()
if [[ "$PROFILE" == "release" ]]; then
    CARGO_FLAGS=(--release)
fi

BIN="target/$PROFILE/mt7601u-macos"
if [[ ! -x "$BIN" ]]; then
    echo "==> Building ($PROFILE)…"
    cargo build "${CARGO_FLAGS[@]}"
fi

if [[ ! -x "$BIN" ]]; then
    echo "error: expected binary at $BIN" >&2
    exit 1
fi

exec "$BIN" "${1:---install-helper}"
