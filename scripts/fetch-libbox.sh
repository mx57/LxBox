#!/usr/bin/env bash
# §104 — builds the pinned sing-box-lx AAR with the reviewed parallel-probe patch.
# Local builds and CI use the same core commit, patch and gomobile command.
# Override ABI target with LIBBOX_PLATFORM=android/arm64 (default: all ABIs).

set -euo pipefail
cd "$(dirname "$0")/.."
exec ./scripts/build-libbox.sh "$@"
