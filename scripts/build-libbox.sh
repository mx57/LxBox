#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
CORE_REPO="https://github.com/Leadaxe/sing-box-lx.git"
CORE_COMMIT="f1bac271853eaf13398ce1030c948aebc3aed2e1"
CORE_VERSION="v1.14.4-lx.35"
PATCH="$REPO_ROOT/ops/core/parallel-probes.patch"
DEST="$REPO_ROOT/app/android/app/libs"
PLATFORM="${LIBBOX_PLATFORM:-android}"

if [ "$(tr -d '[:space:]' < app/android/libbox.version)" != "$CORE_VERSION" ]; then
  echo "libbox.version must stay at $CORE_VERSION for the parallel-probe patch" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  PATCH_HASH="$(sha256sum "$PATCH" | cut -d' ' -f1)"
else
  PATCH_HASH="$(shasum -a 256 "$PATCH" | cut -d' ' -f1)"
fi
MARKER="$CORE_COMMIT:$PATCH_HASH:$PLATFORM"
if [ "${LIBBOX_FORCE:-0}" != "1" ] && [ -f "$DEST/libbox.aar" ] && \
   [ "$(cat "$DEST/.libbox.version" 2>/dev/null || true)" = "$MARKER" ]; then
  echo "libbox.aar already matches the parallel-probe build"
  exit 0
fi

SOURCE_DIR="$(mktemp -d)"
trap 'rm -rf "$SOURCE_DIR"' EXIT
git init -q "$SOURCE_DIR"
git -C "$SOURCE_DIR" remote add origin "$CORE_REPO"
git -C "$SOURCE_DIR" fetch -q --depth 1 origin "$CORE_COMMIT"
git -C "$SOURCE_DIR" checkout -q --detach FETCH_HEAD
git -C "$SOURCE_DIR" submodule update -q --init --depth 1 --jobs 2
git -C "$SOURCE_DIR" apply --check "$PATCH"
git -C "$SOURCE_DIR" apply "$PATCH"

if [ -z "${ANDROID_HOME:-}" ]; then
  if [ -d /c/android-sdk ]; then
    export ANDROID_HOME="C:/android-sdk"
  elif [ -d "$HOME/Android/Sdk" ]; then
    export ANDROID_HOME="$HOME/Android/Sdk"
  else
    echo "ANDROID_HOME is required to build libbox" >&2
    exit 1
  fi
fi
export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export GOTOOLCHAIN=go1.26.10
GOBIN="$(go env GOPATH)/bin" go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.12
GOBIN="$(go env GOPATH)/bin" go install github.com/sagernet/gomobile/cmd/gobind@v0.1.12

(
  cd "$SOURCE_DIR"
  go test ./experimental/libbox
  go run ./cmd/internal/build_libbox -target android -platform "$PLATFORM"
)

mkdir -p "$DEST"
cp "$SOURCE_DIR/libbox.aar" "$DEST/libbox.aar"
printf '%s' "$MARKER" > "$DEST/.libbox.version"
echo "Built $DEST/libbox.aar from $CORE_COMMIT with parallel-probe patch $PATCH_HASH"
