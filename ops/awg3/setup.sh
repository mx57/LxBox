#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME="$ROOT/app/build/awg3-stand"
FIXTURE="$ROOT/app/test/fixtures/wireguard/awg3_docker.conf"
AWG_IMAGE='amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72'

fail() {
  printf 'AWG3 setup: %s\n' "$*" >&2
  exit 1
}

for tool in docker curl tar awk tr mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail 'sha256sum or shasum is required'
fi
[[ "$(uname -s)" == Linux ]] || fail 'the live stand requires Linux'
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail 'the pinned client core requires Linux AMD64' ;;
esac
[[ -c /dev/net/tun ]] || fail '/dev/net/tun is missing; load the tun module or use a Docker-capable Linux host'
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'
[[ -f "$FIXTURE" ]] || fail "fixture not found: $FIXTURE"
[[ ! -L "$RUNTIME" ]] || fail 'runtime directory must not be a symlink'
mkdir -p "$RUNTIME"
chmod 700 "$RUNTIME"
umask 077

awg() {
  docker run --rm -i --platform linux/amd64 --network none \
    --entrypoint /usr/bin/awg "$AWG_IMAGE" "$@"
}

server_private=$(awg genkey)
server_public=$(printf '%s' "$server_private" | awg pubkey)
client_private=$(awg genkey)
client_public=$(printf '%s' "$client_private" | awg pubkey)
pre_shared=$(awg genpsk)
header_key=$(awg genkey)

client=$(<"$FIXTURE")
client=${client//__CLIENT_PRIVATE_KEY__/$client_private}
client=${client//__SERVER_PUBLIC_KEY__/$server_public}
client=${client//__PRE_SHARED_KEY__/$pre_shared}
client=${client//__HEADER_PROTECTION_KEY__/$header_key}
[[ "$client" != *'__CLIENT_PRIVATE_KEY__'* && "$client" != *'__SERVER_PUBLIC_KEY__'* &&
   "$client" != *'__PRE_SHARED_KEY__'* && "$client" != *'__HEADER_PROTECTION_KEY__'* ]] ||
  fail 'fixture contains an unresolved placeholder'

interface=$(printf '%s\n' "$client" | awk '
  /^\[Interface\]$/ { inside = 1; next }
  /^\[Peer\]$/ { inside = 0 }
  inside && $0 !~ /^(PrivateKey|Address)[[:space:]]*=/ { print }
')
server=$(printf '%s\n' "$interface"
  printf '[Peer]\nPublicKey = %s\nPreSharedKey = %s\nAllowedIPs = 10.8.3.2/32\n' \
    "$client_public" "$pre_shared")
server=$(printf 'PrivateKey = %s\nAddress = 10.8.3.1/24\nListenPort = 51820\n%s\n' \
  "$server_private" "$server")

client_tmp=$(mktemp "$RUNTIME/.client.conf.XXXXXX")
server_tmp=$(mktemp "$RUNTIME/.server.conf.XXXXXX")
core_tmp=$(mktemp "$RUNTIME/.sing-box.tar.gz.XXXXXX")
sums_tmp=$(mktemp "$RUNTIME/.SHA256SUMS.XXXXXX")
unpack_tmp=$(mktemp -d "$RUNTIME/.core.XXXXXX")
cleanup() {
  rm -f -- "$client_tmp" "$server_tmp" "$core_tmp" "$sums_tmp"
  rm -rf -- "$unpack_tmp"
}
trap cleanup EXIT
printf '%s\n' "$client" > "$client_tmp"
printf '%s\n' "$server" > "$server_tmp"
# Container root has no DAC override after cap_drop; the 0700 runtime directory
# remains the host-side privacy boundary for this ephemeral server config.
chmod 0644 "$server_tmp"
mv -f -- "$client_tmp" "$RUNTIME/client.conf"
mv -f -- "$server_tmp" "$RUNTIME/server.conf"

core_version=$(tr -d '[:space:]' < "$ROOT/app/android/libbox.version")
core_name=${core_version#v}
asset="sing-box-$core_name-linux-amd64.tar.gz"
base="https://github.com/Leadaxe/sing-box-lx/releases/download/$core_version"
curl -fsSL --retry 3 "$base/$asset" -o "$core_tmp"
curl -fsSL --retry 3 "$base/SHA256SUMS" -o "$sums_tmp"
expected=$(awk -v asset="$asset" '$2 == asset { print $1; exit }' "$sums_tmp")
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || fail "checksum missing for $asset"
actual=$(sha256 "$core_tmp")
[[ "${actual,,}" == "${expected,,}" ]] || fail "checksum mismatch for $asset"
tar -xzf "$core_tmp" -C "$unpack_tmp" --strip-components=1 "sing-box-$core_name-linux-amd64/sing-box"
chmod 700 "$unpack_tmp/sing-box"
mv -f -- "$unpack_tmp/sing-box" "$RUNTIME/sing-box"

docker compose -f "$ROOT/ops/awg3/docker-compose.yml" config --quiet
printf 'AWG3 stand prepared: %s (keys and runtime files stay in app/build/awg3-stand)\n' "$core_version"
