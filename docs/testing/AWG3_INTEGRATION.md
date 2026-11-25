# AWG3 integration stand

The stand checks that the WireGuard body emitted by LxBox is accepted by a real
AmneziaWG Go 3.1 server, completes a UDP handshake and carries HTTP traffic. It
uses synthetic credentials generated on the local machine; no user account or
real VPN credential is needed.

## Requirements

- Linux AMD64 with a working `/dev/net/tun` (`sudo modprobe tun` if necessary).
- Bash, Docker Engine and Docker Compose v2.
- `curl`, `tar`, `awk`, `tr`, `mktemp`, and either `sha256sum` or `shasum`.
- The Flutter version pinned in `app/android/flutter.version`.

Docker must be usable by the current user. Do not weaken host firewall or Docker
permissions just to run this test.

## Run

From the repository root:

```bash
bash ops/awg3/setup.sh
cd app
LX_AWG3_DOCKER=1 flutter test --no-pub --tags integration \
  test/integration/awg3_docker_test.dart
```

`setup.sh` pins both container images by digest, generates server/client keys,
a pre-shared key and an AWG3 header-protection key, and downloads the Linux AMD64
`sing-box-lx` release pinned by `app/android/libbox.version`. The core archive is
accepted only after its release `SHA256SUMS` entry matches.

Generated files live only in `app/build/awg3-stand/`:

- `client.conf` and `server.conf`: private runtime configuration.
- `sing-box`: verified pinned client core.
- `client.sing-box.json`: configuration built by the test from the emitted node.
- `stand.log`: line-buffered log with generated keys redacted.

The directory is ignored by git. Never commit or upload its configuration, keys
or binary. Review even the sanitized log before sharing it.

The test owns the Compose project `lxbox-awg3-stand`. It tears down containers on
success and failure. To stop the stand manually, run from the repository root:

```bash
docker compose -f ops/awg3/docker-compose.yml down -v --remove-orphans
```

After teardown, remove `app/build/awg3-stand/` if the generated credentials are
no longer needed.

## Default test behavior

The fixture-preservation test needs neither Docker nor network access. The live
test skips unless `LX_AWG3_DOCKER` is exactly `1`; once enabled, missing setup
files or a failed handshake is a test failure, not a skip. The file also carries
the `integration` tag so ordinary test runs stay independent of the stand.

```bash
cd app
flutter test --no-pub test/integration/awg3_docker_test.dart
```

## Covered properties

1. The normal INI parser and `WireguardSpec.emitRaw` preserve MTU, address,
   endpoint, allowed IPs and ranged persistent keepalive.
2. AWG2 junk packets and custom signatures survive, including `Jc/Jmin/Jmax`,
   `S1-S4`, disjoint ranged `H1-H4` and `I1-I5`.
3. AWG3 header protection, content padding, rekey/reject/keepalive timings,
   maximum handshake attempts, random trailers and disabled cookies survive.
4. The pinned `sing-box-lx` core accepts the complete emitted endpoint.
5. The AmneziaWG server reports a nonzero handshake for the generated client.
6. An HTTP request through the local SOCKS/mixed inbound and the AWG tunnel
   returns exactly `awg3-ok`.
7. Compose publishes no host port for the echo service. It shares only the AWG
   container network namespace and listens on the tunnel address.

A green run proves this pinned application/core/server combination. AWG3
server-matched parameters vary between providers, so it does not prove
compatibility with every third-party AWG configuration.

## CI

`.github/workflows/awg3-integration.yml` runs manually and nightly on Ubuntu
AMD64. It uploads only `stand.log` as the `awg3-stand-log` artifact, including on
failure. The generated runtime directory is never uploaded.
