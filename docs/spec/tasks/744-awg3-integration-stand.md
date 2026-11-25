# 744 — AmneziaWG 3.1 integration stand

| Field | Value |
|-------|-------|
| Status | In progress |
| Start date | 2026-11-25 |
| Related specs | [`742-awg-node-fields-ui.md`](742-awg-node-fields-ui.md), [`743-verbatim-private-genomes.md`](743-verbatim-private-genomes.md), external audit `GLM_20261125_022835.md` Phase 5 |

## Problem

Unit tests prove that AWG 2.0/3.x fields survive parsing, editing, genome
mutation and JSON emission. They do not prove that a real AmneziaWG 3.1 server
accepts the emitted body, completes a UDP handshake and carries HTTP traffic.
A server/client mismatch can therefore remain invisible until a user tries the
node.

## Solution

1. Add an opt-in Docker Compose stand with AmneziaWG Go 3.1, one full AWG3 peer
   and an HTTP echo service reachable only through the tunnel.
2. Generate stand credentials at setup time and keep generated keys, runtime
   configuration and logs out of git.
3. Add an integration-tagged Dart test that builds the peer with the app's
   normal WireGuard emitter, checks the full AWG3 parameter set, performs the
   handshake probe and requests the echo endpoint through the tunnel.
4. Keep the test disabled in ordinary runs. Require an explicit environment
   opt-in as well as the `integration` tag so a default `flutter test` never
   depends on Docker or a network stand.
5. Add a manual and nightly GitHub Actions workflow. Upload the stand log as an
   artifact on success and failure.
6. Document local setup, teardown, required tools and the exact connection
   properties covered by the stand.

## Invariants

- No real user credential, private key or account is committed or uploaded.
- The client body is produced by the same emitter used by the application.
- The fixture includes header protection, padding, ranged keepalive,
  `random_trailers`, server-matched junk fields and the other AWG3 timings.
- The echo service is not published directly to the host or another network.
- Default unit/widget test runs do not require Docker.
- A failed stand is reported as a failed live check, not silently skipped when
  the explicit opt-in is set.

## Verification

- [x] Compose configuration and workflow YAML pass static validation.
- [x] The full AWG3 fixture survives the normal emitter without field loss.
- [x] The integration test is tagged and skips without the explicit opt-in.
- [ ] With the stand running, handshake and HTTP echo assertions pass.
- [ ] Manual/nightly workflow uploads the stand log artifact.
- [x] Local setup and coverage documentation is present.
- [x] `flutter analyze --no-pub` is clean and the default suite adds no failures
      beyond the clean-`main` Windows baseline.

## Implementation

- Compose pins `amneziavpn/amneziawg-go` at
  `sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72`
  and `hashicorp/http-echo` at
  `sha256:fcb75f691c8b0414d670ae570240cbf95502cc18a9ba57e982ecac589760a186`.
- Setup reads the core version from `app/android/libbox.version`, downloads the
  matching Linux AMD64 release and verifies the exact `SHA256SUMS` row before
  installing it under `app/build/awg3-stand/`.
- The server copies its matched AWG parameters from the rendered client
  fixture, so the two sides cannot silently drift. Only the AWG UDP port is
  published, on loopback; echo shares the container network namespace, waits for
  the tunnel address to become healthy and has no published port. Startup strips
  `Address`/`MTU`/`DNS` before `awg setconf` and applies address and MTU with `ip`.
- The log redactor works on complete lines and has a regression test for a key
  split across process-output chunks.

Local static verification passed: Docker Compose `config` (including shell-dollar
escaping), YAML parsing and isolation assertions, `bash -n`, `git diff --check`,
the pinned core archive checksum/path, and `flutter analyze --no-pub`. The
integration file reports `+2 ~1`: emitter preservation and redaction pass; the
live test skips without opt-in. All strict l10n, Kotlin and documentation parity
checks report zero failures and warnings. The full suite reports
`+8060 ~38 -13`; all 13 failures reproduce on clean `main`, including the
Windows atomic-rename failure in `routing_dns_tab_sync_test.dart`.

## Risks and edge cases

- The current development environment has no usable Docker socket. Static
  checks can run here, but the live handshake/HTTP assertions require the
  GitHub runner or a user machine with Docker.
- AmneziaWG Go images and host kernel/UDP support vary; the workflow must pin
  the tested image and report container logs on failure.
- AWG3 parameters are server-matched. A green test proves the pinned pair, not
  every third-party server configuration.
