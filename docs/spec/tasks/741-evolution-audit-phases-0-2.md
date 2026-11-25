# 741 — Evolution audit: repository hygiene, honest seeds and budget fixes

| Field | Value |
|-------|-------|
| Status | Completed |
| Start date | 2026-11-25 |
| End date | 2026-11-25 |
| Commits | `963a7443`, `589fb4f1`, `bdc60d91`, `dde98cf8`, `020f325c`, `fa1a9e05` |
| Related specs | [`740-warp-awg-profiles.md`](740-warp-awg-profiles.md), external audit `GLM_20261125_022835.md` |

## Problem

The evolution audit found applied bootstrap payloads still tracked in the
repository, useful scanner fixes lost in a later scanner rewrite, private
WireGuard/AmneziaWG nodes incorrectly evaluated with WARP credentials, ranged
AWG3 keepalive values lost during seeding, and several engine defects that can
corrupt a probe body or exceed the request budget.

## Diagnosis

- `.github/patches/evolution-849-patch.b64.001`…`006` have no references in any
  workflow; their functional changes are already in `main`.
- Scanner commit `fdde0115` added IPv6-safe endpoint parsing and an expanded
  Cloudflare colo map. A later scanner rewrite removed those hunks. Remote tip
  `d577974b` duplicates them but also adds a 103 MB APK and unrelated UI reorder
  changes. The evolution port/transport guard from that commit already exists
  in `main`.
- `seedsFromNodes` accepts every `wireguard` body, while
  `ProbeGenomeEvaluator` rebuilds every candidate with WARP/MASQUE accounts.
- `Genome.keepalive` is an `int`, so AWG3 `"N-M"` values become zero and are
  removed by `applyTo`.
- `Genome.applyTo` writes empty masquerade fields, does not guard an explicit
  `i1`, and the engine checks its request budget only between rungs.
- Filtering invalid persisted rung attempts can produce an empty list and
  therefore empty generations.

## Solution

### Phase 0

1. Remove the six applied bootstrap patches.
2. Restore only the scanner colo/country data and IPv6-safe endpoint parsing,
   with focused tests. Do not import the APK or unrelated UI reorder changes.

### Phase 1

1. Add `SeedSkipReason.privateServer` and filter WireGuard seeds against the
   loaded WARP endpoint pool. A missing pool remains fail-open for compatibility,
   but the screen reports that the filter was unavailable.
2. Preserve `int | "N-M"` keepalive values through genome identity, mutation,
   JSON round-trip and body patching. Invalid values normalize to zero.

### Phase 2

1. Inherit non-empty base masquerade values when genome values are empty.
2. Do not write masquerade genes over an explicit base `i1`.
3. Account observations incrementally during a rung and stop the evaluator as
   soon as the request budget is exhausted, preserving result positions and
   marking unprobed candidates honestly.
4. Fall back to `[1, 2, 3]` when persisted rung attempts contain no positive
   values.
5. Deduplicate EDA input, document the engine's one-shot contract and convert an
   evaluator exception into a technical failure instead of losing the campaign.

## Files

- `.github/patches/evolution-849-patch.b64.*`
- `app/lib/services/warp/scan/endpoint_scanner.dart`
- `app/lib/services/warp/scan/scan_pool.dart`
- `app/lib/services/evolution/{seeds,genome,settings,engine,probe_evaluator,objectives}.dart`
- `app/lib/screens/evolution_screen.dart`
- `app/assets/l10n/{en,ru,zh}/ui.json`
- `app/test/warp/scan/endpoint_scanner_test.dart`
- `app/test/warp/scan/scan_pool_test.dart`
- `app/test/warp/evolution/{seeds,genome,settings,engine,objectives}_test.dart`
- `CHANGELOG.md`

## Risks and edge cases

- A custom WARP endpoint outside the bundled CIDRs is classified as private.
  This is intentional until Phase 4 introduces verbatim private-server genomes.
- If the endpoint asset cannot be loaded, WireGuard seeding remains fail-open;
  the UI must disclose that the WARP filter is unavailable.
- Ranged keepalive is valid only for WireGuard/AmneziaWG. MASQUE continues to
  accept numeric seconds only.
- Budget stopping can leave candidates with fewer observations; they must keep
  their original indexes and receive a `budget exhausted` failure observation.
- No `app/contract/**`, `app/contract.lock`, `analysis_options.yaml` or
  `pubspec.lock` changes are part of this task.

## Verification

- [x] Phase 0 scanner restoration: 14 focused tests passed.
- [x] Phase 1.1 seed filtering: 41 focused tests passed; strict l10n, template,
  hardcoded-string and Kotlin checks reported 0 failures and 0 warnings.
- [x] Phases 1.2 and 2: `flutter test --no-pub test/warp/evolution` passed
  151/151 tests, including mid-rung budget stopping, candidate positions,
  partial evaluator failure, empty rung settings, masquerade inheritance and
  explicit `i1`.
- [x] Full `flutter analyze --no-pub`: 0 issues.
- [x] No contract, lock-file or unrelated formatting changes are included.
- [x] The branch remains local for review; no CI push or merge was performed.

## Unresolved / follow-up

- Phase 3: AWG 2.0/3.x fields, header-protection key generation and experimental
  `chrome-full`.
- Phase 4: verbatim genomes for private WG/AWG servers.
- Phase 5: live AWG3 Docker/integration stand.
- Phase 6: re-validation, persistent Hall of Fame, ETA, parallel probes,
  adaptive rungs and JSON reports.
