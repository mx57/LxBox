# 740 — WARP AWG profiles in generator and evolution

| Field | Value |
|-------|-------|
| Status | In progress |
| Start date | 2026-11-24 |
| Related | [§133](133-warp-junk-generators-research.md), [§421](421-awg3-header-protection-timings.md), [§848 evolution notes](../TASKS_LXBOX.md) |

## Problem

The WARP generator and evolution engine only describe the safe AmneziaWG 1.5 decoy
shape: `S1=S2=0`, `H1..H4=1..4`, `ip/id/ib`, and `Jc/Jmin/Jmax`. The data model and
core already understand AWG 2.0 and AWG 3.x fields, but the generator has no profile
object and evolution has no profile locus. A version switch would therefore either be
cosmetic or would create nodes whose wire format cannot work with Cloudflare WARP.

Cloudflare WARP is plain WireGuard. Full AWG 2.0/3.0/3.1 server modes, header
protection, non-standard split/magic headers, and protocol synchronization require a
matching AWG server. They must not be offered as WARP profiles.

## Scope

This task implements the first complete profile-aware stage:

- `warp15`: current safe behavior, the default for old callers and saved genomes;
- `warpCps`: experimental client-side CPS decoys `I2..I5`, while preserving the
  standard WireGuard handshake invariants;
- profile identity through generator, evolution, persistence, UI, and export;
- capability-gated mutation so unsupported fields cannot leak into WARP nodes.

Full AWG server profiles are a follow-up: they need an imported server profile with
its own keys and immutable fields, not the WARP registration account.

## Invariants

- WARP profiles always emit `S1=S2=0` and `H1..H4=1,2,3,4`.
- WARP profiles never emit `header_protection_key`, ranged `H1..H4`, AWG3 padding,
  trailers, cookies, or other server-matched wire-format fields.
- Explicit `I1` remains mutually exclusive with `id/ip/ib`.
- Profile is part of `Genome.key`, tokens, JSON, distance, seed deduplication, and
  displayed genes.
- Missing/unknown profile in old JSON maps to `warp15`.
- Profile changes clear genes the new profile cannot use.
- Export still uses the exact evaluated body, including profile-derived fields.

## Solution

Introduce a small `AwgProfile` enum/helper in the WARP service, extend `AwgParams`,
and pass one selected profile through `generateWarp`, `CandidateGenerator`,
`ScanNodeBuilder`, `Genome`, `EvolutionPools`, and `EvolutionSettings`. The CPS
profile adds deterministic core CPS expressions for `I2..I5`; the core randomizes
`<r>` at packet build time and `<t>` supplies a timestamp.

Add English source UI labels and Russian/Chinese translations for profile selection.
Keep all existing defaults and constructors source-compatible.

## Contract and localization repairs

- Restrict the shared WireGuard `I2` conflict to `ip=sip`; `ip=quic` and `ip=dns`
  remain valid. Update both registry mirrors, generated docs, and regression tests.
- Record the local contract patch honestly in `app/contract.lock`; the launcher
  source repository is unavailable here, so `source_sha` remains empty.
- Normalize Windows path separators before canonical contract sorting so the lock
  hash matches the Unix implementation.
- Repair the earlier fork merge's localization losses: remove 68 obsolete keys,
  restore 133 upstream keys, and translate 86 evolution keys in Russian and Chinese.
- Split MASQUE hosts from `host:port` scanner endpoints to avoid malformed
  double-port candidates while preserving WireGuard endpoints.

## Verification

Local results on 2026-11-24:

- `flutter analyze --no-pub`: 0 issues.
- Focused WARP/evolution/contract/l10n suite: 426 tests passed.
- `template_check --strict`: 0 failures, 0 warnings.
- `ui_check --strict`: ru/zh each 2317 keys, 0 missing, 0 orphan, 0 arity errors.
- `hardcoded_check --strict`: 0 findings in 611 files.
- `kotlin_check --strict`: 0 findings.
- Docs parity: 0 failures, 0 warnings.
- Contract lock and both mirrors: hash
  `48b83da534031fdcb7334549117638a4a503fd208ddc891ab1aafeac49b98211`.
- `git diff --check`: clean.

The full test suite and Android APK/AAB build run in GitHub Actions. No live-device
smoke or visual UI verification was performed; this remains required before making
`warpCps` a default.

## Risks and follow-up

CPS junk changes packet timing/size and can affect battery and first-handshake
latency. It is experimental and off by default. Full AWG2/AWG3 server evolution is
not implemented here because `ProbeGenomeEvaluator` currently rebuilds every node
from WARP credentials; using imported AWG server credentials is a separate task.
