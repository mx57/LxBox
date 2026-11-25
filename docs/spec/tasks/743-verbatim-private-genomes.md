# 743 — Verbatim evolution genomes for private WireGuard and AmneziaWG nodes

| Field | Value |
|-------|-------|
| Status | Done |
| Start date | 2026-11-25 |
| End date | 2026-11-25 |
| Related specs | [`741-evolution-audit-phases-0-2.md`](741-evolution-audit-phases-0-2.md), [`742-awg-node-fields-ui.md`](742-awg-node-fields-ui.md), external audit `GLM_20261125_022835.md` Phase 4 |

## Problem

Phase 1 prevents private WireGuard/AmneziaWG nodes from entering the WARP seed
pool. That removes the unsafe credential substitution, but it also excludes
private servers from evolution entirely. A private server must be evaluated with
its own credentials and server-matched AmneziaWG parameters, not rebuilt through
the WARP/MASQUE account path.

## Diagnosis

The safe phase-1 seed filter removed the credential substitution but also
removed private servers from the candidate pool. The evaluator was coupled to
`ScanNodeBuilder`, while `NodeSpec.patchedJson` already provided a way to submit
an exact body through the existing probe batching and export path.

## Solution

1. Add a verbatim genome carrying the node tag, original sing-box body and only
   three mutable loci: `mtu`, `keepalive` (`int | "N-M"`) and `dnsTag`.
2. Apply a verbatim genome by copying `baseBody` and changing only those loci.
   Preserve every other body field and value, including private keys, peers,
   detours, masquerade and AWG3 parameters.
3. Teach `ProbeGenomeEvaluator` to submit verbatim candidates through the same
   probe batching and result path, using `patchedJson` directly rather than
   `ScanNodeBuilder`. Preparing this group must not request a WARP account.
4. Seed private WG/AWG nodes as verbatim genomes. Keep automatic group selectors
   and nodes that depend on another node's `detour` excluded, as before.
5. Count WARP genomes and private verbatim genomes separately in evolution UI
   and reports so skipped and evaluated populations remain honest.
6. Export the exact body that was evaluated through the existing `exportFor`
   path.
7. Keep WireGuard batch size at four and preserve request-budget enforcement.

## Invariants

- No private node is evaluated with WARP credentials.
- No masquerade or AWG field is mutated by a verbatim genome.
- A ranged AWG3 keepalive survives seeding, evaluation and export.
- A node with a foreign `detour` is not promoted into a direct private seed.
- Fitness and probe outcomes are never shared between WARP and verbatim modes.
- The evaluator never prepares a WARP account for an all-private population.

## Verification

- [x] Verbatim round-trip changes only `mtu`, keepalive and DNS; the remaining
      body stays structurally identical.
- [x] Integer and ranged keepalive values survive apply/export.
- [x] Private seeds evaluate without a WARP account and retain their own body.
- [x] WARP and verbatim fitness/results remain separated.
- [x] Foreign-detour nodes and automatic groups remain excluded.
- [x] WireGuard batches contain at most four nodes and respect the request
      budget.
- [x] UI/report counters distinguish WARP and private genomes.
- [x] Focused evolution tests and `flutter analyze --no-pub` pass.

Verification run on 2026-11-25:

- `flutter analyze --no-pub`: no issues.
- `flutter test --no-pub test/warp/evolution`: 163 tests passed.
- AWG parser/editor and probe regression tests: 97 tests passed.
- Strict UI/template/hardcoded/Kotlin localization checks: zero findings.
- Added Russian text contains no mixed Cyrillic/Latin tokens; `git diff --check`
  is clean.

## Risks and edge cases

- A private server can still reject locally valid parameters; evolution can only
  measure that through a live probe.
- DNS changes must use the same resolver/tag semantics as the existing WARP
  genome path.
- Persisted or reported fitness must include the genome mode/tag so a private
  result cannot be mistaken for a WARP result.
- Verbatim evaluation does not make an unreachable private server reachable; it
  only removes the incorrect WARP-account dependency.

## Unresolved / follow-up

Persistent Hall of Fame reconstruction for private winners belongs to audit
phase 6. `GenomeVerbatim.toJson()` intentionally excludes the body and keys, so
persistence must keep credentials out of settings and reports.
