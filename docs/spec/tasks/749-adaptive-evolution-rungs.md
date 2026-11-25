# 749 — Adaptive evolution rungs for sparse survival

| Field | Value |
|-------|-------|
| Status | Done |
| Start date | 2026-11-26 |
| End date | 2026-11-26 |
| Related specs | [`747-live-evolution-forecast.md`](747-live-evolution-forecast.md), external audit `GLM_20261125_022835.md` Phase 6 / E-7 |

## Problem

Successive halving always executes every configured rung. When fewer than 30%
of the first-rung population survives, later attempts spend requests confirming a
nearly dead network instead of preserving budget for another generation.

## Solution

1. After the first rung, stop the current generation when fewer than 30% of its
   evaluated candidates have at least one passing observation.
2. Keep the survivors, their accumulated fitness, confirmation state and the
   generation summary unchanged.
3. Do not mutate `EvolutionSettings.rungAttempts`; the adaptation belongs to one
   generation only.
4. Add positive and negative tests proving that sparse runs stop after rung one,
   while healthy runs still execute every configured rung.

## Invariants

- The threshold uses the first-rung batch size and strict `< 30%` comparison.
- Existing budget, cancellation and pause checks retain priority.
- A later generation starts again with the configured rung schedule.
- Forecasts remain worst-case estimates over the configured schedule.

## Verification

- [x] Sparse first-rung survival stops before the second rung.
- [x] Healthy survival preserves the configured successive-halving schedule.
- [x] Settings and survivor records remain unchanged by adaptation.
- [x] Focused tests, analyzer, evolution suite and strict guards pass.
- [x] Changelog and diff-scoped language checks pass.

### Results

- Focused engine and forecast tests passed after correcting the test's expected
  halving sizes; the implementation itself did not change.
- Complete evolution suite: `+199` passed.
- `flutter analyze --no-pub`: no issues.
- Strict `template_check`, `ui_check`, `hardcoded_check`, `kotlin_check` and
  `docs_parity`: zero failures and warnings.
- Diff-scoped mixed Cyrillic/Latin token scan and `git diff --check`: clean.
