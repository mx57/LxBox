# 747 — Live evolution budget and ETA forecast

| Field | Value |
|-------|-------|
| Status | Done |
| Start date | 2026-11-26 |
| End date | 2026-11-26 |
| Related specs | [`746-persistent-evolution-hall.md`](746-persistent-evolution-hall.md), external audit `GLM_20261125_022835.md` Phase 6 / E-6 |

## Problem

The evolution screen shows spent requests and a static worst-case full-run
estimate, but it does not explain the observed request price, how many
generations the remaining budget can afford, or how long active probing is
likely to take.

## Solution

1. Keep campaign-local counters for every observed verdict and for paid verdicts
   (`Observation.requests > 0`). Account for streamed callbacks before the UI
   callback and for returned-only observations exactly once.
2. Measure active evaluator time around each `evaluate` call in `finally`.
   Preparation, inter-rung pauses and time outside the evaluator are excluded.
3. Add a pure forecast over the successive-halving verdict plan. Before the
   first observation, retain the existing worst-case request multiplier. After
   observations, use actual requests per paid verdict for price and actual
   active time per observed verdict for throughput.
4. Project the remaining worst-case verdict plan, expose both the raw projection
   and a budget-capped total that never falls below already spent requests, and
   calculate how many generations fit the budget. ETA covers only the remaining
   verdicts affordable before the budget stop.
5. Show the live rate, affordable generation count and ETA under the existing
   budget bar. Keep the static worst-case estimate in settings and before the
   first observation.

## Invariants

- Zero-cost diagnostic observations affect remaining work and throughput, but
  never divide the request-price average.
- Streamed and returned observations are not double-counted.
- Forecast state is campaign-local and does not change probe budgeting or
  successive-halving behavior.
- A budget-capped projection is never lower than actual spend, including the
  existing one-started-verdict overshoot.
- Missing timing or observations produce no fake ETA.
- The projection is explicitly an estimate over the worst-case halving plan;
  early elimination can make the real run cheaper.

## Verification

- [x] Zero-observation fallback, mixed request costs and zero-cost diagnostics.
- [x] Raw projection, budget cap, overspend and affordable-generation math.
- [x] Streamed callback counters, returned-only observations and no double count.
- [x] Preparation and inter-rung pause time are excluded from active time.
- [x] Localized UI strings and strict localization/documentation guards.
- [x] Focused tests, analyzer, evolution suite and full-suite baseline comparison.

### Results

- Focused forecast and engine tests: `+41` passed.
- Complete evolution suite: `+197` passed.
- `flutter analyze --no-pub`: no issues.
- Strict `template_check`, `ui_check`, `hardcoded_check`, `kotlin_check` and
  `docs_parity`: zero failures and warnings.
- Diff-scoped mixed Cyrillic/Latin token scan: zero findings.
- Full suite: `+8086 ~38 -13`; all 13 failures match the established clean-`main`
  Windows baseline and are outside the evolution code.

## Risks and edge cases

- A changing network makes the observed price a snapshot, not a guarantee.
- The planned verdict count assumes the configured survival fraction; a dead
  network can eliminate later rungs and cost less than projected.
- ETA stops at the budget boundary; it does not promise completion of the full
  configured run when the projection exceeds the budget.
