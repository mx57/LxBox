# 745 — Revalidate evolution winners before export

| Field | Value |
|-------|-------|
| Status | Done |
| Start date | 2026-11-25 |
| End date | 2026-11-25 |
| Related specs | [`743-verbatim-private-genomes.md`](743-verbatim-private-genomes.md), external audit `GLM_20261125_022835.md` Phase 6 / E-4 |

## Problem

Hall of Fame fitness describes an earlier campaign. A node can stop passing
before the user opens, copies or saves it, and the current UI rebuilds the body
without a fresh probe. Export would therefore present stale fitness as a live
verdict.

## Diagnosis

`_saveSelected` and `_openCandidate` called `exportFor` directly. That method
only rebuilds a node body; it does not perform a probe. The archive's
confirmations therefore described historical campaigns, not the moment when
the user copied or saved the config.

## Solution

1. Add one guarded export path shared by saving selected winners, opening the
   candidate sheet and copying a candidate.
2. Prepare the existing evaluator for the selected genomes, run one fresh
   attempt per genome, and fail closed on preparation errors, exceptions,
   cancellation, missing observations or exhausted request budget.
3. Rebuild fresh `Fitness` from the returned observations and require the
   configured pass-rate threshold before exporting. Never reuse archive fitness
   or count this check as another campaign confirmation.
4. Bound the check to the selected winners, one attempt each and at most three
   HTTP requests per winner. Export only members that pass the fresh check.
5. Show progress and a clear failure result in the UI. Keep ordinary campaign
   behavior and request accounting unchanged.

## Invariants

- A successful export is based on a fresh observation from the same evaluator.
- Private WG/AWG bodies still use their verbatim credentials and AWG fields.
- Export checks never request a WARP account for an all-private selection.
- A refusal, thrown error, cancellation, short result, empty result or budget
  stop cannot fall back to stale success.
- This one-shot check cannot increment Hall of Fame confirmations or mutate the
  archived `Fitness`.

## Verification

- [x] Fresh observations, not archive fitness, decide export.
- [x] Mixed passing/failing selections export only passing members in index
      order.
- [x] Preparation refusal, evaluator throw, cancellation, budget exhaustion,
      empty results and short results fail closed.
- [x] The request cap counts streamed and returned-extra observations once.
- [x] Save, details and copy use the same guarded path.
- [x] Focused tests, `flutter analyze --no-pub` and localization checks pass.

Verification run on 2026-11-25:

- `flutter analyze --no-pub`: no issues.
- `flutter test --no-pub test/warp/evolution`: 171 tests passed.
- Strict template/UI/hardcoded/Kotlin localization checks: zero findings;
  Russian and Chinese dictionaries have 2379 referenced keys each.

## Risks and edge cases

- Each geo verdict can rotate through three HTTP sources; the cap must include
  that cost rather than treating one attempt as one request.
- The evaluator may deliver an observation through both its callback and return
  value; accounting and fitness construction must not double-count it.
- A live check can still succeed while the later tunnel fails; the existing UI
  honesty note remains necessary.
