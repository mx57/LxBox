# 750 — Shareable safe evolution run report

| Field | Value |
|-------|-------|
| Status | Done |
| Start date | 2026-11-26 |
| End date | 2026-11-26 |
| Related specs | [`749-adaptive-evolution-rungs.md`](749-adaptive-evolution-rungs.md), external audit `GLM_20261125_022835.md` Phase 6 / E-5 |

## Problem

The evolution screen keeps diagnostic details in its transient log. A user can
copy that log, but it is not a stable run report and may contain operational text
that should not be shared. There is no compact account of settings, budget,
generations, candidate metrics and failure categories for a completed run.

## Solution

1. Add an immutable, versioned report DTO with an explicit JSON allowlist.
2. Capture UTC start/end timestamps, duration, status, core version, safe settings,
   seed counts, request/generation totals, active evaluator time and anonymized
   candidate metrics.
3. Use random run IDs and salted ordinal candidate IDs. Never serialize raw
   genome keys, endpoint/SNI/junk-domain values, DNS tags, private tags or bodies,
   credentials, observations, URLs, raw errors or stack traces.
4. Reduce failures to fixed categories and counts. Finalize the report on success,
   failure and cancellation using the same outcome path.
5. Add a share action that sends pretty-printed JSON as text through the system
   share sheet. Add English source strings with Russian and Chinese overlays.
6. Test status/count serialization and recursive secret canaries.

## Invariants

- Report JSON is allowlisted and contains no raw network-private metadata.
- Candidate identifiers cannot be reversed without the discarded per-run salt and
  raw genome key.
- Serialization never calls `Genome.toJson` or embeds `Observation` objects.
- Failure categories belong to a fixed closed set.
- A failed or cancelled run still produces a shareable report.
- Sharing never exports node bodies or credentials.

## Verification

- [x] Success, failure and cancellation status/count serialization.
- [x] Recursive secret canaries are absent from report JSON.
- [x] Candidate IDs are salted and raw genome keys are absent.
- [x] Screen finalizes reports on every terminal outcome and shares JSON text.
- [x] Localized strings and strict localization/documentation guards pass.
- [x] Focused tests, analyzer, evolution suite and diff-scoped language checks pass.

### Results

- Focused report tests: `+6` passed.
- Complete evolution suite: `+205` passed.
- `flutter analyze --no-pub`: no issues.
- Strict `template_check`, `ui_check`, `hardcoded_check`, `kotlin_check` and
  `docs_parity`: zero failures and warnings.
- Diff-scoped mixed Cyrillic/Latin token scan: `0` findings; `git diff --check`
  is clean.
- Report collections and returned JSON maps are unmodifiable; country and core
  version strings are reduced to safe forms before serialization.
- The Android system share sheet was not exercised on a physical device; the
  screen integration is covered by analysis and the report payload by tests.
