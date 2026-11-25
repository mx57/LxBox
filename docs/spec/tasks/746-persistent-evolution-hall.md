# 746 — Persistent evolution Hall of Fame

| Field | Value |
|-------|-------|
| Status | Done |
| Start date | 2026-11-25 |
| End date | 2026-11-25 |
| Related specs | [`743-verbatim-private-genomes.md`](743-verbatim-private-genomes.md), [`745-winner-revalidation.md`](745-winner-revalidation.md), external audit `GLM_20261125_022835.md` Phase 6 / E-2 |

## Problem

The evolution archive and its confirmation hysteresis live only in one
`EvolutionEngine` instance. Restarting the screen or app forgets both confirmed
winners and candidates that need one more independent campaign confirmation.

## Solution

1. Add a versioned `evo_hall` settings value with a random per-archive HMAC key,
   a hard entry cap and Pareto trimming. Keep positive-confirmation contenders as
   well as confirmed winners.
2. Persist only scalar fitness summaries and safe genome loci. Endpoint, SNI,
   junk-domain, DNS tag and private tag/body values are represented by HMAC
   references; private keys, accounts, bodies, errors, logs and raw network
   metadata are never serialized.
3. Restore WARP genomes from the current allele pool or a matching current seed.
   Restore private genomes only when their current node identity matches, then
   apply the three safe verbatim loci. Verify every reconstructed genome against
   its stored HMAC identity.
4. Prepend restored genomes to the next campaign, reset the generation marker so
   a new campaign can add a confirmation, and return the restored archive when
   preparation refuses to start.
5. Save on success, failure and cancellation before the screen's mounted check.
   Keep unmatched entries for a later session instead of discarding them.
6. Replace the fixed Hall of Fame EDA weight with bounded rank/confirmation
   weights and weight private parent sampling by confirmations.
7. Allow `evo_hall` through the default-deny backup var allowlist.

## Invariants

- A malformed, future-version or unknown-field archive is rejected as a whole.
- Archive JSON contains no raw endpoint, SNI, junk domain, private tag, body,
  credential, account, observation text, error or stack trace.
- A private winner is never attached to a different tag, endpoint or port.
- Cross-session confirmations grow, but one campaign still contributes at most
  one confirmation per genome.
- Restored fitness is historical; export continues to require the fresh E-4
  revalidation.
- Persistence failure does not turn a completed probe campaign into a fake
  success or erase its in-memory result.

## Verification

- [x] Version, schema, size and unknown-field rejection.
- [x] Recursive secret canaries are absent from serialized archives.
- [x] WARP pool/seed restoration and private identity mismatch refusal.
- [x] Merge, dedupe, cap and Pareto ordering.
- [x] Cross-session confirmation and preparation-failure restoration.
- [x] Restored seeds are deterministic and private parent weighting is bounded.
- [x] Backup allowlist contains `evo_hall`.
- [x] Focused tests, analyzer, strict guards and full-suite regression comparison.

### Results

- Focused Hall of Fame and engine tests: `+39` passed.
- Complete evolution suite: `+186` passed.
- `flutter analyze --no-pub`: no issues.
- Strict `template_check`, `ui_check`, `hardcoded_check`, `kotlin_check` and
  `docs_parity`: zero failures and warnings.
- Diff-scoped mixed Cyrillic/Latin token scan: zero findings.
- Full suite: `+8074 ~38 -14`. Re-running only the failing files gave `+95 -13`;
  the extra transfer-receiver failure passed on rerun and was a flake. The
  remaining 13 failures are the established Windows baseline on clean `main`,
  outside the evolution code.

## Risks and edge cases

- A WARP allele removed from the current asset cannot be reconstructed until it
  returns; its safe archive entry is retained.
- A private winner whose node is no longer present cannot be restored without
  persisting its identity or secret body, so the archive deliberately keeps only
  its opaque record.
- HMAC references protect against accidental metadata disclosure and casual
  inspection, not against an attacker who controls both the archive and its key.
