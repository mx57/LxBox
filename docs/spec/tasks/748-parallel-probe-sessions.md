# 748 — Safe parallel probe sessions

| Field | Value |
|-------|-------|
| Status | In progress |
| Start date | 2026-11-26 |
| Related specs | external audit `GLM_20261125_022835.md` Phase 6 / E-3, [`669-probe-session-run-id.md`](669-probe-session-run-id.md), [`523-wireguard-probe-memory.md`](523-wireguard-probe-memory.md) |

## Problem

Evolution evaluates one probe batch at a time. The native layer also assumes a
single process-global command socket, so simply overlapping `probeStart` calls
would make clients reconnect to the wrong server. A safe parallel mode must keep
command transport, runtime files, authentication and lifecycle ownership
separate without weakening the existing batch limits.

## Solution

1. Add an opt-in `parallelProbes` evolution setting, defaulting to `false`.
2. Allow at most two native probe sessions. Each session owns its run ID,
   command server, command client, runtime directory and command secret.
3. Add a per-instance libbox server/client API. The existing process-wide API
   remains the default for VPN and ordinary scanner calls.
4. Bind every probe RPC to its run ID. Stopping or cancelling one run cannot
   close another run; stale IDs remain no-ops.
5. Keep one Android default-network monitor and fan interface updates out to all
   registered core listeners. The last owner stops the monitor.
6. Run at most two evolution batches concurrently. A batch keeps the existing
   limits: one naive, four WG/AWG and four MASQUE entries. Attempts for one
   genome remain sequential and results keep their original indexes.
7. Stop all probe sessions before VPN startup. Cancellation, evaluator disposal
   and screen teardown release every run owned by that evaluator.
8. Build the patched AAR from the pinned core commit plus a reviewed patch in
   CI. Do not rely on an untracked local AAR or repeated process-global
   `Libbox.setup()` calls.

## Invariants

- Default settings and the ordinary server scanner remain serial.
- Native capacity is two; a third start fails without displacing either live run.
- No two sessions share a command endpoint, secret, runtime directory or cache
  database.
- A reconnect uses the client instance's original endpoint and secret.
- `≤2 sessions × ≤4 WG/AWG` remains the accepted worst-case memory envelope.
- Existing naive and MASQUE per-config limits are unchanged.
- VPN startup always wins over probes.
- Probe cleanup is idempotent and bounded as before.

## Verification

- [x] Core tests prove per-instance endpoint/secret/path behavior and preserve the
      process-global default.
- [x] Native tests cover capacity, independent routing, stale stop, cancellation,
      forced stop and multi-listener network updates.
- [x] Dart tests cover default-off serial behavior, two-way overlap, original
      indexes, per-genome attempt order and complete cleanup.
- [x] Settings JSON round-trip is covered; RU/ZH strings pass guards.
- [x] A dedicated UI switch widget test is present.
- [x] Patched AAR builds reproducibly in GitHub Actions and is consumed by Android
      CI instead of the unpatched release artifact.
- [x] Analyzer, focused tests, evolution suite, strict guards and the changed-line
      language sweep pass.

## Verification results

- Core package: 5 per-instance/default tests pass.
- Android JVM: 29/29 tests pass, including registry capacity/concurrency and
  identity-based interface-listener fan-out.
- Focused Dart probe/settings tests: 22/22 pass.
- Full evolution suite: 208/208 pass, 0 skipped.
- `flutter analyze --no-pub`: 0 issues.
- Strict template, UI, hardcoded-string and Kotlin guards: 0 failures and 0
  warnings; RU/ZH keys are complete.
- Patched arm64 AAR builds locally and passes the core tests. The local NDK is
  newer than the core-pinned NDK and emits a reproducibility warning; CI installs
  the exact pinned NDK.
- GitHub Actions run `45728984558` completes the Android job successfully. It
  builds `libbox.aar` from core `f1bac271853eaf13398ce1030c948aebc3aed2e1` with
  patch `0d6ab30b0b4ce9eed54575910423f3005f1da09ed681fbc36d194a1c60c9877a`,
  then builds and uploads the 46.8 MB release APK.
- Changed-line sweep: 1,695 added/untracked lines in 26 files, 0 mixed-script or
  CJK findings. Repository-wide baseline scan: 5,446 text files, 211 raw matches
  in pre-existing text (including JSON `\n` false positives); no unrelated cleanup
  is included here.

Still unverified: real two-session Android runtime behavior on a physical device.
