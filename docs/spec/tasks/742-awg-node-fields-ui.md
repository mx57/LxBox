# 742 — AmneziaWG 2.0/3.x node fields and honest AWG3 guidance

| Field | Value |
|-------|-------|
| Status | Completed |
| Start date | 2026-11-25 |
| End date | 2026-11-25 |
| Related specs | [`741-evolution-audit-phases-0-2.md`](741-evolution-audit-phases-0-2.md), external audit `GLM_20261125_022835.md` Phase 3 |

## Problem

The parser and emitter understand AmneziaWG 2.0/3.x fields, including ranged
headers, AWG3 timings, booleans and `header_protection_key`, but node settings
only expose the `ip`/`id`/`ib` masquerade helpers. Users must edit raw source to
change the remaining server-matched fields, and there is no local check for
invalid or mutually incompatible values before Save.

The QUIC browser registry does not accept the experimental `chrome-full`
signature, and AWG3 node cards do not explain that these parameters are
server-matched: a syntactically valid mismatch can start a tunnel that passes no
data.

## Diagnosis

- `Awg` already stores all required JSON keys and parses AWG3 ranges/booleans in
  `app/lib/models/node_spec.dart`.
- `withMasquerade` is the only structured writer for WG/AWG source and preserves
  URI, INI and sing-box JSON dialects.
- `NodeSettingsScreen` writes masquerade immediately through `_saveSource` and
  reloads the parsed node after a successful save.
- Registry validation already defines numeric, range, base64, conflict and
  padding rules; the UI does not consume them before writing.
- `ConfigNode.securityLabel` already identifies the AWG level, but the card has
  no AWG3-specific guidance.
- The launcher contract source is unavailable in this checkout. The existing
  lock already records a local patch with an empty `source_sha`; any further
  registry change must preserve that provenance rather than invent an upstream
  commit.

## Solution

1. Add a general AWG source writer next to `withMasquerade`. It uses the same
   writability rules and updates only the requested AWG keys in URI query, INI
   `[Interface]`, or a bare sing-box endpoint. `null`/disabled booleans remove a
   key; unrelated source bytes and dialect stay intact.
2. Add an `AwgFieldsSection` shown only when `WireguardSpec.awg != null`. Group
   fields by AWG level and edit junk/header fields, `i1..i5`, the header key,
   padding/timings and AWG3 booleans. Keep the existing masquerade section for
   `ip`/`id`/`ib`.
3. Validate live before Save: integer/uint32 syntax, header ranges,
   `Awg.parseAwg3Range`, `Awg.parseAwg3Bool`, standard base64 of exactly 32
   bytes, `i1` versus `id`/`ip`/`ib`, junk-size requirements, header overlap,
   and `s1..s4 >= 12` when the header key is set. Save uses the existing
   raw-source path and reparses the node.
4. Add a header-key button that generates standard base64 from 32
   `Random.secure` bytes and fills the field.
5. Add `chrome-full` as an advanced, experimental browser choice with an LTE
   warning. Extend the body and mapper registry enum, add an informational
   `ib_chrome_full_experimental` advisory, update the mirrors/docs honestly,
   and update sanitizer tests. Ordinary imported values remain valid and kept.
6. Add an AWG3 config-only mismatch explanation to the node card, backed by a
   small `ConfigNode` predicate and covered by model/widget tests.
7. Add English source strings and Russian/Chinese translations for every new
   UI message.

## Files

- `app/lib/models/config_node.dart`
- `app/lib/services/wireguard/masquerade_source.dart`
- `app/lib/widgets/awg_fields.dart`
- `app/lib/widgets/masquerade_fields.dart`
- `app/lib/screens/node_settings_screen.dart`
- `app/lib/screens/home/widgets/node_list.dart` and its node-card widget
- `app/contract/**`, `app/assets/contract/**`, `app/contract.lock`,
  `docs/contract/**` (local contract patch through the standard sync path)
- `app/test/services/masquerade_source_test.dart`
- `app/test/widgets/awg_fields_test.dart`
- `app/test/widgets/masquerade_section_test.dart`
- `app/test/contract/body_sanitizer_test.dart`
- `app/test/models/config_node_test.dart` and node-card tests
- localization source files and `app/assets/l10n/{ru,zh}/ui.json`
- `CHANGELOG.md`

## Risks and edge cases

- AWG2/AWG3 values are server-matched. The UI can validate syntax and known
  incompatibilities, but cannot prove that the server uses the same values.
- A generated header key is not a server key. It is useful for creating a
  matching server profile; replacing the key on an existing node breaks the
  handshake.
- `chrome-full` is experimental and may fail on LTE. It must not become a
  default or silently replace an imported profile.
- Packed links and unsupported source formats remain read-only in this section;
  the user can still edit them through the existing JSON/source workflow.
- No live AWG3 server is part of this phase. Real handshake/data verification
  remains Phase 5.

## Verification

- [x] Source-writer round-trips cover URI, INI and sing-box JSON, including a
      header range and `on` boolean.
- [x] Widget tests cover valid input, malformed base64, short padding, explicit
      `i1` conflict, range/bool parsing and key generation.
- [x] Save → reparse tests retain edited fields in the stored source.
- [x] `chrome-full` survives sanitization and emits
      `ib_chrome_full_experimental`; invalid values still produce
      `awg3_field_invalid`.
- [x] AWG3 card guidance appears only for AWG3 WireGuard nodes.
- [x] Focused tests and `flutter analyze --no-pub` pass; strict l10n/template/
      hardcoded/Kotlin checks and contract parity report zero failures.
- [x] No CI push, PR or merge is performed without explicit authorization.

## Unresolved / follow-up

- Phase 4: verbatim private WG/AWG genomes.
- Phase 5: real AWG3 Docker/integration stand.
- Phase 6: evolution re-validation, persistent Hall of Fame, ETA, parallel
  probes, adaptive rungs and JSON reports.
