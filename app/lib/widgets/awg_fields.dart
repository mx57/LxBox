import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/material.dart';

import '../models/node_spec.dart';
import '../services/l10n/locale_controller.dart';

enum _AwgFieldKind { uint, headerRange, timingRange, text, headerKey }

class _AwgFieldSpec {
  const _AwgFieldSpec(this.key, this.kind);

  final String key;
  final _AwgFieldKind kind;
}

const _junkFields = [
  _AwgFieldSpec('jc', _AwgFieldKind.uint),
  _AwgFieldSpec('jmin', _AwgFieldKind.uint),
  _AwgFieldSpec('jmax', _AwgFieldKind.uint),
  _AwgFieldSpec('s1', _AwgFieldKind.uint),
  _AwgFieldSpec('s2', _AwgFieldKind.uint),
  _AwgFieldSpec('s3', _AwgFieldKind.uint),
  _AwgFieldSpec('s4', _AwgFieldKind.uint),
  _AwgFieldSpec('h1', _AwgFieldKind.headerRange),
  _AwgFieldSpec('h2', _AwgFieldKind.headerRange),
  _AwgFieldSpec('h3', _AwgFieldKind.headerRange),
  _AwgFieldSpec('h4', _AwgFieldKind.headerRange),
];

const _customFields = [
  _AwgFieldSpec('i1', _AwgFieldKind.text),
  _AwgFieldSpec('i2', _AwgFieldKind.text),
  _AwgFieldSpec('i3', _AwgFieldKind.text),
  _AwgFieldSpec('i4', _AwgFieldKind.text),
  _AwgFieldSpec('i5', _AwgFieldKind.text),
];

const _awg3Fields = [
  _AwgFieldSpec(Awg.headerKey, _AwgFieldKind.headerKey),
  _AwgFieldSpec('content_padding_addition', _AwgFieldKind.timingRange),
  _AwgFieldSpec('rekey_after_time', _AwgFieldKind.timingRange),
  _AwgFieldSpec('rekey_timeout', _AwgFieldKind.timingRange),
  _AwgFieldSpec('reject_after_time', _AwgFieldKind.timingRange),
  _AwgFieldSpec('keepalive_timeout', _AwgFieldKind.timingRange),
  _AwgFieldSpec('max_handshake_attempts', _AwgFieldKind.timingRange),
];

String generateAwgHeaderKey({Random? random}) {
  final rng = random ?? Random.secure();
  final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
  if (bytes.every((b) => b == 0)) bytes[0] = 1;
  return base64.encode(bytes);
}

class AwgFieldsSection extends StatefulWidget {
  const AwgFieldsSection({
    super.key,
    required this.fields,
    required this.onSave,
    this.unavailableReason,
    this.sourceDirty = false,
    this.sourceHasMasqueradeKeys = false,
  });

  final Map<String, Object> fields;
  final Future<void> Function(Map<String, Object?>) onSave;
  final String? unavailableReason;
  final bool sourceDirty;
  final bool sourceHasMasqueradeKeys;

  @override
  State<AwgFieldsSection> createState() => _AwgFieldsSectionState();
}

class _AwgFieldsSectionState extends State<AwgFieldsSection> {
  late final Map<String, TextEditingController> _controllers;
  late final Map<String, bool> _booleans;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _controllers = {
      for (final spec in [..._junkFields, ..._customFields, ..._awg3Fields])
        spec.key: TextEditingController(text: _initialText(spec.key)),
    };
    _booleans = {
      for (final key in Awg.awg3BoolKeys) key: widget.fields[key] == true,
    };
    for (final controller in _controllers.values) {
      controller.addListener(_changed);
    }
  }

  String _initialText(String key) {
    final value = widget.fields[key];
    return value == null ? '' : '$value';
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  @override
  void didUpdateWidget(covariant AwgFieldsSection oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (identical(oldWidget.fields, widget.fields)) return;
    for (final entry in _controllers.entries) {
      entry.value.text = _initialText(entry.key);
    }
    for (final key in _booleans.keys) {
      _booleans[key] = widget.fields[key] == true;
    }
  }

  @override
  void dispose() {
    for (final controller in _controllers.values) {
      controller.removeListener(_changed);
      controller.dispose();
    }
    super.dispose();
  }

  Map<String, Object?> _values() {
    Object? valueOf(_AwgFieldSpec spec) {
      final raw = _controllers[spec.key]!.text.trim();
      if (raw.isEmpty) return null;
      return switch (spec.kind) {
        _AwgFieldKind.uint => int.tryParse(raw),
        _AwgFieldKind.headerRange => _headerValue(raw),
        _AwgFieldKind.timingRange => Awg.parseAwg3Range(raw),
        _AwgFieldKind.text => raw,
        _AwgFieldKind.headerKey => raw,
      };
    }

    return {
      for (final spec in [..._junkFields, ..._customFields, ..._awg3Fields])
        spec.key: valueOf(spec),
      for (final key in Awg.awg3BoolKeys)
        key: Awg.parseAwg3Bool(_booleans[key]! ? 'on' : 'off'),
    };
  }

  Map<String, String> _errors() {
    final errors = <String, String>{};
    final values = _values();
    final controllers = {
      for (final spec in [..._junkFields, ..._customFields, ..._awg3Fields])
        spec.key: _controllers[spec.key]!,
    };

    void uintError(String key) {
      final raw = controllers[key]!.text.trim();
      if (raw.isEmpty) return;
      final n = int.tryParse(raw);
      if (n == null || n < 0 || n > 0xFFFFFFFF) {
        errors[key] = getLocalText.s(
          "Enter a whole number from 0 to 4294967295.",
        );
      }
    }

    for (final spec in _junkFields.where((s) => s.kind == _AwgFieldKind.uint)) {
      uintError(spec.key);
    }
    for (final spec in _awg3Fields.where(
      (s) => s.kind == _AwgFieldKind.timingRange,
    )) {
      final raw = controllers[spec.key]!.text.trim();
      if (raw.isNotEmpty && Awg.parseAwg3Range(raw) == null) {
        errors[spec.key] = getLocalText.s(
          "Enter a whole number or an N-M range with N no greater than M.",
        );
      }
    }
    for (final spec in _junkFields.where(
      (s) => s.kind == _AwgFieldKind.headerRange,
    )) {
      final raw = controllers[spec.key]!.text.trim();
      if (raw.isNotEmpty && _headerValue(raw) == null) {
        errors[spec.key] = getLocalText.s(
          "Enter a whole number or an N-M header range.",
        );
      }
    }

    final headerKey = controllers[Awg.headerKey]!.text.trim();
    if (headerKey.isNotEmpty && !_validHeaderKey(headerKey)) {
      errors[Awg.headerKey] = getLocalText.s(
        "The key must be standard base64 of exactly 32 bytes, not all zero.",
      );
    }
    if (headerKey.isNotEmpty && _validHeaderKey(headerKey)) {
      for (final key in const ['s1', 's2', 's3', 's4']) {
        final n = values[key];
        if (n is! int || n < Awg.awg3MinPadding) {
          errors[key] = getLocalText.s(
            "With a header protection key, S1-S4 must each be at least 12.",
          );
        }
      }
    }

    final i1 = controllers['i1']!.text.trim();
    if (i1.isNotEmpty &&
        (widget.sourceHasMasqueradeKeys ||
            const ['id', 'ip', 'ib'].any((k) => widget.fields[k] != null))) {
      errors['i1'] = getLocalText.s(
        "I1 conflicts with Masquerade. Clear the Masquerade protocol first.",
      );
    }
    if (controllers['i2']!.text.trim().isNotEmpty &&
        widget.fields['ip'] == 'sip') {
      errors['i2'] = getLocalText.s(
        "I2 conflicts with the SIP masquerade protocol.",
      );
    }

    final jmin = values['jmin'];
    final jmax = values['jmax'];
    if (jmin is int && jmax is! int) {
      errors['jmin'] = getLocalText.s("Jmin requires Jmax.");
    } else if (jmin is int && jmax is int && jmin > jmax) {
      errors['jmin'] = getLocalText.s("Jmin must not exceed Jmax.");
    }

    final headers = <({int lo, int hi, String key})>[];
    for (var i = 0; i < Awg.headerKeys.length; i++) {
      final key = 'h${i + 1}';
      final value = values[key] ?? i + 1;
      final bounds = _boundsOf(value);
      if (bounds != null) headers.add((lo: bounds.$1, hi: bounds.$2, key: key));
    }
    for (var i = 0; i < headers.length; i++) {
      for (var j = i + 1; j < headers.length; j++) {
        final a = headers[i];
        final b = headers[j];
        if (a.lo <= b.hi && b.lo <= a.hi) {
          errors[a.key] = getLocalText.s(
            "Magic header ranges H1-H4 must not overlap.",
          );
          errors[b.key] = errors[a.key]!;
        }
      }
    }
    return errors;
  }

  bool _validHeaderKey(String raw) {
    if (!RegExp(r'^[A-Za-z0-9+/]{43}=$').hasMatch(raw)) return false;
    try {
      final bytes = base64.decode(raw);
      return bytes.length == 32 && bytes.any((b) => b != 0);
    } catch (_) {
      return false;
    }
  }

  Object? _headerValue(String raw) {
    final match = RegExp(r'^(\d+)(?:\s*-\s*(\d+))?$').firstMatch(raw.trim());
    if (match == null) return null;
    final lo = int.tryParse(match[1]!);
    final hi = match[2] == null ? lo : int.tryParse(match[2]!);
    if (lo == null ||
        hi == null ||
        lo < 0 ||
        hi < 0 ||
        lo > 0xFFFFFFFF ||
        hi > 0xFFFFFFFF) {
      return null;
    }
    if (lo == hi) return lo;
    return lo < hi ? '$lo-$hi' : '$hi-$lo';
  }

  (int, int)? _boundsOf(Object value) {
    if (value is int) return (value, value);
    if (value is String) {
      final parts = value.split('-');
      if (parts.length == 2) {
        final lo = int.tryParse(parts[0]);
        final hi = int.tryParse(parts[1]);
        if (lo != null && hi != null) return (lo, hi);
      }
    }
    return null;
  }

  Future<void> _save() async {
    if (_saving) return;
    setState(() => _saving = true);
    try {
      await widget.onSave(_values());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final errors = _errors();
    final enabled = widget.unavailableReason == null && !widget.sourceDirty;
    final canSave = enabled && errors.isEmpty && !_saving;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (widget.unavailableReason != null || widget.sourceDirty)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              widget.unavailableReason ??
                  getLocalText.s("Source has unsaved changes."),
              style: theme.textTheme.bodySmall,
            ),
          ),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
          child: Text(
            getLocalText.s(
              "These values must match the server. A mismatch can start the tunnel but prevent data transfer.",
            ),
            style: theme.textTheme.bodySmall,
          ),
        ),
        _groupTitle(getLocalText.s("Junk and magic headers")),
        for (final spec in _junkFields)
          _textField(spec, errors[spec.key], enabled),
        _groupTitle(getLocalText.s("Custom packets (I1-I5)")),
        for (final spec in _customFields)
          _textField(spec, errors[spec.key], enabled),
        _groupTitle(getLocalText.s("AmneziaWG 3.0")),
        for (final spec in _awg3Fields)
          _textField(spec, errors[spec.key], enabled),
        _groupTitle(getLocalText.s("AmneziaWG 3.1")),
        for (final key in Awg.awg3BoolKeys)
          SwitchListTile(
            key: ValueKey('awg-$key'),
            contentPadding: const EdgeInsets.symmetric(horizontal: 16),
            title: Text(_booleanLabel(key)),
            value: _booleans[key]!,
            onChanged: enabled
                ? (v) => setState(() => _booleans[key] = v)
                : null,
          ),
        const SizedBox(height: 8),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: FilledButton.icon(
            key: const ValueKey('awg-apply'),
            onPressed: canSave ? () => unawaited(_save()) : null,
            icon: _saving
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.save_outlined),
            label: Text(getLocalText.s("Apply")),
          ),
        ),
      ],
    );
  }

  Widget _groupTitle(String title) => Padding(
    padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
    child: Text(title, style: Theme.of(context).textTheme.titleSmall),
  );

  Widget _textField(_AwgFieldSpec spec, String? error, bool enabled) => Padding(
    padding: const EdgeInsets.fromLTRB(16, 0, 16, 10),
    child: TextField(
      key: ValueKey('awg-${spec.key}'),
      controller: _controllers[spec.key],
      enabled: enabled,
      autocorrect: false,
      enableSuggestions: false,
      keyboardType:
          spec.kind == _AwgFieldKind.text ||
              spec.kind == _AwgFieldKind.headerKey
          ? TextInputType.text
          : TextInputType.number,
      decoration: InputDecoration(
        labelText: _fieldLabel(spec.key),
        helperText: _helperText(spec),
        helperMaxLines: 2,
        errorText: error,
        errorMaxLines: 3,
        isDense: true,
        border: const OutlineInputBorder(),
        suffixIcon: spec.kind == _AwgFieldKind.headerKey
            ? IconButton(
                key: const ValueKey('awg-generate-header-key'),
                tooltip: getLocalText.s("Generate a header protection key"),
                icon: const Icon(Icons.casino_outlined),
                onPressed: enabled
                    ? () =>
                          _controllers[spec.key]!.text = generateAwgHeaderKey()
                    : null,
              )
            : null,
      ),
    ),
  );

  String _fieldLabel(String key) => switch (key) {
    'jc' => getLocalText.s("Junk packet count (Jc)"),
    'jmin' => getLocalText.s("Minimum junk packet size (Jmin)"),
    'jmax' => getLocalText.s("Maximum junk packet size (Jmax)"),
    's1' => getLocalText.s("Initiation padding (S1)"),
    's2' => getLocalText.s("Response padding (S2)"),
    's3' => getLocalText.s("Cookie padding (S3)"),
    's4' => getLocalText.s("Transport padding (S4)"),
    'h1' => getLocalText.s("Initiation magic header (H1)"),
    'h2' => getLocalText.s("Response magic header (H2)"),
    'h3' => getLocalText.s("Cookie magic header (H3)"),
    'h4' => getLocalText.s("Transport magic header (H4)"),
    'i1' => getLocalText.s("Custom packet I1"),
    'i2' => getLocalText.s("Custom packet I2"),
    'i3' => getLocalText.s("Custom packet I3"),
    'i4' => getLocalText.s("Custom packet I4"),
    'i5' => getLocalText.s("Custom packet I5"),
    Awg.headerKey => getLocalText.s("Header protection key"),
    'content_padding_addition' => getLocalText.s("Content padding addition"),
    'rekey_after_time' => getLocalText.s("Rekey after time"),
    'rekey_timeout' => getLocalText.s("Rekey timeout"),
    'reject_after_time' => getLocalText.s("Reject after time"),
    'keepalive_timeout' => getLocalText.s("Keepalive timeout"),
    'max_handshake_attempts' => getLocalText.s("Maximum handshake attempts"),
    _ => key,
  };

  String _booleanLabel(String key) => switch (key) {
    'random_trailers' => getLocalText.s("Random trailers"),
    'disable_cookies' => getLocalText.s("Disable cookies"),
    _ => key,
  };

  String? _helperText(_AwgFieldSpec spec) => switch (spec.kind) {
    _AwgFieldKind.uint => getLocalText.s("Whole number, 0-4294967295."),
    _AwgFieldKind.headerRange => getLocalText.s("Number or N-M range."),
    _AwgFieldKind.timingRange => switch (spec.key) {
      'content_padding_addition' => getLocalText.s(
        "Bytes: number or N-M range.",
      ),
      'max_handshake_attempts' => getLocalText.s(
        "Attempts: number or N-M range.",
      ),
      _ => getLocalText.s("Seconds: number or N-M range."),
    },
    _AwgFieldKind.headerKey => getLocalText.s(
      "Standard base64, 32 bytes. The generated key must also be set on the server.",
    ),
    _AwgFieldKind.text => null,
  };
}
