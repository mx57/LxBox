import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/models/node_spec.dart';
import 'package:lxbox/widgets/awg_fields.dart';

void main() {
  const validKey = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
  const baseFields = <String, Object>{
    'jc': 3,
    'jmin': 0,
    'jmax': 0,
    's1': 12,
    's2': 12,
    's3': 12,
    's4': 12,
    'h1': 1,
    'h2': 2,
    'h3': 3,
    'h4': 4,
  };
  final written = <Map<String, Object?>>[];

  Future<void> pump(
    WidgetTester tester, {
    Map<String, Object> fields = baseFields,
    String? unavailableReason,
    bool sourceDirty = false,
    bool sourceHasMasqueradeKeys = false,
  }) async {
    written.clear();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: AwgFieldsSection(
              fields: fields,
              unavailableReason: unavailableReason,
              sourceDirty: sourceDirty,
              sourceHasMasqueradeKeys: sourceHasMasqueradeKeys,
              onSave: (fields) async => written.add(fields),
            ),
          ),
        ),
      ),
    );
  }

  Finder field(String key) => find.byKey(ValueKey('awg-$key'));
  final apply = find.byKey(const ValueKey('awg-apply'));

  Future<void> enter(WidgetTester tester, String key, String text) async {
    await tester.enterText(field(key), text);
    await tester.pump();
  }

  Future<void> tap(WidgetTester tester, Finder target) async {
    await tester.ensureVisible(target);
    await tester.pumpAndSettle();
    await tester.tap(target);
    await tester.pump();
  }

  testWidgets('valid ranges and AWG3 booleans are written as parsed values', (
    tester,
  ) async {
    await pump(tester);
    await enter(tester, 'h1', '200-100');
    await enter(tester, 'content_padding_addition', '5-15');
    await tap(tester, find.byKey(const ValueKey('awg-random_trailers')));
    await tester.pump();
    expect(tester.widget<FilledButton>(apply).onPressed, isNotNull);
    await tap(tester, apply);
    await tester.pump();
    expect(written, hasLength(1));
    expect(written.single['h1'], '100-200');
    expect(written.single['content_padding_addition'], '5-15');
    expect(written.single['random_trailers'], isTrue);
    expect(written.single['disable_cookies'], isFalse);
  });

  testWidgets('malformed range and reversed timing range block Apply', (
    tester,
  ) async {
    await pump(tester);
    await enter(tester, 'content_padding_addition', '15-5');
    expect(
      find.text(
        'Enter a whole number or an N-M range with N no greater than M.',
      ),
      findsOneWidget,
    );
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
    await enter(tester, 'content_padding_addition', '5-15');
    expect(tester.widget<FilledButton>(apply).onPressed, isNotNull);
    await enter(tester, 'h2', '1-2');
    expect(
      find.text('Magic header ranges H1-H4 must not overlap.'),
      findsNWidgets(2),
    );
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
  });

  testWidgets('header key requires standard base64 and padding at least 12', (
    tester,
  ) async {
    await pump(tester);
    await enter(tester, Awg.headerKey, 'not-base64');
    expect(
      find.text(
        'The key must be standard base64 of exactly 32 bytes, not all zero.',
      ),
      findsOneWidget,
    );
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
    await enter(tester, Awg.headerKey, validKey);
    await enter(tester, 's1', '11');
    expect(
      find.text(
        'With a header protection key, S1-S4 must each be at least 12.',
      ),
      findsOneWidget,
    );
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
    await enter(tester, 's1', '12');
    expect(tester.widget<FilledButton>(apply).onPressed, isNotNull);
  });

  testWidgets('explicit I1 conflicts with masquerade keys', (tester) async {
    await pump(tester, fields: {...baseFields, 'i1': '<b 0x1>', 'ip': 'quic'});
    expect(
      find.text(
        'I1 conflicts with Masquerade. Clear the Masquerade protocol first.',
      ),
      findsOneWidget,
    );
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
  });

  testWidgets('I1 conflict sees masquerade keys hidden by parsing', (
    tester,
  ) async {
    await pump(
      tester,
      fields: {...baseFields, 'i1': '<b 0x1>'},
      sourceHasMasqueradeKeys: true,
    );
    expect(
      find.text(
        'I1 conflicts with Masquerade. Clear the Masquerade protocol first.',
      ),
      findsOneWidget,
    );
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
  });

  testWidgets('secure key button fills 44-character base64 of 32 bytes', (
    tester,
  ) async {
    await pump(tester);
    await tap(tester, find.byKey(const ValueKey('awg-generate-header-key')));
    await tester.pump();
    final input = tester.widget<TextField>(field(Awg.headerKey));
    final key = input.controller!.text;
    expect(key, hasLength(44));
    final bytes = base64.decode(key);
    expect(bytes, hasLength(32));
    expect(bytes.any((b) => b != 0), isTrue);
    expect(tester.widget<FilledButton>(apply).onPressed, isNotNull);
  });

  testWidgets('unsupported source and unsaved Source disable the form', (
    tester,
  ) async {
    await pump(tester, unavailableReason: 'Packed link');
    expect(tester.widget<TextField>(field('jc')).enabled, isFalse);
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
    await pump(tester, sourceDirty: true);
    expect(tester.widget<TextField>(field('jc')).enabled, isFalse);
    expect(tester.widget<FilledButton>(apply).onPressed, isNull);
    expect(find.text('Source has unsaved changes.'), findsOneWidget);
  });
}
