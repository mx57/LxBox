import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/vpn/cc_channel.dart';
import 'package:lxbox/widgets/node_row.dart';
import 'package:lxbox/widgets/node_view_item.dart';

/// §557 — выключенный WG/AWG-узел в списке: не таймаут, а «off»; пункт
/// меню выключателя есть только при переданном колбэке.
void main() {
  NodeViewItem item(String endpointState, {String? infoLine}) => NodeViewItem(
    tag: 'wg-de',
    active: false,
    highlighted: false,
    delay: -1,
    pingBusy: false,
    endpointState: endpointState,
    tunnelUp: true,
    busy: false,
    urltestNow: null,
    hasDetour: false,
    protocolLabel: 'WireGuard',
    infoLine: infoLine,
  );

  Widget host(NodeViewItem i, {VoidCallback? onToggle}) => MaterialApp(
    home: Scaffold(
      body: NodeRow(
        item: i,
        onHighlight: () {},
        onActivate: () {},
        onPing: () {},
        onToggleEndpoint: onToggle,
      ),
    ),
  );

  testWidgets('меню: выключатель зовёт колбэк', (tester) async {
    var taps = 0;
    await tester.pumpWidget(
      host(item(CcEndpointState.up), onToggle: () => taps++),
    );
    await tester.longPress(find.byType(NodeRow));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Turn off'));
    await tester.pumpAndSettle();
    expect(taps, 1);
  });

  testWidgets('без infoLine обычная высота 56', (tester) async {
    await tester.pumpWidget(host(item('')));
    expect(find.byKey(const ValueKey('node-info-line')), findsNothing);
    expect(tester.getSize(find.byType(NodeRow)).height, 56);
  });

  testWidgets('infoLine показан отдельно и увеличивает высоту до 72', (
    tester,
  ) async {
    const info = 'AWG3 settings must match the server.';
    await tester.pumpWidget(host(item('', infoLine: info)));
    expect(find.byKey(const ValueKey('node-info-line')), findsOneWidget);
    expect(find.text(info), findsOneWidget);
    expect(tester.getSize(find.byType(NodeRow)).height, 72);
  });
}
