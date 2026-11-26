// ignore_for_file: depend_on_referenced_packages

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/controllers/subscription_controller.dart';
import 'package:lxbox/screens/evolution_screen.dart';
import 'package:lxbox/services/evolution/settings.dart';
import 'package:lxbox/services/settings_storage.dart';
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'real_io_pump.dart';

class _FakePathProvider extends PathProviderPlatform
    with MockPlatformInterfaceMixin {
  final String tempRoot;
  _FakePathProvider(this.tempRoot);

  @override
  Future<String?> getApplicationSupportPath() async => '$tempRoot/support';

  @override
  Future<String?> getApplicationDocumentsPath() async => '$tempRoot/docs';
}

void main() {
  late Directory tempDir;

  setUp(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tempDir = await Directory.systemTemp.createTemp('evolution_parallel_');
    await Directory('${tempDir.path}/docs').create();
    await Directory('${tempDir.path}/support').create();
    PathProviderPlatform.instance = _FakePathProvider(tempDir.path);
    SettingsStorage.resetCacheForTesting();
  });

  tearDown(() async {
    SettingsStorage.resetCacheForTesting();
    if (tempDir.existsSync()) await tempDir.delete(recursive: true);
  });

  Future<void> settle(WidgetTester tester, bool Function() done) async {
    for (var i = 0; i < 400 && !done(); i++) {
      await realIoStep(tester, fakeTime: const Duration(milliseconds: 50));
    }
    await realIoStep(tester, fakeTime: const Duration(milliseconds: 300));
    expect(done(), isTrue);
  }

  testWidgets('parallel probe batches default off and persist after Apply',
      (tester) async {
    final controller = SubscriptionController();
    addTearDown(controller.dispose);
    await tester.pumpWidget(
      MaterialApp(home: EvolutionScreen(subController: controller)),
    );
    await settle(tester, () => find.byTooltip('Settings').evaluate().isNotEmpty);

    await tester.tap(find.byTooltip('Settings'));
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    final parallel = find.widgetWithText(
      SwitchListTile,
      'Parallel probe batches',
    );
    await tester.ensureVisible(parallel);
    await tester.pump(const Duration(milliseconds: 50));
    expect(tester.widget<SwitchListTile>(parallel).value, isFalse);

    await tester.tap(parallel);
    await tester.pump();
    expect(tester.widget<SwitchListTile>(parallel).value, isTrue);

    final apply = find.text('Apply');
    await tester.ensureVisible(apply);
    await tester.pump(const Duration(milliseconds: 50));
    await tester.tap(apply);
    await settle(
      tester,
      () => find.byType(DraggableScrollableSheet).evaluate().isEmpty,
    );
    final saved = await EvolutionSettings.load();
    expect(saved.parallelProbes, isTrue);
  });
}
