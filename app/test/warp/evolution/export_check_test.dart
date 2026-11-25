import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/engine.dart';
import 'package:lxbox/services/evolution/export_check.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/objectives.dart';
import 'package:lxbox/services/evolution/settings.dart';

GenomeVerbatim _genome(String tag) => GenomeVerbatim.fromBody(tag, {
  'type': 'wireguard',
  'address': ['10.8.0.2/32'],
  'peers': [
    {'address': '192.0.2.1', 'port': 51820},
  ],
})!;

Fitness _stale(String tag) => Fitness(_genome(tag))
  ..attempts = 5
  ..passes = 5
  ..confirmations = 2;

class _Evaluator implements GenomeEvaluator {
  _Evaluator(this.results);

  List<List<Observation>> results;
  String? prepareError;
  bool throwOnEvaluate = false;
  bool cancelled = false;
  bool budgetExceeded = false;
  List<Genome> prepared = const [];
  final exported = <String>[];
  final missing = <String>{};
  final throwing = <String>{};

  @override
  Future<String?> prepare() async => null;

  @override
  Future<String?> prepareFor(List<Genome> genomes) async {
    prepared = genomes;
    return prepareError;
  }

  @override
  Future<List<List<Observation>>> evaluate(
    List<Genome> genomes, {
    required int attempts,
    void Function(int index, Observation observation)? onOne,
    bool Function()? cancelled,
    bool Function()? budgetExceeded,
  }) async {
    if (throwOnEvaluate) throw StateError('probe failed');
    for (var i = 0; i < genomes.length && i < results.length; i++) {
      for (final observation in results[i]) {
        onOne?.call(i, observation);
      }
    }
    this.cancelled = cancelled?.call() ?? false;
    this.budgetExceeded = budgetExceeded?.call() ?? false;
    return results;
  }

  String? exportFor(Genome genome) {
    final tag = (genome as GenomeVerbatim).tag;
    if (throwing.contains(tag)) throw StateError('rebuild failed');
    if (missing.contains(tag)) return null;
    exported.add(tag);
    return '{"tag":"$tag"}';
  }

  @override
  Future<void> dispose() async {}
}

const _settings = EvolutionSettings(minPassRate: 1);

Observation _pass({int requests = 1}) =>
    Observation(responded: true, status: 200, rttMs: 20, requests: requests);

void main() {
  test('fresh failure never falls back to stale archive fitness', () async {
    final stale = _stale('private-a');
    final evaluator = _Evaluator([
      [Observation.failed('timeout')],
    ]);
    final result = await revalidateAndExport(
      [stale],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(result.bodies, isEmpty);
    expect(result.failed, ['private · private-a · 192.0.2.1:51820']);
    expect(evaluator.exported, isEmpty);
    expect(stale.passRate, 1);
    expect(stale.confirmations, 2);
  });

  test('mixed results export passing members in input order', () async {
    final evaluator = _Evaluator([
      [_pass(requests: 3)],
      [Observation.failed('refused', requests: 2)],
      [_pass()],
    ]);
    final result = await revalidateAndExport(
      [_stale('a'), _stale('b'), _stale('c')],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(result.bodies, ['{"tag":"a"}', '{"tag":"c"}']);
    expect(result.failed, ['private · b · 192.0.2.1:51820']);
    expect(evaluator.exported, ['a', 'c']);
    expect(result.requestsUsed, 6);
  });

  test('callback and returned observation are counted once', () async {
    final evaluator = _Evaluator([
      [_pass(requests: 3)],
    ]);
    final result = await revalidateAndExport(
      [_stale('a')],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(result.bodies, hasLength(1));
    expect(result.requestsUsed, 3);
  });

  test('request cap includes all three geo sources', () async {
    final evaluator = _Evaluator([
      [_pass(requests: 3)],
    ]);
    await revalidateAndExport(
      [_stale('a')],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(evaluator.budgetExceeded, isTrue);
  });

  test('preparation refusal fails closed', () async {
    final evaluator = _Evaluator([])..prepareError = 'VPN is running';
    final result = await revalidateAndExport(
      [_stale('a')],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(result.error, 'VPN is running');
    expect(result.bodies, isEmpty);
    expect(result.failed, hasLength(1));
  });

  test('evaluator exception fails closed', () async {
    final evaluator = _Evaluator([])..throwOnEvaluate = true;
    final result = await revalidateAndExport(
      [_stale('a')],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(result.error, 'check failed');
    expect(result.bodies, isEmpty);
  });

  test('cancellation and short results fail closed', () async {
    final cancelled = _Evaluator([
      [_pass()],
    ]);
    final cancelledResult = await revalidateAndExport(
      [_stale('a')],
      evaluator: cancelled,
      export: cancelled.exportFor,
      settings: _settings,
      cancelled: () => true,
    );
    expect(cancelledResult.bodies, isEmpty);
    expect(cancelledResult.failed, hasLength(1));

    final short = _Evaluator(<List<Observation>>[]);
    final shortResult = await revalidateAndExport(
      [_stale('a')],
      evaluator: short,
      export: short.exportFor,
      settings: _settings,
    );
    expect(shortResult.bodies, isEmpty);
    expect(shortResult.failed, hasLength(1));
  });

  test('missing and throwing exports are skipped', () async {
    final evaluator =
        _Evaluator([
            [_pass()],
            [_pass()],
            [_pass()],
          ])
          ..missing.add('a')
          ..throwing.add('b');
    final result = await revalidateAndExport(
      [_stale('a'), _stale('b'), _stale('c')],
      evaluator: evaluator,
      export: evaluator.exportFor,
      settings: _settings,
    );

    expect(result.bodies, ['{"tag":"c"}']);
    expect(result.failed, hasLength(2));
  });
}
