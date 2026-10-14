import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/engine.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/objectives.dart';
import 'package:lxbox/services/evolution/pools.dart';
import 'package:lxbox/services/evolution/settings.dart';

/// §848 — движок эволюции на фейковом оценщике: successive halving, бюджет
/// запросов, гистерезис архива, сохранение элиты и воспроизводимость по seed.
/// Живая probe-сессия здесь не нужна намеренно — вся логика отбора проверяема
/// без устройства.
void main() {
  const pool = EvolutionPools(
    endpoints: ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
    sni: ['yandex.ru'],
    dnsTags: ['d1'],
    wgPorts: [2408],
    h3Ports: [443],
    h2Ports: [8443],
  );

  const seeds = [
    Genome(transport: EvoTransport.awg, endpoint: '1.1.1.1', port: 2408, sni: 'yandex.ru'),
    Genome(
        transport: EvoTransport.masqueH3,
        endpoint: '2.2.2.2',
        port: 443,
        sni: 'yandex.ru',
        keepalive: 25),
    Genome(
        transport: EvoTransport.masqueH2,
        endpoint: '3.3.3.3',
        port: 8443,
        sni: 'yandex.ru',
        fragment: true),
  ];

  EvolutionSettings s({
    int population = 6,
    int generations = 1,
    int maxRequests = 500,
    List<int> rungs = const [1, 2],
    double keep = 0.5,
    int confirmations = 1,
    int hall = 12,
    int seed = 7,
    double eliteFraction = 0.5,
    double minPassRate = 0.34,
    Set<EvoTransport> transports = const {
      EvoTransport.awg,
      EvoTransport.masqueH3,
      EvoTransport.masqueH2,
    },
  }) =>
      EvolutionSettings(
        populationSize: population,
        maxGenerations: generations,
        maxRequests: maxRequests,
        rungAttempts: rungs,
        rungKeepFraction: keep,
        confirmationsNeeded: confirmations,
        hallOfFameSize: hall,
        seed: seed,
        eliteFraction: eliteFraction,
        minPassRate: minPassRate,
        transports: transports,
        immigrantFraction: 0.0,
        mutationRate: 0.0,
      );

  test('prepare отказал — прогон не стартует и не тратит запросы', () async {
    final fake = _FakeEvaluator(
        prepareReason: 'Turn the VPN off — the probe session cannot start');
    final engine =
        EvolutionEngine(evaluator: fake, pools: pool, settings: s());
    final out = await engine.run(seeds);
    expect(out.error, 'Turn the VPN off — the probe session cannot start');
    expect(fake.batches, isEmpty);
    expect(out.requestsUsed, 0);
    expect(out.generations, 0);
    expect(out.hallOfFame, isEmpty);
  });

  test('successive halving: попытки растут, выборка сужается, бюджет = пробы',
      () async {
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1, 2, 3]));
    final out = await engine.run(seeds);

    expect(fake.attempts, [1, 2, 3]);
    expect(fake.batches.map((b) => b.length), [6, 3, 2]);
    expect(out.requestsUsed, 6 * 1 + 3 * 2 + 2 * 3);
    expect(engine.requestsUsed, out.requestsUsed);
    expect(out.stats.single.rungKeeps, 2);
    expect(out.stats.single.evaluated, 6);
    expect(out.stats.single.alive, 6, reason: 'все пробы прошли');
    expect(out.stats.single.paretoFrontSize, greaterThanOrEqualTo(1));
    expect(out.stats.single.bestPassRate, 1);
    expect(out.stats.single.bestRttMs, 100);
    expect(out.stats.single.diversity, greaterThan(0));
  });

  test('гистерезис: один прогон даёт подтверждение, но не архив', () async {
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1, 2, 3], confirmations: 2));
    final out = await engine.run(seeds);
    expect(out.hallOfFame, isEmpty,
        reason: 'подтверждать надо в РАЗНЫХ поколениях, не в разных рангах');
    expect(engine.records.every((r) => r.confirmations <= 1), isTrue);
    // Дошедшие до третьего ранга имеют шесть наблюдений — и одно подтверждение.
    expect(
        engine.records
            .where((r) => r.lifetime.attempts >= 3)
            .every((r) => r.confirmations == 1),
        isTrue);
  });

  test('гистерезис: повторный проход в следующем поколении открывает архив',
      () async {
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1], confirmations: 2, generations: 2));
    final out = await engine.run(seeds);
    expect(out.generations, 2);
    expect(out.hallOfFame, isNotEmpty);
    expect(out.hallOfFame.every((f) => f.confirmations >= 2), isTrue);
  });

  test('ни одна проба не прошла: ноль проходимых и пустой архив', () async {
    final fake = _FakeEvaluator(pass: (_) => false);
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1, 2, 3], confirmations: 2));
    final out = await engine.run(seeds);
    expect(fake.attempts, [1], reason: 'после пустого отсеченного ранга дальше не идём');
    expect(out.stats.single.alive, 0);
    expect(out.stats.single.bestPassRate, 0);
    expect(out.hallOfFame, isEmpty);
    expect(out.requestsUsed, 6);
  });

  test('бюджет запросов — валюта прогона: перерасход ограничен одним рангом',
      () async {
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1, 2, 3], maxRequests: 10, generations: 8));
    final out = await engine.run(seeds);
    // Ранг проверяет бюджет ДО запуска, поэтому первый ранг (6) и второй (6)
    // оплачиваются целиком, а третий уже нет: итог — 12 при потолке 10.
    expect(fake.attempts, [1, 2]);
    expect(out.requestsUsed, 12);
    expect(out.generations, 1);
  });

  test('отмена останавливает движок между рангами', () async {
    final fake = _FakeEvaluator();
    late final EvolutionEngine engine;
    engine = EvolutionEngine(
        evaluator: fake, pools: pool, settings: s(rungs: const [1, 2, 3]));
    fake.beforeEvaluate = () {
      if (fake.batches.length == 1) engine.cancel();
    };
    final out = await engine.run(seeds);
    expect(out.cancelled, isTrue);
    expect(fake.attempts, [1], reason: 'второй ранг уже не стартует');
    expect(out.generations, 1);
  });

  test('пауза держит движок до resume, но не навсегда', () async {
    final fake = _FakeEvaluator();
    late final EvolutionEngine engine;
    engine = EvolutionEngine(
        evaluator: fake, pools: pool, settings: s(rungs: const [1, 2]));
    fake.beforeEvaluate = () {
      if (fake.batches.length == 1) {
        engine.pause();
        Future<void>.delayed(const Duration(milliseconds: 5), engine.resume);
      }
    };
    final out = await engine.run(seeds);
    expect(fake.attempts, [1, 2]);
    expect(out.cancelled, isFalse);
  });

  test('один seed — один и тот же поиск', () async {
    List<String> flatten(List<List<String>> batches) =>
        [for (final b in batches) ...b];
    final a = _FakeEvaluator();
    final b = _FakeEvaluator();
    final settings = s(rungs: const [1], generations: 3, seed: 42);
    await EvolutionEngine(evaluator: a, pools: pool, settings: settings).run(seeds);
    await EvolutionEngine(evaluator: b, pools: pool, settings: settings).run(seeds);
    expect(flatten(b.batches), flatten(a.batches));

    final c = _FakeEvaluator();
    await EvolutionEngine(evaluator: c, pools: pool, settings: s(rungs: const [1], generations: 3, seed: 43))
        .run(seeds);
    expect(flatten(c.batches), isNot(flatten(a.batches)),
        reason: 'разное зерно должно давать разный поиск');
  });

  test('короткий ответ оценщика: считаются только пришедшие пробы', () async {
    final fake = _FakeEvaluator(truncate: true);
    final engine = EvolutionEngine(
        evaluator: fake, pools: pool, settings: s(rungs: const [1]));
    final out = await engine.run(seeds);
    expect(out.requestsUsed, 3, reason: 'из шести особей оценки дошли только трём');
    expect(out.stats.single.evaluated, 6);
    expect(out.stats.single.alive, 3);
    expect(engine.requestsUsed, 3);
  });

  test('элита выживает: чемпион посева остаётся в следующем поколении',
      () async {
    const champion = Genome(
        transport: EvoTransport.awg,
        endpoint: '9.9.9.9',
        port: 2408,
        sni: 'yandex.ru');
    final fake = _FakeEvaluator(pass: (g) => g.endpoint == '9.9.9.9');
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1], generations: 2, confirmations: 2));
    final out = await engine.run([champion, ...seeds]);

    expect(fake.batches[1], contains(champion.key),
        reason: 'лучший кандидат не может исчезнуть из-за одной плохой кампании');
    expect(out.hallOfFame, hasLength(1));
    expect(out.hallOfFame.single.genome.key, champion.key);
    // В первом поколении проверялись все особи, включая случайных иммигрантов.
    expect(fake.batches.first.first, champion.key);
  });

  test('размер архива ограничен настройкой', () async {
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(
            rungs: const [1], generations: 2, confirmations: 2, hall: 2));
    final out = await engine.run(seeds);
    expect(out.hallOfFame.length, lessThanOrEqualTo(2));
    expect(out.hallOfFame, isNotEmpty);
  });

  test('движок не гасит оценщик: ресурсы владельца — вне его ответственности',
      () async {
    final fake = _FakeEvaluator();
    await EvolutionEngine(evaluator: fake, pools: pool, settings: s())
        .run(seeds);
    expect(fake.disposes, 0);
  });

  test('наблюдения и сводка доходят до экрана', () async {    final fake = _FakeEvaluator(rtt: 210, country: 'nl');
    final seen = <String>[];
    final rungsSeen = <int>[];
    final summaries = <GenerationSummary>[];
    final notes = <String>[];
    final engine = EvolutionEngine(
      evaluator: fake,
      pools: pool,
      settings: s(rungs: const [1, 2]),
      onObservation: (g, f, rung) {
        seen.add(g.key);
        rungsSeen.add(rung);
        expect(identical(f.genome, g), isTrue);
      },
      onGeneration: summaries.add,
      onNote: notes.add,
    );
    final out = await engine.run(seeds);
    expect(
        seen,
        hasLength(12),
        reason: '6 проб на первом ранге + 3 выживших × 2 пробы на втором');
    expect(rungsSeen.toSet(), {0, 1});
    expect(summaries, hasLength(1));
    expect(summaries.single.bestRttMs, 210);
    expect(out.stats, hasLength(1));
    expect(notes, isNotEmpty);
    expect(out.generations, 1);
    expect(out.hallOfFame.first.country, 'nl');
  });

  test('посев больше популяции: первый ранг платит только за популяцию',
      () async {
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(population: 4, rungs: const [1], generations: 1));
    final out = await engine.run(_seedsDifferingByDns(10));
    expect(fake.batches.single, hasLength(4),
        reason: '66 рабочих конфигов при pop=16 не должны сжигать 40 % бюджета');
    expect(out.requestsUsed, 4);
    expect(out.stats.single.evaluated, 4);
  });

  test('резерв посева входит иммигрантом, когда потомки не дают новых особей',
      () async {
    // Пул из одного адреса/SNI/порта при нулевой мутации: все дети совпадают с
    // элитой, поэтому единственный способ добить популяцию — резерв посева.
    const narrow = EvolutionPools(
      endpoints: ['1.1.1.1'],
      sni: ['yandex.ru'],
      dnsTags: ['d1'],
      wgPorts: [2408],
      h3Ports: [443],
      h2Ports: [8443],
    );
    final fake = _FakeEvaluator();
    final engine = EvolutionEngine(
      evaluator: fake,
      pools: narrow,
      settings: s(
          population: 4,
          rungs: const [1],
          generations: 2,
          transports: const {EvoTransport.awg}),
    );
    await engine.run(_seedsDifferingByDns(6));
    expect(fake.batches, hasLength(2));
    final first = fake.batches.first.toSet();
    expect(fake.batches[1].where((k) => !first.contains(k)), isNotEmpty,
        reason: 'излишек посева обязан попасть в поиск следующих поколений');
  });

  test('бюджет считается в HTTP-запросах, а не в вердиктах', () async {
    // Ротация источников гео (§844) делает вердикт дороже одного probeGetUrl:
    // без учёта Observation.requests «0 % проходимых» выглядел бы дешевле, чем
    // он стоил, и потолок бюджета врёт.
    final fake = _FakeEvaluator(requestsPerProbe: 3);
    final engine = EvolutionEngine(
        evaluator: fake,
        pools: pool,
        settings: s(rungs: const [1, 2], maxRequests: 500));
    final out = await engine.run(seeds);
    expect(out.requestsUsed, 12 * 3,
        reason: '6×1 + 3×2 вердиктов по 3 запроса каждый');
    expect(out.stats.single.requestsUsed, 36);
  });

  test('проходимых ноль — сводка несёт top-причины отказов', () async {
    final fake = _FakeEvaluator(pass: (_) => false);
    final notes = <String>[];
    final engine = EvolutionEngine(
      evaluator: fake,
      pools: pool,
      settings: s(rungs: const [1]),
      onNote: notes.add,
    );
    final out = await engine.run(seeds);
    expect(out.stats.single.alive, 0);
    expect(out.stats.single.failureReasons, isNotEmpty);
    expect(topReasons({'err=dial tcp: timeout': 6, 'no such host': 1}),
        'err=dial tcp: timeout ×6; no such host ×1');
    expect(notes.any((n) => n.contains('причины отказов')), isTrue,
        reason: 'движок обязан сказать причины в журнале, а не только «0 %»');
  });
}

/// Посев, отличающийся РОВНО одним геном (DNS), чтобы `key` был уникальным, а
/// всё остальное — предсказуемым.
List<Genome> _seedsDifferingByDns(int n) => [
      for (var i = 0; i < n; i++)
        const Genome(
          transport: EvoTransport.awg,
          endpoint: '1.1.1.1',
          port: 2408,
          sni: 'yandex.ru',
        ).copyWith(dnsTag: 'seed$i'),
    ];

/// Детерминированный фейк оценщика: никаких сетей, только воля теста.
class _FakeEvaluator implements GenomeEvaluator {
  _FakeEvaluator({
    this.pass,
    this.rtt = 100,
    this.country = 'de',
    this.prepareReason,
    this.truncate = false,
    this.requestsPerProbe = 1,
  });

  /// null — все пробы проходят.
  final bool Function(Genome genome)? pass;
  final int rtt;
  final String country;
  String? prepareReason;

  /// Сколько HTTP-запросов стоит один вердикт (ротация источников гео).
  final int requestsPerProbe;

  /// Возвращать оценки только для половины особей (урезанный ответ ядра).
  final bool truncate;

  /// Вызывается перед выдачей проб — отсюда тесты отменяют и ставят паузу.
  void Function()? beforeEvaluate;

  final List<List<String>> batches = [];
  final List<int> attempts = [];
  int disposes = 0;

  @override
  Future<String?> prepare() async => prepareReason;

  @override
  Future<void> dispose() async => disposes++;

  @override
  Future<List<List<Observation>>> evaluate(
    List<Genome> genomes, {
    required int attempts,
    void Function(int index, Observation observation)? onOne,
    bool Function()? cancelled,
  }) async {
    batches.add([for (final g in genomes) g.key]);
    this.attempts.add(attempts);
    beforeEvaluate?.call();

    final out = <List<Observation>>[];
    for (var i = 0; i < genomes.length; i++) {
      final ok = (pass ?? (_) => true)(genomes[i]);
      final list = [
        for (var a = 0; a < attempts; a++)
          ok
              ? Observation(
                  responded: true,
                  status: 200,
                  rttMs: rtt,
                  country: country,
                  requests: requestsPerProbe)
              : Observation.failed('timeout', requests: requestsPerProbe),
      ];
      for (final o in list) {
        onOne?.call(i, o);
      }
      out.add(list);
    }
    if (!truncate) return out;
    return out.sublist(0, (out.length / 2).ceil());
  }
}
