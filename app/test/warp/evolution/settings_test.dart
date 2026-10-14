import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/pools.dart';
import 'package:lxbox/services/evolution/settings.dart';

/// §848 — настройки прогона: сериализация, производные величины и то, как
/// настройки превращаются в домены мутаций.
void main() {
  const pool = EvolutionPools(
    endpoints: ['1.1.1.1', '2.2.2.2'],
    transports: {EvoTransport.awg, EvoTransport.masqueH2},
  );

  const custom = EvolutionSettings(
    populationSize: 24,
    maxGenerations: 5,
    maxRequests: 900,
    rungAttempts: [1, 3],
    rungKeepFraction: 0.4,
    eliteFraction: 0.25,
    mutationRate: 0.3,
    immigrantFraction: 0.2,
    hallOfFameSize: 8,
    confirmationsNeeded: 3,
    targetCountry: 'de',
    countries: ['de', 'nl'],
    transports: {EvoTransport.masqueH2},
    disabledLoci: {EvoLocus.mtu, EvoLocus.dns},
    useEda: false,
    allowFragment: false,
    allowRecordFragment: false,
    requestTimeout: Duration(seconds: 3),
    seed: 1234,
    minPassRate: 0.5,
  );

  test('дефолты — в документированных границах', () {
    const s = EvolutionSettings();
    expect(s.populationSize, inInclusiveRange(EvolutionSettings.minPopulation,
        EvolutionSettings.maxPopulation));
    expect(s.maxGenerations,
        inInclusiveRange(EvolutionSettings.minGenerations,
            EvolutionSettings.maxGenerationsLimit));
    expect(s.maxRequests, inInclusiveRange(EvolutionSettings.minRequestBudget,
        EvolutionSettings.maxRequestBudget));
    expect(s.rungAttempts, isNotEmpty);
    expect(s.transports, EvoTransport.values.toSet());
    expect(s.disabledLoci, isEmpty);
    expect(s.locusEnabled(EvoLocus.transport), isTrue);
  });

  test('toJson → fromJson сохраняет всё, включая транспорты и заморозки', () {
    final back = EvolutionSettings.fromJson(custom.toJson());
    expect(back.toJson(), custom.toJson());
    expect(back.transports, {EvoTransport.masqueH2});
    expect(back.disabledLoci, {EvoLocus.mtu, EvoLocus.dns});
    expect(back.locusEnabled(EvoLocus.mtu), isFalse);
    expect(back.useEda, isFalse);
    expect(back.requestTimeout, const Duration(seconds: 3));
    expect(back.countries, ['de', 'nl']);
  });

  test('пустой/битый JSON — не падает, а даёт дефолты', () {
    final empty = EvolutionSettings.fromJson(const {});
    expect(empty.populationSize, 16);
    // Дефолт бюджета = полный прогон по дефолтам с худшим множителем на вердикт
    // (проба чередует 3 источника гео, §844) — иначе потолок режет кампанию.
    expect(empty.maxRequests, 1080);
    expect(empty.transports, EvoTransport.values.toSet(),
        reason: 'пустышка транспортов = запрет поиска, берём все');
    expect(EvolutionSettings.fromJson(const {'rungAttempts': [0, -1, 2]}).rungAttempts, [2]);
    expect(
        EvolutionSettings.fromJson(const {'maxRequests': 'oops'}).maxRequests,
        1080);
  });

  group('производные величины', () {
    test('keepOf: две особи не усечатся, дальше — доля с округлением', () {
      const s = EvolutionSettings(rungKeepFraction: 0.5);
      expect(s.keepOf(1), 1);
      expect(s.keepOf(2), 2);
      expect(s.keepOf(3), 2);
      expect(s.keepOf(16), 8);
      expect(const EvolutionSettings(rungKeepFraction: 0.1).keepOf(16), 2);
      expect(const EvolutionSettings(rungKeepFraction: 0.9).keepOf(10), 9);
    });

    test('eliteSize не опускается ниже двух — UMDA без пары родителей мертва',
        () {
      expect(const EvolutionSettings(populationSize: 6, eliteFraction: 0.05).eliteSize, 2);
      expect(const EvolutionSettings(populationSize: 16, eliteFraction: 0.35).eliteSize, 6);
    });

    test('budgetLeft считает до потолка включительно', () {
      const s = EvolutionSettings(maxRequests: 100);
      expect(s.budgetLeft(99), isTrue);
      expect(s.budgetLeft(100), isFalse);
    });

    test("фиксированный seed повторяем, разные seed'ы расходятся", () {
      const fixed = EvolutionSettings(seed: 777);
      expect(fixed.rng().nextDouble(), fixed.rng().nextDouble());
      // seed=0 берёт время с часов — два вызова подряд попадают в один тик,
      // поэтому сравнивать между собой его нельзя; проверяем только расхождение
      // явных seed'ов (именно это нужно для «почему вчера было лучше»).
      expect(const EvolutionSettings(seed: 777).rng().nextDouble(),
          isNot(const EvolutionSettings(seed: 778).rng().nextDouble()));
      expect(const EvolutionSettings(seed: 0).rng().nextDouble(), inInclusiveRange(0, 1));
    });
  });

  group('poolsFor', () {
    test('настройки ограничивают домен transport', () {
      final p = const EvolutionSettings(
              transports: {EvoTransport.masqueH2}).poolsFor(pool);
      expect(p.alleles(EvoLocus.transport).values, ['h2']);
    });

    test('замороженные локусы теряют домен', () {
      final p = const EvolutionSettings(
              disabledLoci: {EvoLocus.mtu, EvoLocus.endpoint})
          .poolsFor(pool);
      expect(p.alleles(EvoLocus.mtu).isEmpty, isTrue);
      expect(p.alleles(EvoLocus.endpoint).isEmpty, isTrue);
      expect(p.alleles(EvoLocus.port).isEmpty, isFalse);
    });

    test('запрет фрагментации снимает её из домена и из посевной особи', () {
      final p = const EvolutionSettings(
              allowFragment: false, allowRecordFragment: false)
          .poolsFor(pool);
      expect(p.alleles(EvoLocus.fragment).values, ['0']);
      final g = p.random(Random(0));
      expect(g.fragment, isFalse);
      expect(g.recordFragment, isFalse);
    });

    test('страны из настроек доходят до выборки', () {
      final withCountries = EvolutionPools(
        endpoints: const ['1.1.1.1'],
        endpointsByCountry: const {
          'de': ['2.2.2.2'],
        },
      );
      final p = const EvolutionSettings(countries: ['de']).poolsFor(withCountries);
      expect(p.alleles(EvoLocus.endpoint, countries: const ['de']).values,
          ['2.2.2.2']);
    });
  });
}
