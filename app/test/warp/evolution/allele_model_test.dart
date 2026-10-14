import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/allele_model.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/pools.dart';

/// §848 — модель аллелей (UMDA): сглаживание, веса элиты, семпл, мутация,
/// кроссовер и метрики разнообразия.
void main() {
  const pool = EvolutionPools(
    endpoints: ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
    sni: ['yandex.ru', 'mail.ru'],
    dnsTags: ['d1'],
    wgPorts: [2408],
    h3Ports: [443],
    h2Ports: [8443],
    keepalives: [0, 25],
    mtus: [0, 1280],
    junkProtocols: ['quic', 'dns'],
    junkBrowsers: ['chrome'],
    junkCounts: [0, 4],
    junkSizeMins: [40],
    junkSizeMaxs: [70],
    sniCaseSeeds: [0, 1],
  );

  Genome g({
    EvoTransport t = EvoTransport.awg,
    String endpoint = '1.1.1.1',
    int port = 2408,
    String sni = 'yandex.ru',
    String dnsTag = '',
    int sniCase = 0,
  }) =>
      Genome(
          transport: t,
          endpoint: endpoint,
          port: port,
          sni: sni,
          dnsTag: dnsTag,
          sniCase: sniCase);

  group('AlleleModel.fit', () {
    test('пустая элита — пустая модель', () {
      expect(AlleleModel.fit(const [], pool).locusCount, 0);
    });

    test('сглаживание Лапласа оставляет шанс непроверенному аллелю', () {
      final m = AlleleModel.fit([g(sni: 'yandex.ru')], pool);
      expect(m.probability(EvoLocus.sni, 'yandex.ru'), greaterThan(0.5));
      expect(m.probability(EvoLocus.sni, 'mail.ru'), greaterThan(0),
          reason: 'без права на разведку поиск вырождается в копии элиты');
    });

    test('prior=0 копирует элиту буквально', () {
      final m = AlleleModel.fit([g(sni: 'yandex.ru')], pool, prior: 0);
      expect(m.probability(EvoLocus.sni, 'mail.ru'), 0);
      expect(m.probability(EvoLocus.sni, 'yandex.ru'), 1);
    });

    test('вероятности локуса нормированы', () {
      final m = AlleleModel.fit([g(), g(sni: 'mail.ru')], pool);
      final sum = m.allelesOf(EvoLocus.sni)!.values.fold<double>(0, (a, b) => a + b);
      expect(sum, closeTo(1, 1e-9));
    });

    test('вес элиты смещает распределение к лучшим', () {
      final m = AlleleModel.fit(
        [g(sni: 'yandex.ru'), g(sni: 'mail.ru')],
        pool,
        weighting: const [3, 1],
        prior: 0,
      );
      expect(m.probability(EvoLocus.sni, 'yandex.ru'), closeTo(0.75, 1e-9));
      expect(m.probability(EvoLocus.sni, 'mail.ru'), closeTo(0.25, 1e-9));
    });

    test('значение вне домена не выбрасывается, а добавляется в модель', () {
      final m = AlleleModel.fit([g(endpoint: '9.9.9.9')], pool);
      expect(m.probability(EvoLocus.endpoint, '9.9.9.9'), greaterThan(0),
          reason: 'посев пользователя — его выбор, а не ошибка модели');
    });

    test('локусы с пустым доменом в модель не попадают', () {
      const empty = EvolutionPools();
      final m = AlleleModel.fit([g()], empty);
      expect(m.allelesOf(EvoLocus.endpoint), isNull);
      expect(m.allelesOf(EvoLocus.keepalive), isNotNull,
          reason: 'тайминги имеют домен по умолчанию');
    });
  });

  group('sample', () {
    test('порт всегда из диапазона транспорта', () {
      final m = AlleleModel.fit(
          [g(t: EvoTransport.masqueH3, endpoint: '2.2.2.2', port: 443)], pool);
      final rng = Random(2);
      for (var i = 0; i < 200; i++) {
        final s = m.sample(rng, pool);
        expect(pool.portsFor(s.transport), contains(s.port));
        expect(s.endpoint, isNotEmpty);
      }
    });

    test('частоты модели воспроизводятся в выборке', () {
      final m = AlleleModel.fit(
          [g(sni: 'yandex.ru'), g(sni: 'mail.ru'), g(sni: 'mail.ru')], pool);
      final rng = Random(7);
      var mail = 0;
      for (var i = 0; i < 400; i++) {
        if (m.sample(rng, pool).sni == 'mail.ru') mail++;
      }
      expect(mail / 400, greaterThan(0.4),
          reason: 'аллель победителя должен встречаться чаще');
    });

    test('locus без модели берётся из пула, а пустой пул остаётся пустым', () {
      final m = AlleleModel({});
      final s = m.sample(Random(1), pool);
      expect(s.endpoint, isNotEmpty);
      expect(m.sample(Random(1), const EvolutionPools()).endpoint, isEmpty);
    });
  });

  group('mutate / uniformCrossover', () {
    test('mutationRate=0 не меняет особь', () {
      final rng = Random(1);
      final base = g(sni: 'mail.ru', dnsTag: 'd1');
      for (var i = 0; i < 50; i++) {
        expect(mutate(base, pool, rng, mutationRate: 0).key, base.key);
      }
    });

    test('мутация берёт значения только из пула', () {
      final rng = Random(5);
      for (var i = 0; i < 200; i++) {
        final m = mutate(g(), pool, rng, mutationRate: 0.4);
        expect([...pool.endpoints], contains(m.endpoint));
        expect([...pool.sni, ''], contains(m.sni));
        expect([...pool.dnsTags, ''], contains(m.dnsTag));
      }
    });

    test('замороженный локус мутация не трогает', () {
      const r = RestrictedPools(pool, disabledLoci: {EvoLocus.sni, EvoLocus.dns});
      final rng = Random(9);
      for (var i = 0; i < 200; i++) {
        final m = mutate(g(sni: 'mail.ru', dnsTag: 'd1'), r, rng,
            mutationRate: 1);
        expect(m.sni, 'mail.ru');
        expect(m.dnsTag, 'd1');
      }
    });

    test('кроссовер собирает ребёнка только из значений родителей', () {
      final a = g(endpoint: '1.1.1.1', sni: 'yandex.ru', dnsTag: 'd1');
      final b = g(endpoint: '2.2.2.2', sni: 'mail.ru', dnsTag: '');
      final rng = Random(13);
      final ta = a.tokens();
      final tb = b.tokens();
      for (var i = 0; i < 200; i++) {
        final c = uniformCrossover(a, b, rng);
        for (final l in EvoLocus.values) {
          final v = c.tokens()[l];
          expect([ta[l], tb[l]], contains(v), reason: l.wire);
        }
        expect([a.port, b.port], contains(c.port));
      }
    });

    test('alpha=1 → весь геном от первого родителя', () {
      final a = g(endpoint: '1.1.1.1', sni: 'yandex.ru');
      final b = g(endpoint: '2.2.2.2', sni: 'mail.ru');
      expect(uniformCrossover(a, b, Random(3), alpha: 1).key, a.key);
    });
  });

  group('разнообразие', () {
    test('одинаковые особи — ноль, разные — положительно', () {
      expect(diversity([g(), g()]), 0);
      expect(diversity([g()]), 0);
      expect(diversity(const []), 0);
      expect(
          diversity([
            g(),
            g(
              t: EvoTransport.masqueH2,
              endpoint: '3.3.3.3',
              port: 8443,
              sni: 'mail.ru',
              dnsTag: 'd1',
              sniCase: 1,
            ),
          ]),
          greaterThan(0));
    });

    test('всплеск иммигрантов при схлопывании популяции', () {
      expect(immigrantCount(16, 0.5, 0.15), (16 * 0.15).round());
      expect(immigrantCount(16, 0.05, 0.15), (16 * 0.5).round(),
          reason: 'diversity < 0.12 → ×4, но не больше половины популяции');
      expect(immigrantCount(16, 0.05, 0.3), 8, reason: 'потолок 0.5');
    });
  });
}
