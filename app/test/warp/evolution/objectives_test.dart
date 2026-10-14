import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/objectives.dart';

/// §848 — накопитель наблюдений и многокритериальный отбор (NSGA-II).
void main() {
  const g =
      Genome(transport: EvoTransport.awg, endpoint: '162.159.192.7', port: 2408);

  Observation ok({int rtt = 100, String country = 'de', String colo = 'fra01'}) =>
      Observation(responded: true, status: 200, rttMs: rtt, country: country, colo: colo);
  Observation bad({String error = 'timeout', int requests = 1}) =>
      Observation.failed(error, requests: requests);

  Fitness of(List<Observation> obs) {
    final f = Fitness(g);
    for (final o in obs) {
      f.add(o);
    }
    return f;
  }

  group('Fitness', () {
    test('пустая особь: нули и нет медианы', () {
      final f = Fitness(g);
      expect(f.attempts, 0);
      expect(f.passRate, 0);
      expect(f.confidence, 0);
      expect(f.medianRtt, isNull);
      expect(f.country, isEmpty);
      expect(f.colo, isEmpty);
      expect(f.lastError, isEmpty);
    });

    test('passRate и confidence: одна проба — ещё не вердикт', () {
      final f = of([ok(), bad(), bad()]);
      expect(f.attempts, 3);
      expect(f.passes, 1);
      expect(f.passRate, closeTo(1 / 3, 1e-9));
      expect(of([ok()]).confidence, closeTo(1 / 3, 1e-9));
      expect(of([ok(), ok()]).confidence, closeTo(2 / 3, 1e-9));
      expect(f.confidence, 1.0);
      expect(of([ok(), ok(), ok(), ok()]).confidence, 1.0,
          reason: 'confidence насыщается на трёх наблюдениях');
      expect(f.requestsUsed, 3, reason: 'каждое наблюдение = один запрос');
    });

    test('медиана RTT по успешным пробам (чётное число — среднее двух)', () {
      expect(of([ok(rtt: 300), ok(rtt: 100), ok(rtt: 200)]).medianRtt, 200);
      expect(of([ok(rtt: 100), ok(rtt: 300)]).medianRtt, 200);
      expect(of([ok(rtt: 100), bad(), ok(rtt: 900)]).medianRtt, 500);
    });

    test('страна и colo — мода голосов только по успешным пробам', () {
      final f = of([
        ok(country: 'de', colo: 'fra01'),
        ok(country: 'de', colo: 'fra01'),
        ok(country: 'nl', colo: 'ams01'),
        bad(),
      ]);
      expect(f.country, 'de');
      expect(f.colo, 'fra01');
    });

    test('последняя ошибка — из последнего неудачного наблюдения', () {
      expect(of([bad(), ok(), bad()]).lastError, 'timeout');
    });

    test('copy сохраняет накопленные счётчики', () {
      final f = of([ok(rtt: 120), bad()])
        ..confirmations = 2
        ..rungReached = 3;
      final c = f.copy();
      expect(c.attempts, f.attempts);
      expect(c.passes, f.passes);
      expect(c.medianRtt, f.medianRtt);
      expect(c.country, f.country);
      expect(c.confirmations, 2);
      expect(c.rungReached, 3);
      expect(identical(c, f), isFalse);
    });

    test('observations хранят весь ряд и переносятся в copy', () {
      final f = of([ok(rtt: 120), bad(), ok(rtt: 90)]);
      expect(f.observations, hasLength(f.attempts),
          reason: 'без исходного ряда слияние поколений теряет пробы (§848)');
      expect(f.copy().observations, hasLength(3));
      final merged = f.copy()..add(ok(rtt: 70));
      expect(merged.observations, hasLength(4));
      expect(merged.attempts, 4);
      expect(merged.medianRtt, 90, reason: 'медиана ряда 70/90/120');
    });

    test('requests суммируются: вердикт стоит не один запрос', () {
      // Ротация источников гео (§844) делает одну пробу дороже — бюджет прогона
      // обязан считать запросы, а не вердикты.
      final f = of([
        const Observation(responded: true, status: 200, rttMs: 50, requests: 3),
        Observation.failed('timeout', requests: 2),
      ]);
      expect(f.attempts, 2);
      expect(f.requestsUsed, 5);
      expect(f.copy().requestsUsed, 5);
    });

    test('errorSignatures сворачивает адреса и тайминги в одну корзину', () {
      final f = of([
        Observation.failed('dial tcp 162.159.192.1:443: i/o timeout after 8000 ms'),
        Observation.failed('dial tcp 162.159.130.5:8443: i/o timeout after 8000 ms'),
        Observation.failed('no such host', requests: 3),
      ]);
      final s = f.errorSignatures();
      expect(s.values.reduce((a, b) => a + b), 3);
      expect(s, hasLength(2),
          reason: 'иначе 66 одинаковых причин дали бы 66 корзин');
      expect(errorSignature('HTTP 403 (не 2xx) — error code: 1020'),
          contains('#'));
      expect(errorSignature('   '), isEmpty);
    });
  });

  group('objectives', () {
    test('все три цели на максимизацию: проходимость, скорость, попадание', () {
      final f = of([ok(rtt: 400), ok(rtt: 400), ok(rtt: 400)]);
      final o = f.objectives(targetCountry: 'de');
      expect(o[0], 1);
      expect(o[1], closeTo(1 - 400 / 2000, 1e-9));
      expect(o[2], 1);
    });

    test('мёртвый кандидат не выигрывает по скорости «пустым» RTT', () {
      expect(of([bad(), bad()]).objectives()[1], 0);
      expect(Fitness(g).objectives()[1], 0);
    });

    test('скорость гаснет к 2000 мс и не уходит в минус', () {
      expect(of([ok(rtt: 2000)]).objectives()[1], 0);
      expect(of([ok(rtt: 5000)]).objectives()[1], 0);
    });

    test('без целевой страны попадание нейтрально, с целью — штраф за страну',
        () {
      final f = of([ok(country: 'de')]);
      expect(f.objectives(targetCountry: '')[2], 1);
      expect(f.objectives(targetCountry: 'de')[2], 1);
      expect(f.objectives(targetCountry: 'nl')[2], 0);
      expect(Fitness(g).objectives(targetCountry: 'nl')[2], 0.25,
          reason: 'страна ещё не известна — небольшой кредит, чтобы особь '
              'дожила до следующих проб');
    });
  });

  group('fastNonDominatedSort', () {
    test('пустой вход и одиночка', () {
      expect(fastNonDominatedSort(const []), isEmpty);
      expect(fastNonDominatedSort(const [[1.0, 0.5]]), [
        [0]
      ]);
    });

    test('компромиссы стоят в одном фронте, заведомо худший — во втором', () {
      final fronts = fastNonDominatedSort(const [
        [1.0, 0.0], //
        [0.0, 1.0],
        [0.5, 0.5],
        [0.4, 0.4], // хуже [0.5,0.5] по обеим целям
      ]);
      expect(fronts[0], [0, 1, 2]);
      expect(fronts[1], [3]);
    });

    test('полная цепочка доминирования даёт по одной особи на фронт', () {
      final fronts = fastNonDominatedSort(
          [for (var i = 0; i < 5; i++) [i.toDouble(), i.toDouble()]]);
      expect(fronts, [
        [4],
        [3],
        [2],
        [1],
        [0]
      ]);
    });

    test('равные особи не доминируют друг друга', () {
      expect(
          fastNonDominatedSort(const [
            [0.5, 0.5],
            [0.5, 0.5],
            [0.5, 0.5],
          ]),
          [
            [0, 1, 2]
          ]);
    });
  });

  group('crowdingDistance', () {
    test('фронт из двух и меньше — все бесконечные', () {
      expect(crowdingDistance(const [0], const [[1.0]]), [double.infinity]);
      expect(crowdingDistance(const [0, 1], const [[1.0], [0.0]]),
          [double.infinity, double.infinity]);
    });

    test('границы фронта бесконечны, середина считает размах соседей', () {
      final d = crowdingDistance(const [0, 1, 2], const [[1.0], [2.0], [3.0]]);
      expect(d[0], double.infinity);
      expect(d[2], double.infinity);
      expect(d[1], closeTo(1.0, 1e-9),
          reason: '(3-1)/(3-1) = 1 по единственной цели');
    });

    test('константная цель не даёт NaN', () {
      final d = crowdingDistance(const [0, 1, 2],
          const [[1.0, 0.5], [1.0, 0.25], [1.0, 0.75]]);
      expect(d.every((e) => !e.isNaN), isTrue);
    });
  });

  group('nsga2Order', () {
    Fitness make(List<Observation> obs) {
      final f = Fitness(g);
      for (final o in obs) {
        f.add(o);
      }
      return f;
    }

    test('идентичные особи стоят в одном фронте', () {
      final list = [for (var i = 0; i < 3; i++) make([ok(rtt: 100)])];
      expect(nsga2Order(list).toSet(), {0, 1, 2});
    });

    test('особь без ответа уступает ответившей', () {
      final order = nsga2Order([make([bad()]), make([ok(rtt: 50)])]);
      expect(order.first, 1);
    });

    test('цепочка доминирования: фронты по одному, maxFronts их усекает', () {
      final chain = [for (var i = 0; i < 6; i++) make([ok(rtt: i * 100)])];
      expect(nsga2Order(chain).first, 0, reason: 'самый быстрый — вне конкуренции');
      expect(nsga2Order(chain, maxFronts: 2), hasLength(2));
      expect(nsga2Order(chain, maxFronts: 2), [0, 1]);
    });

    test('целевая страна меняет структуру фронта', () {
      final de = make([ok(rtt: 200, country: 'de')]);
      final nl = make([ok(rtt: 100, country: 'nl')]);
      // Без цели более быстрый узел доминирует над более «своим».
      expect(fastNonDominatedSort([de.objectives(), nl.objectives()]), [
        [1],
        [0],
      ]);
      // С целью «de» компромисс становится парето-несравнимым.
      expect(
          fastNonDominatedSort([
            de.objectives(targetCountry: 'de'),
            nl.objectives(targetCountry: 'de'),
          ]),
          [
            [0, 1]
          ]);
      expect(nsga2Order([de, nl], targetCountry: 'de').toSet(), {0, 1});
    });
  });
}
