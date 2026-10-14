// §847 — юнит-агрегация шага 4 (SNI). Сеть и ядро не задействуются: на вход
// подаём синтетические заходы (эндпоинт × SNI), сверяем вердикты и порядок.
// Смысл шага: в генератор попадают только домены, реально ответившие СЕГОДНЯ,
// поэтому «прошёл хоть где-то» и «лучший RTT» — то, что ломает конфиг, если
// перепутать.

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/warp/scan/sni_scanner.dart';

SniAttempt _a(
  String sni,
  String ep, {
  bool ok = false,
  int rtt = 0,
  String d = '',
}) {
  return (sni: sni, endpoint: ep, responded: ok, rttMs: rtt, detail: d);
}

void main() {
  group('sniScanCandidates', () {
    test('MASQUE-пул раньше WG, дубли схлопываются, порядок сохранён', () {
      final c = sniScanCandidates(
        masque: ['a.ru', 'B.RU', 'shared.ru'],
        wg: ['shared.ru', 'c.ru'],
      );
      expect(c, ['a.ru', 'b.ru', 'shared.ru', 'c.ru']);
    });

    test('мусор и IP-подобные значения отбрасываются', () {
      final c = sniScanCandidates(
        masque: ['', '   ', 'nodot', '162.159.198.2', 'two words.ru', 'a:443'],
        wg: ['ok.ru'],
      );
      expect(c, ['ok.ru']);
    });

    test('кап по max и max<=0 → пусто', () {
      final many = [for (var i = 0; i < 40; i++) 'h$i.ru'];
      expect(sniScanCandidates(masque: many, wg: const [], max: 5).length, 5);
      expect(sniScanCandidates(masque: many, wg: many, max: 0), isEmpty);
    });

    test('default cap = kSniScanPerEndpoint (размер probe-сессии ограничен)', () {
      final many = [for (var i = 0; i < 200; i++) 'h$i.ru'];
      expect(sniScanCandidates(masque: many, wg: const []),
          hasLength(kSniScanPerEndpoint));
    });
  });

  group('summariseSniAttempts', () {
    test('порядок — первое появление SNI, а не алфавит', () {
      final r = summariseSniAttempts([
        _a('z.ru', '1.1.1.1:4500', ok: true),
        _a('a.ru', '1.1.1.1:4500'),
        _a('z.ru', '2.2.2.2:4500'),
      ]);
      expect(r.map((e) => e.sni), ['z.ru', 'a.ru']);
      expect(r[0].tried, 2);
      expect(r[1].tried, 1);
    });

    test('успех на любом эндпоинте засчитывается, провал его не отменяет', () {
      final r = summariseSniAttempts([
        _a('a.ru', '1.1.1.1:4500'),
        _a('a.ru', '2.2.2.2:4500', ok: true, rtt: 40, d: 'HTTP 200'),
        _a('a.ru', '3.3.3.3:4500', d: 'timeout'),
      ]);
      expect(r.single.verdict, kSniVerdictOk);
      expect(r.single.valid, isTrue);
      expect(r.single.rttMs, 40);
      expect(r.single.endpoint, '2.2.2.2:4500');
      expect(r.single.tried, 3);
      // Деталь победного захода: провал ПОСЛЕ успеха её не перетирает.
      expect(r.single.detail, 'HTTP 200');
    });

    test('без успеха — вердикт blocked и деталь последнего провала', () {
      final r = summariseSniAttempts([
        _a('a.ru', '1.1.1.1:4500', d: 'timeout'),
        _a('a.ru', '2.2.2.2:4500', d: 'junk'),
      ]);
      expect(r.single.valid, isFalse);
      expect(r.single.verdict, kSniVerdictBlocked);
      expect(r.single.detail, 'junk');
      expect(r.single.rttMs, 0);
    });

    test('лучший RTT выигрывает, худший не перезаписывает адрес', () {
      final r = summariseSniAttempts([
        _a('a.ru', 'fast.ep', ok: true, rtt: 25),
        _a('a.ru', 'slow.ep', ok: true, rtt: 90),
      ]);
      expect(r.single.rttMs, 25);
      expect(r.single.endpoint, 'fast.ep');
    });

    test('rtt==0 у второго успеха не считается быстрее измеряемого', () {
      final r = summariseSniAttempts([
        _a('a.ru', 'fast.ep', ok: true, rtt: 25),
        _a('a.ru', 'zero.ep', ok: true, rtt: 0),
      ]);
      expect(r.single.rttMs, 25);
      expect(r.single.endpoint, 'fast.ep');
    });

    test('пустой вход → пусто', () {
      expect(summariseSniAttempts(const []), isEmpty);
    });
  });
}
