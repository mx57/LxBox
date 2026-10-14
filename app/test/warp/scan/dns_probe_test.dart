// §845 — юнит-тест DNS-кодека и критерия «валидный резолвер». Сеть не трогаем:
// на вход подаём синтетические пакеты (buildDnsResponse), сверяем вердикты.
// Здесь решается вся суть фазы 3: «порт открыт» ≠ «резолвер честный».

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/warp/scan/dns_probe.dart';
import 'package:lxbox/services/warp/scan/dns_scanner.dart';

void main() {
  group('buildDnsQuery / parseDnsPacket', () {
    test('запрос разбирается: ID, имя, QR=0', () {
      const name = 'lxscan010001.invalid';
      final q = buildDnsQuery(name, id: 0x1234);
      final p = parseDnsPacket(q)!;
      expect(p.id, 0x1234);
      expect(p.question, name);
      expect(p.isResponse, isFalse);
      expect(p.answerCount, 0);
    });

    test('idServerTxt — CH/TXT на id.server, имя из аргента игнорируется', () {
      final q = buildDnsQuery('что-угодно.invalid',
          id: 4242, kind: DnsQueryKind.idServerTxt);
      final p = parseDnsPacket(q)!;
      expect(p.question, kDnsIdServerName);
    });

    test('короткий байт-мусор → null, не исключение', () {
      expect(parseDnsPacket(Uint8List(4)), isNull);
      expect(parseDnsPacket(Uint8List.fromList(List<int>.filled(11, 0))), isNull);
      // 12 байт заголовка, но вопрос обрезан.
      final truncated = Uint8List.fromList(List<int>.filled(14, 0));
      truncated[5] = 1; // QDCOUNT = 1
      expect(parseDnsPacket(truncated), isNull);
    });

    test('QDCOUNT != 1 → null (мы шлём ровно один вопрос)', () {
      final resp = buildDnsResponse('a.invalid', id: 1);
      resp[5] = 2; // QDCOUNT := 2
      expect(parseDnsPacket(resp), isNull);
    });
  });

  group('readName — сжатые указатели', () {
    test('указатель 0xc0 в ответе раскрывается в имя из вопроса', () {
      // заголовок + вопрос a.invalid + A-ответ с imя=указатель на 12.
      final bb = BytesBuilder(copy: false);
      void u16(int v) => bb..addByte((v >> 8) & 0xff)..addByte(v & 0xff);
      u16(0x00ab); // ID
      u16(0x8180); // flags: QR|RD|RA
      u16(1); // QDCOUNT
      u16(1); // ANCOUNT
      u16(0);
      u16(0);
      for (final l in ['a', 'invalid']) {
        bb.addByte(l.length);
        bb.add(l.codeUnits);
      }
      bb.addByte(0);
      u16(1); // QTYPE A
      u16(1); // QCLASS IN
      bb.addByte(0xc0); // NAME → offset 12
      bb.addByte(12);
      u16(1); // TYPE A
      u16(1); // CLASS IN
      u16(0); // TTL (high)
      u16(60); // TTL (low)
      u16(4); // RDLENGTH
      bb.add(Uint8List.fromList([93, 188, 16, 1]));

      final p = parseDnsPacket(bb.toBytes())!;
      expect(p.question, 'a.invalid');
      expect(p.ips, ['93.188.16.1']);
    });

    test('цикл указателя → null', () {
      final bytes = Uint8List(14);
      bytes[5] = 1; // QDCOUNT=1
      bytes[12] = 0xc0; // имя = указатель на 12 → сам на себя
      bytes[13] = 12;
      expect(parseDnsPacket(bytes), isNull);
    });
  });

  group('classifyDnsProbe', () {
    const canary = 'lxscan010002.invalid';
    const id = 0x1234;
    ({String verdict, bool ok, bool proven, bool identified, String identity,
        String detail}) cls(
      DnsPacket? p, {
      bool timedOut = false,
      String sentName = canary,
      int sentId = id,
      DnsQueryKind kind = DnsQueryKind.a,
    }) =>
        classifyDnsProbe(
          sentId: sentId,
          sentName: sentName,
          kind: kind,
          packet: p,
          timedOut: timedOut,
        );

    test('таймаут → timeout', () {
      expect(cls(null, timedOut: true).verdict, 'timeout');
    });

    test('NXDOMAIN по .invalid → ok + proven (это и есть «резолвер честный»)',
        () {
      final p = parseDnsPacket(
        buildDnsResponse(canary, id: id, rcode: 3),
      );
      final r = cls(p);
      expect(r.verdict, 'ok');
      expect(r.ok, isTrue);
      expect(r.proven, isTrue);
    });

    test('запрос-не-ответ (QR=0) → malformed', () {
      final p = parseDnsPacket(buildDnsQuery(canary, id: id));
      expect(cls(p).verdict, 'malformed');
    });

    test('чужой ID ответа → spoofed', () {
      final p = parseDnsPacket(buildDnsResponse(canary, id: 0x9999, rcode: 3));
      final r = cls(p);
      expect(r.verdict, 'spoofed');
      expect(r.ok, isFalse);
      expect(r.detail, contains('ID'));
    });

    test('чужое имя в вопросе → spoofed (перехват резолвит своё)', () {
      final p = parseDnsPacket(buildDnsResponse('example.com', id: id, rcode: 3));
      expect(cls(p).verdict, 'spoofed');
    });

    test('NOERROR с адресом на .invalid → spoofed (подмена)', () {
      final p = parseDnsPacket(
        buildDnsResponse(canary, id: id, ips: ['93.188.16.1']),
      );
      final r = cls(p);
      expect(r.verdict, 'spoofed');
      expect(r.detail, contains('перехват'));
    });

    test('REFUSED → refused, не валиден', () {
      final p = parseDnsPacket(buildDnsResponse(canary, id: id, rcode: 5));
      expect(cls(p).verdict, 'refused');
      expect(cls(p).ok, isFalse);
    });

    test('NOERROR без ответа → ok (резолвер жив, просто пусто)', () {
      final p = parseDnsPacket(buildDnsResponse(canary, id: id));
      expect(cls(p).ok, isTrue);
    });

    test('TC=1 → truncated, ok (нужен TCP, но запрос дошёл)', () {
      final p = parseDnsPacket(
        buildDnsResponse(canary, id: id, truncated: true),
      );
      final r = cls(p);
      expect(r.verdict, 'truncated');
      expect(r.ok, isTrue);
    });

    test('id.server TXT → identified + identity', () {
      final p = parseDnsPacket(
        buildDnsResponse(kDnsIdServerName,
            id: id, kind: DnsQueryKind.idServerTxt, texts: ['dnsovertls3']),
      );
      final r = cls(p, sentName: kDnsIdServerName, kind: DnsQueryKind.idServerTxt);
      expect(r.verdict, 'identified');
      expect(r.identified, isTrue);
      expect(r.identity, 'dnsovertls3');
    });

    test('id.server без TXT → nodata, но ok', () {
      final p = parseDnsPacket(
        buildDnsResponse(kDnsIdServerName,
            id: id, kind: DnsQueryKind.idServerTxt, rcode: 5),
      );
      final r = cls(p, sentName: kDnsIdServerName, kind: DnsQueryKind.idServerTxt);
      expect(r.verdict, 'nodata');
      expect(r.ok, isTrue);
      expect(r.identity, isEmpty);
    });
  });

  group('DnsServerResult / справочник', () {
    test('valid только при dns-ok', () {
      DnsServerResult r(String v) =>
          DnsServerResult(ip: '1.1.1.1', label: 'Cloudflare', verdict: v);
      expect(r(kDnsVerdictOk).valid, isTrue);
      expect(r(kDnsVerdictSpoofed).valid, isFalse);
      expect(r(kDnsVerdictTimeout).valid, isFalse);
      expect(r(kDnsVerdictRefused).valid, isFalse);
      expect(r(kDnsVerdictError).valid, isFalse);
    });

    test('endpoint — порт 53, IPv6 в скобках', () {
      const v4 = DnsServerResult(
          ip: '1.1.1.1', label: 'x', verdict: kDnsVerdictOk);
      const v6 = DnsServerResult(
          ip: '2606:4700:4700::1111', label: 'x', verdict: kDnsVerdictOk);
      expect(v4.endpoint, '1.1.1.1:53');
      expect(v6.endpoint, '[2606:4700:4700::1111]:53');
    });

    test('kKnownDnsServers — IPv4/IPv6 адреса валидны и не дублируются', () {
      expect(kKnownDnsServers, isNotEmpty);
      final ips = <String>{};
      for (final s in kKnownDnsServers) {
        expect(ips.add(s.ip), isTrue, reason: 'дубль ${s.ip}');
        expect(s.ip.contains('.') || s.ip.contains(':'), isTrue);
        expect(s.label, isNotEmpty);
      }
      // Обе ветки стека представлены: резолверы нужно отбирать и для IPv6-сетей.
      expect(kKnownDnsServers.where((s) => s.ip.contains(':')), isNotEmpty);
      expect(kKnownDnsServers.where((s) => !s.ip.contains(':')), isNotEmpty);
    });

    test('вердикты фазы 3 не пересекаются с вердиктами эндпоинтов', () {
      // ScanEndpointStatus.alive завязан на 'alive'/'cookie'/'geo-ok' — dns-*
      // не должен попадать в счётчик живых эндпоинтов.
      expect(const DnsServerResult(
        ip: '8.8.8.8',
        label: 'Google',
        verdict: kDnsVerdictOk,
      ).verdict, isNot('geo-ok'));
    });
  });

  // §847 — выбор из фазы 3 должен доезжать до генератора конфигов: резолверы
  // становятся обычными inline-записями хранилища DNS, их забирает пост-шаг
  // сборки. Ключевые свойства — стабильный тег (повторный скан обновляет запись
  // вместо дублирования) и отсев невалидных.
  group('scannedDnsTag / scannedDnsRecords — выбор уходит в генератор', () {
    const google = DnsServerResult(
      ip: '8.8.8.8',
      label: 'Google DNS',
      verdict: kDnsVerdictOk,
      rttMs: 12,
    );
    const quad9 = DnsServerResult(
      ip: '9.9.9.9',
      label: 'Quad9',
      verdict: kDnsVerdictOk,
      rttMs: 30,
    );

    test('тег стабильный, ASCII и с адресом внутри', () {
      final t = scannedDnsTag(google);
      expect(t, scannedDnsTag(google));
      expect(t, matches(RegExp(r'^scan[a-z0-9_]*_8888$')));
    });

    test('v6-адрес не ломает тег (двоеточие вырезается)', () {
      final t = scannedDnsTag(const DnsServerResult(
        ip: '2606:4700:4700::1111',
        label: 'Cloudflare',
        verdict: kDnsVerdictOk,
      ));
      expect(t, isNot(contains(':')));
      expect(t, contains('1111'));
    });

    test('валидные → inline-записи с udp-телом и включённым тумблером', () {
      final recs = scannedDnsRecords([google, quad9]);
      expect(recs, hasLength(2));
      final g = recs.first;
      expect(g.enabled, isTrue);
      expect(g.tag, scannedDnsTag(google));
      expect(g.description, 'Google DNS');
      expect(g.body, {'type': 'udp', 'server': '8.8.8.8'});
    });

    test('невалидные (подмена/таймаут) отбрасываются, дубли тега — одна запись',
        () {
      final recs = scannedDnsRecords([
        google,
        const DnsServerResult(
          ip: '1.1.1.1',
          label: 'spoofed',
          verdict: kDnsVerdictSpoofed,
        ),
        google,
      ]);
      expect(recs.map((r) => r.tag), [scannedDnsTag(google)]);
    });

    test('пустой выбор → пусто (генератор не трогает настройки DNS)', () {
      expect(scannedDnsRecords(const []), isEmpty);
    });
  });

  test('canaryName — детерминирован и в .invalid', () {
    expect(canaryName(0x100000), 'lxscan100000.invalid');
    expect(canaryName(1), contains('.invalid'));
    expect(canaryName(1), canaryName(1));
  });
}
