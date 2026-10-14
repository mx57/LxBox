// §834 — юнит-тест движка сканера: группировка по странам, счётчики,
// сортировка, парсер cdn-cgi/trace, выборка IP по блокам. Сеть/ядро не
// трогаем — проверяем чистую логику.

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/models/node_spec.dart';
import 'package:lxbox/services/parser/mappers/uri_pipeline.dart'
    show parseLinkViaPipeline;
import 'package:lxbox/services/probe/probe_config.dart';
import 'package:lxbox/services/warp/scan/dns_scanner.dart';
import 'package:lxbox/services/warp/scan/endpoint_scanner.dart';
import 'package:lxbox/services/warp/scan/scan_models.dart';
import 'package:lxbox/services/warp/scan/scan_node_builder.dart';
import 'package:lxbox/services/warp/scan/scan_wire.dart';
import 'package:lxbox/services/warp/warp_account.dart';

import '../../parser/engine_test_setup.dart';

void main() {
  setUpAll(loadEngineSections);
  tearDownAll(unloadEngineSections);

  test('country names resolve to Russian where known', () {
    expect(countryName('DE'), 'Германия');
    expect(countryName('RU'), 'Россия');
    expect(countryName(''), '');
    expect(countryName('zz'), 'ZZ');
  });

  group('parseCloudflareTrace', () {
    test('extracts loc and colo (uppercased)', () {
      const body = 'fl=123abc\n'
          'h=1.1.1.1\n'
          'ip=203.0.113.7\n'
          'loc=DE\n'
          'colo=FRA\n'
          'warp=on\n'
          'ts=1700000000.000\n';
      final r = parseCloudflareTrace(body);
      expect(r.country, 'DE');
      expect(r.colo, 'FRA');
    });

    test('lowercase values are normalised', () {
      final r = parseCloudflareTrace('loc=de\ncolo=fra\n');
      expect(r.country, 'DE');
      expect(r.colo, 'FRA');
    });

    test('missing loc → empty country, junk tolerated', () {
      final r = parseCloudflareTrace('ip=1.2.3.4\ncolo=AMS\nnot-a-pair\n');
      expect(r.country, '');
      expect(r.colo, 'AMS');
    });

    test('empty body → empty', () {
      final r = parseCloudflareTrace('');
      expect(r.country, '');
      expect(r.colo, '');
    });

    test('§844 — loc=XX (псевдо-страна GeoLite) не страной, colo живой', () {
      final r = parseCloudflareTrace('colo=DME\nloc=XX\n');
      expect(r.country, '');
      expect(r.colo, 'DME');
    });
  });

  group('§844 — критерий страны', () {
    test('правдоподобна только пара A-Z без псевдо-кодов', () {
      expect(isPlausibleCountry('DE'), isTrue);
      expect(isPlausibleCountry('de'), isTrue);
      for (final junk in ['', 'D', 'RUS', '12', 'U ', '-', 'XX', 'A1', 'A2', 'T1']) {
        expect(isPlausibleCountry(junk), isFalse, reason: junk);
      }
      expect(kGeoPseudoCountries, contains('XX'));
    });

    test('meta JSON: country/colo; псевдо-страна и мусор → пусто', () {
      final ok = parseCloudflareMeta(
        '{"colo":"AMS","country":"NL","ip":"1.1.1.1"}',
      );
      expect(ok.country, 'NL');
      expect(ok.colo, 'AMS');
      final pseudo = parseCloudflareMeta('{"country":"A1","colo":"FRA"}');
      expect(pseudo.country, '');
      expect(pseudo.colo, 'FRA');
      for (final junk in ['', 'не json', '[1,2]', 'null', '"NL"', '{"country":null}', '{"country":123}']) {
        expect(parseCloudflareMeta(junk).country, '', reason: junk);
      }
    });

    test('parseGeoBody разбирает и trace, и meta; HTML перехватчика — пусто', () {
      expect(parseGeoBody('loc=DE\ncolo=FRA\n'),
          (country: 'DE', colo: 'FRA'));
      expect(parseGeoBody('{"country":"NL","colo":"AMS"}'),
          (country: 'NL', colo: 'AMS'));
      expect(parseGeoBody('<html><body>Captive portal</body></html>'),
          (country: '', colo: ''));
      // §846 — trace без страны, но с узлом: страна берётся из узла.
      expect(parseGeoBody('colo=AMS\nloc=\n'), (country: 'NL', colo: 'AMS'));
    });

    group('§846 — страна из colo, когда loc молчит', () {
      // Реальные ответы CF на хостинговых IP: loc — псевдокод, colo есть.
      test('loc=T1 + colo → страна узла, а не «не определена»', () {
        expect(parseGeoBody('colo=DFW\nloc=T1\n'),
            (country: 'US', colo: 'DFW'));
        expect(parseGeoBody('colo=EWR\nloc=T1\n'),
            (country: 'US', colo: 'EWR'));
        expect(parseGeoBody('colo=FRA\nloc=XX\n'),
            (country: 'DE', colo: 'FRA'));
        expect(parseGeoBody('colo=HEL\nloc=A1\n'),
            (country: 'FI', colo: 'HEL'));
        expect(parseCloudflareMeta('{"country":"A1","colo":"FRA"}').country, '');
        expect(parseGeoBody('{"country":"A1","colo":"FRA"}'),
            (country: 'DE', colo: 'FRA'));
      });

      test('§848 — страна узла (colo) важнее loc: loc описывает клиента', () {
        // Замер с машины в RU-сети, оба запроса без туннеля: два разных
        // anycast-адреса при одном loc=RU (`colo=LED` и `colo=HEL`). То есть
        // `loc`/`country` — география ИСТОЧНИКА запроса, а точка выхода — это
        // `colo`. До §848 приоритет loc складывал весь скан в группу «RU».
        expect(parseGeoBody('colo=HEL\nloc=RU\n'),
            (country: 'FI', colo: 'HEL'));
        expect(parseGeoBody('colo=FRA\nloc=RU\n'),
            (country: 'DE', colo: 'FRA'));
        expect(parseGeoBody('{"colo":"AMS","country":"RU"}'),
            (country: 'NL', colo: 'AMS'));
        // Неизвестный узел — честная «не определена»: подставлять страну
        // клиента нельзя, иначе весь скан снова станет «RU».
        expect(parseGeoBody('colo=ZZZ\nloc=DE\n'), (country: '', colo: 'ZZZ'));
        // loc и meta.country остаются запасным кругом для ответов без colo.
        expect(parseGeoBody('loc=DE\n'), (country: 'DE', colo: ''));
        expect(parseGeoBody('{"country":"FI"}'), (country: 'FI', colo: ''));
      });

      test('countryFromColo: известные узлы, регистр, неизвестный код', () {
        expect(countryFromColo('FRA'), 'DE');
        expect(countryFromColo('fra'), 'DE');
        expect(countryFromColo(' HEL '), 'FI');
        expect(countryFromColo('AMS'), 'NL');
        expect(countryFromColo('LHR'), 'GB');
        expect(countryFromColo('CDG'), 'FR');
        expect(countryFromColo('IST'), 'TR');
        expect(countryFromColo('WAW'), 'PL');
        expect(countryFromColo('PRG'), 'CZ');
        expect(countryFromColo('KIV'), 'MD');
        expect(countryFromColo('NRT'), 'JP');
        expect(countryFromColo('SIN'), 'SG');
        expect(countryFromColo('GRU'), 'BR');
        expect(countryFromColo('ZZZ'), '');
        expect(countryFromColo(''), '');
      });

      test('псевдо-коды в kColoCountries не прячутся и страны валидны', () {
        for (final e in kColoCountries.entries) {
          expect(e.key.length, 3, reason: e.key);
          expect(isPlausibleCountry(e.value), isTrue,
              reason: '${e.key} → ${e.value}');
        }
      });

      test('каждая страна из карты colo подписана по-русски', () {
        for (final code in kColoCountries.values.toSet()) {
          expect(countryName(code), isNot(code), reason: code);
        }
      });
    });

    test('geoBodyHint — одна строка для журнала, пустое тело помечено', () {
      expect(geoBodyHint(''), 'пустое тело');
      expect(geoBodyHint('fl=202408-1\nh=api.mcd\n'), 'fl=202408-1 h=api.mcd');
      expect(geoBodyHint('a' * 200), endsWith('…'));
      expect(geoBodyHint('a' * 200).length, 61);
    });

    test('источники гео — домены CF первыми, IP-trace последним', () {
      expect(kGeoUrls.first, contains('speed.cloudflare.com'));
      expect(kGeoUrls.last, 'https://1.1.1.1/cdn-cgi/trace');
      expect(kGeoUrls.every((u) => u.startsWith('https://')), isTrue);
      // Потолок запросов не должен отрезать целый круг источников.
      expect(kGeoMaxRequestsPerEndpoint, greaterThanOrEqualTo(kGeoUrls.length));
    });
  });

  group('§845 — фаза 3 в результате скана', () {
    test('DNS-статусы не портят счётчики эндпоинтов, validDns отбирает живых',
        () {
      final r = EndpointScanResult(
        groups: const [],
        scanAt: DateTime.now().toUtc(),
        scanDurationMs: 0,
        failedCount: 0,
        statuses: [
          ScanEndpointStatus(
              endpoint: '1.1.1.1:53', phase: 3, verdict: kDnsVerdictOk),
          ScanEndpointStatus(
              endpoint: '8.8.8.8:53', phase: 3, verdict: kDnsVerdictSpoofed),
          ScanEndpointStatus(
              endpoint: '162.159.192.1:2408', phase: 1, verdict: 'alive'),
        ],
        dns: const [
          DnsServerResult(ip: '1.1.1.1', label: 'Cloudflare', verdict: kDnsVerdictOk),
          DnsServerResult(ip: '8.8.8.8', label: 'Google', verdict: kDnsVerdictSpoofed),
        ],
      );
      expect(r.totalProbed, 1);
      expect(r.totalAlive, 1);
      expect(r.validDns.map((d) => d.ip), ['1.1.1.1']);
      expect(r.dns.length, 2);
    });

    test('пустой результат — dns пуст, без валидных', () {
      final r = EndpointScanResult(
        groups: const [],
        scanAt: DateTime.now().toUtc(),
        scanDurationMs: 0,
        failedCount: 0,
      );
      expect(r.dns, isEmpty);
      expect(r.validDns, isEmpty);
      expect(r.totalProbed, 0);
    });
  });

  test('groups sort by valid count desc and count found/valid', () {
    const g1 = EndpointCountryGroup(
      code: 'DE',
      name: 'Германия',
      endpoints: [
        EndpointResult(
          endpoint: 'a:2408',
          country: 'DE',
          colo: 'FRA',
          rttMs: 10,
          alive: true,
        ),
        EndpointResult(
          endpoint: 'b:2408',
          country: 'DE',
          colo: 'FRA',
          rttMs: 20,
          alive: true,
        ),
      ],
    );
    const g0 = EndpointCountryGroup(
      code: 'NL',
      name: 'Нидерланды',
      endpoints: [
        EndpointResult(
          endpoint: 'c:2408',
          country: 'NL',
          colo: 'AMS',
          rttMs: 5,
          alive: false,
        ),
      ],
    );
    final sorted = [g0, g1]..sort((a, b) => b.valid.compareTo(a.valid));
    expect(sorted.first.code, 'DE');
    expect(sorted.first.found, 2);
    expect(sorted.first.valid, 2);
    expect(sorted.last.valid, 0);

    final result = EndpointScanResult(
      groups: [g1, g0],
      scanAt: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      scanDurationMs: 100,
      failedCount: 3,
    );
    expect(result.totalFound, 3);
    expect(result.totalValid, 2);
  });

  test('unknown-country group is flagged and sorted last', () {
    const known = EndpointCountryGroup(
      code: 'DE',
      name: 'Германия',
      endpoints: [
        EndpointResult(
          endpoint: 'a:2408',
          country: 'DE',
          colo: 'FRA',
          rttMs: 10,
          alive: true,
        ),
      ],
    );
    const unknown = EndpointCountryGroup(
      code: '',
      name: '',
      endpoints: [
        EndpointResult(
          endpoint: 'z:2408',
          country: '',
          colo: '',
          rttMs: 0,
          alive: true,
        ),
      ],
    );
    expect(unknown.isUnknown, isTrue);
    expect(known.isUnknown, isFalse);
    final sorted = [unknown, known]..sort((a, b) {
        if (a.isUnknown != b.isUnknown) return a.isUnknown ? 1 : -1;
        return b.valid.compareTo(a.valid);
      });
    expect(sorted.first.code, 'DE');
    expect(sorted.last.isUnknown, isTrue);
  });

  test('classifyWgResponse treats junk as not alive', () {
    expect(classifyWgResponse([1, 2, 3]).alive, isFalse);
    expect(classifyWgResponse([2, ...List.filled(91, 0)]).alive, isTrue);
    expect(classifyWgResponse([3, ...List.filled(63, 0)]).alive, isTrue);
  });

  test(
    'фаза 2 строит рабочий probe-конфиг ядра под конкретный эндпоинт '
    '(это и есть суть фикса: без сессии страна/valid были пусты)',
    () {
      const acc = WarpAccount(
        privKey: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=',
        peerPub: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=',
        clientV4: '172.16.0.2/32',
        clientV6: '',
        clientId: 'AAAA',
        accountId: 'acc',
        deviceId: 'dev',
        token: 'tok',
        endpoint: 'engage.cloudflareclient.com:2408',
        createdAt: '2026-01-01T00:00:00Z',
      );
      final builder = ScanNodeBuilder(warp: acc);

      // Тот же путь, что у сканера: ScanCandidate → URI → parseUri → узел.
      final candidate = const ScanCandidate(
        ip: '162.159.192.7',
        port: 2408,
        protocol: ScanProtocol.awg,
        sni: 'www.google.com',
        awgParams: AwgParams(ip: 'quic', jc: 4, jmin: 40, jmax: 70),
      );
      final uri = builder.uriFor(candidate);
      expect(uri, isNotNull);
      final node = parseLinkViaPipeline(uri!);
      expect(node, isA<WireguardSpec>());

      // Узел собирается в probe-конфиг с реальным тегом (не фиктивным
      // `ep_<addr>`) — именно его зовёт probeGetUrl.
      final cfg = buildProbeConfig([node]);
      expect(cfg.configJson, isNotNull);
      expect(cfg.tagByIndex[0], isNotNull);
      expect(cfg.tagByIndex[0], isNot(contains('162.159.192.7')),
          reason: 'тег ядра — из allocate(), а не адрес');
      final decoded = cfg.configJson!;
      expect(decoded, contains('162.159.192.7'));
      expect(decoded, contains('endpoints'));
    },
  );
}
