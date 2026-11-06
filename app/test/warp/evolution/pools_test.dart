import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/pools.dart';
import 'package:lxbox/services/warp/scan/scan_pool.dart';

/// §848 — мутационные пулы: границы домена, фильтр по странам, заморозка
/// локусов и ограничение по транспортам.
void main() {
  const pool = EvolutionPools(
    endpoints: ['162.159.192.1', '162.159.192.2', '185.228.228.10', 'dns.google'],
    endpointsByCountry: {
      'de': ['162.159.192.1', '185.228.228.10'],
      'nl': ['162.159.192.2'],
      '': ['dns.google'],
    },
    sni: ['yandex.ru', 'mail.ru'],
    dnsTags: ['scanned-1', 'scanned-2'],
    wgPorts: [2408, 500],
    h3Ports: [443],
    h2Ports: [8443],
  );

  const emptyEndpoints = EvolutionPools();

  group('домены значений', () {
    test('endpointsFor: пустой выбор стран = весь пул', () {
      expect(pool.endpointsFor(const []), pool.endpoints);
    });

    test('endpointsFor: только адреса выбранных стран, без дублей', () {
      expect(
        pool.endpointsFor(const ['de', 'nl', 'de']),
        ['162.159.192.1', '185.228.228.10', '162.159.192.2'],
      );
    });

    test('endpointsFor: пустой результат фильтра не обнуляет поиск', () {
      expect(pool.endpointsFor(const ['zz']), pool.endpoints,
          reason: 'страна без адресов → фолбэк на полный пул');
      expect(pool.endpointsFor(const ['']), ['dns.google']);
    });

    test('alleles: пустой домен = локус не мутируется', () {
      expect(emptyEndpoints.alleles(EvoLocus.endpoint).isEmpty, isTrue);
      expect(emptyEndpoints.alleles(EvoLocus.sni).isEmpty, isTrue);
      // Пустой пул SNI не мешает приманке: домен остаётся «пустое значение».
      expect(emptyEndpoints.alleles(EvoLocus.junkDomain).values, ['']);
    });

    test('alleles: DNS всегда содержит штатный резолвер', () {
      expect(pool.alleles(EvoLocus.dns).values, ['', 'scanned-1', 'scanned-2']);
      expect(emptyEndpoints.alleles(EvoLocus.dns).values, ['']);
    });

    test('alleles: выключенная фрагментация даёт только «выкл»', () {
      const off = EvolutionPools(fragment: false, recordFragment: false);
      expect(off.alleles(EvoLocus.fragment).values, ['0']);
      expect(off.alleles(EvoLocus.recordFragment).values, ['0']);
      expect(pool.alleles(EvoLocus.fragment).values, ['0', '1']);
    });

    test('alleles: транспорты пула — домен локуса transport', () {
      const onlyH2 = EvolutionPools(transports: {EvoTransport.masqueH2});
      expect(onlyH2.alleles(EvoLocus.transport).values, ['h2']);
      // Пустое множество транспортов — не «запрет всего», а «не ограничивать».
      const none = EvolutionPools(transports: {});
      expect(none.alleles(EvoLocus.transport).values.length,
          EvoTransport.values.length);
    });

    test('portsFor соответствует транспорту', () {
      expect(pool.portsFor(EvoTransport.awg), [2408, 500]);
      expect(pool.portsFor(EvoTransport.masqueH3), [443]);
      expect(pool.portsFor(EvoTransport.masqueH2), [8443]);
    });
  });

  group('случайная особь', () {
    test('значения не покидают пулы', () {
      final rng = Random(11);
      for (var i = 0; i < 200; i++) {
        final g = pool.random(rng);
        expect(pool.endpoints, contains(g.endpoint));
        expect([...pool.wgPorts, ...pool.h3Ports, ...pool.h2Ports],
            contains(g.port));
        expect([...pool.sni, ''], contains(g.sni));
        expect([...pool.dnsTags, ''], contains(g.dnsTag));
        expect(pool.portsFor(g.transport), contains(g.port),
            reason: 'порт обязан подходить транспорту');
      }
    });

    test('фильтр по странам сужает адрес', () {
      final rng = Random(3);
      for (var i = 0; i < 60; i++) {
        final g = pool.random(rng, countries: const ['nl']);
        expect(g.endpoint, '162.159.192.2');
      }
    });

    test('пустой пул адресов → особь без адреса (её отсеет посев)', () {
      expect(emptyEndpoints.random(Random(1)).endpoint, isEmpty);
    });
  });

  group('RestrictedPools', () {
    test('замороженный локус имеет пустой домен', () {
      const r = RestrictedPools(pool, disabledLoci: {EvoLocus.dns, EvoLocus.mtu});
      expect(r.alleles(EvoLocus.dns).isEmpty, isTrue);
      expect(r.alleles(EvoLocus.mtu).isEmpty, isTrue);
      expect(r.alleles(EvoLocus.sni).values, pool.sni);
    });

    test('замороженный локус не получает значение и из посева', () {
      const r = RestrictedPools(pool,
          disabledLoci: {EvoLocus.dns, EvoLocus.fragment, EvoLocus.sniCase});
      final rng = Random(5);
      for (var i = 0; i < 100; i++) {
        final g = r.random(rng);
        expect(g.dnsTag, isEmpty);
        expect(g.fragment, isFalse);
        expect(g.sniCase, 0);
      }
    });

    test('галки транспортов ограничивают и домен, и посев', () {
      const r = RestrictedPools(pool, transports: {EvoTransport.masqueH2});
      expect(r.alleles(EvoLocus.transport).values, ['h2']);
      final rng = Random(9);
      for (var i = 0; i < 100; i++) {
        final g = r.random(rng);
        expect(g.transport, EvoTransport.masqueH2);
        expect(g.port, 8443, reason: 'порт пересэмплирован под транспорт');
      }
    });

    test('непересечение с базой не даёт пустой локус transport', () {
      const base = EvolutionPools(transports: {EvoTransport.awg});
      const r = RestrictedPools(base, transports: {EvoTransport.masqueH3});
      expect(r.alleles(EvoLocus.transport).values, ['h3']);
      expect(r.random(Random(2)).transport, EvoTransport.masqueH3);
    });

    test('выключатель фрагментации перекрывает базу', () {
      const r = RestrictedPools(pool, fragment: false, recordFragment: false);
      expect(r.alleles(EvoLocus.fragment).values, ['0']);
      final rng = Random(4);
      for (var i = 0; i < 60; i++) {
        final g = r.random(rng);
        expect(g.fragment, isFalse);
        expect(g.recordFragment, isFalse);
      }
    });
  });

  group('Эволюция из пула скана', () {
    test('fromScanPool(null) живёт на штатных портах', () {
      final p = EvolutionPools.fromScanPool(null,
          dnsTags: const ['a'], endpointsByCountry: const {'de': ['1.1.1.1']});
      expect(p.wgPorts, [2408, 500, 1701, 4500]);
      expect(p.h3Ports, [443, 4443, 8095]);
      expect(p.h2Ports, [500, 4500, 8443]);
      expect(p.endpoints, ['1.1.1.1']);
      expect(p.dnsTags, ['a']);
      expect(p.alleles(EvoLocus.sni).isEmpty, isTrue);
    });

    test('fromScanPool берёт адреса, порты и SNI из пула скана', () {
      final scan = ScanPool(
        wgV4Cidr: const ['162.159.192.0/24'],
        wgV6Cidr: const [],
        wgEndpointsPreset: const ['engage.cloudflareclient.com:2408'],
        wgPorts: const [2408],
        wgPortsExtra: const [4500],
        wgSniPool: const ['yandex.ru'],
        utlsFpPool: const [],
        masqueHostsPreset: const ['162.159.198.1'],
        masqueV4Cidr: const [],
        masquePortsH3: const [443, 8095],
        masquePortsH2: const [8443],
        masqueSniPool: const ['www.cloudflare.com'],
      );
      final p = EvolutionPools.fromScanPool(scan,
          sniOverride: const ['mail.ru'], dnsTags: const ['d1']);
      expect(p.wgPorts, [2408, 4500]);
      expect(p.h3Ports, [443, 8095]);
      expect(p.h2Ports, [8443]);
      expect(p.endpoints, containsAll(<String>[
        'engage.cloudflareclient.com',
        '162.159.198.1',
        '162.159.192.0',
      ]));
      expect(p.endpoints, hasLength(3));
      expect(p.alleles(EvoLocus.sni).values, containsAll(['mail.ru', 'yandex.ru']));
      expect(p.alleles(EvoLocus.dns).values, ['', 'd1']);
    });
  });

  test('endpointHost снимает порт и раскрывает скобки IPv6', () {
    expect(endpointHost('162.159.192.1:2408'), '162.159.192.1');
    expect(endpointHost('[2606:4700::1]:443'), '2606:4700::1');
    expect(endpointHost('yandex.ru'), 'yandex.ru');
    expect(endpointHost('host:notaport'), 'host:notaport');
    expect(endpointHost(' 1.1.1.1:443 '), '1.1.1.1');
  });
}
