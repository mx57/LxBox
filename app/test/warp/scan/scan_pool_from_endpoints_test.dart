// §834 — тест ScanPool.fromEndpoints: пул из отсканированных эндпоинтов
// превращается в /32-CIDR для WG и h2, а hasData валиден.

import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/warp/scan/scan_pool.dart';

void main() {
  test('fromEndpoints builds /32 pool with hasData', () {
    final pool = ScanPool.fromEndpoints([
      '162.159.192.1:2408',
      '162.159.193.1:2408',
      '188.114.96.1:2408',
    ]);
    expect(pool, isNotNull);
    expect(pool!.wgV4Cidr, contains('162.159.192.1/32'));
    expect(pool.wgV4Cidr, contains('162.159.193.1/32'));
    expect(pool.wgV4Cidr, contains('188.114.96.1/32'));
    expect(pool.masqueV4Cidr, contains('162.159.192.1/32'));
    expect(pool.wgPorts, isNotEmpty);
    expect(pool.hasData, isTrue);
  });

  test('fromEndpoints empty returns null', () {
    expect(ScanPool.fromEndpoints([]), isNull);
  });

  test('fromEndpoints dedupes and strips ports in cidr', () {
    final pool = ScanPool.fromEndpoints([
      '1.2.3.4:2408',
      '1.2.3.4:2408', // дубль
      '5.6.7.8',
    ]);
    expect(pool, isNotNull);
    expect(pool!.wgV4Cidr.length, 2);
    expect(pool.wgV4Cidr, contains('1.2.3.4/32'));
    expect(pool.wgV4Cidr, contains('5.6.7.8/32'));
  });

  test('fromEndpoints preserves base sni/ports when base given', () {
    final base = ScanPool(
      wgV4Cidr: const ['10.0.0.0/30'],
      wgV6Cidr: const [],
      wgPorts: const [2408],
      wgPortsExtra: const [],
      wgSniPool: const ['ya.ru'],
      utlsFpPool: const ['chrome'],
      masqueV4Cidr: const ['10.0.1.0/30'],
      masquePortsH3: const [443],
      masquePortsH2: const [500],
      masqueSniPool: const ['consumer-masque.cloudflareclient.com'],
    );
    final pool = ScanPool.fromEndpoints(['9.9.9.9:2408'], base: base);
    expect(pool, isNotNull);
    expect(pool!.wgSniPool, contains('ya.ru'));
    expect(pool.masquePortsH3, contains(443));
    expect(pool.masqueRecommendedSni, '');
  });

  // §843b — регресс: MASQUE-хосты из endpoints-пула обязаны быть ЧИСТЫМИ IP.
  // раньше preset/h3 получали строку `ip:port`, randomMasqueIp('h3') отдавал её
  // дословно в ScanCandidate.ip, а MasqueAccount.toMasqueUri клеит `@$server:
  // $port` сам → битый `masque://…@1.2.3.4:2408:443`.
  group('§843b masque hosts port-free', () {
    test('preset/h3 несут хосты без порта, combobox WG — с портом', () {
      final pool = ScanPool.fromEndpoints([
        '162.159.192.1:2408',
        '188.114.96.7:443',
      ]);
      expect(pool, isNotNull);
      expect(pool!.masqueHostsPreset, ['162.159.192.1', '188.114.96.7']);
      expect(pool.masqueH3Hosts, ['162.159.192.1', '188.114.96.7']);
      // Генератор берёт h3-IP отсюда дословно — порт внутри ломает URI.
      for (var i = 0; i < 25; i++) {
        final ip = pool.randomMasqueIp('h3', Random(i));
        expect(ip, isNotNull);
        expect(ip, isNot(contains(':')), reason: 'h3 IP с портом: $ip');
      }
      // wgEndpointsPreset — пункты combobox'а, порт там нужен.
      expect(pool.wgEndpointsPreset, contains('162.159.192.1:2408'));
    });

    test('один IP на разных портах → одна /32 и один хост', () {
      final pool = ScanPool.fromEndpoints(['1.2.3.4:2408', '1.2.3.4:443']);
      expect(pool, isNotNull);
      expect(pool!.wgV4Cidr, ['1.2.3.4/32']);
      expect(pool.masqueV4Cidr, ['1.2.3.4/32']);
      expect(pool.masqueH3Hosts, ['1.2.3.4']);
    });
  });

  group('endpointHost', () {
    test('снимает порт, раскрывает v6 в скобках', () {
      expect(ScanPool.endpointHost('1.2.3.4:2408'), '1.2.3.4');
      expect(ScanPool.endpointHost('1.2.3.4'), '1.2.3.4');
      expect(ScanPool.endpointHost('[2606:4700::1]:443'), '2606:4700::1');
      expect(ScanPool.endpointHost('[2606:4700::1]'), '2606:4700::1');
      expect(ScanPool.endpointHost(''), '');
    });

    test('v6-эндпоинт → /128, не /32', () {
      final pool = ScanPool.fromEndpoints(['[2606:4700::64]:443']);
      expect(pool!.wgV4Cidr, ['2606:4700::64/128']);
    });
  });

  // §847 — SNI, выбранные после фазы 4, подменяют пулы ЦЕЛИКОМ: иначе
  // Монте-Карло сеял бы узлы и на зарезанные домены, а выбор пользователя
  // просто терялся бы в пуле.
  group('§847 sniOverride', () {
    final base = ScanPool(
      wgV4Cidr: const ['10.0.0.0/30'],
      wgV6Cidr: const [],
      wgPorts: const [2408],
      wgPortsExtra: const [],
      wgSniPool: const ['www.google.com', 'www.bing.com'],
      utlsFpPool: const ['chrome'],
      masqueV4Cidr: const ['10.0.1.0/30'],
      masquePortsH3: const [443],
      masquePortsH2: const [500],
      masqueSniPool: const ['consumer-masque.cloudflareclient.com'],
      masqueRecommendedSni: 'consumer-masque.cloudflareclient.com',
    );

    test('оба пула (WG и MASQUE) = только выбранные, порядок сохранён', () {
      final pool = ScanPool.fromEndpoints(
        ['1.2.3.4:2408'],
        base: base,
        sniOverride: const ['yandex.ru', 'vk.ru'],
      );
      expect(pool, isNotNull);
      expect(pool!.wgSniPool, ['yandex.ru', 'vk.ru']);
      expect(pool.masqueSniPool, ['yandex.ru', 'vk.ru']);
      // Рекомендуемый SNI из bundled-пула больше не действителен.
      expect(pool.masqueRecommendedSni, '');
    });

    test('регистр/пробелы нормализуются, дубли схлопаются, мусор падает', () {
      final pool = ScanPool.fromEndpoints(
        ['1.2.3.4:2408'],
        sniOverride: const [' Yandex.RU', 'yandex.ru', '', '  '],
      );
      expect(pool!.wgSniPool, ['yandex.ru']);
    });

    test('пустой override → пулы как из base (old behavior)', () {
      final pool = ScanPool.fromEndpoints(
        ['1.2.3.4:2408'],
        base: base,
        sniOverride: const [],
      );
      expect(pool!.wgSniPool, base.wgSniPool);
      expect(pool.masqueSniPool, base.masqueSniPool);
      expect(pool.masqueRecommendedSni, base.masqueRecommendedSni);
    });
  });
}
