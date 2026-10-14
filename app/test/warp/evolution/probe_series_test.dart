import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/probe_evaluator.dart';
import 'package:lxbox/services/warp/scan/endpoint_scanner.dart' show kGeoUrls;
import 'package:lxbox/vpn/cc_channel.dart';

/// §848 — серия гео-проб одной особи без устройства и ядра: [probeGeoSeries]
/// получает транспорт через [get], поэтому здесь проверяется ровно то, из-за
/// чего реальный прогон давал «проходимых 0» при заведомо рабочих конфигах.
void main() {
  const genome = Genome(
    transport: EvoTransport.masqueH3,
    endpoint: '162.159.198.1',
    port: 443,
    sni: 'www.cloudflare.com',
  );

  const traceFra = 'floc=51.5002,-0.1262\nvizxaz=359289\n colo=FRA\ngwips=...\nloc=GB\n';

  CcGetUrlResult result({
    int status = 200,
    String content = '',
    String error = '',
    int elapsedMs = 42,
  }) =>
      CcGetUrlResult(
        status: status,
        content: content,
        truncated: false,
        contentType: '',
        remoteAddr: '162.159.192.1',
        elapsedMs: elapsedMs,
        error: error,
      );

  test('DNS-неживой первый источник: вердикт со второго, запросы посчитаны',
      () async {
    final called = <String>[];
    final o = await probeGeoSeries(
      genome,
      (url) async {
        called.add(url);
        return called.length == 1
            ? result(status: 0, error: 'lookup speed.cloudflare.com: no such host')
            : result(content: traceFra);
      },
      urls: const ['https://a', 'https://b'],
    );
    expect(called, ['https://a', 'https://b']);
    expect(o.responded, isTrue);
    expect(o.colo, 'FRA');
    expect(o.country, 'DE', reason: 'страна узла берётся из colo (§848)');
    expect(o.requests, 2);
    expect(o.rttMs, 42);
    expect(o.url, 'https://b');
  });

  test('один источник без ротации больше не означает «узел мёртв»', () async {
    // Ровно та ловушка, что убила кампанию из 66 рабочих конфигов: проба звала
    // только kGeoUrls.first и на отравленном DNS получала 0 % для всех.
    final o = await probeGeoSeries(
      genome,
      (url) async => url.endsWith('1.1.1.1/cdn-cgi/trace')
          ? result(content: 'colo=AMS\nloc=NL\n')
          : result(status: 0, error: 'dns resolution failed'),
    );
    expect(o.responded, isTrue, reason: 'IP-литерал резолвится без DNS');
    expect(o.requests, kGeoUrls.length);
    expect(o.colo, 'AMS');
  });

  test('HTTP 200 с чужим телом — не проход, а подмена (§844)', () async {
    final o = await probeGeoSeries(
      genome,
      (url) async =>
          result(status: 200, content: '<html><title>Вход в сеть</title></html>'),
      urls: const ['https://a', 'https://b'],
    );
    expect(o.responded, isFalse,
        reason: 'перехватчик отдаёт 200 — по нему нельзя судить о проходимости');
    expect(o.error, contains('без geo-ответа'));
    expect(o.error, contains('Вход в сеть'));
    expect(o.requests, 2);
  });

  test('все источники мертвы: requests = их число, причина — последняя',
      () async {
    final messages = <String>[];
    final o = await probeGeoSeries(
      genome,
      (url) async => result(status: 0, error: 'dial tcp: i/o timeout', elapsedMs: 8000),
      urls: const ['https://a', 'https://b', 'https://c'],
      log: messages.add,
    );
    expect(o.responded, isFalse);
    expect(o.error, 'err=dial tcp: i/o timeout');
    expect(o.requests, 3);
    expect(o.rttMs, 8000);
    expect(messages.single, contains('3 з-сов по 3 источникам'));
  });

  test('не-2xx без ошибки транспорта подписывается статусом', () async {
    final o = await probeGeoSeries(
      genome,
      (url) async => result(status: 403, content: 'error code: 1020'),
      urls: const ['https://a'],
    );
    expect(o.responded, isFalse);
    expect(o.error, contains('HTTP 403'));
    expect(o.error, contains('error code: 1020'));
  });

  test('исключение по пути не роняет серию', () async {
    final o = await probeGeoSeries(
      genome,
      (url) async => throw StateError('channel closed'),
      urls: const ['https://a', 'https://b'],
    );
    expect(o.responded, isFalse);
    expect(o.error, startsWith('err=probeGetUrl: Bad state'));
    expect(o.requests, 2);
  });
}
