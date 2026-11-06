import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';

import '../../contract_paths.dart';

/// §848 — геном как патч эмитированного тела: значения локусов, сборка WG/AWG
/// и MASQUE-тела, гейт годности поля через реестр.
void main() {
  setUpAll(loadTestRegistry);

  Map<String, dynamic> awgBody() => {
        'type': 'wireguard',
        'tag': 'warp-awg',
        'private_key': 'k=',
        'mtu': 1280,
        'ip': 'quic',
        'jc': 4,
        'jmin': 40,
        'jmax': 70,
        'id': 'yandex.ru',
        'ib': 'chrome',
        'peers': [
          {
            'address': '162.159.192.1',
            'port': 2408,
            'public_key': 'p=',
            'persistent_keepalive_interval': 25,
          },
        ],
      };

  Map<String, dynamic> masqueBody({String vhttp = 'h3', bool tls = true}) => {
        'type': 'masque',
        'tag': 'warp-h3',
        'server': '162.159.198.1',
        'server_port': 443,
        'vhttp': vhttp,
        'profile': 'cloudflare',
        if (tls) 'tls': {'server_name': 'www.cloudflare.com'},
      };

  const awg = Genome(
    transport: EvoTransport.awg,
    endpoint: '162.159.192.7',
    port: 500,
    sni: 'ya.ru',
    keepalive: 15,
    mtu: 1400,
    junkProto: 'dns',
    junkBrowser: 'firefox',
    junkDomain: 'mail.ru',
    jc: 2,
    jitterMin: 20,
    jitterMax: 128,
    dnsTag: 'scanned',
  );

  const h2 = Genome(
    transport: EvoTransport.masqueH2,
    endpoint: '162.159.199.5',
    port: 8443,
    sni: 'www.wikipedia.org',
    keepalive: 25,
    mtu: 1280,
    fragment: true,
    recordFragment: true,
  );

  group('идентичность', () {
    test('tokens → fromTokens сохраняет key', () {
      expect(Genome.fromTokens(awg.tokens()).key, awg.key);
      expect(Genome.fromTokens(h2.tokens()).key, h2.key);
    });

    test('key различает каждый из локусов', () {
      // Альтернативы ОБЯЗАНЫ быть из домена локуса: `fromTokens` нормализует
      // мусор к умолчанию (`'zz-transport'` → awg), и ключ совпал бы с базовым.
      const alt = {
        'transport': 'h3',
        'endpoint': '9.9.9.9',
        'port': '8443',
        'sni': 'other.ru',
        'keepalive': '25',
        'mtu': '1280',
        'junkProto': 'stun',
        'junkBrowser': 'curl',
        'junkDomain': 'other.ru',
        'jc': '8',
        'jitterMin': '33',
        'jitterMax': '99',
        'fragment': '1',
        'recordFragment': '1',
        'sniCase': '2',
        'dns': 'other',
      };
      for (final l in EvoLocus.values) {
        final t = awg.tokens()..[l] = alt[l.wire]!;
        expect(Genome.fromTokens(t).key, isNot(awg.key), reason: l.wire);
      }
    });

    test('json → Genome — round-trip', () {
      expect(Genome.fromJson(awg.toJson()..remove('key')).key, awg.key);
    });

    test('distanceTo — доля различающихся локусов', () {
      expect(awg.distanceTo(awg), 0);
      expect(awg.distanceTo(awg.copyWith(port: 4500)), 1 / EvoLocus.values.length);
      expect(awg.distanceTo(h2), greaterThan(0.3));
    });

    test('endpointHostPort — IPv6 в скобках', () {
      expect(awg.endpointHostPort, '162.159.192.7:500');
      expect(
        const Genome(
                transport: EvoTransport.awg, endpoint: '2606:4700::1', port: 1701)
            .endpointHostPort,
        '[2606:4700::1]:1701',
      );
    });

    test('shortLabel несёт транспорт, адрес и SNI', () {
      expect(h2.shortLabel, 'h2 · 162.159.199.5:8443 · www.wikipedia.org');
    });
  });

  group('applyTo — WireGuard/AmneziaWG', () {
    test('адрес, порт и keepalive уходят в peers; вход не мутируется', () {
      final base = awgBody();
      final before = awgBody();
      final body = awg.applyTo(base);
      final peer = (body['peers'] as List).first as Map<String, dynamic>;
      expect(peer['address'], '162.159.192.7');
      expect(peer['port'], 500);
      expect(peer['persistent_keepalive_interval'], 15);
      expect(body['mtu'], 1400);
      expect(base, before, reason: 'applyTo обязан работать на копии');
    });

    test('keepalive=0 снимает ключ (ядро берёт своё)', () {
      final body = const Genome(
              transport: EvoTransport.awg, endpoint: '1.1.1.1', port: 2408)
          .applyTo(awgBody());
      final peer = (body['peers'] as List).first as Map<String, dynamic>;
      expect(peer.containsKey('persistent_keepalive_interval'), isFalse);
      expect(body.containsKey('mtu'), isFalse, reason: 'mtu=0 → ключ не пишем');
    });

    test('приманка AWG переписывается из генома', () {
      final body = awg.applyTo(awgBody());
      expect(body['ip'], 'dns');
      expect(body['jc'], 2);
      expect(body['jmin'], 20);
      expect(body['jmax'], 128);
      expect(body['id'], 'mail.ru');
      expect(body.containsKey('ib'), isFalse,
          reason: 'ib осмыслен только при junkProto=quic');
    });

    test('junkDomain пуст → приманка берёт sni', () {
      final body =
          const Genome(transport: EvoTransport.awg, endpoint: '1.1.1.1', port: 2408, sni: 'sni.ru')
              .applyTo(awgBody());
      expect(body['id'], 'sni.ru');
    });

    test('голый WG (без jc/ip) приманки не получает', () {
      final plain = awgBody()
        ..remove('jc')
        ..remove('ip')
        ..remove('id')
        ..remove('ib')
        ..remove('jmin')
        ..remove('jmax');
      final body = awg.applyTo(plain);
      expect(body.containsKey('jc'), isFalse);
      expect(body.containsKey('ip'), isFalse);
      expect((body['peers'] as List).first['address'], '162.159.192.7');
    });
  });

  group('applyTo — MASQUE', () {
    test('транспорт задаёт vhttp, адрес/порт/SNI ложатся в тело', () {
      final body = h2.applyTo(masqueBody());
      expect(body['server'], '162.159.199.5');
      expect(body['server_port'], 8443);
      expect(body['vhttp'], 'h2');
      expect((body['tls'] as Map)['server_name'], 'www.wikipedia.org');
      expect(body['keep_alive_period'], '25s');
      expect(body['mtu'], 1280);
    });

    test('keepalive=0 снимает keep_alive_period', () {
      final body = const Genome(
              transport: EvoTransport.masqueH3, endpoint: '1.1.1.1', port: 443)
          .applyTo(masqueBody(tls: false));
      expect(body.containsKey('keep_alive_period'), isFalse);
      expect(body.containsKey('tls'), isFalse,
          reason: 'пустой tls{} в тело не пишется');
    });

    test('sni пуст → server_name удаляется, а не пишется пустым', () {
      const g = Genome(
          transport: EvoTransport.masqueH2,
          endpoint: '1.1.1.1',
          port: 8443,
          fragment: true);
      final tls = g.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map;
      expect(tls.containsKey('server_name'), isFalse);
      expect(tls['fragment'], true, reason: 'блок жив, просто без SNI');

      final noTls = const Genome(
              transport: EvoTransport.masqueH3, endpoint: '1.1.1.1', port: 443)
          .applyTo(masqueBody());
      expect(noTls.containsKey('tls'), isFalse,
          reason: 'пустой tls{} в тело не пишется');
    });

    test('sniCase>0 даёт смешанный регистр детерминированно', () {
      final g = const Genome(
          transport: EvoTransport.masqueH2,
          endpoint: '1.1.1.1',
          port: 8443,
          sni: 'www.wikipedia.org',
          sniCase: 3);
      final first = (g.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map)['server_name'];
      final second = (g.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map)['server_name'];
      expect(first, second, reason: 'fitness должен быть воспроизводим');
      expect('$first', isNot('www.wikipedia.org'));
      expect('$first'.toLowerCase(), 'www.wikipedia.org');
    });

    test('фрагментация легальна на h2 и снимается реестром на h3', () {
      final h2Body = h2.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map;
      expect(h2Body['fragment'], true);
      expect(h2Body['record_fragment'], true);
      expect(h2Body['fragment_fallback_delay'], '500ms');

      final h3 = h2.copyWith(transport: EvoTransport.masqueH3, port: 443);
      final h3Body = h3.applyTo(masqueBody())['tls'] as Map;
      expect(h3Body.containsKey('fragment'), isFalse,
          reason: 'masque_tls_fragment_h3: на h3 ядро флаг игнорирует');
      expect(h3Body.containsKey('record_fragment'), isFalse);
      expect(h3Body.containsKey('fragment_fallback_delay'), isFalse);
    });

    test('запрет мутации фрагментации (fragment=false) не оставляет ключей',
        () {
      final tls = const Genome(
              transport: EvoTransport.masqueH2,
              endpoint: '1.1.1.1',
              port: 8443,
              sni: 'ex.org')
          .applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map;
      expect(tls.containsKey('fragment'), isFalse);
      expect(tls['server_name'], 'ex.org');
    });
  });

  group('caseShuffle', () {
    test('seed=0 — без изменений', () {
      expect(caseShuffle('www.example.com', 0), 'www.example.com');
    });

    test('детерминирован по seed и сохраняет нижний регистр как set', () {
      expect(caseShuffle('www.example.com', 7), caseShuffle('www.example.com', 7));
      expect(caseShuffle('www.example.com', 7).toLowerCase(), 'www.example.com');
      expect(caseShuffle('www.example.com', 7), isNot(caseShuffle('www.example.com', 8)));
    });

    test('punycode-метки не трогает (регистр там значим)', () {
      expect(caseShuffle('xn--80ak6aa92e.com', 5).split('.').first,
          'xn--80ak6aa92e');
    });
  });
}
