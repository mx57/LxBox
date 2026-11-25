import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/warp/awg_profile.dart';

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
        'awgProfile': 'warp-cps',
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
      expect(
        Genome.fromJson(
          awg.copyWith(awgProfile: AwgProfile.warpCps).toJson(),
        ).awgProfile,
        AwgProfile.warpCps,
      );
      expect(
        Genome.fromJson(const {'transport': 'awg'}).awgProfile,
        AwgProfile.warp15,
      );
    });

    test('AWG3 keepalive range survives identity, copy and JSON', () {
      const ranged = Genome(
        transport: EvoTransport.awg,
        endpoint: '162.159.192.7',
        port: 2408,
        keepalive: '25-35',
      );
      expect(ranged.tokens()[EvoLocus.keepalive], '25-35');
      expect(Genome.fromTokens(ranged.tokens()).key, ranged.key);
      expect(ranged.copyWith(port: 500).keepalive, '25-35');
      expect(Genome.fromJson(ranged.toJson()).keepalive, '25-35');
      expect(ranged.key, isNot(ranged.copyWith(keepalive: 25).key));
    });

    test('invalid keepalive normalizes to zero', () {
      for (final value in ['', 'nope', '-1', '35-25', '4294967296']) {
        final tokens = awg.tokens()..[EvoLocus.keepalive] = value;
        expect(Genome.fromTokens(tokens).keepalive, 0, reason: value);
      }
      expect(awg.copyWith(keepalive: 'bad').keepalive, 0);
      expect(Genome.fromJson({'keepalive': 'bad'}).keepalive, 0);
    });

    test('distanceTo — доля различающихся локусов', () {
      expect(awg.distanceTo(awg), 0);
      expect(
        awg.distanceTo(awg.copyWith(port: 4500)),
        1 / EvoLocus.values.length,
      );
      expect(awg.distanceTo(h2), greaterThan(0.3));
    });

    test('endpointHostPort — IPv6 в скобках', () {
      expect(awg.endpointHostPort, '162.159.192.7:500');
      expect(
        const Genome(
          transport: EvoTransport.awg,
          endpoint: '2606:4700::1',
          port: 1701,
        ).endpointHostPort,
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
        transport: EvoTransport.awg,
        endpoint: '1.1.1.1',
        port: 2408,
      ).applyTo(awgBody());
      final peer = (body['peers'] as List).first as Map<String, dynamic>;
      expect(peer.containsKey('persistent_keepalive_interval'), isFalse);
      expect(body.containsKey('mtu'), isFalse, reason: 'mtu=0 → ключ не пишем');
    });

    test('AWG3 keepalive range is written verbatim', () {
      final body = const Genome(
        transport: EvoTransport.awg,
        endpoint: '162.159.192.7',
        port: 2408,
        keepalive: '25-35',
      ).applyTo(awgBody());
      final peer = (body['peers'] as List).first as Map<String, dynamic>;
      expect(peer['persistent_keepalive_interval'], '25-35');
    });

    test('приманка AWG переписывается из генома', () {
      final body = awg.applyTo(awgBody());
      expect(body['ip'], 'dns');
      expect(body['jc'], 2);
      expect(body['jmin'], 20);
      expect(body['jmax'], 128);
      expect(body['id'], 'mail.ru');
      expect(
        body.containsKey('ib'),
        isFalse,
        reason: 'ib осмыслен только при junkProto=quic',
      );
    });

    test('warpCps добавляет CPS-поля, warp15 их снимает', () {
      final cps =
          awg.copyWith(awgProfile: AwgProfile.warpCps).applyTo(awgBody());
      expect(cps['i2'], '<t><r 28>');
      expect(cps['i5'], '<r 32>');
      expect(cps['s1'], awgBody()['s1']);
      expect(cps['h4'], awgBody()['h4']);
      final reverted = awg.applyTo(cps);
      for (final key in const ['i2', 'i3', 'i4', 'i5']) {
        expect(reverted.containsKey(key), isFalse);
      }
    });

    test('warpCps с SIP оставляет I3..I5 и удаляет I2', () {
      final cps = awg.copyWith(awgProfile: AwgProfile.warpCps);
      final quic = cps.applyTo(awgBody());
      final sip = cps.copyWith(junkProto: 'sip').applyTo(quic);
      expect(sip['ip'], 'sip');
      expect(sip.containsKey('i2'), isFalse);
      expect(sip['i3'], '<r 32>');
      expect(sip['i5'], '<r 32>');
    });

    test('профиль доходит до кандидата, MASQUE его игнорирует', () {
      final cps = awg.copyWith(awgProfile: AwgProfile.warpCps);
      expect(cps.toCandidate().awgParams?.profile, AwgProfile.warpCps);
      expect(
        h2.copyWith(awgProfile: AwgProfile.warpCps).toCandidate().awgParams,
        isNull,
      );
    });

    test('junkDomain пуст → приманка берёт sni', () {
      final body = const Genome(
        transport: EvoTransport.awg,
        endpoint: '1.1.1.1',
        port: 2408,
        sni: 'sni.ru',
      ).applyTo(awgBody());
      expect(body['id'], 'sni.ru');
    });

    test('пустые masquerade-гены наследуют непустые значения базы', () {
      final base = awgBody()
        ..['id'] = 'www.google.com'
        ..['ib'] = 'firefox';
      final body = const Genome(
        transport: EvoTransport.awg,
        endpoint: '1.1.1.1',
        port: 2408,
        junkProto: '',
        junkBrowser: '',
      ).applyTo(base);
      expect(body['ip'], 'quic');
      expect(body['id'], 'www.google.com');
      expect(body['ib'], 'firefox');
    });

    test('пустая приманка не создаёт id, если в базе его нет', () {
      final base = awgBody()
        ..remove('id')
        ..remove('ip')
        ..remove('ib');
      final body = const Genome(
        transport: EvoTransport.awg,
        endpoint: '1.1.1.1',
        port: 2408,
        junkProto: '',
        junkBrowser: '',
      ).applyTo(base);
      expect(body.containsKey('id'), isFalse);
      expect(body.containsKey('ip'), isFalse);
      expect(body.containsKey('ib'), isFalse);
    });

    test('явный i1 блокирует запись masquerade-генов', () {
      final base = awgBody()
        ..remove('ip')
        ..remove('id')
        ..remove('ib')
        ..['i1'] = '<b 0x01><r 32>';
      final body = awg.applyTo(base);
      expect(body['i1'], '<b 0x01><r 32>');
      expect(body.containsKey('ip'), isFalse);
      expect(body.containsKey('id'), isFalse);
      expect(body.containsKey('ib'), isFalse);
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
        transport: EvoTransport.masqueH3,
        endpoint: '1.1.1.1',
        port: 443,
      ).applyTo(masqueBody(tls: false));
      expect(body.containsKey('keep_alive_period'), isFalse);
      expect(
        body.containsKey('tls'),
        isFalse,
        reason: 'пустой tls{} в тело не пишется',
      );
    });

    test('MASQUE rejects a ranged keepalive instead of writing N-Ms', () {
      final ranged = h2.copyWith(keepalive: '25-35');
      expect(ranged.keepalive, 0);
      expect(ranged.tokens()[EvoLocus.keepalive], '0');
      final base = masqueBody(vhttp: 'h2')..['keep_alive_period'] = '25s';
      final body = ranged.applyTo(base);
      expect(body.containsKey('keep_alive_period'), isFalse);
    });

    test('sni пуст → server_name удаляется, а не пишется пустым', () {
      const g = Genome(
          transport: EvoTransport.masqueH2,
          endpoint: '1.1.1.1',
          port: 8443,
        fragment: true,
      );
      final tls = g.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map;
      expect(tls.containsKey('server_name'), isFalse);
      expect(tls['fragment'], true, reason: 'блок жив, просто без SNI');

      final noTls = const Genome(
        transport: EvoTransport.masqueH3,
        endpoint: '1.1.1.1',
        port: 443,
      ).applyTo(masqueBody());
      expect(
        noTls.containsKey('tls'),
        isFalse,
        reason: 'пустой tls{} в тело не пишется',
      );
    });

    test('sniCase>0 даёт смешанный регистр детерминированно', () {
      final g = const Genome(
          transport: EvoTransport.masqueH2,
          endpoint: '1.1.1.1',
          port: 8443,
          sni: 'www.wikipedia.org',
        sniCase: 3,
      );
      final first =
          (g.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map)['server_name'];
      final second =
          (g.applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map)['server_name'];
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
      expect(
        h3Body.containsKey('fragment'),
        isFalse,
        reason: 'masque_tls_fragment_h3: на h3 ядро флаг игнорирует',
      );
      expect(h3Body.containsKey('record_fragment'), isFalse);
      expect(h3Body.containsKey('fragment_fallback_delay'), isFalse);
    });

    test(
      'запрет мутации фрагментации (fragment=false) не оставляет ключей',
        () {
      final tls = const Genome(
              transport: EvoTransport.masqueH2,
              endpoint: '1.1.1.1',
              port: 8443,
          sni: 'ex.org',
        ).applyTo(masqueBody(vhttp: 'h2'))['tls'] as Map;
      expect(tls.containsKey('fragment'), isFalse);
      expect(tls['server_name'], 'ex.org');
      },
    );
  });

  group('GenomeVerbatim', () {
    Map<String, dynamic> privateBody() => {
          'type': 'wireguard',
          'tag': 'own-awg',
          'address': ['172.16.0.2/32'],
          'private_key': 'private-key-must-stay',
          'mtu': 1280,
          'ip': 'quic',
          'jc': 4,
          'jmin': 40,
          'jmax': 70,
          'id': 'yandex.ru',
          'ib': 'chrome',
          'i1': '<b 0x01><r 32>',
          's3': 16,
          'h1': '100-200',
          'header_protection_key': 'header-key-must-stay',
          'content_padding_addition': '12-24',
          'random_trailers': true,
          'peers': [
            {
              'address': '203.0.113.5',
              'port': 2408,
              'public_key': 'peer-key-must-stay',
              'pre_shared_key': 'psk-must-stay',
              'allowed_ips': ['0.0.0.0/0'],
              'persistent_keepalive_interval': '25-35',
            },
          ],
        };

    test('меняет только MTU и keepalive; вход и исходное тело не мутируются', () {
      final source = privateBody();
      final before = jsonDecode(jsonEncode(source)) as Map<String, dynamic>;
      final genome = GenomeVerbatim.fromBody('own-awg', source)!
          .copyWith(mtu: 1400, keepalive: '30-40', dnsTag: 'own-dns');
      final body = genome.applyTo({'mtu': 1});
      final expected = jsonDecode(jsonEncode(before)) as Map<String, dynamic>
        ..['mtu'] = 1400;
      ((expected['peers'] as List).first as Map<String, dynamic>)[
          'persistent_keepalive_interval'] = '30-40';

      expect(body, expected);
      expect(source, before);
      expect(genome.baseBody, before);
      expect(body['private_key'], 'private-key-must-stay');
      expect(body['header_protection_key'], 'header-key-must-stay');
      expect(body['i1'], '<b 0x01><r 32>');
      expect(body['content_padding_addition'], '12-24');
      expect(body['random_trailers'], isTrue);
      expect(body, isNot(contains('dnsTag')));
    });

    test('посев сохраняет ranged keepalive; нули снимают только свои ключи', () {
      final genome = GenomeVerbatim.fromBody('own-awg', privateBody())!;
      expect(genome.keepalive, '25-35');
      final seeded = genome.applyTo(privateBody());
      expect(
        ((seeded['peers'] as List).first as Map<String, dynamic>)[
            'persistent_keepalive_interval'],
        '25-35',
      );
      final cleared = genome.copyWith(mtu: 0, keepalive: 0).applyTo(privateBody());
      expect(cleared.containsKey('mtu'), isFalse);
      expect(
        ((cleared['peers'] as List).first as Map<String, dynamic>)
            .containsKey('persistent_keepalive_interval'),
        isFalse,
      );
    });

    test('identity несёт режим, tag и DNS, но не утекает телом и ключами', () {
      final genome = GenomeVerbatim.fromBody('own-awg', privateBody())!;
      final changedDns = genome.copyWith(dnsTag: 'own-dns');
      final changedTag = GenomeVerbatim.fromBody('other-awg', privateBody())!;
      expect(genome.key, startsWith('verbatim:'));
      expect(changedDns.key, isNot(genome.key));
      expect(changedTag.key, isNot(genome.key));
      expect(genome.key, isNot(genome.copyWith(keepalive: 25).key));
      final report = genome.json;
      expect(report, contains('verbatim'));
      expect(report, contains('own-awg'));
      expect(report, isNot(contains('private-key-must-stay')));
      expect(report, isNot(contains('peer-key-must-stay')));
      expect(report, isNot(contains('header-key-must-stay')));
    });

    test('copyWith игнорирует все фиксированные локусы', () {
      final genome = GenomeVerbatim.fromBody('own-awg', privateBody())!;
      final changed = genome.copyWith(
        endpoint: '9.9.9.9',
        port: 443,
        junkProto: 'sip',
        jc: 8,
        fragment: true,
        awgProfile: AwgProfile.warpCps,
      );
      expect(changed.endpoint, genome.endpoint);
      expect(changed.port, genome.port);
      expect(changed.junkProto, genome.junkProto);
      expect(changed.jc, genome.jc);
      expect(changed.fragment, isFalse);
      expect(changed.awgProfile, genome.awgProfile);
      expect(changed.key, genome.key);
    });

    test('distanceTo сравнивает три локуса только внутри одного tag', () {
      final genome = GenomeVerbatim.fromBody('own-awg', privateBody())!;
      expect(genome.distanceTo(genome), 0);
      expect(genome.distanceTo(genome.copyWith(mtu: 1400)), 1 / 3);
      final other = GenomeVerbatim.fromBody('other-awg', privateBody())!;
      expect(genome.distanceTo(other), 1);
      expect(genome.distanceTo(awg), 1);
    });

    test('foreign detour, отсутствие адреса и не-WG тело отвергаются', () {
      final foreign = privateBody()..['detour'] = 'foreign-exit';
      expect(GenomeVerbatim.fromBody('own-awg', foreign), isNull);
      final noAddress = privateBody()..['address'] = <String>[];
      expect(GenomeVerbatim.fromBody('own-awg', noAddress), isNull);
      expect(GenomeVerbatim.fromBody('own-awg', masqueBody()), isNull);
    });
  });

  group('caseShuffle', () {
    test('seed=0 — без изменений', () {
      expect(caseShuffle('www.example.com', 0), 'www.example.com');
    });

    test('детерминирован по seed и сохраняет нижний регистр как set', () {
      expect(
        caseShuffle('www.example.com', 7),
        caseShuffle('www.example.com', 7),
      );
      expect(
        caseShuffle('www.example.com', 7).toLowerCase(),
        'www.example.com',
      );
      expect(
        caseShuffle('www.example.com', 7),
        isNot(caseShuffle('www.example.com', 8)),
      );
    });

    test('punycode-метки не трогает (регистр там значим)', () {
      expect(
        caseShuffle('xn--80ak6aa92e.com', 5).split('.').first,
        'xn--80ak6aa92e',
      );
    });
  });
}
