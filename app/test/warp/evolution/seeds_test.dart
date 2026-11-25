import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/models/node_spec.dart';
import 'package:lxbox/models/template_vars.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/seeds.dart';
import 'package:lxbox/services/warp/awg_profile.dart';
import 'package:lxbox/services/warp/masque_account.dart';
import 'package:lxbox/services/warp/scan/scan_models.dart';
import 'package:lxbox/services/warp/scan/scan_node_builder.dart';
import 'package:lxbox/services/warp/scan/scan_pool.dart';
import 'package:lxbox/services/warp/warp_account.dart';

import '../../parser/engine_test_setup.dart';
import '../../parser/parse_link_as.dart';

/// §848 — посев популяции из того, что уже есть на экране серверов: узел
/// разбирается тем же конвейером, что и боевой конфиг, и геном описывает ровно
/// то, что в его теле меняется.
void main() {
  setUpAll(loadEngineSections);

  WarpAccount warp() => const WarpAccount(
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

  MasqueAccount masque() => const MasqueAccount(
        privKeyDer: 'a2V5',
        serverPubDer: 'cHVi',
        clientV4: '172.16.0.2',
        clientV6: '',
        server: '162.159.198.1',
        port: 443,
        deviceId: 'dev',
        token: 'tok',
        createdAt: '2026-01-01T00:00:00Z',
      );

  NodeSpec awgNode({
    String ip = '162.159.192.7',
    int port = 2408,
    String sni = 'yandex.ru',
    AwgProfile profile = AwgProfile.warp15,
    String junkProto = 'quic',
  }) {
    final uri = ScanNodeBuilder(warp: warp(), wgKeepalive: 25).uriFor(
      ScanCandidate(
        ip: ip,
        port: port,
        protocol: ScanProtocol.awg,
        sni: sni,
        awgParams: AwgParams(
          ip: junkProto,
          jc: 4,
          jmin: 40,
          jmax: 70,
          profile: profile,
        ),
      ),
    )!;
    return parseLinkAs<WireguardSpec>(uri)!;
  }

  NodeSpec masqueNode({
    String ip = '162.159.199.5',
    int port = 4443,
    EvoTransport t = EvoTransport.masqueH3,
  }) {
    final uri = ScanNodeBuilder(masque: masque()).uriFor(
      ScanCandidate(
      ip: ip,
      port: port,
      protocol: t.scanProtocol,
      sni: 'www.cloudflare.com',
      ),
    )!;
    return parseLinkAs<MasqueSpec>(uri)!;
  }

  group('genomeOfNode', () {
    test('AWG-узел → геном с адресом кандидата и приманкой', () {
      final g = genomeOfNode(awgNode())!;
      expect(g.transport, EvoTransport.awg);
      expect(g.awgProfile, AwgProfile.warp15);
      expect(g.endpoint, '162.159.192.7');
      expect(g.port, 2408);
      expect(g.keepalive, 25);
      expect(g.junkProto, 'quic');
      expect(g.jc, 4);
      expect(g.jitterMin, 40);
      expect(g.jitterMax, 70);
      expect(g.junkDomain, 'yandex.ru');
      expect(g.sni, 'yandex.ru');
    });

    test('AWG3 ranged keepalive survives seeding and body patching', () {
      final node = WireguardSpec(
        id: 'wg-ranged',
        tag: 'wg-ranged',
        label: 'ranged',
        server: '162.159.192.7',
        port: 2408,
        rawSource: '',
        privateKey: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=',
        localAddresses: const ['172.16.0.2/32'],
        peers: [
          WireguardPeer(
            publicKey: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=',
            endpointHost: '162.159.192.7',
            endpointPort: 2408,
            persistentKeepalive: '25-35',
          ),
        ],
        awg: const Awg({
          'ip': 'quic',
          'jc': 4,
          'jmin': 40,
          'jmax': 70,
          'id': 'yandex.ru',
          'ib': 'chrome',
        }),
      );
      final genome = genomeOfNode(node)!;
      expect(genome.keepalive, '25-35');
      final body = node.emit(TemplateVars.empty).map;
      final patched = genome.applyTo(body);
      final peer = (patched['peers'] as List).first as Map<String, dynamic>;
      expect(peer['persistent_keepalive_interval'], '25-35');
    });

    test('warpCps узел распознаётся по CPS-полям, а не по одним I2..I5', () {
      final cps = genomeOfNode(awgNode(profile: AwgProfile.warpCps))!;
      expect(cps.awgProfile, AwgProfile.warpCps);
      expect(genomeOfNode(awgNode())!.awgProfile, AwgProfile.warp15);
      final set = seedsFromNodes(
        [awgNode(), awgNode(profile: AwgProfile.warpCps)],
        pool: ScanPool.fromFullJson({
          'wireguard': {
            'v4_cidr': ['162.159.192.0/24'],
            'ports': [2408],
            'endpoints_preset': ['engage.cloudflareclient.com:2408'],
          },
        })!,
      );
      expect(set.genomes, hasLength(2), reason: 'профиль входит в identity');
    });

    test('warpCps с SIP распознаётся по I3..I5 без I2', () {
      final cps = genomeOfNode(
        awgNode(profile: AwgProfile.warpCps, junkProto: 'sip'),
      )!;
      expect(cps.awgProfile, AwgProfile.warpCps);
      expect(cps.junkProto, 'sip');
    });

    test('MASQUE h3 и h2 → соответствующий транспорт и SNI', () {
      final h3 = genomeOfNode(masqueNode())!;
      expect(h3.transport, EvoTransport.masqueH3);
      expect(h3.endpoint, '162.159.199.5');
      expect(h3.port, 4443);
      expect(h3.sni, 'www.cloudflare.com');

      final h2 = genomeOfNode(
        masqueNode(ip: '162.159.198.5', port: 8443, t: EvoTransport.masqueH2),
      )!;
      expect(h2.transport, EvoTransport.masqueH2);
      expect(h2.endpoint, '162.159.198.5');
      expect(h2.port, 8443);
    });

    test('геном посева применяется к собственному телу без потери адреса', () {
      final node = awgNode(ip: '162.159.193.9', port: 500);
      final body = node.emit(TemplateVars.empty).map;
      final patched = genomeOfNode(node)!.applyTo(body);
      final peer = (patched['peers'] as List).first as Map<String, dynamic>;
      expect(peer['address'], '162.159.193.9');
      expect(peer['port'], 500);
    });

    test('не-WARP узел не эволюционируем', () {
      final socks = parseLinkAs<SocksSpec>(
        'socks5://user:pass@1.2.3.4:1080#node',
      );
      expect(socks, isNotNull);
      expect(genomeOfNode(socks!), isNull);
    });

    test('узел без адреса (пустые peers) → null', () {
      final bare = WireguardSpec(
        id: 'wg-bare',
        tag: 'wg-bare',
        label: 'bare',
        server: '',
        port: 0,
        rawSource: '',
        privateKey: 'a=',
        localAddresses: const [],
        peers: const [],
      );
      expect(genomeOfNode(bare), isNull);
    });
  });

  group('seedsFromNodes', () {
    ScanPool warpPool() => ScanPool.fromFullJson({
          'wireguard': {
            'v4_cidr': ['162.159.192.0/24'],
            'ports': [2408],
            'endpoints_preset': ['engage.cloudflareclient.com:2408'],
          },
        })!;

    test('приватный WG/AWG становится дословным геномом, не WARP', () {
      final set = seedsFromNodes(
        [awgNode(ip: '203.0.113.5'), awgNode()],
        pool: warpPool(),
      );
      expect(set.total, 2);
      expect(set.genomes, hasLength(2));
      expect(set.warpCount, 1);
      expect(set.privateCount, 1);
      expect(set.skipped, isEmpty);
      final own = set.genomes.singleWhere((g) => g.isVerbatim);
      expect(own.endpoint, '203.0.113.5');
      expect(own.toJson()['mode'], 'verbatim');
      expect(own.toJson(), isNot(contains('private_key')));
    });

    test('WARP preset и MASQUE проходят фильтр', () {
      final set = seedsFromNodes(
        [
          awgNode(ip: 'engage.cloudflareclient.com'),
          masqueNode(ip: '203.0.113.9'),
        ],
        pool: warpPool(),
      );
      expect(set.genomes, hasLength(2));
      expect(set.skipped, isEmpty);
    });

    test('недоступный пул сохраняет WG/AWG как дословный геном', () {
      final set = seedsFromNodes([awgNode(ip: '203.0.113.5')]);
      expect(set.genomes, hasLength(1));
      expect(set.genomes.single.isVerbatim, isTrue);
      expect(set.skipped, isEmpty);
    });

    test('загруженный MASQUE-only пул не считает WG адреса WARP', () {
      final pool = ScanPool.fromFullJson({
        'masque': {
          'v4_cidr': ['162.159.198.0/24'],
          'ports_h3': [443],
        },
      })!;
      final set = seedsFromNodes([awgNode()], pool: pool);
      expect(set.genomes, hasLength(1));
      expect(set.privateCount, 1);
      expect(set.skipped, isEmpty);
    });

    test('узел с чужим detour не становится прямым семенем', () {
      final body = awgNode(ip: '203.0.113.5').emit(TemplateVars.empty).map;
      final node = awgNode(ip: '203.0.113.5')
        ..patchedJson = (body..['detour'] = 'foreign-exit');
      final set = seedsFromNodes([node], pool: warpPool());
      expect(set.genomes, isEmpty);
      expect(set.skipped[SeedSkipReason.foreignDetour], 1);
    });

    test('считает все узлы и не дублирует одинаковые геномы', () {
      final set = seedsFromNodes([awgNode(), awgNode(), masqueNode()]);
      expect(set.total, 3);
      expect(set.genomes, hasLength(2));
      expect(set.skippedCount, 0);
      expect(set.genomes.map((g) => g.transport).toSet(), {
        EvoTransport.awg,
        EvoTransport.masqueH3,
      });
    });

    test('подписной протокол попадает в notWarp, а не в молчание', () {
      final ss = parseLinkAs<ShadowsocksSpec>(
        'ss://YWVzLTI1Ni1nY206cGFzcw==@198.51.100.26:8388#three',
      )!;
      final set = seedsFromNodes([ss]);
      expect(set.genomes, isEmpty);
      expect(set.skipped[SeedSkipReason.notWarp], 1);
      expect(set.isEmpty, isTrue);
    });

    test('узел-группа отсеивается как group', () {
      final group = AutoSelectSpec(id: 'g1', tag: 'pool', label: 'pool');
      final set = seedsFromNodes([group, awgNode()]);
      expect(set.skipped[SeedSkipReason.group], 1);
      expect(set.genomes, hasLength(1));
    });

    test('WG без адреса — причина noAddress', () {
      final bare = WireguardSpec(
        id: 'wg-2',
        tag: 'wg-2',
        label: 'wg',
        server: '',
        port: 0,
        rawSource: '',
        privateKey: 'a=',
        localAddresses: const [],
        peers: const [],
      );
      final set = seedsFromNodes([bare]);
      expect(set.skipped[SeedSkipReason.noAddress], 1);
      expect(set.skipped.containsKey(SeedSkipReason.notWarp), isFalse);
    });

    test('пустой вход — пустой посев, а не исключение', () {
      final set = seedsFromNodes(const []);
      expect(set.total, 0);
      expect(set.genomes, isEmpty);
      expect(SeedSet.empty.genomes, isEmpty);
    });
  });
}
