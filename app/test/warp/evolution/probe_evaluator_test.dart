import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/models/dns_ref.dart';
import 'package:lxbox/models/tunnel_status.dart';
import 'package:lxbox/services/builder/core_chain_capability.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/probe_evaluator.dart';
import 'package:lxbox/services/probe/probe_config.dart';
import 'package:lxbox/services/settings_storage.dart';
import 'package:lxbox/services/warp/scan/scan_log.dart';
import 'package:lxbox/services/warp/warp_client.dart';
import 'package:lxbox/vpn/box_vpn_client.dart';
import 'package:lxbox/vpn/cc_channel.dart';

import '../../parser/engine_test_setup.dart';

const _privateKey = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
const _publicKey = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';
const _preSharedKey = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=';
const _headerKey = 'Bw4VHCMqMTg/Rk1UW2JpcHd+hYyTmqGor7a9xMvS2eA=';

Map<String, dynamic> _body(String tag) => {
  'type': 'wireguard',
  'tag': tag,
  'mtu': 1280,
  'address': ['10.8.3.7/32'],
  'private_key': _privateKey,
  'peers': [
    {
      'address': '203.0.113.9',
      'port': 30565,
      'public_key': _publicKey,
      'allowed_ips': ['0.0.0.0/0', '::/0'],
      'pre_shared_key': _preSharedKey,
      'persistent_keepalive_interval': '25-35',
    },
  ],
  'header_protection_key': _headerKey,
  'content_padding_addition': '10-100',
  'rekey_after_time': '100-120',
  'rekey_timeout': '3-7',
  'reject_after_time': '150-180',
  'keepalive_timeout': '5-15',
  'max_handshake_attempts': '15-20',
  'random_trailers': true,
  'disable_cookies': true,
  'jc': 4,
  'jmin': 10,
  'jmax': 50,
  's1': 55,
  's2': 42,
  's3': 40,
  's4': 12,
  'h1': 1,
  'h2': 2,
  'h3': 3,
  'h4': 4,
};

GenomeVerbatim _private(String tag, {String dnsTag = ''}) {
  final genome = GenomeVerbatim.fromBody(tag, _body(tag))!;
  return genome.copyWith(mtu: 1200, keepalive: '30-40', dnsTag: dnsTag);
}

class _Vpn implements BoxVpnClient {
  @override
  Future<TunnelStatus> getVpnStatus() async => TunnelStatus.disconnected;

  @override
  Future<String> getCoreVersion() async => '1.14.4-lx.35';

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('unexpected VPN call: ${invocation.memberName}');
}

class _ForbiddenWarpClient implements WarpClient {
  @override
  dynamic noSuchMethod(Invocation invocation) => throw StateError(
    'private probe must not use WARP: ${invocation.memberName}',
  );
}

class _CoreChannel implements CcChannel {
  final configs = <Map<String, dynamic>>[];
  final requestedTags = <String>[];
  final stoppedRunIds = <int>[];

  @override
  Future<CcProbeStart> probeStart(String config) async {
    configs.add(jsonDecode(config) as Map<String, dynamic>);
    return CcProbeStart(error: '', runId: configs.length);
  }

  @override
  Future<CcGetUrlResult> probeGetUrl(
    String tag, {
    required int runId,
    required String link,
    int timeoutMs = 0,
    int maxBytes = 0,
    String userAgent = '',
  }) async {
    requestedTags.add(tag);
    return const CcGetUrlResult(
      status: 200,
      content: 'colo=AMS\nloc=NL\nip=198.51.100.7\nwarp=off\n',
      truncated: false,
      contentType: 'text/plain',
      remoteAddr: '198.51.100.7',
      elapsedMs: 17,
      error: '',
    );
  }

  @override
  Future<void> probeStop(int runId) async {
    stoppedRunIds.add(runId);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('unexpected core call: ${invocation.memberName}');
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const pathChannel = MethodChannel('plugins.flutter.io/path_provider');
  late Directory storage;
  late _CoreChannel core;
  late ScanLog log;

  setUpAll(loadEngineSections);

  setUp(() async {
    storage = await Directory.systemTemp.createTemp('lxbox_evo_private_');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, (call) async {
          if (call.method.startsWith('getApplicationDocuments')) {
            return storage.path;
          }
          return null;
        });
    SettingsStorage.resetCacheForTesting();
    CoreVersionCache.resetForTest();
    await SettingsStorage.saveDnsServers(const [
      DnsServerInline(
        enabled: true,
        tag: 'evo-dns',
        body: {'type': 'udp', 'server': '9.9.9.9', 'server_port': 53},
      ),
    ]);
    core = _CoreChannel();
    log = ScanLog();
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, null);
    SettingsStorage.resetCacheForTesting();
    storage.deleteSync(recursive: true);
  });

  test(
    'private-only probe preserves AWG3 body and respects WG batch limit',
    () async {
      final genomes = [
        for (var i = 0; i < 5; i++) _private('private-$i', dnsTag: 'evo-dns'),
      ];
      final evaluator = ProbeGenomeEvaluator(
        log: log,
        cc: core,
        vpn: _Vpn(),
        warp: _ForbiddenWarpClient(),
      );
      addTearDown(evaluator.dispose);

      expect(await evaluator.prepareFor(genomes), isNull);
      final observations = await evaluator.evaluate(genomes, attempts: 1);

      expect(core.configs, hasLength(2));
      for (final config in core.configs) {
        final endpoints = (config['endpoints'] as List)
            .cast<Map<String, dynamic>>();
        expect(
          endpoints.length,
          lessThanOrEqualTo(kProbeMaxWireguardPerConfig),
        );
        expect(config['route']['default_domain_resolver'], 'evo-dns');
        expect(
          config['dns']['servers'],
          contains(
            equals({
              'tag': 'evo-dns',
              'type': 'udp',
              'server': '9.9.9.9',
              'server_port': 53,
            }),
          ),
        );
      }

      final endpoints = [
        for (final config in core.configs)
          ...(config['endpoints'] as List).cast<Map<String, dynamic>>(),
      ];
      expect(endpoints, hasLength(genomes.length));
      for (final genome in genomes) {
        final tag = genome.tag;
        final emitted = endpoints.firstWhere((body) => body['tag'] == tag);
        expect(emitted, genome.applyTo(_body(tag)));
        expect(observations[genomes.indexOf(genome)].single.responded, isTrue);
        expect(genome.baseBody, _body(tag));
        expect(genome.json, isNot(contains(_privateKey)));
        expect(genome.json, isNot(contains(_preSharedKey)));
        expect(genome.json, isNot(contains(_headerKey)));

        final exported =
            jsonDecode(evaluator.exportFor(genome)!) as Map<String, dynamic>;
        final exportedBody =
            (exported['endpoints'] as List).single as Map<String, dynamic>;
        expect(exportedBody['tag'], '🧬 ${genome.shortLabel}');
        expect(exportedBody..remove('tag'), emitted..remove('tag'));
      }
      expect(core.requestedTags, hasLength(genomes.length));
      expect(core.stoppedRunIds, [1, 2]);
      expect(log.text, isNot(contains(_privateKey)));
      expect(log.text, isNot(contains(_preSharedKey)));
      expect(log.text, isNot(contains(_headerKey)));
    },
  );

  test(
    'empty private DNS gene keeps the local resolver out of the node body',
    () async {
      final genome = _private('private-local');
      final evaluator = ProbeGenomeEvaluator(
        log: log,
        cc: core,
        vpn: _Vpn(),
        warp: _ForbiddenWarpClient(),
      );
      addTearDown(evaluator.dispose);

      expect(await evaluator.prepareFor([genome]), isNull);
      final observations = await evaluator.evaluate([genome], attempts: 1);
      expect(observations.single.single.responded, isTrue);
      expect(core.configs, hasLength(1));

      final config = core.configs.single;
      expect(config['route']['default_domain_resolver'], kProbeDnsTag);
      expect(config['dns']['servers'], [
        {'type': 'local', 'tag': kProbeDnsTag},
      ]);
      final body = (config['endpoints'] as List).single as Map<String, dynamic>;
      expect(body.containsKey('dnsTag'), isFalse);
      expect(body, genome.applyTo(_body('private-local')));
    },
  );
}
