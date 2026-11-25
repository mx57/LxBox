import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/hall_of_fame.dart';
import 'package:lxbox/services/evolution/objectives.dart';
import 'package:lxbox/services/evolution/pools.dart';
import 'package:lxbox/services/settings_storage.dart';

void main() {
  const warp = Genome(
    transport: EvoTransport.masqueH2,
    endpoint: '198.51.100.7',
    port: 8443,
    sni: 'sni-canary.example',
    junkDomain: 'domain-canary.example',
    keepalive: 25,
    mtu: 1280,
    junkProto: 'sip',
    junkBrowser: 'curl',
    jc: 6,
    jitterMin: 64,
    jitterMax: 128,
    fragment: true,
    recordFragment: true,
    sniCase: 3,
    dnsTag: 'dns-canary',
  );
  const pool = EvolutionPools(
    endpoints: ['198.51.100.7'],
    sni: ['sni-canary.example', 'domain-canary.example'],
    dnsTags: ['dns-canary'],
    h2Ports: [8443],
  );

  test('archive round-trip restores a WARP genome from the current pool', () {
    final hall = _archive([_record(warp)]);
    final raw = hall.toJsonString();
    final restored = EvolutionHall.fromJson(
      jsonDecode(raw) as Map<String, dynamic>,
    ).restore(const [], pool);

    expect(restored, hasLength(1));
    expect(restored.single.genome.key, warp.key);
    expect(restored.single.fitness.passRate, 1);
    expect(restored.single.fitness.medianRtt, 120);
    expect(restored.single.confirmations, 1);
  });

  test('empty optional genome tokens survive strict parsing', () {
    final sparse = warp.copyWith(junkProto: '', junkBrowser: '', dnsTag: '');
    final hall = _archive([_record(sparse)]);
    final restored = EvolutionHall.fromJson(
      jsonDecode(hall.toJsonString()) as Map<String, dynamic>,
    ).restore(const [], pool);

    expect(restored.single.genome.key, sparse.key);
  });

  test('a current seed outside the pool supplies only network identity', () {
    final hall = _archive([_record(warp)]);
    final seed = warp.copyWith(mtu: 1400, dnsTag: 'other');
    final restored = hall.restore([
      seed,
    ], const EvolutionPools(dnsTags: ['dns-canary']));

    expect(restored, hasLength(1));
    expect(restored.single.genome.key, warp.key);
    expect(restored.single.genome.endpoint, seed.endpoint);
    expect(restored.single.genome.sni, seed.sni);
  });

  test('serialized archive contains no raw network or secret canaries', () {
    final private = _private();
    final hall = _archive([_record(warp), _record(private)]);
    final raw = hall.toJsonString();

    for (final canary in const [
      '198.51.100.7',
      'sni-canary.example',
      'domain-canary.example',
      'dns-canary',
      'private-tag-canary',
      'private-key-canary',
      'peer-key-canary',
      'body-canary',
    ]) {
      expect(raw, isNot(contains(canary)));
    }
    expect(raw, isNot(contains('private_key')));
    expect(raw, isNot(contains('observations')));
    expect(raw, isNot(contains('error')));
  });

  test('private restore requires the same tag, endpoint and port', () {
    final private = _private();
    final hall = _archive([_record(private)]);
    final matching = private.copyWith(mtu: 1400, keepalive: 30, dnsTag: 'new');
    final restored = hall.restore([matching], const EvolutionPools());

    expect(restored, hasLength(1));
    expect(restored.single.genome.key, private.key);
    expect(restored.single.genome, isA<GenomeVerbatim>());
    expect((restored.single.genome as GenomeVerbatim).tag, private.tag);

    final wrongTag = GenomeVerbatim.fromBody('another-tag', private.baseBody)!;
    final wrongEndpoint = private.baseBody;
    final endpointPeer = Map<String, dynamic>.from(
      (wrongEndpoint['peers'] as List).single as Map,
    );
    wrongEndpoint['peers'] = [
      {...endpointPeer, 'address': '203.0.113.9'},
    ];
    final moved = GenomeVerbatim.fromBody(private.tag, wrongEndpoint)!;
    final wrongPort = private.baseBody;
    final portPeer = Map<String, dynamic>.from(
      (wrongPort['peers'] as List).single as Map,
    );
    wrongPort['peers'] = [
      {...portPeer, 'port': 51821},
    ];
    final movedPort = GenomeVerbatim.fromBody(private.tag, wrongPort)!;

    expect(hall.restore([wrongTag], const EvolutionPools()), isEmpty);
    expect(hall.restore([moved], const EvolutionPools()), isEmpty);
    expect(hall.restore([movedPort], const EvolutionPools()), isEmpty);
  });

  test('future versions and unknown fields are rejected as a whole', () {
    final json =
        jsonDecode(_archive([_record(warp)]).toJsonString())
            as Map<String, dynamic>;
    final future = {...json, 'version': 2};
    expect(() => EvolutionHall.fromJson(future), throwsFormatException);

    final entries = (json['entries'] as List).cast<Map<String, dynamic>>();
    final genes = (entries.single['genome'] as Map<String, dynamic>);
    final injected = {
      ...json,
      'entries': [
        {
          ...entries.single,
          'genome': {...genes, 'privateKey': 'secret-canary'},
        },
      ],
    };
    expect(() => EvolutionHall.fromJson(injected), throwsFormatException);

    final rootInjected = {...json, 'debug': 'secret-canary'};
    expect(() => EvolutionHall.fromJson(rootInjected), throwsFormatException);
  });

  test('malformed salt, metrics and duplicate identities fail closed', () {
    final json =
        jsonDecode(_archive([_record(warp)]).toJsonString())
            as Map<String, dynamic>;
    expect(
      () => EvolutionHall.fromJson({...json, 'salt': 'not-base64'}),
      throwsFormatException,
    );

    final entries = (json['entries'] as List).cast<Map<String, dynamic>>();
    final fitness = (entries.single['fitness'] as Map<String, dynamic>);
    final badMetrics = {
      ...json,
      'entries': [
        {
          ...entries.single,
          'fitness': {...fitness, 'passes': 2},
        },
      ],
    };
    expect(() => EvolutionHall.fromJson(badMetrics), throwsFormatException);
    expect(
      () => EvolutionHall.fromJson({
        ...json,
        'entries': [
          {
            ...entries.single,
            'fitness': {...fitness, 'attempts': 0},
          },
        ],
      }),
      throwsFormatException,
    );
    expect(
      () => EvolutionHall.fromJson({
        ...json,
        'entries': [
          {
            ...entries.single,
            'fitness': {...fitness, 'confirmations': 2},
          },
        ],
      }),
      throwsFormatException,
    );

    expect(
      () => EvolutionHall.fromJson({
        ...json,
        'entries': [entries.single, entries.single],
      }),
      throwsFormatException,
    );
  });

  test('merge deduplicates, caps and keeps Pareto contenders', () {
    final contenders = [
      warp,
      warp.copyWith(keepalive: 30),
      warp.copyWith(keepalive: 60),
    ];
    final dominated = [
      for (var i = 0; i < 80; i++)
        warp.copyWith(endpoint: '198.51.100.${i + 20}', keepalive: 15),
    ];
    final hall = _archive([
      for (var i = 0; i < contenders.length; i++)
        _record(contenders[i], confirmations: i + 1, rtt: 100 - i * 20),
      for (final genome in dominated) _record(genome, passes: 0, rtt: 1000),
    ]);

    expect(hall.entries, hasLength(EvolutionHall.maxEntries));
    final ids = hall.entries.map((e) => e.id).toSet();
    expect(ids, hasLength(EvolutionHall.maxEntries));
    for (final contender in contenders) {
      expect(ids, contains(hall.identityOf(contender)));
    }

    final duplicate = hall.mergeRecords([
      _record(contenders.first, confirmations: 9),
    ]);
    expect(duplicate.entries, hasLength(EvolutionHall.maxEntries));
    expect(
      duplicate.entries
          .singleWhere((e) => e.id == hall.identityOf(contenders.first))
          .confirmations,
      9,
    );

    final historical = _archive([
      _record(warp, attempts: 6, passes: 5, confirmations: 3, rtt: 90),
    ]);
    final shorter = historical.mergeRecords([_record(warp)]);
    final merged = shorter.entries.single;
    expect(merged.confirmations, 3);
    expect(merged.toJson()['fitness'], containsPair('attempts', 6));
    expect(merged.toJson()['fitness'], containsPair('passes', 5));
    expect(
      () => EvolutionHall.fromJson(
        jsonDecode(shorter.toJsonString()) as Map<String, dynamic>,
      ),
      returnsNormally,
    );
  });

  test('backup allowlist accepts the safe evolution archive', () {
    expect(SettingsStorage.allowedVarKeys(const []), contains('evo_hall'));
  });

  test('save and load survive a settings cache reset', () async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final tmp = await Directory.systemTemp.createTemp('lxbox_evo_hall_');
    const channel = MethodChannel('plugins.flutter.io/path_provider');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getApplicationDocumentsDirectory' ||
          call.method == 'getApplicationDocumentsPath') {
        return tmp.path;
      }
      return null;
    });
    SettingsStorage.resetCacheForTesting();
    try {
      final hall = _archive([_record(warp)]);
      await hall.save();
      SettingsStorage.resetCacheForTesting();
      final loaded = await EvolutionHall.load();
      expect(loaded.entries.single.id, hall.entries.single.id);
      expect(loaded.restore(const [], pool).single.genome.key, warp.key);

      await SettingsStorage.setVar(EvolutionHall.storageKey, '{"version":99}');
      SettingsStorage.resetCacheForTesting();
      expect((await EvolutionHall.load()).entries, isEmpty);
    } finally {
      SettingsStorage.resetCacheForTesting();
      messenger.setMockMethodCallHandler(channel, null);
      try {
        await tmp.delete(recursive: true);
      } on FileSystemException {
        // AppLog может ещё дописывать свой файл в этот временный каталог.
      }
    }
  });
}

EvolutionHall _archive(List<EvolutionHallRecord> records) =>
    EvolutionHall().mergeRecords(records, now: DateTime.utc(2026, 11, 25));

EvolutionHallRecord _record(
  Genome genome, {
  int confirmations = 1,
  int passes = 1,
  int attempts = 1,
  int rtt = 120,
}) {
  final effectiveAttempts = max(attempts, confirmations);
  final fitness = Fitness(genome)
    ..confirmations = confirmations
    ..rungReached = 1;
  for (var i = 0; i < passes; i++) {
    fitness.add(Observation(responded: true, rttMs: rtt));
  }
  for (var i = passes; i < effectiveAttempts; i++) {
    fitness.add(const Observation.failed('timeout'));
  }
  return EvolutionHallRecord(
    genome: genome,
    fitness: fitness,
    confirmations: confirmations,
    bestRung: 1,
  );
}

GenomeVerbatim _private() => GenomeVerbatim.fromBody('private-tag-canary', {
  'type': 'wireguard',
  'tag': 'private-tag-canary',
  'address': ['172.16.0.2/32'],
  'private_key': 'private-key-canary',
  'mtu': 1280,
  'body_canary': 'body-canary',
  'peers': [
    {
      'address': '203.0.113.5',
      'port': 2408,
      'public_key': 'peer-key-canary',
      'allowed_ips': ['0.0.0.0/0'],
      'persistent_keepalive_interval': '25-35',
    },
  ],
})!;
