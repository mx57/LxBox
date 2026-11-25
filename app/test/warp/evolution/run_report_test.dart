import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/services/evolution/engine.dart';
import 'package:lxbox/services/evolution/genome.dart';
import 'package:lxbox/services/evolution/objectives.dart';
import 'package:lxbox/services/evolution/run_report.dart';
import 'package:lxbox/services/evolution/settings.dart';
import 'package:lxbox/services/warp/awg_profile.dart';

const _endpointCanary = 'ENDPOINT_CANARY.invalid';
const _sniCanary = 'SNI_CANARY.invalid';
const _junkCanary = 'JUNK_CANARY.invalid';
const _dnsCanary = 'DNS_CANARY';
const _privateTagCanary = 'PRIVATE_TAG_CANARY';
const _privateBodyCanary = 'PRIVATE_BODY_CANARY';
const _privateKeyCanary = 'PRIVATE_KEY_CANARY';
const _privateEndpointCanary = 'PRIVATE_ENDPOINT_CANARY.invalid';
const _privateDnsCanary = 'PRIVATE_DNS_CANARY';
const _urlCanary = 'https://PROBE_CANARY.invalid/path';
const _observationCanary = 'OBSERVATION_CANARY';
const _outcomeCanary = 'OUTCOME_CANARY';
const _stackCanary = 'STACK_CANARY';
const _countryCanary = 'TARGET_COUNTRY_CANARY';
const _coreCanary = 'CORE_VERSION_CANARY\nPRIVATE_KEY_CANARY';

final _startedAt = DateTime.utc(2026, 11, 26, 10);
final _finishedAt = DateTime.utc(2026, 11, 26, 10, 0, 5);

const _settings = EvolutionSettings(
  populationSize: 12,
  maxGenerations: 3,
  maxRequests: 120,
  rungAttempts: [1, 2],
  targetCountry: _countryCanary,
  countries: ['nl', _countryCanary],
  transports: {EvoTransport.masqueH2, EvoTransport.awg},
  awgProfiles: {AwgProfile.warpCps, AwgProfile.warp15},
  disabledLoci: {EvoLocus.sni, EvoLocus.dns},
  useEda: false,
  allowFragment: false,
  allowRecordFragment: false,
  requestTimeout: Duration(seconds: 4),
  seed: 42,
  minPassRate: 0.5,
);

Genome _warpGenome() => Genome(
      transport: EvoTransport.awg,
      awgProfile: AwgProfile.warpCps,
      endpoint: _endpointCanary,
      port: 2408,
      sni: _sniCanary,
      junkDomain: _junkCanary,
      dnsTag: _dnsCanary,
    );

GenomeVerbatim _privateGenome() => GenomeVerbatim.fromBody(
      _privateTagCanary,
      {
        'type': 'wireguard',
        'tag': _privateTagCanary,
        'private_key': _privateKeyCanary,
        'address': ['10.8.0.2/32'],
        'peers': [
          {
            'address': _privateEndpointCanary,
            'port': 51820,
            'public_key': 'PUBLIC_KEY_CANARY',
            'allowed_ips': ['0.0.0.0/0'],
          },
        ],
        'private_body': _privateBodyCanary,
      },
    )!.copyWith(dnsTag: _privateDnsCanary);

EvoRecord _record(
  Genome genome,
  List<Observation> observations, {
  int confirmations = 0,
  int bestRung = 0,
  int rungReached = 0,
}) {
  final fitness = Fitness(genome)..rungReached = rungReached;
  for (final observation in observations) {
    fitness.add(observation);
  }
  return EvoRecord(genome, fitness)
    ..confirmations = confirmations
    ..bestRung = bestRung;
}

EvolutionRunReport _report({
  required List<EvoRecord> records,
  required EvolutionOutcome outcome,
  EvolutionSettings settings = _settings,
  String runId = '0123456789abcdef0123456789abcdef',
  String candidateSalt = 'salt-a',
  String coreVersion = '1.14.4-lx.35',
}) =>
    EvolutionRunReport.fromRun(
      runId: runId,
      candidateSalt: candidateSalt,
      startedAt: _startedAt,
      finishedAt: _finishedAt,
      settings: settings,
      seedCount: 2,
      warpSeedCount: 1,
      privateSeedCount: 1,
      outcome: outcome,
      records: records,
      observedVerdicts: 3,
      paidVerdicts: 2,
      activeTime: const Duration(seconds: 4),
      coreVersion: coreVersion,
    );

void main() {
  test('успешный отчёт сериализует сводку и обезличенные метрики', () {
    final warp = _record(
      _warpGenome(),
      [
        const Observation(
          responded: true,
          status: 200,
          rttMs: 20,
          country: 'nl',
          colo: 'AMS',
          url: _urlCanary,
          requests: 2,
        ),
        const Observation.failed(
          'TLS handshake timeout $_observationCanary',
          rttMs: 50,
          url: _urlCanary,
          requests: 3,
        ),
      ],
      confirmations: 2,
      bestRung: 2,
      rungReached: 2,
    );
    final private = _record(
      _privateGenome(),
      [
        const Observation.failed(
          'WireGuard handshake $_observationCanary',
          requests: 0,
        ),
      ],
    );
    final unprobed = _record(_warpGenome(), const []);
    final outcome = EvolutionOutcome(
      hallOfFame: [warp.lifetime],
      stats: [
        const GenerationSummary(
          index: 1,
          evaluated: 2,
          alive: 1,
          bestPassRate: 0.5,
          bestRttMs: 20,
          diversity: 0.75,
          paretoFrontSize: 1,
          requestsUsed: 5,
          rungKeeps: 1,
          failureReasons: 'RAW_FAILURE_CANARY ×1',
        ),
      ],
      requestsUsed: 5,
      generations: 1,
    );

    final report = _report(records: [warp, private, unprobed], outcome: outcome);
    final json = report.toJson();

    expect(json.keys, unorderedEquals([
      'schema',
      'schemaVersion',
      'runId',
      'startedAt',
      'finishedAt',
      'durationMs',
      'status',
      'coreVersion',
      'settings',
      'seeds',
      'totals',
      'generations',
      'candidates',
    ]));
    expect(json['schema'], 'lxbox.evolution-run');
    expect(json['schemaVersion'], 1);
    expect(json['status'], 'finished');
    expect(json['startedAt'], '2026-11-26T10:00:00.000Z');
    expect(json['finishedAt'], '2026-11-26T10:00:05.000Z');
    expect(json['durationMs'], 5000);
    expect(report.startedAt.isUtc, isTrue);
    expect(report.finishedAt.isUtc, isTrue);
    expect(json['seeds'], {'total': 2, 'warp': 1, 'private': 1});
    expect(json['totals'], {
      'requestsUsed': 5,
      'generations': 1,
      'observedVerdicts': 3,
      'paidVerdicts': 2,
      'activeTimeMs': 4000,
      'hallOfFameSize': 1,
      'errorCategory': null,
    });
    expect(json['generations'], [
      {
        'index': 1,
        'evaluated': 2,
        'alive': 1,
        'bestPassRate': 0.5,
        'bestRttMs': 20,
        'diversity': 0.75,
        'paretoFrontSize': 1,
        'requestsUsed': 5,
        'rungKeeps': 1,
      },
    ]);

    final settings = (json['settings'] as Map).cast<String, Object?>();
    expect(settings.keys, unorderedEquals([
      'populationSize',
      'maxGenerations',
      'maxRequests',
      'rungAttempts',
      'rungKeepFraction',
      'eliteFraction',
      'mutationRate',
      'immigrantFraction',
      'hallOfFameSize',
      'confirmationsNeeded',
      'targetCountry',
      'countries',
      'transports',
      'awgProfiles',
      'disabledLoci',
      'useEda',
      'allowFragment',
      'allowRecordFragment',
      'requestTimeoutMs',
      'seed',
      'minPassRate',
    ]));
    expect(settings['populationSize'], 12);
    expect(settings['maxGenerations'], 3);
    expect(settings['maxRequests'], 120);
    expect(settings['rungAttempts'], [1, 2]);
    expect(settings['targetCountry'], '');
    expect(settings['countries'], ['NL']);
    expect(settings['transports'], ['awg', 'h2']);
    expect(settings['awgProfiles'], ['warp-cps', 'warp15']);
    expect(settings['disabledLoci'], ['dns', 'sni']);
    expect(settings['requestTimeoutMs'], 4000);
    expect(settings['seed'], 42);
    expect(settings['minPassRate'], 0.5);

    final candidates = (json['candidates'] as List).cast<Map>();
    expect(candidates, hasLength(2));
    expect(candidates.first.keys, unorderedEquals([
      'id',
      'transport',
      'awgProfile',
      'privateNode',
      'inHall',
      'attempts',
      'passes',
      'passRate',
      'medianRttMs',
      'country',
      'requestsUsed',
      'confirmations',
      'bestRung',
      'rungReached',
      'failureCategories',
    ]));
    expect(candidates.first['id'], matches(r'^c1-[0-9a-f]{12}$'));
    expect(candidates.first['transport'], 'awg');
    expect(candidates.first['awgProfile'], 'warp-cps');
    expect(candidates.first['privateNode'], isFalse);
    expect(candidates.first['inHall'], isTrue);
    expect(candidates.first['attempts'], 2);
    expect(candidates.first['passes'], 1);
    expect(candidates.first['passRate'], 0.5);
    expect(candidates.first['medianRttMs'], 20);
    expect(candidates.first['country'], 'NL');
    expect(candidates.first['requestsUsed'], 5);
    expect(candidates.first['confirmations'], 2);
    expect(candidates.first['bestRung'], 2);
    expect(candidates.first['rungReached'], 2);
    expect(candidates.first['failureCategories'], {'timeout': 1});
    expect(candidates.last['id'], matches(r'^c2-[0-9a-f]{12}$'));
    expect(candidates.last['awgProfile'], '');
    expect(candidates.last['privateNode'], isTrue);
    expect(candidates.last['attempts'], 1);
    expect(candidates.last['passes'], 0);
    expect(candidates.last['medianRttMs'], isNull);
    expect(candidates.last['country'], '');
    expect(candidates.last['requestsUsed'], 0);
    expect(candidates.last['failureCategories'], {'handshake': 1});
    expect(report.toJsonText(), contains('\n  "schema": "lxbox.evolution-run"'));
  });

  test('ошибка и отмена дают готовый отчёт с закрытой категорией', () {
    final failed = _report(
      records: const [],
      outcome: const EvolutionOutcome(
        hallOfFame: [],
        stats: [],
        requestsUsed: 0,
        generations: 0,
        error: 'probeStart failed: $_outcomeCanary',
      ),
    );
    final cancelled = _report(
      records: const [],
      outcome: const EvolutionOutcome(
        hallOfFame: [],
        stats: [],
        requestsUsed: 0,
        generations: 0,
        error: 'cancelled before probe',
        cancelled: true,
      ),
    );

    expect(failed.status, 'failed');
    expect(failed.totals['errorCategory'], 'core');
    expect(cancelled.status, 'cancelled');
    expect(cancelled.totals['errorCategory'], 'cancelled');
    expect(failed.toJsonText(), isNot(contains(_outcomeCanary)));
    expect(failed.candidates, isEmpty);
    expect(cancelled.candidates, isEmpty);
  });

  test('ID кандидатов зависит от соли, а ID прогонов случайны', () {
    final record = _record(
      _warpGenome(),
      [const Observation.failed('build failed', requests: 0)],
    );
    final outcome = EvolutionOutcome(
      hallOfFame: const [],
      stats: const [],
      requestsUsed: 0,
      generations: 0,
    );
    final first = _report(
      records: [record],
      outcome: outcome,
      candidateSalt: 'salt-a',
    );
    final same = _report(
      records: [record],
      outcome: outcome,
      candidateSalt: 'salt-a',
    );
    final other = _report(
      records: [record],
      outcome: outcome,
      candidateSalt: 'salt-b',
    );

    expect(first.candidates.single.id, same.candidates.single.id);
    expect(first.candidates.single.id, isNot(other.candidates.single.id));
    expect(first.candidates.single.id, isNot(contains(record.genome.key)));
    expect(first.candidates.single.id, isNot(contains(_endpointCanary)));
    expect(first.toJsonText(), isNot(contains('salt-a')));
    expect(first.toJsonText(), isNot(contains('salt-b')));

    final runIds = {for (var i = 0; i < 8; i++) EvolutionRunReport.newRunId()};
    expect(runIds, hasLength(8));
    expect(runIds, everyElement(matches(r'^[0-9a-f]{32}$')));
    final salts = {
      for (var i = 0; i < 8; i++) EvolutionRunReport.newCandidateSalt(),
    };
    expect(salts, hasLength(8));
    expect(salts, everyElement(matches(r'^[0-9a-f]{32}$')));
  });

  test('рекурсивные секреты не попадают в сериализованный отчёт', () {
    final genome = _privateGenome();
    final record = _record(
      genome,
      [
        const Observation.failed(
          'DNS resolve $_observationCanary at $_urlCanary',
          url: _urlCanary,
          requests: 1,
        ),
      ],
    );
    final report = _report(
      records: [record],
      outcome: EvolutionOutcome(
        hallOfFame: const [],
        stats: const [
          GenerationSummary(
            index: 1,
            evaluated: 1,
            alive: 0,
            bestPassRate: 0,
            bestRttMs: null,
            diversity: 0,
            paretoFrontSize: 0,
            requestsUsed: 1,
            rungKeeps: 0,
            failureReasons: '$_stackCanary; $_privateBodyCanary',
          ),
        ],
        requestsUsed: 1,
        generations: 1,
        error: 'core crashed: $_outcomeCanary\n$_stackCanary',
      ),
      coreVersion: _coreCanary,
    );
    final text = report.toJsonText();

    for (final canary in [
      _endpointCanary,
      _sniCanary,
      _junkCanary,
      _dnsCanary,
      _privateTagCanary,
      _privateBodyCanary,
      _privateKeyCanary,
      _privateEndpointCanary,
      _privateDnsCanary,
      _urlCanary,
      _observationCanary,
      _outcomeCanary,
      _stackCanary,
      _countryCanary,
      _coreCanary,
      genome.key,
      '${genome.baseBody}',
    ]) {
      expect(text, isNot(contains(canary)), reason: canary);
    }
    expect(report.coreVersion, '');
    expect(text, isNot(contains('private_key')));
    expect(text, isNot(contains('peers')));
    expect(text, isNot(contains('observations')));
    expect(text, isNot(contains('failureReasons')));
    expect(text, isNot(contains('colo')));
    expect(text, isNot(contains('url')));
  });

  test('категории отказов принадлежат фиксированному набору', () {
    const cases = {
      'node build failed': 'build',
      'cancelled before probe': 'cancelled',
      'probeStart failed': 'core',
      'DNS resolve failed': 'dns',
      'WireGuard handshake failed': 'handshake',
      'HTTP 503': 'http',
      'unexpected private text': 'other',
      'TLS certificate rejected': 'tls',
      'deadline exceeded': 'timeout',
    };
    for (final entry in cases.entries) {
      final category = evolutionFailureCategory(entry.key);
      expect(category, entry.value);
      expect(evolutionFailureCategories, contains(category));
    }
  });

  test('коллекции отчёта и его JSON нельзя изменить', () {
    final record = _record(
      _warpGenome(),
      [const Observation.failed('build failed')],
    );
    final report = _report(
      records: [record],
      outcome: EvolutionOutcome(
        hallOfFame: const [],
        stats: const [
          GenerationSummary(
            index: 1,
            evaluated: 1,
            alive: 0,
            bestPassRate: 0,
            bestRttMs: null,
            diversity: 0,
            paretoFrontSize: 0,
            requestsUsed: 0,
            rungKeeps: 0,
          ),
        ],
        requestsUsed: 0,
        generations: 1,
      ),
    );

    expect(
      () => (report.settings['rungAttempts'] as List).add(3),
      throwsUnsupportedError,
    );
    expect(
      () => (report.settings['transports'] as List).add('h3'),
      throwsUnsupportedError,
    );
    expect(() => report.generations.single['index'] = 9, throwsUnsupportedError);
    expect(
      () => report.candidates.single.failureCategories['other'] = 1,
      throwsUnsupportedError,
    );

    final json = report.toJson();
    expect(() => json['status'] = 'changed', throwsUnsupportedError);
    expect(
      () => (json['settings'] as Map)['seed'] = 7,
      throwsUnsupportedError,
    );
    expect(() => (json['generations'] as List).clear(), throwsUnsupportedError);
    expect(
      () => ((json['candidates'] as List).single as Map)['id'] = 'changed',
      throwsUnsupportedError,
    );
    expect(
      () => (((json['candidates'] as List).single as Map)['failureCategories']
          as Map)['other'] = 1,
      throwsUnsupportedError,
    );
  });
}
