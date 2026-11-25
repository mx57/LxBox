import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

import '../settings_storage.dart';
import '../warp/awg_profile.dart';
import 'genome.dart';
import 'objectives.dart';
import 'pools.dart';

class EvolutionHallRecord {
  const EvolutionHallRecord({
    required this.genome,
    required this.fitness,
    required this.confirmations,
    required this.bestRung,
  });

  final Genome genome;
  final Fitness fitness;
  final int confirmations;
  final int bestRung;
}

class EvolutionHall {
  EvolutionHall({
    List<int>? salt,
    Iterable<EvolutionHallEntry> entries = const [],
  }) : _salt = List<int>.unmodifiable(salt ?? _newSalt()),
       entries = List.unmodifiable(entries);

  static const storageKey = 'evo_hall';
  static const version = 1;
  static const maxEntries = 64;
  static const maxJsonChars = 131072;

  final List<int> _salt;
  final List<EvolutionHallEntry> entries;

  static List<int> _newSalt() {
    final rng = Random.secure();
    return List<int>.generate(32, (_) => rng.nextInt(256));
  }

  String _mac(String value) =>
      Hmac(sha256, _salt).convert(utf8.encode(value)).toString();

  String _ref(EvoLocus locus, String value) => _mac('${locus.wire}\x00$value');

  String identityOf(Genome genome) => _mac('genome\x00${genome.key}');

  String _privateIdentity(GenomeVerbatim genome) =>
      _mac('private\x00${genome.tag}\x00${genome.endpoint}\x00${genome.port}');

  String _warpNetwork(Genome genome) =>
      '${genome.transport.wire}|${genome.port}|'
      '${_ref(EvoLocus.endpoint, genome.endpoint)}|'
      '${_ref(EvoLocus.sni, genome.sni)}|'
      '${_ref(EvoLocus.junkDomain, genome.junkDomain)}';

  EvolutionHall mergeRecords(
    Iterable<EvolutionHallRecord> records, {
    DateTime? now,
  }) {
    final byId = <String, EvolutionHallEntry>{for (final e in entries) e.id: e};
    final stamp = (now ?? DateTime.now()).millisecondsSinceEpoch;
    for (final record in records) {
      if (record.confirmations <= 0 ||
          record.fitness.attempts <= 0 ||
          record.confirmations > record.fitness.attempts ||
          record.fitness.passes < 0 ||
          record.fitness.passes > record.fitness.attempts) {
        continue;
      }
      final id = identityOf(record.genome);
      final previous = byId[id];
      final confirmations = max(
        previous?._fitness.confirmations ?? 0,
        record.confirmations,
      );
      final bestRung = max(
        previous?._fitness.rungReached ?? 0,
        record.bestRung,
      );
      final fitness =
          previous != null &&
              previous._fitness.attempts > record.fitness.attempts
          ? previous._fitness.toFitness(record.genome)
          : record.fitness.copy();
      fitness
        ..confirmations = confirmations
        ..rungReached = bestRung;
      byId[id] = _capture(
        EvolutionHallRecord(
          genome: record.genome,
          fitness: fitness,
          confirmations: confirmations,
          bestRung: bestRung,
        ),
        stamp,
        confirmations: confirmations,
      );
    }
    return EvolutionHall(salt: _salt, entries: _trim(byId.values));
  }

  List<EvolutionHallRecord> restore(
    Iterable<Genome> seeds,
    AlleleSource pools, {
    Iterable<String> countries = const [],
  }) {
    final current = seeds.toList();
    final countryList = countries.toList();
    final restored = <String, EvolutionHallRecord>{};
    for (final entry in entries) {
      final dnsTag = _resolve(
        entry.genome['dnsRef'] as String,
        EvoLocus.dns,
        pools,
        countryList,
      );
      final Genome? genome;
      if (entry.mode == 'verbatim') {
        final identity = entry.genome['identityRef'] as String;
        GenomeVerbatim? seed;
        for (final candidate in current) {
          if (candidate is GenomeVerbatim &&
              _privateIdentity(candidate) == identity) {
            seed = candidate;
            break;
          }
        }
        if (seed == null) continue;
        genome = seed.copyWith(
          mtu: int.parse(entry.genome['mtu'] as String),
          keepalive: Genome.normalizeKeepalive(
            entry.genome['keepalive'],
            allowRange: true,
          ),
          dnsTag: dnsTag,
        );
      } else {
        final network = _storedNetwork(entry);
        Genome? seed;
        for (final candidate in current) {
          if (!candidate.isVerbatim && _warpNetwork(candidate) == network) {
            seed = candidate;
            break;
          }
        }
        final stored = _storedTokens(entry);
        late final GeneTokens tokens;
        if (seed != null) {
          tokens = {...seed.tokens(), ...stored, EvoLocus.dns: dnsTag};
        } else {
          final endpoint = _resolve(
            entry.genome['endpointRef'] as String,
            EvoLocus.endpoint,
            pools,
            countryList,
          );
          final sni = _resolve(
            entry.genome['sniRef'] as String,
            EvoLocus.sni,
            pools,
            countryList,
          );
          final junkDomain = _resolve(
            entry.genome['junkDomainRef'] as String,
            EvoLocus.junkDomain,
            pools,
            countryList,
          );
          if (endpoint.isEmpty) continue;
          tokens = {
            ...stored,
            EvoLocus.endpoint: endpoint,
            EvoLocus.sni: sni,
            EvoLocus.junkDomain: junkDomain,
            EvoLocus.dns: dnsTag,
          };
        }
        genome = Genome.fromTokens(tokens);
      }
      if (genome.endpoint.isEmpty ||
          genome.port <= 0 ||
          identityOf(genome) != entry.id) {
        continue;
      }
      restored[genome.key] = EvolutionHallRecord(
        genome: genome,
        fitness: entry._fitness.toFitness(genome),
        confirmations: entry._fitness.confirmations,
        bestRung: entry._fitness.rungReached,
      );
    }
    return List.unmodifiable(restored.values);
  }

  String _resolve(
    String ref,
    EvoLocus locus,
    AlleleSource pools,
    List<String> countries,
  ) {
    if (ref == _ref(locus, '')) return '';
    for (final value in pools.alleles(locus, countries: countries).values) {
      if (_ref(locus, value) == ref) return value;
    }
    return '';
  }

  GeneTokens _storedTokens(EvolutionHallEntry entry) => {
    EvoLocus.transport: entry.genome['transport'] as String,
    EvoLocus.awgProfile: entry.genome['awgProfile'] as String,
    EvoLocus.port: '${entry.genome['port']}',
    EvoLocus.keepalive: entry.genome['keepalive'] as String,
    EvoLocus.mtu: entry.genome['mtu'] as String,
    EvoLocus.junkProto: entry.genome['junkProto'] as String,
    EvoLocus.junkBrowser: entry.genome['junkBrowser'] as String,
    EvoLocus.jc: entry.genome['jc'] as String,
    EvoLocus.jitterMin: entry.genome['jitterMin'] as String,
    EvoLocus.jitterMax: entry.genome['jitterMax'] as String,
    EvoLocus.fragment: entry.genome['fragment'] == true ? '1' : '0',
    EvoLocus.recordFragment: entry.genome['recordFragment'] == true ? '1' : '0',
    EvoLocus.sniCase: entry.genome['sniCase'] as String,
  };

  String _storedNetwork(EvolutionHallEntry entry) =>
      '${entry.genome['transport']}|${entry.genome['port']}|'
      '${entry.genome['endpointRef']}|${entry.genome['sniRef']}|'
      '${entry.genome['junkDomainRef']}';

  EvolutionHallEntry _capture(
    EvolutionHallRecord record,
    int stamp, {
    required int confirmations,
  }) {
    final genome = record.genome;
    final tokens = genome.tokens();
    final genes = genome is GenomeVerbatim
        ? <String, Object>{
            'identityRef': _privateIdentity(genome),
            'keepalive': tokens[EvoLocus.keepalive]!,
            'mtu': tokens[EvoLocus.mtu]!,
            'dnsRef': _ref(EvoLocus.dns, tokens[EvoLocus.dns]!),
          }
        : <String, Object>{
            'transport': tokens[EvoLocus.transport]!,
            'awgProfile': tokens[EvoLocus.awgProfile]!,
            'port': genome.port,
            'endpointRef': _ref(EvoLocus.endpoint, genome.endpoint),
            'sniRef': _ref(EvoLocus.sni, genome.sni),
            'junkDomainRef': _ref(EvoLocus.junkDomain, genome.junkDomain),
            'keepalive': tokens[EvoLocus.keepalive]!,
            'mtu': tokens[EvoLocus.mtu]!,
            'junkProto': tokens[EvoLocus.junkProto]!,
            'junkBrowser': tokens[EvoLocus.junkBrowser]!,
            'jc': tokens[EvoLocus.jc]!,
            'jitterMin': tokens[EvoLocus.jitterMin]!,
            'jitterMax': tokens[EvoLocus.jitterMax]!,
            'fragment': genome.fragment,
            'recordFragment': genome.recordFragment,
            'sniCase': tokens[EvoLocus.sniCase]!,
            'dnsRef': _ref(EvoLocus.dns, tokens[EvoLocus.dns]!),
          };
    return EvolutionHallEntry._(
      id: identityOf(genome),
      mode: genome.isVerbatim ? 'verbatim' : 'warp',
      genome: Map<String, Object>.unmodifiable(genes),
      fitness: _HallFitness.fromFitness(record.fitness, confirmations),
      updatedAt: stamp,
    );
  }

  List<EvolutionHallEntry> _trim(Iterable<EvolutionHallEntry> source) {
    final candidates = source.toList()..sort(_entryCompare);
    final shortlist = candidates.take(maxEntries * 4).toList();
    if (shortlist.isEmpty) return const [];
    final objectives = [for (final e in shortlist) e._fitness.objectives];
    final ordered = <EvolutionHallEntry>[];
    for (final front in fastNonDominatedSort(objectives)) {
      final distances = crowdingDistance(front, objectives);
      final pairs =
          <MapEntry<int, double>>[
            for (var i = 0; i < front.length; i++)
              MapEntry(front[i], distances[i]),
          ]..sort((a, b) {
            final byDistance = b.value.compareTo(a.value);
            return byDistance != 0
                ? byDistance
                : _entryCompare(shortlist[a.key], shortlist[b.key]);
          });
      for (final pair in pairs) {
        ordered.add(shortlist[pair.key]);
        if (ordered.length == maxEntries) return ordered;
      }
    }
    return ordered;
  }

  static int _entryCompare(EvolutionHallEntry a, EvolutionHallEntry b) {
    final confirmations = b._fitness.confirmations.compareTo(
      a._fitness.confirmations,
    );
    if (confirmations != 0) return confirmations;
    final passRate = b._fitness.passRate.compareTo(a._fitness.passRate);
    if (passRate != 0) return passRate;
    final speed = b._fitness.objectives[1].compareTo(a._fitness.objectives[1]);
    if (speed != 0) return speed;
    final updated = b.updatedAt.compareTo(a.updatedAt);
    return updated != 0 ? updated : a.id.compareTo(b.id);
  }

  Map<String, Object> toJson() => {
    'version': version,
    'salt': base64Encode(_salt),
    'entries': [for (final e in entries) e.toJson()],
  };

  String toJsonString() => jsonEncode(toJson());

  static EvolutionHall fromJson(Map<String, dynamic> json) {
    _exactKeys(json, {'version', 'salt', 'entries'});
    if (json['version'] != version) throw const FormatException();
    final saltText = json['salt'];
    if (saltText is! String || saltText.length > 64) {
      throw const FormatException();
    }
    final salt = base64.decode(saltText);
    if (salt.length != 32 || base64Encode(salt) != saltText) {
      throw const FormatException();
    }
    final rawEntries = json['entries'];
    if (rawEntries is! List || rawEntries.length > maxEntries) {
      throw const FormatException();
    }
    final entries = <EvolutionHallEntry>[];
    final ids = <String>{};
    for (final raw in rawEntries) {
      if (raw is! Map<String, dynamic>) throw const FormatException();
      final entry = EvolutionHallEntry._fromJson(raw);
      if (!ids.add(entry.id)) throw const FormatException();
      entries.add(entry);
    }
    return EvolutionHall(salt: salt, entries: entries);
  }

  static Future<EvolutionHall> load() async {
    final raw = await SettingsStorage.getVar(storageKey, '');
    if (raw.isEmpty) return EvolutionHall();
    if (raw.length > maxJsonChars) return EvolutionHall();
    try {
      return fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      return EvolutionHall();
    }
  }

  Future<void> save() => SettingsStorage.setVar(storageKey, toJsonString());
}

class EvolutionHallEntry {
  const EvolutionHallEntry._({
    required this.id,
    required this.mode,
    required this.genome,
    required _HallFitness fitness,
    required this.updatedAt,
  }) : _fitness = fitness;

  final String id;
  final String mode;
  final Map<String, Object> genome;
  final _HallFitness _fitness;
  final int updatedAt;

  int get confirmations => _fitness.confirmations;

  Map<String, Object> toJson() => {
    'id': id,
    'mode': mode,
    'genome': genome,
    'fitness': _fitness.toJson(),
    'updatedAt': updatedAt,
  };

  static EvolutionHallEntry _fromJson(Map<String, dynamic> json) {
    _exactKeys(json, {'id', 'mode', 'genome', 'fitness', 'updatedAt'});
    final id = _hex(json['id']);
    final mode = json['mode'];
    final rawGenes = json['genome'];
    if (mode != 'warp' && mode != 'verbatim') throw const FormatException();
    if (rawGenes is! Map<String, dynamic>) throw const FormatException();
    final genes = mode == 'warp'
        ? _warpGenes(rawGenes)
        : _verbatimGenes(rawGenes);
    final rawFitness = json['fitness'];
    if (rawFitness is! Map<String, dynamic>) throw const FormatException();
    return EvolutionHallEntry._(
      id: id,
      mode: mode as String,
      genome: Map<String, Object>.unmodifiable(genes),
      fitness: _HallFitness.fromJson(rawFitness),
      updatedAt: _int(json['updatedAt'], 0, 4102444800000),
    );
  }
}

Map<String, Object> _warpGenes(Map<String, dynamic> json) {
  _exactKeys(json, {
    'transport',
    'awgProfile',
    'port',
    'endpointRef',
    'sniRef',
    'junkDomainRef',
    'keepalive',
    'mtu',
    'junkProto',
    'junkBrowser',
    'jc',
    'jitterMin',
    'jitterMax',
    'fragment',
    'recordFragment',
    'sniCase',
    'dnsRef',
  });
  final transport = _text(json['transport'], 16);
  final profile = _text(json['awgProfile'], 32);
  if (!EvoTransport.values.any((e) => e.wire == transport) ||
      !AwgProfile.values.any((e) => e.wire == profile)) {
    throw const FormatException();
  }
  if (json['fragment'] is! bool || json['recordFragment'] is! bool) {
    throw const FormatException();
  }
  final keepalive = _text(json['keepalive'], 32);
  final normalized = Genome.normalizeKeepalive(keepalive, allowRange: true);
  if ('$normalized' != keepalive) throw const FormatException();
  return {
    'transport': transport,
    'awgProfile': profile,
    'port': _int(json['port'], 1, 65535),
    'endpointRef': _hex(json['endpointRef']),
    'sniRef': _hex(json['sniRef']),
    'junkDomainRef': _hex(json['junkDomainRef']),
    'keepalive': keepalive,
    'mtu': _numberToken(json['mtu']),
    'junkProto': _optionalText(json['junkProto'], 32),
    'junkBrowser': _optionalText(json['junkBrowser'], 64),
    'jc': _numberToken(json['jc']),
    'jitterMin': _numberToken(json['jitterMin']),
    'jitterMax': _numberToken(json['jitterMax']),
    'fragment': json['fragment'] as bool,
    'recordFragment': json['recordFragment'] as bool,
    'sniCase': _numberToken(json['sniCase']),
    'dnsRef': _hex(json['dnsRef']),
  };
}

Map<String, Object> _verbatimGenes(Map<String, dynamic> json) {
  _exactKeys(json, {'identityRef', 'keepalive', 'mtu', 'dnsRef'});
  final keepalive = _text(json['keepalive'], 32);
  final normalized = Genome.normalizeKeepalive(keepalive, allowRange: true);
  if ('$normalized' != keepalive) throw const FormatException();
  return {
    'identityRef': _hex(json['identityRef']),
    'keepalive': keepalive,
    'mtu': _numberToken(json['mtu']),
    'dnsRef': _hex(json['dnsRef']),
  };
}

class _HallFitness {
  const _HallFitness({
    required this.attempts,
    required this.passes,
    required this.requestsUsed,
    required this.confirmations,
    required this.rungReached,
    required this.medianRttMs,
  });

  final int attempts;
  final int passes;
  final int requestsUsed;
  final int confirmations;
  final int rungReached;
  final int? medianRttMs;

  double get passRate => attempts == 0 ? 0 : passes / attempts;

  List<double> get objectives => [
    passRate,
    passes == 0 ? 0 : max(0.0, 1 - (medianRttMs ?? 2000) / 2000),
    confirmations.toDouble(),
  ];

  factory _HallFitness.fromFitness(Fitness fitness, int confirmations) =>
      _HallFitness(
        attempts: fitness.attempts,
        passes: fitness.passes,
        requestsUsed: fitness.requestsUsed,
        confirmations: confirmations,
        rungReached: fitness.rungReached,
        medianRttMs: fitness.medianRtt,
      );

  Fitness toFitness(Genome genome) {
    final fitness = Fitness(genome)
      ..attempts = attempts
      ..passes = passes
      ..requestsUsed = requestsUsed
      ..confirmations = confirmations
      ..rungReached = rungReached;
    final rtt = medianRttMs ?? 0;
    for (var i = 0; i < passes; i++) {
      fitness.add(Observation(responded: true, rttMs: rtt, requests: 0));
    }
    for (var i = passes; i < attempts; i++) {
      fitness.add(const Observation.failed('', requests: 0));
    }
    fitness
      ..attempts = attempts
      ..passes = passes
      ..requestsUsed = requestsUsed;
    return fitness;
  }

  Map<String, Object?> toJson() => {
    'attempts': attempts,
    'passes': passes,
    'requestsUsed': requestsUsed,
    'confirmations': confirmations,
    'rungReached': rungReached,
    'medianRttMs': medianRttMs,
  };

  static _HallFitness fromJson(Map<String, dynamic> json) {
    _exactKeys(json, {
      'attempts',
      'passes',
      'requestsUsed',
      'confirmations',
      'rungReached',
      'medianRttMs',
    });
    final attempts = _int(json['attempts'], 0, 10000);
    final passes = _int(json['passes'], 0, attempts);
    final confirmations = _int(json['confirmations'], 1, 10000);
    final rtt = json['medianRttMs'];
    final medianRttMs = rtt == null ? null : _int(rtt, 0, 600000);
    if (attempts == 0 ||
        confirmations > attempts ||
        (passes == 0) != (medianRttMs == null)) {
      throw const FormatException();
    }
    return _HallFitness(
      attempts: attempts,
      passes: passes,
      requestsUsed: _int(json['requestsUsed'], 0, 10000000),
      confirmations: confirmations,
      rungReached: _int(json['rungReached'], 0, 1000),
      medianRttMs: medianRttMs,
    );
  }
}

void _exactKeys(Map<String, dynamic> json, Set<String> expected) {
  if (json.length != expected.length || !json.keys.every(expected.contains)) {
    throw const FormatException();
  }
}

String _hex(Object? value) {
  if (value is! String || !RegExp(r'^[0-9a-f]{64}$').hasMatch(value)) {
    throw const FormatException();
  }
  return value;
}

String _text(Object? value, int maxLength) {
  if (value is! String || value.isEmpty || value.length > maxLength) {
    throw const FormatException();
  }
  return value;
}

String _optionalText(Object? value, int maxLength) {
  if (value is! String || value.length > maxLength) {
    throw const FormatException();
  }
  return value;
}

String _numberToken(Object? value) {
  final text = _text(value, 16);
  final number = int.tryParse(text);
  if (number == null || number < 0 || number > 1000000) {
    throw const FormatException();
  }
  return text;
}

int _int(Object? value, int min, int max) {
  if (value is! int || value < min || value > max) {
    throw const FormatException();
  }
  return value;
}
