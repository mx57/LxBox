import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

import 'engine.dart';
import 'genome.dart';
import 'settings.dart';

const evolutionFailureCategories = <String>{
  'build',
  'cancelled',
  'core',
  'dns',
  'handshake',
  'http',
  'other',
  'tls',
  'timeout',
};

String evolutionFailureCategory(String text) {
  final value = text.toLowerCase();
  if (value.contains('cancel') || value.contains('stopped')) return 'cancelled';
  if (value.contains('timeout') || value.contains('deadline')) return 'timeout';
  if (value.contains('dns') || value.contains('resolve')) return 'dns';
  if (value.contains('tls') || value.contains('certificate')) return 'tls';
  if (value.contains('handshake') ||
      value.contains('wireguard') ||
      value.contains('amnezia') ||
      value.contains('awg')) {
    return 'handshake';
  }
  if (value.contains('http') || value.contains('status')) return 'http';
  if (value.contains('build') || value.contains('config')) return 'build';
  if (value.contains('core') ||
      value.contains('session') ||
      value.contains('probe start') ||
      value.contains('probestart')) {
    return 'core';
  }
  return 'other';
}

class EvolutionReportCandidate {
  EvolutionReportCandidate({
    required this.id,
    required this.transport,
    required this.awgProfile,
    required this.privateNode,
    required this.inHall,
    required this.attempts,
    required this.passes,
    required this.passRate,
    required this.medianRttMs,
    required this.country,
    required this.requestsUsed,
    required this.confirmations,
    required this.bestRung,
    required this.rungReached,
    required Map<String, int> failureCategories,
  }) : failureCategories = Map.unmodifiable(failureCategories);

  final String id;
  final String transport;
  final String awgProfile;
  final bool privateNode;
  final bool inHall;
  final int attempts;
  final int passes;
  final double passRate;
  final int? medianRttMs;
  final String country;
  final int requestsUsed;
  final int confirmations;
  final int bestRung;
  final int rungReached;
  final Map<String, int> failureCategories;

  Map<String, Object?> toJson() => Map.unmodifiable({
        'id': id,
        'transport': transport,
        'awgProfile': awgProfile,
        'privateNode': privateNode,
        'inHall': inHall,
        'attempts': attempts,
        'passes': passes,
        'passRate': passRate,
        'medianRttMs': medianRttMs,
        'country': country,
        'requestsUsed': requestsUsed,
        'confirmations': confirmations,
        'bestRung': bestRung,
        'rungReached': rungReached,
        'failureCategories': Map.unmodifiable(failureCategories),
      });
}

class EvolutionRunReport {
  EvolutionRunReport._({
    required this.runId,
    required this.startedAt,
    required this.finishedAt,
    required this.status,
    required this.coreVersion,
    required this.settings,
    required this.seeds,
    required this.totals,
    required this.generations,
    required this.candidates,
  });

  factory EvolutionRunReport.fromRun({
    required String runId,
    required String candidateSalt,
    required DateTime startedAt,
    required DateTime finishedAt,
    required EvolutionSettings settings,
    required int seedCount,
    required int warpSeedCount,
    required int privateSeedCount,
    required EvolutionOutcome outcome,
    required List<EvoRecord> records,
    required int observedVerdicts,
    required int paidVerdicts,
    required Duration activeTime,
    required String coreVersion,
  }) {
    final start = startedAt.toUtc();
    final finish = finishedAt.toUtc();
    final hall = {for (final fitness in outcome.hallOfFame) fitness.genome.key};
    final candidates = <EvolutionReportCandidate>[];
    for (final record in records) {
      final fitness = record.lifetime;
      if (fitness.attempts <= 0) continue;
      final failures = <String, int>{};
      fitness.errorSignatures().forEach((signature, count) {
        final category = evolutionFailureCategory(signature);
        failures[category] = (failures[category] ?? 0) + count;
      });
      final index = candidates.length + 1;
      candidates.add(EvolutionReportCandidate(
        id: _candidateId(candidateSalt, record.genome.key, index),
        transport: record.genome.transport.wire,
        awgProfile: record.genome.isVerbatim ||
                record.genome.transport != EvoTransport.awg
            ? ''
            : record.genome.awgProfile.wire,
        privateNode: record.genome.isVerbatim,
        inHall: hall.contains(record.genome.key),
        attempts: fitness.attempts,
        passes: fitness.passes,
        passRate: fitness.passRate,
        medianRttMs: fitness.medianRtt,
        country: _countryCode(fitness.country),
        requestsUsed: fitness.requestsUsed,
        confirmations: record.confirmations,
        bestRung: record.bestRung,
        rungReached: fitness.rungReached,
        failureCategories: Map.unmodifiable(failures),
      ));
    }
    final safeSettings = <String, Object?>{
      'populationSize': settings.populationSize,
      'maxGenerations': settings.maxGenerations,
      'maxRequests': settings.maxRequests,
      'rungAttempts': List<int>.unmodifiable(settings.rungAttempts),
      'rungKeepFraction': settings.rungKeepFraction,
      'eliteFraction': settings.eliteFraction,
      'mutationRate': settings.mutationRate,
      'immigrantFraction': settings.immigrantFraction,
      'hallOfFameSize': settings.hallOfFameSize,
      'confirmationsNeeded': settings.confirmationsNeeded,
      'targetCountry': _countryCode(settings.targetCountry),
      'countries': List<String>.unmodifiable(
        settings.countries.map(_countryCode).where((c) => c.isNotEmpty).toList()
          ..sort(),
      ),
      'transports': List<String>.unmodifiable(
        settings.transports.map((t) => t.wire).toList()..sort(),
      ),
      'awgProfiles': List<String>.unmodifiable(
        settings.awgProfiles.map((p) => p.wire).toList()..sort(),
      ),
      'disabledLoci': List<String>.unmodifiable(
        settings.disabledLoci.map((l) => l.wire).toList()..sort(),
      ),
      'useEda': settings.useEda,
      'allowFragment': settings.allowFragment,
      'allowRecordFragment': settings.allowRecordFragment,
      'requestTimeoutMs': settings.requestTimeout.inMilliseconds,
      'seed': settings.seed,
      'minPassRate': settings.minPassRate,
    };
    return EvolutionRunReport._(
      runId: runId,
      startedAt: start,
      finishedAt: finish,
      status: outcome.cancelled
          ? 'cancelled'
          : outcome.error != null
              ? 'failed'
              : 'finished',
      coreVersion: _safeCoreVersion(coreVersion),
      settings: Map.unmodifiable(safeSettings),
      seeds: Map.unmodifiable({
        'total': seedCount,
        'warp': warpSeedCount,
        'private': privateSeedCount,
      }),
      totals: Map.unmodifiable({
        'requestsUsed': outcome.requestsUsed,
        'generations': outcome.generations,
        'observedVerdicts': observedVerdicts,
        'paidVerdicts': paidVerdicts,
        'activeTimeMs': activeTime.inMilliseconds,
        'hallOfFameSize': outcome.hallOfFame.length,
        'errorCategory': outcome.error == null || outcome.error!.isEmpty
            ? null
            : evolutionFailureCategory(outcome.error!),
      }),
      generations: List<Map<String, Object?>>.unmodifiable([
        for (final summary in outcome.stats)
          Map<String, Object?>.unmodifiable({
            'index': summary.index,
            'evaluated': summary.evaluated,
            'alive': summary.alive,
            'bestPassRate': summary.bestPassRate,
            'bestRttMs': summary.bestRttMs,
            'diversity': summary.diversity,
            'paretoFrontSize': summary.paretoFrontSize,
            'requestsUsed': summary.requestsUsed,
            'rungKeeps': summary.rungKeeps,
          }),
      ]),
      candidates: List.unmodifiable(candidates),
    );
  }

  static String newRunId() => _randomHex(16);
  static String newCandidateSalt() => _randomHex(16);

  final String runId;
  final DateTime startedAt;
  final DateTime finishedAt;
  final String status;
  final String coreVersion;
  final Map<String, Object?> settings;
  final Map<String, Object?> seeds;
  final Map<String, Object?> totals;
  final List<Map<String, Object?>> generations;
  final List<EvolutionReportCandidate> candidates;

  Map<String, Object?> toJson() => Map.unmodifiable({
        'schema': 'lxbox.evolution-run',
        'schemaVersion': 1,
        'runId': runId,
        'startedAt': startedAt.toIso8601String(),
        'finishedAt': finishedAt.toIso8601String(),
        'durationMs': max(0, finishedAt.difference(startedAt).inMilliseconds),
        'status': status,
        'coreVersion': coreVersion,
        'settings': Map<String, Object?>.unmodifiable(settings),
        'seeds': Map<String, Object?>.unmodifiable(seeds),
        'totals': Map<String, Object?>.unmodifiable(totals),
        'generations': List<Map<String, Object?>>.unmodifiable(generations),
        'candidates': List<Map<String, Object?>>.unmodifiable(
          [for (final candidate in candidates) candidate.toJson()],
        ),
      });

  String toJsonText() =>
      const JsonEncoder.withIndent('  ').convert(toJson());
}

String _countryCode(String raw) {
  final value = raw.trim().toUpperCase();
  return RegExp(r'^[A-Z]{2}$').hasMatch(value) ? value : '';
}

String _safeCoreVersion(String raw) {
  final value = raw.trim();
  return RegExp(r'^[0-9A-Za-z][0-9A-Za-z._+-]{0,79}$').hasMatch(value)
      ? value
      : '';
}

String _candidateId(String salt, String key, int ordinal) {
  final digest = sha256.convert(utf8.encode('$salt\x00$key')).toString();
  return 'c$ordinal-${digest.substring(0, 12)}';
}

String _randomHex(int bytes) {
  final rng = Random.secure();
  return List.generate(bytes, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
}
