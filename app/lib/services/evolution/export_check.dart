import 'engine.dart';
import 'genome.dart';
import 'objectives.dart';
import 'probe_evaluator.dart' show kGeoUrls;
import 'settings.dart';

class EvolutionExportCheck {
  const EvolutionExportCheck({
    required this.bodies,
    required this.verified,
    required this.failed,
    required this.requestsUsed,
    this.error = '',
  });

  final List<String> bodies;
  final List<Fitness> verified;
  final List<String> failed;
  final int requestsUsed;
  final String? error;
}

Future<EvolutionExportCheck> revalidateAndExport(
  Iterable<Fitness> selected, {
  required GenomeEvaluator evaluator,
  required String? Function(Genome genome) export,
  required EvolutionSettings settings,
  bool Function()? cancelled,
}) async {
  final entries = selected.toList();
  final failedLabels = [for (final f in entries) f.genome.shortLabel];
  if (entries.isEmpty) {
    return const EvolutionExportCheck(
      bodies: [],
      verified: [],
      failed: [],
      requestsUsed: 0,
    );
  }
  if (cancelled?.call() ?? false) {
    return EvolutionExportCheck(
      bodies: const [],
      verified: const [],
      failed: failedLabels,
      requestsUsed: 0,
      error: 'cancelled',
    );
  }

  final genomes = [for (final f in entries) f.genome];
  final streamed = <int, List<Observation>>{};
  var requests = 0;
  try {
    final reason = await evaluator.prepareFor(genomes);
    if (reason != null) {
      return EvolutionExportCheck(
        bodies: const [],
        verified: const [],
        failed: failedLabels,
        requestsUsed: 0,
        error: reason,
      );
    }
    if (cancelled?.call() ?? false) {
      return EvolutionExportCheck(
        bodies: const [],
        verified: const [],
        failed: failedLabels,
        requestsUsed: 0,
        error: 'cancelled',
      );
    }

    final requestCap = genomes.length * kGeoUrls.length;
    final results = await evaluator.evaluate(
      genomes,
      attempts: 1,
      cancelled: cancelled,
      budgetExceeded: () => requests >= requestCap,
      onOne: (index, observation) {
        if (index < 0 || index >= genomes.length) return;
        (streamed[index] ??= <Observation>[]).add(observation);
        requests += observation.requests;
      },
    );

    final bodies = <String>[];
    final verified = <Fitness>[];
    final failed = <String>[];
    for (var i = 0; i < entries.length; i++) {
      final notified = streamed[i] ?? const <Observation>[];
      final returned = i < results.length ? results[i] : const <Observation>[];
      final extra = returned.skip(notified.length);
      final observations = [...notified, ...extra];
      requests += extra.fold<int>(
        0,
        (sum, observation) => sum + observation.requests,
      );
      if (cancelled?.call() ??
          false || observations.length != 1 || !observations.single.responded) {
        failed.add(genomes[i].shortLabel);
        continue;
      }
      final fresh = Fitness(genomes[i])
        ..add(observations.single)
        ..confirmations = entries[i].confirmations;
      if (fresh.passRate < settings.minPassRate) {
        failed.add(genomes[i].shortLabel);
        continue;
      }
      try {
        final body = export(genomes[i]);
        if (body == null) {
          failed.add(genomes[i].shortLabel);
        } else {
          bodies.add(body);
          verified.add(fresh);
        }
      } catch (_) {
        failed.add(genomes[i].shortLabel);
      }
    }
    if (requests > requestCap || (cancelled?.call() ?? false)) {
      return EvolutionExportCheck(
        bodies: const [],
        verified: const [],
        failed: failedLabels,
        requestsUsed: requests,
        error: (cancelled?.call() ?? false) ? 'cancelled' : 'budget exhausted',
      );
    }
    return EvolutionExportCheck(
      bodies: bodies,
      verified: verified,
      failed: failed,
      requestsUsed: requests,
    );
  } catch (_) {
    return EvolutionExportCheck(
      bodies: const [],
      verified: const [],
      failed: failedLabels,
      requestsUsed: requests,
      error: 'check failed',
    );
  }
}
