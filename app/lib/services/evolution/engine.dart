// §848 — движок эволюции: steady-state (μ+λ) + successive halving + гистерезис.
//
// Три механики, и каждая закрыта конкретным ограничением задачи:
//
// 1. SUCCESSIVE HALVING (Jamieson & Talwalkar, 2016). Оценка особи стоит
//    HTTP-запрос через поднятое ядро, а не микроквинету CPU: 6 проб на каждого
//    из 16 кандидатов = 96 запросов на поколение. Halving даёт каждому 1 пробу,
//    выжившим ещё 2, финалистам ещё 3: та же точность наверху при в 3–4 раза
//    меньшем бюджете. Без этого фильтр на телефоне неприменим вовсе.
//
// 2. NSGA-II (objectives.dart) — отбор по Парето, а не по одному числу, плюс
//    скученность внутри фронта держит разнообразие: пользователю нужно НЕСКОЛЬКО
//    разных проходимых конфигов, а не сходство в одну лучшую точку.
//
// 3. ГУСТЕРЕЗИС архива. Проходимость через DPI нестабильна: особь, прошедшая
//    однажды, могла повезти. В архив славы она попадает, только подтвердив
//    проходимость в [EvolutionSettings.confirmationsNeeded] РАЗНЫХ поколениях
//    (каждое поколение — отдельная probe-кампания). Это единственная защита от
//    «эволюция показала 100 %, а в бою не работает».
//
// Честная оговорка, которую экран повторяет: «HTTP-ответ прошёл через узел» ≠
// «туннель держит нагрузку». Оптимизируется проходимость handshake + одного GET.

import 'dart:async';
import 'dart:math';

import 'allele_model.dart';
import 'genome.dart';
import 'hall_of_fame.dart';
import 'objectives.dart';
import 'pools.dart';
import 'settings.dart';

/// То, что движок просит у внешнего мира: «прогони эти геномы N раз».
///
/// Боевая реализация — [ProbeGenomeEvaluator] (headless probe-сессия ядра);
/// для тестов — фейк с детерминированным фитнесом. Движок сознательно НЕ знает
/// ни про ядро, ни про аккаунты: вся логика отбора остаётся проверяемой без
/// устройства.
abstract class GenomeEvaluator {
  /// Подготовка (аккаунты, версия ядра, guard «VPN активен»). null — всё готово,
  /// иначе — причина, по которой прогон не стартует (её показывает экран).
  Future<String?> prepare();

  /// Подготовка с учётом состава посева: приватным геномам аккаунты WARP не
  /// нужны. Старые оценщики достаточно реализуют [prepare].
  Future<String?> prepareFor(List<Genome> genomes) => prepare();

  /// [attempts] проб на каждый геном. Возвращает наблюдения ПО ИНДЕКСУ входа
  /// (короткий список = пробы не дошли). Наблюдения прилетают и через [onOne],
  /// чтобы UI жил во время долгого rung'а. [onOne] вызывается до возврата и в
  /// том же порядке, что и наблюдения этого индекса в результате.
  ///
  /// Оценщик проверяет [cancelled] и [budgetExceeded] между узлами и пробами.
  /// При остановке он возвращает уже сделанные наблюдения и добавляет честный
  /// `Observation.failed` тем, кто остался без пробы.
  Future<List<List<Observation>>> evaluate(
    List<Genome> genomes, {
    required int attempts,
    void Function(int index, Observation observation)? onOne,
    bool Function()? cancelled,
    bool Function()? budgetExceeded,
  });

  /// Сброс ресурсов. Владелец — экран: движок НЕ гасит оценщик между
  /// прогонами, чтобы повторный старт не перерегистрировал аккаунты.
  Future<void> dispose();
}

/// История одной особи за весь прогон (архив + живая таблица).
class EvoRecord {
  EvoRecord(this.genome, Fitness fitness) : lifetime = fitness;

  final Genome genome;

  /// Накопленный фитнес за все кампании прогона.
  Fitness lifetime;

  /// Поколения, в которых особь подтвердила проходимость (гистерезис).
  int confirmations = 0;

  /// Поколение последнего подтверждения — чтобы повтор одного замера внутри
  /// поколения не засчитался вторым подтверждением.
  int lastConfirmedGeneration = -1;

  /// Самый глубокий достигнутый rung (0 = отсечена на первом).
  int bestRung = 0;

  String get key => genome.key;
}

/// Сводка поколения — точка графика и строка журнала.
class GenerationSummary {
  const GenerationSummary({
    required this.index,
    required this.evaluated,
    required this.alive,
    required this.bestPassRate,
    required this.bestRttMs,
    required this.diversity,
    required this.paretoFrontSize,
    required this.requestsUsed,
    required this.rungKeeps,
    this.failureReasons = '',
  });

  final int index;
  final int evaluated;

  /// Особей с passRate >= порога — они и есть «проходимые».
  final int alive;
  final double bestPassRate;
  final int? bestRttMs;

  /// Разнообразие популяции (0..1) — главный сигнал «поиск ещё жив».
  final double diversity;
  final int paretoFrontSize;
  final int requestsUsed;

  /// Сколько особей дошло до конца последнего ранга.
  final int rungKeeps;

  /// Top-причин отказов поколения в виде «подпись ×N; …»; пусто — отказов нет.
  final String failureReasons;
}

/// «подпись ×N; подпись ×N» — не больше [max] самых частых причин.
String topReasons(Map<String, int> counts, {int max = 3}) {
  if (counts.isEmpty) return '';
  final list = counts.entries.toList()
    ..sort((a, b) => b.value.compareTo(a.value));
  return [for (final e in list.take(max)) '${e.key} ×${e.value}'].join('; ');
}

int estimateVerdictsPerGeneration(EvolutionSettings settings) {
  var alive = settings.populationSize;
  var verdicts = 0;
  for (final attempts in settings.rungAttempts) {
    if (alive <= 0) break;
    verdicts += attempts * alive;
    alive = settings.keepOf(alive);
  }
  return verdicts;
}

int estimateVerdicts(EvolutionSettings settings) =>
    estimateVerdictsPerGeneration(settings) *
    max(0, settings.maxGenerations);

int estimateRequests(
  EvolutionSettings settings, {
  int requestsPerVerdict = 1,
}) =>
    estimateVerdicts(settings) * max(1, requestsPerVerdict);

class EvolutionForecast {
  const EvolutionForecast({
    required this.plannedVerdicts,
    required this.observedVerdicts,
    required this.paidVerdicts,
    required this.remainingVerdicts,
    required this.requestsPerVerdict,
    required this.projectedRequests,
    required this.budgetCappedRequests,
    required this.generationsWithinBudget,
    required this.budgetLimited,
    required this.eta,
  });

  factory EvolutionForecast.estimate({
    required EvolutionSettings settings,
    required int requestsUsed,
    required int observedVerdicts,
    required int paidVerdicts,
    required Duration activeTime,
    required int worstCaseRequestsPerVerdict,
  }) {
    final planned = estimateVerdicts(settings);
    final observed = max(0, observedVerdicts);
    final paid = max(0, paidVerdicts);
    final spent = max(0, requestsUsed);
    final budget = max(0, settings.maxRequests);
    final fallbackPrice = max(1, worstCaseRequestsPerVerdict).toDouble();
    final price = paid == 0 ? fallbackPrice : spent / paid;
    final remaining = max(0, planned - observed);
    final projected = spent + price * remaining;
    final projectedRequests = projected.ceil();
    final budgetCappedRequests = max(
      spent,
      min(projectedRequests, budget),
    );
    final perGeneration = estimateVerdictsPerGeneration(settings);
    final generationsWithinBudget = perGeneration == 0
        ? max(0, settings.maxGenerations)
        : (budget / (price * perGeneration))
            .floor()
            .clamp(0, max(0, settings.maxGenerations))
            .toInt();
    final affordableRemaining = min(
      remaining,
      (max(0, budget - spent) / price).floor(),
    );
    final eta = observed > 0 &&
            activeTime > Duration.zero &&
            affordableRemaining > 0
        ? Duration(
            microseconds: (activeTime.inMicroseconds / observed *
                    affordableRemaining)
                .round(),
          )
        : null;
    return EvolutionForecast(
      plannedVerdicts: planned,
      observedVerdicts: observed,
      paidVerdicts: paid,
      remainingVerdicts: remaining,
      requestsPerVerdict: price,
      projectedRequests: projectedRequests,
      budgetCappedRequests: budgetCappedRequests,
      generationsWithinBudget: generationsWithinBudget,
      budgetLimited: projected > budget,
      eta: eta,
    );
  }

  final int plannedVerdicts;
  final int observedVerdicts;
  final int paidVerdicts;
  final int remainingVerdicts;
  final double requestsPerVerdict;
  final int projectedRequests;
  final int budgetCappedRequests;
  final int generationsWithinBudget;
  final bool budgetLimited;
  final Duration? eta;
}

/// Итог прогона.
class EvolutionOutcome {
  const EvolutionOutcome({
    required this.hallOfFame,
    required this.stats,
    required this.requestsUsed,
    required this.generations,
    this.error,
    this.cancelled = false,
  });

  final List<Fitness> hallOfFame;
  final List<GenerationSummary> stats;
  final int requestsUsed;
  final int generations;
  final String? error;
  final bool cancelled;
}

/// Одноразовый прогон: архив, статистика и счётчик бюджета принадлежат одному
/// экземпляру. Для нового запуска экран создаёт новый [EvolutionEngine].
class EvolutionEngine {
  EvolutionEngine({
    required this.evaluator,
    required this.pools,
    required this.settings,
    this.onGeneration,
    this.onObservation,
    this.onNote,
    Iterable<EvolutionHallRecord> restored = const [],
  }) {
    for (final record in restored) {
      _records[record.genome.key] = EvoRecord(record.genome, record.fitness)
        ..confirmations = record.confirmations
        ..lastConfirmedGeneration = -1
        ..bestRung = record.bestRung;
    }
  }

  final GenomeEvaluator evaluator;

  /// Пулы с учётом замороженных локусов (см. [EvolutionSettings.poolsFor]).
  final AlleleSource pools;
  final EvolutionSettings settings;

  final void Function(GenerationSummary summary)? onGeneration;

  /// На каждое наблюдение: особь, её фитнес ТекуЩЕго поколения, номер rung.
  final void Function(Genome genome, Fitness fitness, int rung)? onObservation;

  /// Журнал: фазы, всплеск разнообразия, стоп по бюджету.
  final void Function(String message)? onNote;

  final _records = <String, EvoRecord>{};
  final _stats = <GenerationSummary>[];

  /// Посев сверх размера популяции: входит в поиск иммигрантами (§848).
  final _reserve = <Genome>[];
  final _privateSeeds = <GenomeVerbatim>[];
  int _privateSlots = 0;

  bool _cancelled = false;
  bool _started = false;
  Completer<void>? _pauseGate;
  int _requestsUsed = 0;
  int _observedVerdicts = 0;
  int _paidVerdicts = 0;
  Duration _activeTime = Duration.zero;
  String _error = '';

  bool get cancelled => _cancelled;
  int get requestsUsed => _requestsUsed;
  int get observedVerdicts => _observedVerdicts;
  int get paidVerdicts => _paidVerdicts;
  Duration get activeTime => _activeTime;
  List<GenerationSummary> get stats => List.unmodifiable(_stats);
  List<EvoRecord> get records => List.unmodifiable(_records.values);

  void cancel() {
    _cancelled = true;
    _releasePause();
  }

  /// Пауза останавливает движок МЕЖДУ rung'ами, не посреди probe-сессии: ядро
  /// нельзя бросить с поднятым endpoint'ом — teardown обязателен (§523).
  void pause() => _pauseGate ??= Completer<void>();

  void resume() => _releasePause();

  void _releasePause() {
    final gate = _pauseGate;
    _pauseGate = null;
    if (gate != null && !gate.isCompleted) gate.complete();
  }

  Future<void> _waitPause() async {
    final gate = _pauseGate;
    if (gate == null || _cancelled) return;
    _note('пауза');
    await gate.future;
  }

  /// Архив слава: подтверждённые особи, отсортированные по Парето-порядку.
  List<Fitness> get hallOfFame {
    final confirmed = _records.values
        .where((r) => r.confirmations >= settings.confirmationsNeeded)
        .map((r) => r.lifetime)
        .toList();
    if (confirmed.isEmpty) return const [];
    final order = nsga2Order(confirmed, targetCountry: settings.targetCountry);
    return [for (final i in order.take(settings.hallOfFameSize)) confirmed[i]];
  }

  Future<EvolutionOutcome> run(List<Genome> seeds) async {
    assert(!_started, 'EvolutionEngine is one-shot; create a new engine');
    _started = true;
    final uniqueSeeds = _dedupe([
      for (final record in _records.values)
        if (record.lifetime.attempts > 0) record.genome,
      ...seeds,
    ]);
    final reason = await evaluator.prepareFor(uniqueSeeds);
    if (reason != null) {
      _error = reason;
      _note('старт невозможен: $reason');
      return EvolutionOutcome(
        hallOfFame: hallOfFame,
        stats: const [],
        requestsUsed: 0,
        generations: 0,
        error: reason,
      );
    }
    final rng = settings.rng();
    _privateSeeds
      ..clear()
      ..addAll(uniqueSeeds.whereType<GenomeVerbatim>());
    _privateSlots = _privateTarget(uniqueSeeds);
    var population = _fill(uniqueSeeds, rng);
    var generation = 0;
    while (generation < settings.maxGenerations &&
        _requestsUsed < settings.maxRequests &&
        !_cancelled) {
      generation++;
      final summary = await _runGeneration(generation, population, rng);
      if (summary != null) _stats.add(summary);
      if (_cancelled) break;
      population = _nextGeneration(rng);
    }
    if (_requestsUsed >= settings.maxRequests && !_cancelled) {
      _note('бюджет запросов исчерпан ($_requestsUsed)');
    }
    return EvolutionOutcome(
      hallOfFame: hallOfFame,
      stats: _stats,
      requestsUsed: _requestsUsed,
      generations: generation,
      error: _error.isEmpty ? null : _error,
      cancelled: _cancelled,
    );
  }

  /// Одно поколение = последовательность rung'ов successive halving.
  Future<GenerationSummary?> _runGeneration(
    int generation,
    List<Genome> population,
    Random rng,
  ) async {
    // Фитнс ТЕКУЩЕГО поколения: rung'ы накапливаются в нём, а в [_records]
    // уходит только итог — иначе переобранная особь получила бы двойной вес.
    final current = {for (final g in population) g.key: Fitness(g)};
    var tier = current.keys.toList();
    var rung = 0;
    final keeps = <int>[];
    for (final attempts in settings.rungAttempts) {
      if (_cancelled || tier.isEmpty) break;
      await _waitPause();
      if (_cancelled) break;
      if (_requestsUsed >= settings.maxRequests) {
        _note('бюджет исчерпан на rung $rung — поколение усекается');
        break;
      }
      final batch = [for (final k in tier) current[k]!.genome];
      final streamed = <int, List<Observation>>{};
      late final List<List<Observation>> results;
      final watch = Stopwatch()..start();
      try {
        results = await evaluator.evaluate(
          batch,
          attempts: attempts,
          cancelled: () => _cancelled,
          budgetExceeded: () => _requestsUsed >= settings.maxRequests,
          onOne: (i, o) {
            if (i < 0 || i >= batch.length) return;
            (streamed[i] ??= <Observation>[]).add(o);
            _accountObservation(o);
            onObservation?.call(batch[i], current[batch[i].key]!, rung);
          },
        );
      } catch (e) {
        final reason = 'probe session: $e';
        _note('rung ${rung + 1}: технический сбой оценщика ($e)');
        results = [
          for (var i = 0; i < batch.length; i++)
            [
              ...?streamed[i],
              if ((streamed[i]?.length ?? 0) < attempts)
                Observation.failed(reason, requests: 0),
            ],
        ];
      } finally {
        watch.stop();
        _activeTime += watch.elapsed;
      }
      rung++;
      var aliveKeys = <String>[];
      for (var i = 0; i < batch.length; i++) {
        final g = batch[i];
        final f = current[g.key]!;
        final notified = streamed[i] ?? const <Observation>[];
        final returned = i < results.length ? results[i] : const <Observation>[];
        final extra = returned.length > notified.length
            ? returned.skip(notified.length)
            : const Iterable<Observation>.empty();
        final obs = [...notified, ...extra];
        for (final o in extra) {
          _accountObservation(o);
        }
        for (final o in obs) {
          f.add(o);
        }
        final rec = _records.putIfAbsent(g.key, () => EvoRecord(g, Fitness(g)));
        if (f.passRate >= settings.minPassRate &&
            rec.lastConfirmedGeneration != generation) {
          rec.confirmations++;
          rec.lastConfirmedGeneration = generation;
          // Живая таблица показывает Fitness текущего поколения — счётчик
          // должен быть виден сразу, а не только в итоговом lifetime.
          f.confirmations = rec.confirmations;
        }
        if (rung > rec.bestRung) rec.bestRung = rung;
        if (f.passes > 0) aliveKeys.add(g.key);
      }
      keeps.add(aliveKeys.length);
      if (rung == 1 && aliveKeys.length * 10 < batch.length * 3) {
        _note('после первого ранга выжило менее 30% — остальные ранги пропущены');
        break;
      }
      // Отсев по Парето внутри каждого режима: WARP и приватный результат не
      // соревнуются за одни слоты, иначе удачный WARP-прогон может вытеснить
      // приватные серверы из следующего ранга только из-за пропорции популяции.
      final take = settings.keepOf(aliveKeys.length);
      if (aliveKeys.length > take) {
        final privateAlive =
            aliveKeys.where((k) => current[k]!.genome.isVerbatim).length;
        final warpAlive = aliveKeys.length - privateAlive;
        var privateTake = privateAlive == 0
            ? 0
            : (take * privateAlive / aliveKeys.length)
                .round()
                .clamp(privateAlive > 0 && take > 0 ? 1 : 0, privateAlive);
        if (warpAlive > 0 && take > 0 && privateTake == take) privateTake--;
        final warpTake = take - privateTake;
        List<String> kept(bool private, int quota) {
          final scored = [
            for (final k in aliveKeys)
              if (current[k]!.genome.isVerbatim == private) current[k]!,
          ];
          if (scored.length <= quota) {
            return [for (final f in scored) f.genome.key];
          }
          final order =
              nsga2Order(scored, targetCountry: settings.targetCountry);
          return [for (final i in order.take(quota)) scored[i].genome.key];
        }

        aliveKeys = [...kept(false, warpTake), ...kept(true, privateTake)];
      }
      tier = aliveKeys;
    }
    for (final f in current.values) {
      final rec = _records.putIfAbsent(f.genome.key, () => EvoRecord(f.genome, f));
      rec.lifetime = _accumulate(rec.lifetime, f);
      // Счётчик подтверждений живёт в записи, а наружу (архив, экспорт, экран)
      // уходит Fitness — иначе победители выходили бы с «0 подтверждений».
      rec.lifetime.confirmations = rec.confirmations;
    }
    final all = current.values.toList();
    final rtts = [for (final f in all) if (f.medianRtt != null) f.medianRtt!];
    final fronts = fastNonDominatedSort(
      [for (final f in all) f.objectives(targetCountry: settings.targetCountry)],
    );
    // Причины отказов по всему поколению: «проходимых 0» без них неотличимо от
    // поломки пробы, а это ровно то, что пользователь видит первым.
    final reasons = <String, int>{};
    for (final f in all) {
      f.errorSignatures().forEach((k, v) => reasons[k] = (reasons[k] ?? 0) + v);
    }
    final failureReasons = topReasons(reasons);
    final summary = GenerationSummary(
      index: generation,
      evaluated: current.length,
      alive: all.where((f) => f.passRate >= settings.minPassRate).length,
      bestPassRate: all.isEmpty
          ? 0
          : all.map((f) => f.passRate).reduce((a, b) => a > b ? a : b),
      bestRttMs: rtts.isEmpty ? null : rtts.reduce((a, b) => a < b ? a : b),
      diversity: diversity([for (final f in all) f.genome]),
      paretoFrontSize: fronts.firstOrNull?.length ?? 0,
      requestsUsed: _requestsUsed,
      rungKeeps: keeps.lastOrNull ?? 0,
      failureReasons: failureReasons,
    );
    onGeneration?.call(summary);
    _note(
      'поколение $generation: проверено ${summary.evaluated}, '
      'проходимых ${summary.alive}, лучшее '
      '${(summary.bestPassRate * 100).toStringAsFixed(0)} %, '
      'выживших по рангам ${keeps.join('→')}',
    );
    if (summary.alive == 0 && failureReasons.isNotEmpty) {
      _note('причины отказов: $failureReasons');
    }
    return summary;
  }

  /// Следующее поколение: элита (μ) + потомки (λ) + иммигранты. WARP и
  /// приватные геномы ранжируются и размножаются отдельно.
  List<Genome> _nextGeneration(Random rng) {
    final observed = [
      for (final r in _records.values)
        if (r.lifetime.attempts > 0) r.lifetime,
    ];
    if (observed.isEmpty) return _fill(const [], rng);
    List<Fitness> ranked(Iterable<Fitness> source) {
      final list = source.toList();
      final order = nsga2Order(list, targetCountry: settings.targetCountry);
      return [for (final i in order) list[i]];
    }

    final warpRanked = ranked(observed.where((f) => !f.genome.isVerbatim));
    final privateRanked = ranked(observed.where((f) => f.genome.isVerbatim));
    final eliteTotal = settings.eliteSize;
    final privateElites = _privateSlots == 0
        ? 0
        : _privateSlots == settings.populationSize
            ? eliteTotal
            : (eliteTotal * _privateSlots / settings.populationSize)
                .round()
                .clamp(1, eliteTotal - 1);
    final warpElites = warpRanked
        .take(eliteTotal - privateElites)
        .map((f) => f.genome)
        .toList();
    final verbatimElites = privateRanked
        .take(privateElites)
        .map((f) => f.genome)
        .cast<GenomeVerbatim>()
        .toList();

    // Архив славы входит в EDA только WARP-модели. Приватное размножение
    // работают над тремя безопасными локусами и не знают полной частотной модели.
    final eda = <String, MapEntry<Genome, double>>{};
    void feedEda(Genome genome, double weight) {
      final previous = eda[genome.key];
      eda[genome.key] = MapEntry(
        previous?.key ?? genome,
        (previous?.value ?? 0) + weight,
      );
    }

    for (var i = 0; i < warpElites.length; i++) {
      feedEda(warpElites[i], 1.0 / (1.0 + i));
    }
    final archive = hallOfFame;
    for (var i = 0; i < archive.length; i++) {
      final f = archive[i];
      if (f.genome.isVerbatim) continue;
      final rankWeight = min(1.0, 1.0 / (1.0 + i));
      final confirmationWeight = 1.0 + 0.25 * min(f.confirmations, 4);
      feedEda(f.genome, rankWeight * confirmationWeight);
    }
    final model = AlleleModel.fit(
      [for (final e in eda.values) e.key],
      pools,
      weighting: [for (final e in eda.values) e.value],
      countries: settings.countries,
    );
    final div = max(
      diversity(warpElites),
      diversity(verbatimElites),
    );
    final immigrants =
        immigrantCount(settings.populationSize, div, settings.immigrantFraction);
    if (div < 0.12) {
      _note(
        'разнообразие элиты ${(div * 100).toStringAsFixed(0)} % — '
        'популяция схлопывается, иммигрантов добавлено ×2',
      );
    }
    final privateImmigrants = _privateSlots == 0
        ? 0
        : _privateSlots == settings.populationSize
            ? immigrants
            : (immigrants * _privateSlots / settings.populationSize).round();
    final warpTarget = settings.populationSize - _privateSlots;
    final warpOut = <Genome>[];
    final privateOut = <GenomeVerbatim>[];
    final seen = <String>{};
    void addWarp(Genome g) {
      if (warpOut.length >= warpTarget || !seen.add(g.key)) return;
      warpOut.add(g);
    }

    void addPrivate(GenomeVerbatim g) {
      if (privateOut.length >= _privateSlots || !seen.add(g.key)) return;
      privateOut.add(g);
    }

    for (final e in warpElites) {
      addWarp(e);
    }
    for (final e in verbatimElites) {
      addPrivate(e);
    }
    final warpChildSlots = warpTarget - (immigrants - privateImmigrants);
    var guard = 0;
    while (warpOut.length < warpChildSlots && guard < 300) {
      guard++;
      final child = settings.useEda
          ? model.sample(rng, pools, countries: settings.countries)
          : uniformCrossover(
              warpElites[rng.nextInt(warpElites.length)],
              warpElites[rng.nextInt(warpElites.length)],
              rng,
            );
      addWarp(mutate(child, pools, rng,
          mutationRate: settings.mutationRate, countries: settings.countries));
    }
    guard = 0;
    while (privateOut.length < _privateSlots - privateImmigrants && guard < 300) {
      guard++;
      final parent = verbatimElites.isEmpty
          ? _privateSeeds
          : verbatimElites;
      if (parent.isEmpty) break;
      final source = _pickPrivateParent(parent, rng);
      addPrivate(mutateVerbatim(source, pools, rng,
          mutationRate: settings.mutationRate,
          countries: settings.countries));
    }
    guard = 0;
    while (warpOut.length < warpTarget && guard < 300) {
      guard++;
      final g = _takeReserve(false) ??
          pools.random(rng, countries: settings.countries);
      addWarp(g);
    }
    guard = 0;
    while (privateOut.length < _privateSlots && guard < 300) {
      guard++;
      final g = _takeReserve(true) ?? _randomPrivate(rng, verbatimElites);
      if (g is! GenomeVerbatim) break;
      addPrivate(g);
    }
    guard = 0;
    while (warpOut.length + privateOut.length < settings.populationSize &&
        guard < settings.populationSize) {
      guard++;
      final before = warpOut.length + privateOut.length;
      if (warpOut.length < warpTarget) {
        addWarp(pools.random(rng, countries: settings.countries));
      } else {
        final g = _randomPrivate(rng, verbatimElites);
        if (g != null) addPrivate(g);
      }
      if (warpOut.length + privateOut.length == before) break;
    }
    return [...warpOut, ...privateOut];
  }

  /// Долгоживущий фитнес = накопленные наблюдения (медиана RTT и голоса стран
  /// считаются по всему ряду, а не по последнему поколению).
  Fitness _accumulate(Fitness old, Fitness fresh) {
    if (identical(old, fresh)) return old;
    final m = old.copy();
    for (final o in fresh.observations) {
      m.add(o);
    }
    m.confirmations = old.confirmations;
    m.rungReached = max(old.rungReached, fresh.rungReached);
    return m;
  }

  /// Добивает популяцию до размера и собирает резерв посева.
  ///
  /// Посев бываЕТ заметно больше популяции (66 рабочих конфигов при pop=16), и
  /// тогда весь посев в первом поколении сжёг бы ~40 % бюджета за один rung, а
  /// настройка «популяция» перестала бы означать что-либо. Излишек уходит в
  /// [_reserve] и входит в поиск иммигрантом в следующих поколениях — то есть
  /// каждый конфиг пользователя всё равно бывает оценён, но по расписанию.
  List<Genome> _fill(List<Genome> seed, Random rng) {
    final warpOut = <Genome>[];
    final privateOut = <GenomeVerbatim>[];
    final seen = <String>{};
    for (final g in seed) {
      // Адрес — единственное, без чего узел не собирается вовсе (ни WG, ни
      // MASQUE не имеют «глухого» адреса-умолчения).
      if (g.endpoint.isEmpty) continue;
      if (!seen.add(g.key)) continue;
      if (g.isVerbatim) {
        if (privateOut.length < _privateSlots) {
          privateOut.add(g as GenomeVerbatim);
        } else {
          _reserve.add(g);
        }
      } else if (warpOut.length < settings.populationSize - _privateSlots) {
        warpOut.add(g);
      } else {
        _reserve.add(g);
      }
    }
    if (_reserve.isNotEmpty) {
      _note(
        'посев ${seen.length} > популяции ${settings.populationSize}: '
        '${_reserve.length} особей в резерве, войдут иммигрантами',
      );
    }
    var guard = 0;
    while (warpOut.length < settings.populationSize - _privateSlots &&
        guard < 300) {
      guard++;
      final g = pools.random(rng, countries: settings.countries);
      if (seen.add(g.key)) warpOut.add(g);
    }
    guard = 0;
    while (privateOut.length < _privateSlots && guard < 300) {
      guard++;
      final g = _randomPrivate(rng, const []);
      if (g == null || !seen.add(g.key)) continue;
      privateOut.add(g);
    }
    return [...warpOut, ...privateOut];
  }

  int _privateTarget(List<Genome> seeds) {
    final count = seeds.where((g) => g.isVerbatim).length;
    if (count == 0 || seeds.isEmpty) return 0;
    if (count == seeds.length) return settings.populationSize;
    return (settings.populationSize * count / seeds.length)
        .round()
        .clamp(1, settings.populationSize - 1);
  }

  GenomeVerbatim? _randomPrivate(
    Random rng,
    List<GenomeVerbatim> preferred,
  ) {
    final parents = preferred.isNotEmpty
        ? preferred
        : (_privateSeeds.isNotEmpty ? _privateSeeds : const <GenomeVerbatim>[]);
    if (parents.isEmpty) return null;
    return mutateVerbatim(
      _pickPrivateParent(parents, rng),
      pools,
      rng,
      mutationRate: 1,
      countries: settings.countries,
    );
  }

  GenomeVerbatim _pickPrivateParent(
    List<GenomeVerbatim> parents,
    Random rng,
  ) {
    if (parents.length == 1) return parents.first;
    final weights = <int>[
      for (final parent in parents)
        1 + min(_records[parent.key]?.confirmations ?? 0, 8),
    ];
    final total = weights.fold<int>(0, (sum, weight) => sum + weight);
    var ticket = rng.nextInt(total);
    for (var i = 0; i < parents.length; i++) {
      ticket -= weights[i];
      if (ticket < 0) return parents[i];
    }
    return parents.last;
  }

  Genome? _takeReserve(bool private) {
    final i = _reserve.indexWhere((g) => g.isVerbatim == private);
    if (i < 0) return null;
    return _reserve.removeAt(i);
  }

  void _accountObservation(Observation observation) {
    // Следующая проба не должна стартовать, пока её цена ещё не учтена.
    _requestsUsed += observation.requests;
    _observedVerdicts++;
    if (observation.requests > 0) _paidVerdicts++;
  }

  List<Genome> _dedupe(List<Genome> pop) {
    final seen = <String>{};
    return [for (final g in pop) if (seen.add(g.key)) g];
  }

  void _note(String message) => onNote?.call(message);
}
