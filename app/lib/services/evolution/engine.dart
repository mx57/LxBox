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

  /// [attempts] проб на каждый геном. Возвращает наблюдения ПО ИНДЕКСУ входа
  /// (короткий список = пробы не дошли). Наблюдения прилетают и через [onOne],
  /// чтобы UI жил во время долгого rung'а.
  Future<List<List<Observation>>> evaluate(
    List<Genome> genomes, {
    required int attempts,
    void Function(int index, Observation observation)? onOne,
    bool Function()? cancelled,
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

class EvolutionEngine {
  EvolutionEngine({
    required this.evaluator,
    required this.pools,
    required this.settings,
    this.onGeneration,
    this.onObservation,
    this.onNote,
  });

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

  bool _cancelled = false;
  Completer<void>? _pauseGate;
  int _requestsUsed = 0;
  String _error = '';

  bool get cancelled => _cancelled;
  int get requestsUsed => _requestsUsed;
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
    final reason = await evaluator.prepare();
    if (reason != null) {
      _error = reason;
      _note('старт невозможен: $reason');
      return EvolutionOutcome(
        hallOfFame: const [],
        stats: const [],
        requestsUsed: 0,
        generations: 0,
        error: reason,
      );
    }
    final rng = settings.rng();
    var population = _fill(_dedupe(seeds), rng);
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
      final results = await evaluator.evaluate(
        batch,
        attempts: attempts,
        cancelled: () => _cancelled,
        onOne: (i, o) {
          if (i < 0 || i >= batch.length) return;
          onObservation?.call(batch[i], current[batch[i].key]!, rung);
        },
      );
      rung++;
      var aliveKeys = <String>[];
      for (var i = 0; i < batch.length; i++) {
        final g = batch[i];
        final f = current[g.key]!;
        final obs = i < results.length ? results[i] : const <Observation>[];
        for (final o in obs) {
          f.add(o);
        }
        // Бюджет — в ЗАПРОСАХ (валюта прогона): вердикт одной особи может стоить
        // не одного GET'а, а столько, сколько источников гео проба перебрала
        // (§844), поэтому считаем [Observation.requests], а не число вердиктов.
        _requestsUsed +=
            obs.fold<int>(0, (a, o) => a + (o.requests <= 0 ? 1 : o.requests));
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
      // Отсев по Парето, а не по «лучший RTT»: у одной пробы статистики
      // скорости нет, зато есть «прошёл / не прошёл».
      if (aliveKeys.length > settings.keepOf(aliveKeys.length)) {
        final scored = [for (final k in aliveKeys) current[k]!];
        final take = settings.keepOf(scored.length);
        final order =
            nsga2Order(scored, targetCountry: settings.targetCountry);
        aliveKeys = [for (final i in order.take(take)) scored[i].genome.key];
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

  /// Следующее поколение: элита (μ) + потомки (λ) + иммигранты.
  List<Genome> _nextGeneration(Random rng) {
    final observed = [
      for (final r in _records.values)
        if (r.lifetime.attempts > 0) r.lifetime,
    ];
    if (observed.isEmpty) return _fill(const [], rng);
    final order = nsga2Order(observed, targetCountry: settings.targetCountry);
    final ranked = [for (final i in order) observed[i]];
    final elites = ranked.take(settings.eliteSize).map((f) => f.genome).toList();
    final model = AlleleModel.fit(
      elites,
      pools,
      // Вес по рангу: лучшая особь формирует распределение сильнее.
      weighting: [for (var i = 0; i < elites.length; i++) 1.0 / (1.0 + i)],
      countries: settings.countries,
    );
    final div = diversity(elites);
    var immigrants =
        immigrantCount(settings.populationSize, div, settings.immigrantFraction);
    if (div < 0.12) {
      _note(
        'разнообразие элиты ${(div * 100).toStringAsFixed(0)} % — '
        'популяция схлопывается, иммигрантов добавлено ×2',
      );
    }
    final out = <Genome>[];
    final seen = <String>{};
    void add(Genome g) {
      if (out.length >= settings.populationSize || !seen.add(g.key)) return;
      out.add(g);
    }

    // Стабильная элита: лучший кандидат обязан остаться в выборке — иначе
    // прогон может потерять найденное из-за одной неудачной кампании.
    for (final e in elites) {
      add(e);
    }
    final childSlots = settings.populationSize - immigrants;
    var guard = 0;
    while (out.length < childSlots && guard < 300) {
      guard++;
      final child = settings.useEda
          ? model.sample(rng, pools, countries: settings.countries)
          : uniformCrossover(
              elites[rng.nextInt(elites.length)],
              elites[rng.nextInt(elites.length)],
              rng,
            );
      add(mutate(child, pools, rng,
          mutationRate: settings.mutationRate, countries: settings.countries));
    }
    guard = 0;
    while (out.length < settings.populationSize && guard < 300) {
      guard++;
      // Резерв посева первее случайного иммигранта: узел, который УЖЕ
      // соединялся, ценнее слепой выборки из пула.
      final g = _reserve.isNotEmpty
          ? _reserve.removeAt(0)
          : pools.random(rng, countries: settings.countries);
      add(g);
    }
    return out;
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
    final out = <Genome>[];
    final seen = <String>{};
    for (final g in seed) {
      // Адрес — единственное, без чего узел не собирается вовсе (ни WG, ни
      // MASQUE не имеют «глухого» адреса-умолчения).
      if (g.endpoint.isEmpty) continue;
      if (!seen.add(g.key)) continue;
      if (out.length < settings.populationSize) {
        out.add(g);
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
    while (out.length < settings.populationSize && guard < 300) {
      guard++;
      final g = pools.random(rng, countries: settings.countries);
      if (seen.add(g.key)) out.add(g);
    }
    return out;
  }

  List<Genome> _dedupe(List<Genome> pop) {
    final seen = <String>{};
    return [for (final g in pop) if (seen.add(g.key)) g];
  }

  void _note(String message) => onNote?.call(message);
}
