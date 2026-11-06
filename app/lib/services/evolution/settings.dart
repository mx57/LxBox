// §848 — настройки эволюции: всё, что пользователь крутит руками.
//
// Намеренно не «один ползунок сложности»: у каждой ручки есть физический смысл
// и цена. Цена измеряется в HTTP-запросах через ядро (одна probe-сессия
// поднимает ВГ/AWG-эндпоинты с предвыделением буферов, §523), поэтому бюджет
// ([EvolutionSettings.maxRequests]) — первичное ограничение, а поколения —
// вторичные.
//
// Хранится одним JSON-значением в var `evo_settings`: набор настроек меняется
// целиком (экран → старт прогона), частичных записей делать незачем.

import 'dart:convert';
import 'dart:math';

import '../settings_storage.dart';
import 'genome.dart';
import 'pools.dart';

/// Все ручко-настраиваемые параметры прогона.
class EvolutionSettings {
  const EvolutionSettings({
    this.populationSize = 16,
    this.maxGenerations = 8,
    this.maxRequests = 1080,
    this.rungAttempts = const [1, 2, 3],
    this.rungKeepFraction = 0.5,
    this.eliteFraction = 0.35,
    this.mutationRate = 0.12,
    this.immigrantFraction = 0.15,
    this.hallOfFameSize = 12,
    this.confirmationsNeeded = 2,
    this.targetCountry = '',
    this.countries = const [],
    this.transports = const {
      EvoTransport.awg,
      EvoTransport.masqueH3,
      EvoTransport.masqueH2,
    },
    this.disabledLoci = const {},
    this.useEda = true,
    this.allowFragment = true,
    this.allowRecordFragment = true,
    this.requestTimeout = const Duration(seconds: 8),
    this.seed = 0,
    this.minPassRate = 0.34,
  });

  /// Сколько особей в поколении. Верхняя граница дикту не «красотой графика», а
  /// batch-лимитами пробы: 4 WG + 4 MASQUE на конфиг (probe_config.dart), т.е.
  /// популяция 16 — это ~4 probe-сессии на rung. Больше — линейно дороже.
  final int populationSize;

  /// Остановка по числу поколений (срабатывает раньше бюджета только у совсем
  /// маленьких прогонов).
  final int maxGenerations;

  /// Потолок HTTP-запросов через ядро за весь прогон. Это ЕДИНСТВЕННАЯ честная
  /// валюта: время одного запроса зависит от сети, а запрос — нет.
  ///
  /// Дефолт = полный прогон настроек по умолчанию (16×8 при рангах [1,2,3]) с
  /// ХУДШИМ множителем на вердикт: проба чередует `kGeoUrls.length` источников
  /// гео (§844), поэтому один вердикт стоит до трёх запросов. Потолок,
  /// посчитанный от вердиктов, обрезал бы кампании на трети поколений.
  final int maxRequests;

  /// Successive halving: попытки на ранг. `[1, 2, 3]` = каждый кандидат
  /// получает 1 пробу, выжившие — ещё 2 (итого 3), финалисты — ещё 3 (итого 6).
  final List<int> rungAttempts;

  /// Доля особей, переходящих на следующий ранг. 0.5 — классический η=2.
  final double rungKeepFraction;

  /// Доля поколений, идущая в оценку частот (элита для UMDA).
  final double eliteFraction;

  /// Вероятность пересэмплировать локус при мутации.
  final double mutationRate;

  /// Доля случайных иммигрантов в новом поколении (страховка от схлопывания).
  final double immigrantFraction;

  /// Размер архива славы (экспортируемых победителей).
  final int hallOfFameSize;

  /// Сколько РАЗНЫХ probe-сессий должны подтвердить проходимость особи, чтобы
  /// она попала в архив. 1 = «поверили одному замеру» — на нестационарном DPI
  /// это шум; 2–3 = устойчивый результат.
  final int confirmationsNeeded;

  /// Желаемая страна выхода ('' = любая). Третья цель Парето.
  final String targetCountry;

  /// Фильтр адресных пулов по странам ('' = страна не определена).
  final List<String> countries;

  /// Какие транспорты участвуют в поиске.
  final Set<EvoTransport> transports;

  /// Локусы, которые ЗАПРЕЩЕНО мутировать (пользователь фиксирует параметр).
  final Set<EvoLocus> disabledLoci;

  /// true — EDA (UMDA) как основной оператор; false — классический ГА
  /// (равномерный кроссовер двух родителей).
  final bool useEda;

  /// Разрешены ли мутации TLS-фрагментации / record-фрагментации.
  final bool allowFragment;
  final bool allowRecordFragment;

  /// Таймаут одного probeGetUrl.
  final Duration requestTimeout;

  /// 0 = каждый прогон свой Random; иначе — воспроизводимый прогон (для
  /// сравнения настроек и для отладки «почему вчера было лучше»).
  final int seed;

  /// Порог «проходимый» для статистики и архива (доля успешных проб).
  final double minPassRate;

  Random rng() => Random(seed == 0 ? DateTime.now().microsecondsSinceEpoch : seed);

  bool locusEnabled(EvoLocus l) => !disabledLoci.contains(l);

  int get eliteSize => max(2, (populationSize * eliteFraction).round());

  /// Кандидатов на следующий ранг.
  int keepOf(int evaluated) =>
      evaluated <= 2 ? evaluated : max(1, (evaluated * rungKeepFraction).round());

  /// Потолок поколений: либо по числу, либо по бюджету запросов.
  bool budgetLeft(int requestsUsed) => requestsUsed < maxRequests;

  EvolutionSettings copyWith({
    int? populationSize,
    int? maxGenerations,
    int? maxRequests,
    List<int>? rungAttempts,
    double? rungKeepFraction,
    double? eliteFraction,
    double? mutationRate,
    double? immigrantFraction,
    int? hallOfFameSize,
    int? confirmationsNeeded,
    String? targetCountry,
    List<String>? countries,
    Set<EvoTransport>? transports,
    Set<EvoLocus>? disabledLoci,
    bool? useEda,
    bool? allowFragment,
    bool? allowRecordFragment,
    Duration? requestTimeout,
    int? seed,
    double? minPassRate,
  }) =>
      EvolutionSettings(
        populationSize: populationSize ?? this.populationSize,
        maxGenerations: maxGenerations ?? this.maxGenerations,
        maxRequests: maxRequests ?? this.maxRequests,
        rungAttempts: rungAttempts ?? this.rungAttempts,
        rungKeepFraction: rungKeepFraction ?? this.rungKeepFraction,
        eliteFraction: eliteFraction ?? this.eliteFraction,
        mutationRate: mutationRate ?? this.mutationRate,
        immigrantFraction: immigrantFraction ?? this.immigrantFraction,
        hallOfFameSize: hallOfFameSize ?? this.hallOfFameSize,
        confirmationsNeeded: confirmationsNeeded ?? this.confirmationsNeeded,
        targetCountry: targetCountry ?? this.targetCountry,
        countries: countries ?? this.countries,
        transports: transports ?? this.transports,
        disabledLoci: disabledLoci ?? this.disabledLoci,
        useEda: useEda ?? this.useEda,
        allowFragment: allowFragment ?? this.allowFragment,
        allowRecordFragment: allowRecordFragment ?? this.allowRecordFragment,
        requestTimeout: requestTimeout ?? this.requestTimeout,
        seed: seed ?? this.seed,
        minPassRate: minPassRate ?? this.minPassRate,
      );

  Map<String, Object> toJson() => {
        'populationSize': populationSize,
        'maxGenerations': maxGenerations,
        'maxRequests': maxRequests,
        'rungAttempts': rungAttempts,
        'rungKeepFraction': rungKeepFraction,
        'eliteFraction': eliteFraction,
        'mutationRate': mutationRate,
        'immigrantFraction': immigrantFraction,
        'hallOfFameSize': hallOfFameSize,
        'confirmationsNeeded': confirmationsNeeded,
        'targetCountry': targetCountry,
        'countries': countries,
        'transports': [for (final t in transports) t.wire],
        'disabledLoci': [for (final l in disabledLoci) l.wire],
        'useEda': useEda,
        'allowFragment': allowFragment,
        'allowRecordFragment': allowRecordFragment,
        'requestTimeoutMs': requestTimeout.inMilliseconds,
        'seed': seed,
        'minPassRate': minPassRate,
      };

  static EvolutionSettings fromJson(Map<String, dynamic> j) {
    List<String> strs(Object? v) =>
        v is List ? [for (final e in v) '$e'] : const [];
    return EvolutionSettings(
      populationSize: _int(j['populationSize'], 16),
      maxGenerations: _int(j['maxGenerations'], 8),
      maxRequests: _int(j['maxRequests'], 1080),
      rungAttempts: [for (final e in (j['rungAttempts'] as List? ?? const [1, 2, 3])) _int(e, 1)]
          .where((e) => e > 0)
          .toList(),
      rungKeepFraction: _double(j['rungKeepFraction'], 0.5),
      eliteFraction: _double(j['eliteFraction'], 0.35),
      mutationRate: _double(j['mutationRate'], 0.12),
      immigrantFraction: _double(j['immigrantFraction'], 0.15),
      hallOfFameSize: _int(j['hallOfFameSize'], 12),
      confirmationsNeeded: _int(j['confirmationsNeeded'], 2),
      targetCountry: '${j['targetCountry'] ?? ''}',
      countries: strs(j['countries']),
      transports: {
        for (final w in strs(j['transports'])) EvoTransport.fromWire(w),
        if (strs(j['transports']).isEmpty) ...EvoTransport.values,
      },
      disabledLoci: {
        for (final w in strs(j['disabledLoci']))
          EvoLocus.values.firstWhere((l) => l.wire == w,
              orElse: () => EvoLocus.transport),
      },
      useEda: j['useEda'] != false,
      allowFragment: j['allowFragment'] != false,
      allowRecordFragment: j['allowRecordFragment'] != false,
      requestTimeout:
          Duration(milliseconds: _int(j['requestTimeoutMs'], 8000)),
      seed: _int(j['seed'], 0),
      minPassRate: _double(j['minPassRate'], 0.34),
    );
  }

  static int _int(Object? v, int dflt) => v is num ? v.toInt() : dflt;
  static double _double(Object? v, double dflt) => v is num ? v.toDouble() : dflt;

  /// Диапазоны ручного ввода (экран их валидирует, движок — нет: настройки
  /// приходят с экрана, а не из сети).
  static const int minPopulation = 6;
  static const int maxPopulation = 48;
  static const int minGenerations = 1;
  static const int maxGenerationsLimit = 40;
  static const int minRequestBudget = 30;
  static const int maxRequestBudget = 3000;

  static const String storageKey = 'evo_settings';

  static Future<EvolutionSettings> load() async {
    final raw = await SettingsStorage.getVar(storageKey, '');
    if (raw.isEmpty) return const EvolutionSettings();
    try {
      return EvolutionSettings.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      // Побитый JSON не должен валить экран настроек: молча берём дефолты.
      return const EvolutionSettings();
    }
  }

  Future<void> save() =>
      SettingsStorage.setVar(storageKey, jsonEncode(toJson()));

  /// Пулы мутаций под текущие настройки: транспорты, страны, отключённые
  /// локусы и фрагментация. [base] — штатный пул из скана/asset'а.
  AlleleSource poolsFor(EvolutionPools base) => RestrictedPools(
        base,
        transports: transports,
        disabledLoci: disabledLoci,
        fragment: allowFragment,
        recordFragment: allowRecordFragment,
      );
}
