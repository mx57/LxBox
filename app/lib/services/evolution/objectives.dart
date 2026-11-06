// §848 — цели (objectives) и многокритериальный отбор.
//
// Эволюция обхода блокировок НЕ может оптимизировать одно число: «самый
// быстрый» узел бесполезен, если DPI его режет, а «самый проходимый» бесполезен
// в 3000 км от пользователя. Поэтому особь оценивается ТРЕМЯ независимыми
// критериями и отбор идёт по Парето (NSGA-II), а не по взвешенной сумме —
// свесы пришлось бы назначать наугад, а ранжирование по фронту ничего не
// предполагает и остаётся честным при смене сети.
//
// Ключевой факт о фитнесе: вердикт DPI НЕСТАЦИОНАРЕN. Одна проба — это одно
// наблюдение, а не свойство конфига, поэтому [Fitness] накапливает наблюдения
// (pass-rate), а архив славы требует повторного подтверждения в ДРУГОЙ
// probe-сессии (см. engine.dart, гистерезис).

import 'dart:math';

import 'genome.dart';

/// Одно наблюдение: одна HTTP-проба через узел конкретного генома.
class Observation {
  const Observation({
    required this.responded,
    this.status = 0,
    this.rttMs = 0,
    this.country = '',
    this.colo = '',
    this.error = '',
    this.url = '',
    this.requests = 1,
  });

  /// Проба не дошла до ответа (таймаут, ошибка туннеля, пустой ответ).
  const Observation.failed(this.error,
      {this.rttMs = 0, this.url = '', this.requests = 1})
      : responded = false,
        status = 0,
        country = '',
        colo = '';

  /// Сколько HTTP-запросов ушло на ВЕРДИКТ, а не на одну попытку: проба
  /// чередует источники гео (§844 — на зарезанном DNS один источник означает
  /// «не ответило всё»), а бюджет прогона считается именно в запросах. Без
  /// этого поля «0 % проходимых» выглядел бы дешевле, чем он стоил.
  final int requests;

  final bool responded;

  /// HTTP-код ответа (0 — ответа не было).
  final int status;

  /// Замеренная задержка probeGetUrl, мс.
  final int rttMs;

  /// Страна УЗЛА (из `colo`, §848) — не страна клиента.
  final String country;
  final String colo;
  final String error;

  /// Источник geo (ротация по kGeoUrls) — для журнала.
  final String url;
}

/// Накопленная приспособленность одной особи.
///
/// Мутируемый аккумулятор: движок добавляет наблюдения rung за rung'ом, и
/// именно поэтому ранги successive halving сравнимы — у отсечённых рано особей
/// меньше попыток, и их `passRate` ненадёжнее (см. [confidence]).
class Fitness {
  Fitness(this.genome);

  final Genome genome;

  int attempts = 0;
  int passes = 0;

  /// Наблюдения только успешных проб (для медианы RTT).
  final List<int> _rtts = [];

  /// Наблюдения только неудачных проб (для журнала и вердикта).
  final List<String> _errors = [];

  /// Страны/узла по успешным пробам — мода даёт основную страну выхода.
  final Map<String, int> _countryVotes = {};
  final Map<String, int> _coloVotes = {};

  /// ВСЕ наблюдения подряд (успешные и нет). Нужны для слияния фитнеса между
  /// поколениями: без исходных наблюдений нельзя честно пересчитать медиану
  /// RTT и голоса стран на накопленном ряду.
  final List<Observation> _observations = [];

  List<Observation> get observations => List.unmodifiable(_observations);

  /// Сколько ПОКОЛЕНИЙ особь наблюдалась с проход ≥1 (гистерезис архива).
  /// Считается в движке, здесь — поле-накопитель.
  int confirmations = 0;

  /// Последний rung, на котором особь дошла до конца (для честной картинки:
  /// «проверено 1 из 5 попыток»).
  int rungReached = 0;

  /// Суммарные HTTP-запросы, потраченные на эту особь (бюджет в UI).
  int requestsUsed = 0;

  double get passRate => attempts == 0 ? 0 : passes / attempts;

  /// Насколько цифрам можно верить: 1 попытка из 5 — это ещё не вердикт.
  double get confidence => min(1, attempts / 3);

  int? get medianRtt {
    if (_rtts.isEmpty) return null;
    final s = [..._rtts]..sort();
    final m = s.length ~/ 2;
    return s.length.isOdd ? s[m] : ((s[m - 1] + s[m]) / 2).round();
  }

  String get country {
    if (_countryVotes.isEmpty) return '';
    final e = _countryVotes.entries.reduce((a, b) => a.value >= b.value ? a : b);
    return e.value == 0 ? '' : e.key;
  }

  String get colo {
    if (_coloVotes.isEmpty) return '';
    final e = _coloVotes.entries.reduce((a, b) => a.value >= b.value ? a : b);
    return e.value == 0 ? '' : e.key;
  }

  String get lastError => _errors.isEmpty ? '' : _errors.last;

  /// Ошибки наблюдений, свёрнутые в «подпись → сколько раз». Нужно для честной
  /// картинки «проходимых 0»: без причин прогон неотличим от «сеть режет всё»
  /// от «у нас не поднят резолвер». Цифры (тайминги, IP) сворачиваются в `#`,
  /// иначе один и тот же текст дал бы N разных корзин.
  Map<String, int> errorSignatures() {
    final out = <String, int>{};
    for (final e in _errors) {
      final s = errorSignature(e);
      if (s.isEmpty) continue;
      out[s] = (out[s] ?? 0) + 1;
    }
    return out;
  }

  void add(Observation o) {
    _observations.add(o);
    attempts++;
    requestsUsed += o.requests <= 0 ? 1 : o.requests;
    if (!o.responded) {
      if (o.error.isNotEmpty) _errors.add(o.error);
      return;
    }
    passes++;
    _rtts.add(o.rttMs);
    if (o.country.isNotEmpty) {
      _countryVotes[o.country] = (_countryVotes[o.country] ?? 0) + 1;
    }
    if (o.colo.isNotEmpty) {
      _coloVotes[o.colo] = (_coloVotes[o.colo] ?? 0) + 1;
    }
  }

  /// Цели ВСЕ на максимизацию: [проходимость, скорость, попадание в страну].
  ///
  /// Скорость линейно гаснет к 2000 мс и равна нулю без ни одной успешной пробы
  /// — иначе «мёртвый» кандидат с фиктивно-маленьким RTT обгонял бы живой.
  List<double> objectives({String targetCountry = ''}) {
    final speed = passes == 0
        ? 0.0
        : max(0.0, 1 - (medianRtt ?? 2000) / 2000);
    final hit = switch ((targetCountry, country)) {
      ('', _) => 1.0,
      (_, '') => 0.25,
      (final t, final c) => t == c ? 1.0 : 0.0,
    };
    return [passRate, speed, hit];
  }

  Fitness copy() {
    final f = Fitness(genome)
      ..attempts = attempts
      ..passes = passes
      ..confirmations = confirmations
      ..rungReached = rungReached
      ..requestsUsed = requestsUsed;
    f._rtts.addAll(_rtts);
    f._errors.addAll(_errors);
    f._observations.addAll(_observations);
    f._countryVotes.addAll(_countryVotes);
    f._coloVotes.addAll(_coloVotes);
    return f;
  }
}

/// §848 — быстрая непарето-сортировка NSGA-II (Deb, 2002).
///
/// Возвращает фронты индексов: `out[0]` — недоминируемые, `out[1]` — следующий
/// слой и т.д. O(M·N²) при N ≤ 64 и M = 3 — на телефоне это микросекунды, а
/// probe-сессия рядом не стояла: сложность здесь не ограничивает ничего.
List<List<int>> fastNonDominatedSort(List<List<double>> objectives) {
  final n = objectives.length;
  if (n == 0) return const [];
  final dominates = List.generate(n, (_) => <int>[]);
  final count = List<int>.filled(n, 0);
  final fronts = <List<int>>[[]];
  for (var p = 0; p < n; p++) {
    for (var q = 0; q < n; q++) {
      if (p == q) continue;
      if (_dominates(objectives[p], objectives[q])) {
        dominates[p].add(q);
      } else if (_dominates(objectives[q], objectives[p])) {
        count[p]++;
      }
    }
    if (count[p] == 0) fronts.first.add(p);
  }
  var i = 0;
  while (fronts[i].isNotEmpty) {
    final next = <int>[];
    for (final p in fronts[i]) {
      for (final q in dominates[p]) {
        count[q]--;
        if (count[q] == 0) next.add(q);
      }
    }
    fronts.add(next);
    i++;
  }
  fronts.removeWhere((f) => f.isEmpty);
  return fronts;
}

/// Строго ли [a] доминирует [b]: не хуже по всем целям и лучше хотя бы по одной.
bool _dominates(List<double> a, List<double> b) {
  var better = false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return false;
    if (a[i] > b[i]) better = true;
  }
  return better;
}

/// Дистанция скученности (crowding distance) внутри фронта: суммарная
/// нормированная разница между соседями по каждой цели. Фронтовые границы
/// получают `infinity` — они всегда впереди, и именно это не даёт фронту
/// схлопнуться в одну точку (разнообразие = способность дальше мутироваться).
List<double> crowdingDistance(
  List<int> front,
  List<List<double>> objectives,
) {
  final n = front.length;
  if (n <= 2) return List<double>.filled(n, double.infinity);
  final dist = List<double>.filled(n, 0);
  final m = objectives[front.first].length;
  // `dist` индексуют по позиции во фронте, а цели берутся через `front[i]`:
  // иначе `infinity` достался бы не тем особям.
  for (var k = 0; k < m; k++) {
    final order = List<int>.generate(n, (i) => i)
      ..sort((x, y) =>
          objectives[front[x]][k].compareTo(objectives[front[y]][k]));
    dist[order.first] = double.infinity;
    dist[order.last] = double.infinity;
    final lo = objectives[front[order.first]][k];
    final hi = objectives[front[order.last]][k];
    final span = hi - lo;
    if (span == 0) continue;
    for (var i = 1; i < n - 1; i++) {
      final a = objectives[front[order[i - 1]]][k];
      final b = objectives[front[order[i + 1]]][k];
      dist[order[i]] += (b - a) / span;
    }
  }
  return dist;
}

/// Порядок отбора: сначала по фронту, внутри фронта — по скученности.
/// Возвращает индексы [fitness] в отборочном порядке.
List<int> nsga2Order(
  List<Fitness> fitness, {
  String targetCountry = '',
  int maxFronts = 8,
}) {
  final objs = [for (final f in fitness) f.objectives(targetCountry: targetCountry)];
  final fronts = fastNonDominatedSort(objs);
  final out = <int>[];
  for (var i = 0; i < fronts.length && i < maxFronts; i++) {
    final front = fronts[i];
    final d = crowdingDistance(front, objs);
    final pairs = <MapEntry<int, double>>[
      for (var k = 0; k < front.length; k++) MapEntry(front[k], d[k]),
    ]..sort((a, b) => b.value.compareTo(a.value));
    out.addAll(pairs.map((e) => e.key));
  }
  return out;
}

/// Подпись ошибки для группировки: цифры сворачиваются в `#`, пробелы схлопнуты,
/// длина ограничена 90 символами.
final RegExp _digits = RegExp(r'\d+');

String errorSignature(String error) {
  final s = error.replaceAll(_digits, '#').replaceAll(RegExp(r'\s+'), ' ').trim();
  if (s.isEmpty) return '';
  return s.length <= 90 ? s : '${s.substring(0, 90)}…';
}
