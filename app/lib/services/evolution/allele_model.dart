// §848 — модель аллелей: распределительная оценка (EDA, UMDA) по элите.
//
// Почему EDA, а не классический ГА с кроссовером/мутацией: пространство поиска
// — комбинации дискретных настроек, и важны не отдельные «хорошие биты», а
// СВЯЗИ между параметрами (этот SNI живёт только с этим портом, фрагментация —
// только с h2). UMDA оценивает частоту каждого аллеля по элите и семплирует
// новые особи из этой частоты, то есть переносит ВСЮ элиту в следующее
// поколение как распределение, а не как попарные скрещивания двух родителей.
// На комбинаторных задачах прохода DPI это сходится быстрее обычного ГА
// (Larranaga & Lozano, "A Review on Estimation of Distribution Algorithms").
//
// Ограничение честности: UMDA — модель НЕЗАВИСИМЫХ маргинальных частот (связи
// между локусами не учитываются, в отличие от BOA/EGNA). Это осознанный компромисс:
// структура связей стоит памяти и вычислений, а ограничитель здесь — число
// probe-сессий (одна оценка = запрос через ядро), не CPU.
//
// Второе следствие: модель никогда не «забывает» пул. Сглаживание (Laplace)
// даёт ненулевую вероятность каждому аллелю домена, поэтому популяция не
// схлопывается в одну точку за 3 поколения — схлопнувшаяся эволюция продолжает
// жевать бюджет, ничего не узнавая.

import 'dart:math';

import 'genome.dart';
import 'pools.dart';

/// Частотная модель по локусам, построенная на элите.
class AlleleModel {
  AlleleModel(this._probs);

  /// locus → (значение → вероятность). Локусы с пустым доменом отсутствуют.
  final Map<EvoLocus, Map<String, double>> _probs;

  int get locusCount => _probs.length;

  Map<String, double>? allelesOf(EvoLocus locus) => _probs[locus];

  /// Вероятность аллеля (0, если локуса нет в модели).
  double probability(EvoLocus locus, String value) =>
      _probs[locus]?[value] ?? 0;

  /// Оценивает модель по элите.
  ///
  /// [weighting] — вес особи (обычно ранг Парето: чем лучше, тем сильнее влияет
  /// на частоты). Без весов UMDA вырождается в «равный вклад всех элитных».
  ///
  /// [prior] — сила сглаживания относительно равномерного распределения по
  /// домену. При `prior=0` модель копирует элиту буквально и теряет всё, чего
  /// элита не пробовала, — то есть дальнейший поиск идёт в уже виденном.
  static AlleleModel fit(
    List<Genome> elites,
    AlleleSource pools, {
    List<double>? weighting,
    double prior = 0.15,
    Iterable<String> countries = const [],
  }) {
    final probs = <EvoLocus, Map<String, double>>{};
    if (elites.isEmpty) return AlleleModel(probs);
    final w = weighting != null && weighting.length == elites.length
        ? weighting
        : List<double>.filled(elites.length, 1);
    for (final locus in EvoLocus.values) {
      final domain = pools.alleles(locus, countries: countries).values;
      if (domain.isEmpty) continue;
      final counts = <String, double>{for (final v in domain) v: 0};
      for (var i = 0; i < elites.length; i++) {
        final v = elites[i].tokens()[locus] ?? '';
        // Значение вне домена (напр. seeded-адрес из чужой страны) не
        // выбрасываем: модель не должна «исправлять» посев пользователя
        // против его же выбора.
        counts[v] = (counts[v] ?? 0) + w[i];
      }
      // Laplace-сглаживание по размеру домена: аллель, которого в элите нет,
      // сохраняет ненулевую вероятность — это право на разведку, без него
      // модель за 2–3 поколения выродится в копии одного и того же кандидата.
      final mass = counts.values.fold<double>(0, (a, b) => a + b);
      final norm = mass + prior * counts.length;
      probs[locus] = {
        for (final e in counts.entries)
          e.key: (e.value + prior) / (norm <= 0 ? 1 : norm),
      };
    }
    return AlleleModel(probs);
  }

  /// Семпл из модели (индицирование по кумулятивной вероятности).
  Genome sample(Random rng, AlleleSource pools,
      {Iterable<String> countries = const []}) {
    final t = <EvoLocus, String>{};
    for (final locus in EvoLocus.values) {
      final p = _probs[locus];
      if (p == null || p.isEmpty) {
        final v = pools.alleles(locus, countries: countries).pick(rng);
        if (v.isNotEmpty) t[locus] = v;
        continue;
      }
      t[locus] = _pick(p, rng);
    }
    final g = Genome.fromTokens(t);
    // Порт обязан соответствовать транспорту: модель оценивает локусы
    // независимо и легко выдаёт `h3` на WG-порту 2408 — ядро такой узел
    // поднимет, но прова не будет вовсе.
    final ports = pools.portsFor(g.transport);
    if (ports.isEmpty) return g;
    if (!ports.contains(g.port)) {
      return g.copyWith(port: ports[rng.nextInt(ports.length)]);
    }
    return g;
  }

  static String _pick(Map<String, double> p, Random rng) {
    final total = p.values.fold<double>(0, (a, b) => a + b);
    if (total <= 0) return p.keys.first;
    var x = rng.nextDouble() * total;
    for (final e in p.entries) {
      x -= e.value;
      if (x <= 0) return e.key;
    }
    return p.keys.last;
  }
}

/// Помеха в модель: точечная мутация по [mutationRate] на каждый локус и
/// равномерная кроссовер-помеха. Без неё EDA сходится к константе.
Genome mutate(
  Genome g,
  AlleleSource pools,
  Random rng, {
  required double mutationRate,
  Iterable<String> countries = const [],
}) {
  var out = g;
  for (final locus in EvoLocus.values) {
    if (rng.nextDouble() >= mutationRate) continue;
    final alleles = pools.alleles(locus, countries: countries);
    if (alleles.isEmpty) continue;
    final value = alleles.pick(rng);
    if (value.isEmpty) continue;
    final t = out.tokens()..[locus] = value;
    out = Genome.fromTokens(t);
  }
  return out;
}

/// Равномерный кроссовер (0.5 на локус) — альтернатива EDA-семплу, когда
/// пользователь просит «классический ГА». Возвращает ребёнка.
Genome uniformCrossover(
  Genome a,
  Genome b,
  Random rng, {
  double alpha = 0.5,
}) {
  final ta = a.tokens();
  final tb = b.tokens();
  final t = <EvoLocus, String>{};
  for (final locus in EvoLocus.values) {
    final use = rng.nextDouble() < alpha ? ta[locus] : tb[locus];
    if (use != null) t[locus] = use;
  }
  final child = Genome.fromTokens(t);
  final ports = [a, b].map((p) => p.port).toSet();
  return ports.contains(child.port)
      ? child
      : child.copyWith(
          port: rng.nextBool() ? a.port : b.port,
        );
}

/// Разнообразие популяции (средняя доля различающихся локусов по всем парам) —
/// метрика для UI: «популяция разошлась» / «сошлась в одну точку, нужен
/// всплеск иммигрантов».
double diversity(List<Genome> pop) {
  if (pop.length < 2) return 0;
  var sum = 0.0;
  var pairs = 0;
  for (var i = 0; i < pop.length; i++) {
    for (var j = i + 1; j < pop.length; j++) {
      sum += pop[i].distanceTo(pop[j]);
      pairs++;
    }
  }
  // `distanceTo` — уже доля (0..1), поэтому среднее по парам и есть
  // разнообразие популяции.
  return min(1.0, sum / max(pairs, 1));
}

/// Всплеск разнообразия: сколько иммигрантов добавить, если популяция схлопнулась.
int immigrantCount(int population, double currentDiversity, double base) {
  if (currentDiversity > 0.15) return (population * base).round();
  return (population * min(0.5, base * 4)).round();
}
