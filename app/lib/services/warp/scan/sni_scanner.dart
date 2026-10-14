// §847 — модель шага 4 сканера: прогон SNI-кандидатов через живые эндпоинты.
//
// Движок — в `EndpointScanner` (метод `_probeSni`): проверить SNI можно только
// внутри поднятого туннеля (probe-сессия ядра строит узел с конкретным SNI и
// гоняет GET), поэтому здесь живут модель, константы и ЧИСТАЯ агрегация — она
// покрыта юнит-тестом без сети и ядра.
//
// Зачем этот шаг нужен именно в РФ. Оператор фильтрует MASQUE/QUIC по SNI
// внешнего handshake: домены вне «белого списка» CDN-реестра на 443 режутся, и
// адрес формально живой даёт «geo-fail» ровно на тех SNI, что не в списке.
// `assets/warp_endpoints.json` несёт готовые списки (`loc.ru.masque.sni_pool`,
// `loc.ru.wireguard.sni_pool`), но список ≠ пропуск: проходит тот, что реально
// отвечает СЕГОДНЯ с СЕГОДНЯШНЕго эндпоинта. Поэтому кандидаты прогоняются через
// подтверждённые эндпоинты, а в генератор попадают только те, что прошли.

/// Вердикты шага 4 (совпадают с `ScanEndpointStatus.verdict`, как и DNS-фаза).
const String kSniVerdictOk = 'sni-ok';
const String kSniVerdictBlocked = 'sni-blocked';

/// Сколько эндпоинтов участвуют в прогоне SNI.
///
/// Больше — дороже (каждый эндпоинт умножает число узлов probe-сессии), а
/// смысл в проверке ДОМЕНА, не адреса: если SNI режут, он порезан на всех
/// адресах CF одного транспорта. Два подтверждённых эндпоинта — это уже «не на
/// одном везёт».
const int kSniScanEndpoints = 2;

/// Сколько SNI проверяем на одном эндпоинте за прогон.
///
/// Пул `loc.ru` даёт 60+ доменов; 72 узла (2×36) в одной probe-сессии — это и
/// минуты ожидания, и большой конфиг. 16 — покрывает верх списка (он руками
/// отсортирован по предпочтению), остальное пользователь допрогонит повтором.
const int kSniScanPerEndpoint = 16;

/// Сколько GET'ов на одну пару (эндпоинт × SNI). Одного источника гео хватает:
/// здесь решаем «прошёл/не прошёл», а не «какая страна».
const int kSniScanRequestsPerPair = 2;

/// Итог проверки одного SNI-кандидата.
class SniScanResult {
  const SniScanResult({
    required this.sni,
    required this.verdict,
    this.rttMs = 0,
    this.endpoint = '',
    this.tried = 0,
    this.detail = '',
  });

  final String sni;
  final String verdict;

  /// Лучший RTT из прошедших заходов.
  final int rttMs;

  /// Эндпоинт, на котором SNI прошёл (или последний проверенный — для журнала).
  final String endpoint;

  /// Сколько эндпоинтов успели прогнать этот SNI.
  final int tried;

  final String detail;

  /// SNI годен в генератор, если хотя бы один эндпоинт с ним ответил.
  bool get valid => verdict == kSniVerdictOk;
}

/// Один заход: пара (эндпоинт, SNI) и её результат. Агрегируется в
/// [summariseSniAttempts]; выводится сканером в живой список как фаза 4.
typedef SniAttempt = ({
  String sni,
  String endpoint,
  bool responded,
  int rttMs,
  String detail,
});

/// §847 — кандидаты прогона: пул MASQUE + пул WG (у AWG SNI тоже во внешнем
/// handshake), дедупликация в исходном порядке, мусор отброшен, не больше
/// [max].
///
/// Мусор = пусто, без точки, пробел, `:` (IPv6-литерал), IPv4-литерал:
/// MASQUE-хосты по форме похожи на домен, а в SNI они бесполезны — узел с
/// таким «SNI» не проходит TLS-MASQUE и проба была бы ложно-мёртвой.
///
/// Порядок пула важен: `loc.ru.*.sni_pool` отсортирован по предпочтению
/// (родной домен, затем белые списки), поэтому берём префикс, а не перемешиваем.
List<String> sniScanCandidates({
  required List<String> masque,
  required List<String> wg,
  int max = kSniScanPerEndpoint,
}) {
  if (max <= 0) return const [];
  final out = <String>[];
  final seen = <String>{};
  for (final raw in [...masque, ...wg]) {
    final s = raw.trim().toLowerCase();
    if (s.isEmpty || !s.contains('.') || s.contains(' ') || s.contains(':')) {
      continue;
    }
    if (_ipv4Literal.hasMatch(s)) continue;
    if (!seen.add(s)) continue;
    out.add(s);
    if (out.length >= max) break;
  }
  return out;
}

final RegExp _ipv4Literal = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$');

/// §847 — заходы → итог по каждому SNI.
///
/// Критерий — «прошёл хоть где-то»: SNI-фильтрация у операторов точечная (один
/// адрес ещё отвечает, сосед уже режут), поэтому один успех засчитываем, а
/// провал на втором эндпоинте лишь виден в [SniScanResult.tried]/detail.
/// Порядок — как в [attempts] (первое появление SNI), чтобы список UI совпадал с
/// порядком кандидатов.
List<SniScanResult> summariseSniAttempts(List<SniAttempt> attempts) {
  final order = <String>[];
  final agg = <String, SniScanResult>{};
  for (final a in attempts) {
    final prev = agg[a.sni];
    if (prev == null) {
      agg[a.sni] = _one(a);
      order.add(a.sni);
    } else {
      agg[a.sni] = _merge(prev, a);
    }
  }
  return [for (final sni in order) agg[sni]!];
}

SniScanResult _one(SniAttempt a) => SniScanResult(
  sni: a.sni,
  verdict: a.responded ? kSniVerdictOk : kSniVerdictBlocked,
  rttMs: a.responded ? a.rttMs : 0,
  endpoint: a.endpoint,
  tried: 1,
  detail: a.detail,
);

/// [prev] — уже агрегат по SNI, [a] — следующий заход по нему.
SniScanResult _merge(SniScanResult prev, SniAttempt a) {
  final tried = prev.tried + 1;
  if (!a.responded) {
    // Провал после успеха ничего не меняет (кроме счётчика); провал без
    // успеха — деталь свежая.
    return SniScanResult(
      sni: prev.sni,
      verdict: prev.verdict,
      rttMs: prev.rttMs,
      endpoint: prev.endpoint,
      tried: tried,
      detail: prev.valid ? prev.detail : a.detail,
    );
  }
  if (!prev.valid) {
    return SniScanResult(
      sni: prev.sni,
      verdict: kSniVerdictOk,
      rttMs: a.rttMs,
      endpoint: a.endpoint,
      tried: tried,
      detail: a.detail,
    );
  }
  final faster = a.rttMs > 0 && (prev.rttMs == 0 || a.rttMs < prev.rttMs);
  return SniScanResult(
    sni: prev.sni,
    verdict: kSniVerdictOk,
    rttMs: faster ? a.rttMs : prev.rttMs,
    endpoint: faster ? a.endpoint : prev.endpoint,
    tried: tried,
    detail: prev.detail,
  );
}
