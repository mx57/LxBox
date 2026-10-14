// §848 — посев популяции из ТОГО, что уже есть на экране серверов.
//
// Пользователь просил: «открываешь три точки, эволюция берёт все конфиги оттуда
// и эволюционирует лучшие». Здесь это и реализовано: узел разбирается до
// эмитированного тела (тот же `emit`, что уходит в боевой конфиг), и из тела
// считываются значения локусов генома.
//
// Что НЕ попадает в посев, и почему это надо показать, а не промолчать:
// эволюция мутирует тела WARP-узлов (AWG/MASQUE) — только они собираются через
// [ScanNodeBuilder] с аккаунтами WARP. Подписные протоколы (vless/trojan/…)
// эволюции недоступны: у движка нет их билдера, и «смутить» их было бы
// подменой смысла. Поэтому пропущенные считаются и выводятся на экран.

import '../../models/node_spec.dart' show NodeSpec;
import '../../models/template_vars.dart' show TemplateVars;
import 'genome.dart';

/// Причина, по которой узел не стал геномом. Коды, а не строки: перевод — дело
/// экрана (UI-тексты живут в l10n, сервис их не генерит).
enum SeedSkipReason {
  /// Не WARP-транспорт (подписка, raw-протокол, socks и т.п.).
  notWarp,

  /// Узел-группа (§322): адреса нет, мутировать нечего.
  group,

  /// Тело есть, но адреса/порта в нём нет (битый или особая форма).
  noAddress,

  /// `emit` бросил — узел не разбирается.
  broken,
}

/// Результат посева.
class SeedSet {
  SeedSet({
    required this.genomes,
    required this.skipped,
    required this.total,
  });

  final List<Genome> genomes;

  /// причина → сколько узлов.
  final Map<SeedSkipReason, int> skipped;

  /// Сколько узлов вообще посмотрели (включая ставшие геномами).
  final int total;

  int get skippedCount => skipped.values.fold(0, (a, b) => a + b);

  bool get isEmpty => genomes.isEmpty;

  static SeedSet get empty => SeedSet(genomes: const [], skipped: const {}, total: 0);
}

/// Собирает посев из списка узлов (экран передаёт `entry.list.nodes` по всем
/// источникам). Дубликаты снимаются по [Genome.key] — два одинаковых узла дали
/// бы два одинаковых генома и удвоили бы цену пробы.
SeedSet seedsFromNodes(Iterable<NodeSpec> nodes) {
  final genomes = <Genome>[];
  final seen = <String>{};
  final skipped = <SeedSkipReason, int>{};
  var total = 0;
  for (final n in nodes) {
    total++;
    if (n.isGroup) {
      skipped[SeedSkipReason.group] = (skipped[SeedSkipReason.group] ?? 0) + 1;
      continue;
    }
    final g = genomeOfNode(n);
    if (g == null) {
      final why = n.protocol == 'masque' || n.protocol == 'wireguard'
          ? SeedSkipReason.noAddress
          : SeedSkipReason.notWarp;
      skipped[why] = (skipped[why] ?? 0) + 1;
      continue;
    }
    if (seen.add(g.key)) genomes.add(g);
  }
  return SeedSet(genomes: genomes, skipped: skipped, total: total);
}

/// Геном одного узла по его ЭМИТИРОВАННОМУ телу. null — узел не эволюционируем.
///
/// Тело берётся из `emit`, а не из типизированной модели узла: у AWG-обфускации
/// и MASQUE-параметров разные носители (корень endpoint'а / `tls{}` outbound'а),
/// и читать их по одному пути дешевле, чем знать про оба.
Genome? genomeOfNode(NodeSpec node) {
  try {
    final body = node.emit(TemplateVars.empty).map;
    return switch (body['type']) {
      'masque' => _fromMasque(body),
      'wireguard' => _fromWireguard(body),
      _ => null,
    };
  } catch (_) {
    return null;
  }
}

Genome? _fromMasque(Map<String, dynamic> body) {
  final server = '${body['server'] ?? ''}';
  final port = (body['server_port'] as num?)?.toInt() ?? 0;
  if (server.isEmpty || port <= 0) return null;
  final tls = body['tls'];
  final sni = tls is Map ? '${tls['server_name'] ?? ''}' : '';
  final vhttp = '${body['vhttp'] ?? 'h3'}';
  return Genome(
    transport: vhttp == 'h2' ? EvoTransport.masqueH2 : EvoTransport.masqueH3,
    endpoint: server,
    port: port,
    sni: sni,
    // `keep_alive_period` эмитится строкой с суффиксом ('25s').
    keepalive: _seconds(body['keep_alive_period']),
    mtu: (body['mtu'] as num?)?.toInt() ?? 0,
    fragment: _boolAt(body, 'fragment') || _boolInTls(body, 'fragment'),
    recordFragment: _boolInTls(body, 'record_fragment'),
  );
}

Genome? _fromWireguard(Map<String, dynamic> body) {
  final peers = (body['peers'] as List?)?.cast<Map<String, dynamic>>() ??
      const <Map<String, dynamic>>[];
  if (peers.isEmpty) return null;
  final address = '${peers.first['address'] ?? ''}';
  final port = (peers.first['port'] as num?)?.toInt() ?? 0;
  if (address.isEmpty || port <= 0) return null;
  // AWG-поля живут в корне endpoint'а (Awg.writeInto). Голый WG их не имеет —
  // но это НЕ повод ставить нули: [ScanNodeBuilder] всегда оборачивает WG в
  // AmneziaWG (`buildAmneziaAwg`, masquerade-defaults `quic/chrome/4/40/70`),
  // и геном обязан описывать ТО, что будет оценено, а не исходное тело.
  // Значения ниже — те же дефолты, что дадут этот же билдер.
  final isAwg = body.containsKey('jc') || body.containsKey('ip');
  return Genome(
    transport: EvoTransport.awg,
    endpoint: address,
    port: port,
    sni: isAwg ? '${body['id'] ?? ''}' : '',
    junkDomain: isAwg ? '${body['id'] ?? ''}' : '',
    junkProto: isAwg ? '${body['ip'] ?? 'quic'}' : 'quic',
    junkBrowser: isAwg ? '${body['ib'] ?? 'chrome'}' : 'chrome',
    jc: (body['jc'] as num?)?.toInt() ?? 4,
    jitterMin: (body['jmin'] as num?)?.toInt() ?? 40,
    jitterMax: (body['jmax'] as num?)?.toInt() ?? 70,
    keepalive:
        (peers.first['persistent_keepalive_interval'] as num?)?.toInt() ?? 0,
    mtu: (body['mtu'] as num?)?.toInt() ?? 0,
  );
}

int _seconds(Object? v) {
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v.replaceAll(RegExp(r'[^0-9]'), '')) ?? 0;
  return 0;
}

/// `fragment` легально и в корне (deprecated-синоним), и в `tls{}` — читаем оба,
/// чтобы посев не потерял включённую фрагментацию подписного узла.
bool _boolAt(Map<String, dynamic> body, String key) => body[key] == true;

bool _boolInTls(Map<String, dynamic> body, String key) {
  final tls = body['tls'];
  return tls is Map && tls[key] == true;
}
