// §848 — боевая реализация [GenomeEvaluator]: оценка геномов через headless
// probe-сессию ядра (тот же путь, что фаза 2 сканера эндпоинтов, §284/§834).
//
// Почему именно probe-сессия, а не «поднять VPN и проверить»:
//   • `openTun` не вызывается (probe-конфиг без inbound'ов, §119-инвариант) —
//     не трогаем системный туннель и не просим прав;
//   • тот же эмит и тот же гард реестра, что у боевой сборки ([buildProbeBatches]):
//     мутация, негодная по реестру, не годится и здесь;
//   • ядро отвечает на «дошёл ли запрос через ЭТОТ узел», то есть фитнес меряет
//     проходимость, а не доступность IP извне.
//
// Batch-лимиты (§518/§523/§839: 1 naive, 4 WG/AWG, 4 MASQUE на конфиг) дают
// ровно то, что умеет ядро: популяция раскладывается на N probe-сессий, каждая
// — probeStart → пробы → probeStop. Отсюда цена: 16 MASQUE = 4 сессии на ранг,
// и поэтому successive halving в движке не косметика.
//
// ГЕН DNS требует отдельного внимания: адреса кандидатов — IP-литералы, ядро их
// не резолвит. Резолвится ЦЕЛЬ пробы (speed.cloudflare.com и другие), и именно
// её отравляет провайдер. Значит `dnsTag` меняет не «как подключить узел», а
// «чем разрешается имя за узлом» — и это единственный ген, влияющий на конфиг, а
// не на тело узла, поэтому он реализуется отдельно ([_withDns]).

import 'dart:convert';

import '../../models/dns_ref.dart';
import '../../models/node_spec.dart' show NodeSpec, deepCopyJson;
import '../../models/singbox_entry.dart' show Endpoint;
import '../../models/template_vars.dart' show TemplateVars;
import '../../models/tunnel_status.dart';
import '../../vpn/box_vpn_client.dart';
import '../../vpn/cc_channel.dart';
import '../builder/core_chain_capability.dart' show CoreVersionCache;
import '../parser/mappers/uri_pipeline.dart' show parseLinkViaPipeline;
import '../probe/probe_config.dart';
import '../settings_storage.dart';
import '../warp/scan/endpoint_scanner.dart'
    show geoBodyHint, kGeoUrls, parseGeoBody, probeGeoAttempt;
import '../warp/scan/scan_log.dart';
import '../warp/scan/scan_node_builder.dart';
import '../warp/scan/scan_pool.dart';
import '../warp/warp_account.dart';
import '../warp/warp_client.dart';
import 'engine.dart';
import 'genome.dart';
import 'objectives.dart';

/// Оценка геномов через ядро. Один экземпляр переживает несколько прогонов:
/// аккаунты и версия ядра кэшируются в [prepare], а probe-сессия живёт только
/// внутри одного ранга.
class ProbeGenomeEvaluator implements GenomeEvaluator {
  ProbeGenomeEvaluator({
    required this.log,
    this.pool,
    this.wgKeepalive = 0,
    this.timeout = const Duration(seconds: 8),
    CcChannel? cc,
    BoxVpnClient? vpn,
    WarpClient? warp,
  })  : _cc = cc ?? CcChannel.instance,
        _vpn = vpn ?? BoxVpnClient(),
        _warp = warp;

  final ScanLog log;

  /// Пул сканера: отсюда keepalive WG и (в принципе) штатные значения, которые
  /// геном не задаёт. Сами адреса/SNI приходят из генома.
  final ScanPool? pool;
  final int wgKeepalive;

  /// Таймаут одного probeGetUrl.
  final Duration timeout;

  final CcChannel _cc;
  final BoxVpnClient _vpn;
  final WarpClient? _warp;

  ScanNodeBuilder? _builder;
  String _coreVersion = '';
  Map<String, String> _vars = const {};
  Map<String, Map<String, dynamic>> _dnsBodyByTag = const {};
  bool _prepared = false;
  bool _stopped = false;

  @override
  Future<String?> prepare() async {
    if (_prepared) return null;
    // Probe-сессия и боевой туннель в одном процессе не уживаются (два
    // CommandServer невозможны, §236) — поэтому эволюция идёт только на
    // выключенном VPN, и это надо сказать пользователю прямо.
    try {
      final status = await _vpn.getVpnStatus();
      log.i('evo', 'VPN status: $status');
      if (status != TunnelStatus.disconnected) {
        return 'Turn the VPN off — the probe session cannot start while the tunnel is up';
      }
    } catch (e) {
      log.w('evo', 'VPN status unavailable ($e) — trying anyway');
    }

    final now = DateTime.now().toUtc().toIso8601String();
    final client = _warp ?? WarpClient();
    try {
      var warpAcc = await SettingsStorage.getWarpAccount();
      var masqueAcc = await SettingsStorage.getMasqueAccount();
      log.i(
        'evo',
        'accounts: WARP=${warpAcc != null ? 'ok' : 'none'} '
        'MASQUE=${masqueAcc != null ? 'ok' : 'none'}',
      );
      // Регистрация — штатным клиентом с сохранением в хранилище: эволюция не
      // заводит «свои» аккаунты в обход генератора.
      if (warpAcc == null) {
        try {
          warpAcc = await client.register(
            endpoint: WarpAccount.defaultEndpoint,
            nowIso8601: now,
          );
          await SettingsStorage.setWarpAccount(warpAcc);
          log.i('evo', 'WARP account registered');
        } catch (e) {
          log.e('evo', 'WARP register failed: $e');
        }
      }
      if (masqueAcc == null) {
        try {
          masqueAcc = await client.registerMasque(nowIso8601: now);
          await SettingsStorage.setMasqueAccount(masqueAcc);
          log.i('evo', 'MASQUE account registered');
        } catch (e) {
          log.e('evo', 'MASQUE register failed: $e');
        }
      }
      if (warpAcc == null && masqueAcc == null) {
        return 'No WARP account could be obtained (registration failed)';
      }
      _builder = ScanNodeBuilder(
        warp: warpAcc,
        masque: masqueAcc,
        wgKeepalive: wgKeepalive > 0
            ? wgKeepalive
            : (pool?.wgKeepalive ?? 0),
      );
    } finally {
      if (_warp == null) client.close();
    }

    _coreVersion = await CoreVersionCache.ensure(() => _vpn.getCoreVersion());
    _vars = await loadProbeVars();
    _dnsBodyByTag = await _dnsBodies();
    _prepared = true;
    log.i(
      'evo',
      'ready: core=$_coreVersion dns tags=${_dnsBodyByTag.keys.join(', ')}',
    );
    return null;
  }

  /// Теги DNS из хранилища → тела `dns.servers[]`. Разворачиваются только
  /// `inline`-записи: их пишет скан резолверов (§847) и редактор DNS, а
  /// preset/template требуют всего пост-шага сборки, которого в пробе нет.
  Future<Map<String, Map<String, dynamic>>> _dnsBodies() async {
    try {
      final stored = await SettingsStorage.getDnsServers();
      return {
        for (final s in stored)
          if (s is DnsServerInline && s.enabled)
            s.tag: {
              'tag': s.tag,
              ...deepCopyJson(s.body) as Map<String, dynamic>,
            },
      };
    } catch (e) {
      log.w('evo', 'DNS storage unreadable ($e) — dns gene disabled');
      return const {};
    }
  }

  @override
  Future<List<List<Observation>>> evaluate(
    List<Genome> genomes, {
    required int attempts,
    void Function(int index, Observation observation)? onOne,
    bool Function()? cancelled,
  }) async {
    final out = [for (var i = 0; i < genomes.length; i++) <Observation>[]];
    final builder = _builder;
    if (builder == null || genomes.isEmpty) {
      for (var i = 0; i < genomes.length; i++) {
        final o = const Observation.failed('evaluator is not prepared');
        out[i].add(o);
        onOne?.call(i, o);
      }
      return out;
    }
    bool stopped() => _stopped || (cancelled?.call() ?? false);

    // Особи с разным геном DNS расходятся по разным сессиям: одна probe-сессия
    // имеет ОДИН default_domain_resolver, иначе «ген DNS» ничего не означал бы.
    final byDnsTag = <String, List<int>>{};
    for (var i = 0; i < genomes.length; i++) {
      byDnsTag.putIfAbsent(genomes[i].dnsTag, () => []).add(i);
    }

    for (final group in byDnsTag.entries) {
      if (stopped()) break;
      final indexes = group.value;
      // Позиции СОХРАНЯЮТСЯ: `tagByIndex` ключуется позицией во входящем списке
      // (см. `buildProbeBatches`), а до этого сюда попадал сжатый список узлов —
      // и после первого же несобранного узла вердикты уезжали на чужие геномы.
      final nodes = <NodeSpec?>[
        for (final i in indexes) _buildNode(genomes[i], builder),
      ];
      // Причина «вердикта нет» на каждую особь: её знает гард реестра
      // (`brokenByIndex`), а без него — наш билдер или сорванный probeStart.
      // Молча оставить особь без пробы нельзя: «не проверена» неотличима от
      // «не прошла», а именно это и выглядело как «проходимых 0 при рабочих
      // конфигах».
      final why = <int, String>{};
      for (var k = 0; k < indexes.length; k++) {
        if (nodes[k] != null) continue;
        final i = indexes[k];
        why[i] = 'node build failed';
        log.w('evo', '${genomes[i].shortLabel}: узел не собрался');
      }
      void closeUnprobed() {
        for (final i in indexes) {
          if (out[i].isNotEmpty) continue;
          final o = Observation.failed(why[i] ??
              (stopped()
                  ? 'cancelled before probe'
                  : 'no probe slot in session'));
          out[i].add(o);
          onOne?.call(i, o);
          log.w('evo', '${genomes[i].shortLabel}: пробы не было (${o.error})');
        }
      }

      if (nodes.every((n) => n == null)) {
        closeUnprobed();
        continue;
      }

      final batches = buildProbeBatches(
        nodes,
        coreVersion: _coreVersion,
        vars: _vars,
      );
      for (final cfg in batches) {
        if (stopped()) break;
        // Вердикт гарда реестра (битый emit, неподдерживаемый тип ядром) — его
        // раньше не видно вовсе.
        cfg.brokenByIndex.forEach((k, reason) {
          if (k >= indexes.length) return;
          final i = indexes[k];
          why[i] = 'registry: $reason';
          log.w('evo', '${genomes[i].shortLabel}: $reason');
        });
        final json = cfg.configJson;
        if (json == null) continue;
        final err = await _cc.probeStart(_withDns(json, group.key));
        if (err.isNotEmpty) {
          log.e('evo', 'probeStart failed: $err');
          // Сессия не поднялась — это ТЕХНИЧЕСКИЙ сбой, а не «проходимость 0»:
          // различать их важно, иначе эволюция похоронит живых кандидатов.
          // Следующий батч всё равно пробуем, поэтому вердикт ставится только
          // тем, кто к концу группы так и не будет проверен.
          for (final i in indexes) {
            why.putIfAbsent(i, () => 'probe session: $err');
          }
          continue;
        }
        log.i('evo', 'probe session up: ${cfg.tagByIndex.length} tags');
        try {
          for (final slot in cfg.tagByIndex.entries) {
            if (stopped()) break;
            if (slot.key >= indexes.length) continue;
            final i = indexes[slot.key];
            final g = genomes[i];
            for (var a = 0; a < attempts; a++) {
              if (stopped()) break;
              final o = await _probeSeries(g, slot.value);
              out[i].add(o);
              onOne?.call(i, o);
            }
          }
        } finally {
          await _cc.probeStop();
        }
      }
      closeUnprobed();
    }
    return out;
  }

  /// Одна проба = СЕРИЯ GET'ов по источникам гео (см. [probeGeoSeries]).
  /// Страна берётся из `colo`, RTT — `elapsedMs` ядра.
  Future<Observation> _probeSeries(Genome g, String tag) => probeGeoSeries(
        g,
        (url) => _cc.probeGetUrl(
          tag,
          link: url,
          timeoutMs: timeout.inMilliseconds,
          maxBytes: 4096,
        ),
        log: (message) => log.w('evo', message),
      );

  /// Готовый член папки для победителя: JSON-тело узла (`{"endpoints":[…]}` /
  /// `{"outbounds":[…]}`), ТОЧНО такое же, как оценивалось.
  ///
  /// Именно тело, а не URI: URI собирает [ScanNodeBuilder] по геному, а мутации
  /// гена (`tls.fragment`, смешанный регистр SNI, `mtu`, `keep_alive_period`)
  /// ложатся поверх эмита в `patchedJson` и в URI не попадают. Отдать пользователю
  /// «ссылку на проверенное» — означало бы «потерять половину результата»:
  /// парсер папки принимает дословное sing-box-тело
  /// (`body_decoder`: `outbounds[]+endpoints[]`), поэтому экспорт честнее ссылки.
  String? exportFor(Genome g) {
    final builder = _builder;
    if (builder == null) return null;
    final node = _buildNode(g, builder);
    if (node == null) return null;
    try {
      final entry = node.getEntries(null).main;
      final body = Map<String, dynamic>.from(entry.map)
        ..['tag'] = '🧬 ${g.shortLabel}';
      return jsonEncode(entry is Endpoint
          ? {'endpoints': [body]}
          : {'outbounds': [body]});
    } catch (e) {
      log.e('evo', 'export ${g.shortLabel}: $e');
      return null;
    }
  }

  /// Узел генома: штатный билдер (креды WARP/MASQUE → URI) → парсер → узел, и
  /// поверх — мутация генома в `patchedJson`. Это ТО ЖЕ эмитированное тело, что
  /// уходит в боевой конфиг, и дальше его проверяет гард реестра.
  NodeSpec? _buildNode(Genome g, ScanNodeBuilder builder) {
    try {
      final uri = builder.uriFor(g.toCandidate());
      if (uri == null) return null;
      final node = parseLinkViaPipeline(uri);
      if (node == null) return null;
      node.patchedJson = g.applyTo(node.emit(TemplateVars.empty).map);
      return node;
    } catch (e) {
      log.e('evo', 'build ${g.shortLabel}: $e');
      return null;
    }
  }

  /// Резолвер гена DNS в `dns.servers[]` + `route.default_domain_resolver`.
  /// Пустой или неизвестный тег — конфиг как есть (штатный `local`): «гена DNS
  /// нет» — это не ошибка прогона.
  String _withDns(String configJson, String dnsTag) {
    final body = dnsTag.isEmpty ? null : _dnsBodyByTag[dnsTag];
    if (body == null) return configJson;
    try {
      final cfg = jsonDecode(configJson) as Map<String, dynamic>;
      final dns = (cfg['dns'] as Map<String, dynamic>?) ?? <String, dynamic>{};
      final servers = <Map<String, dynamic>>[
        ...((dns['servers'] as List?)?.cast<Map<String, dynamic>>() ??
            const <Map<String, dynamic>>[]),
      ];
      if (servers.every((s) => s['tag'] != dnsTag)) servers.add(body);
      dns['servers'] = servers;
      cfg['dns'] = dns;
      final route =
          (cfg['route'] as Map<String, dynamic>?) ?? <String, dynamic>{};
      route['default_domain_resolver'] = dnsTag;
      cfg['route'] = route;
      return jsonEncode(cfg);
    } catch (e) {
      log.w('evo', 'dns gene $dnsTag not injected ($e)');
      return configJson;
    }
  }

  @override
  Future<void> dispose() async {
    _stopped = true;
    _builder = null;
    _prepared = false;
    try {
      await _cc.probeStop();
    } catch (_) {
      // Идемпотентно: сессии могло и не быть (probeStart не вызывался).
    }
  }

  /// Немедленная остановка (UI при закрытии экрана; движок использует `cancel`).
  void stop() => _stopped = true;
}

/// §848 — вердикт ОДНОЙ пробы по одному узлу: серия GET'ов по источникам гео.
///
/// Почему серия, а не один запрос: до этого проба звала только
/// `kGeoUrls.first` (`speed.cloudflare.com/meta`), и на сети, где это имя не
/// резолвится (отравленный/зарезанный DNS провайдера — ровно та сеть, ради
/// которой всё и делается), падало ВСЁ: 66 заведомо рабочих конфигов давали
/// «проходимых 0 %». Сканер эндпоинтов (§844) от этого защищён чередованием
/// источников, включая IP-литерал `1.1.1.1/cdn-cgi/trace`, которому DNS не
/// нужен; эволюция обязана мерить проходимость тем же эталоном, иначе её
/// вердикт — артефакт канала, а не свойства конфига.
///
/// Критерий «прошёл» — не «любой 2xx», а 2xx с гео-ответом (`colo` или страна),
/// ровно как у сканера (§844 отверг мягкий критерий §843): перехватчик отвечает
/// своим HTML с HTTP 200, и мягкий критерий дал бы «100 % проходимых» на
/// убитой сети — эволюция тогда отбирала бы конфиги по тому, какой из них
/// красивее подменяется. Отсутствие `colo` при живом ответе страну не убивает,
/// но тело обязано быть ответом Cloudflare.
///
/// [get] внедряется, чтобы ветки (успех со второго источника, все источники
/// мертвы, исключение по пути) проверялись без устройства и ядра.
Future<Observation> probeGeoSeries(
  Genome g,
  Future<CcGetUrlResult> Function(String url) get, {
  List<String> urls = kGeoUrls,
  void Function(String message)? log,
}) async {
  var requests = 0;
  CcGetUrlResult? last;
  var usedUrl = urls.isEmpty ? '' : urls.first;
  var why = 'нет ответа';
  for (final url in urls) {
    usedUrl = url;
    final started = DateTime.now();
    CcGetUrlResult r;
    try {
      r = await get(url);
    } catch (e) {
      r = CcGetUrlResult(
        status: 0,
        content: '',
        truncated: false,
        contentType: '',
        remoteAddr: '',
        elapsedMs: DateTime.now().difference(started).inMilliseconds,
        error: 'probeGetUrl: $e',
      );
    }
    requests++;
    last = r;
    final parsed = probeGeoAttempt(r);
    if (!parsed.ok) {
      why = r.error.isNotEmpty
          ? 'err=${r.error}'
          : 'HTTP ${r.status} (не 2xx) — ${geoBodyHint(r.content)}';
      continue;
    }
    final geo = parseGeoBody(parsed.content);
    // 2xx без гео-ответа — тело чужое (перехват/редирект): идём по следующим
    // источникам, «прошёл» по такому ответу не выставляется.
    if (geo.country.isEmpty && geo.colo.isEmpty) {
      why = 'HTTP ${r.status} без geo-ответа — ${geoBodyHint(parsed.content)}';
      continue;
    }
    return Observation(
      responded: true,
      status: r.status,
      rttMs: r.elapsedMs > 0
          ? r.elapsedMs
          : DateTime.now().difference(started).inMilliseconds,
      country: geo.country,
      colo: geo.colo,
      url: url,
      requests: requests,
    );
  }
  log?.call('${g.shortLabel}: проба не прошла — $why '
      '($requests з-сов по ${urls.length} источникам)');
  return Observation.failed(
    why,
    rttMs: last?.elapsedMs ?? 0,
    url: usedUrl,
    requests: requests,
  );
}
