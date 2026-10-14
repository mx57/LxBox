// §834 — экран «Сканер эндпоинтов»: двухфазный скан WARP-эндпоинтов.
//
// §835 — что добавлено к прежней версии:
//   • ЖИВОЙ список: и живые, и мёртвые адреса показываются по мере проверки
//     (не только итог по странам). Видно, что скан реально идёт: адрес,
//     вердикт (`alive`/`cookie`/`timeout`/`junk`), RTT, страна/узел, деталь
//     ответа сервера.
//   • ОКНО ЛОГОВ: журнал скана (фазы, probe-сессия ядра, ответы серверов,
//     ошибки) с кнопками «Копировать» и «Поделиться» — отдать для диагноза.
//   • Счётчики: проверено / живых / групп.
//   • Список стран с чекбоксами (+ найдено/валидных), как раньше.
//
// §847 — экран стал четырёхшаговым конвейером выбора, как задумано:
//   скан эндпоинтов → выбор СТРАН выходных точек → выбор отсканированных
//   DNS-резолверов → выбор отсканированных SNI (белые списки РФ-провайдеров).
//   Шаги 3 и 4 — такие же чекбоксы, как страны; результат отдаётся одним
//   [EndpointScanSelection], и генератор получает пул + DNS + SNI за один раз.

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart'
    show rootBundle, Clipboard, ClipboardData;
import 'package:share_plus/share_plus.dart';

import '../services/l10n/locale_controller.dart';
import '../services/usage_region.dart';
import '../services/warp/scan/dns_scanner.dart' show DnsServerResult;
import '../services/warp/scan/endpoint_scanner.dart';
import '../services/warp/scan/scan_log.dart';
import '../services/warp/scan/scan_models.dart';
import '../services/warp/scan/scan_pool.dart';
import '../services/warp/scan/sni_scanner.dart';
import '../services/ui_helpers.dart';
import '../widgets/app_bottom_sheet.dart';
import '../widgets/safe_bottom.dart';

/// §847 — выбор пользователя со всех шагов сканера.
///
/// [pool] — эндпоинты выбранных стран (уже с SNI-пулом из [sni], если выбран),
/// [dns] — отобранные резолверы фазы 3: контроллер пишет их в хранилище DNS,
/// откуда их забирает пост-шаг сборки. Пустой [dns]/[sni] = «ничего не меняем».
class EndpointScanSelection {
  const EndpointScanSelection({
    required this.pool,
    this.dns = const [],
    this.sni = const [],
  });

  final ScanPool pool;
  final List<DnsServerResult> dns;
  final List<String> sni;
}

/// Возвращает выбор через [Navigator.pop] ([EndpointScanSelection]) или
/// null (отмена).
class EndpointScanScreen extends StatefulWidget {
  const EndpointScanScreen({
    super.key,
    this.concurrency = 16,
    this.timeout = const Duration(seconds: 3),
    this.perCountryLimit = 0,
    this.excludeColos = const {},
  });

  final int concurrency;
  final Duration timeout;
  final int perCountryLimit;

  /// IATA-коды узлов, исключаемые из результатов. По умолчанию ПУСТО: для
  /// пользователя в РФ ближайший узел почти всегда московский (DME), и
  /// исключение DME прятало бы именно те эндпоинты, что работают («ничего не
  /// найдено»). Параметр оставлен для точечных экспериментов.
  final Set<String> excludeColos;

  @override
  State<EndpointScanScreen> createState() => _EndpointScanScreenState();
}

class _EndpointScanScreenState extends State<EndpointScanScreen>
    with SnackHelper<EndpointScanScreen> {
  final _scanner = EndpointScanner();
  final _log = ScanLog();
  ScanPool? _basePool;
  bool _scanning = false;
  bool _viaTcp = false;
  EndpointScanResult? _result;
  final _selected = <String>{}; // коды стран ('' = «не определена»)
  String? _error;
  String _note = '';
  int _phase1Done = 0;
  int _phase1Total = 0;
  int _phase2Done = 0;
  int _phase2Total = 0;
  int _phase4Done = 0;
  int _phase4Total = 0;
  Timer? _ticker;

  /// §847 — выбор шага 3 (ключ — `DnsServerResult.endpoint`) и шага 4 (SNI).
  /// Отдельные множества по той же причине, что и страны: строки DNS/SNI
  /// приходят из разных фаз и пересечений с адресами не имеют.
  final _selectedDns = <String>{};
  final _selectedSni = <String>{};

  /// §847 — кандидаты фазы 4: SNI-пулы пула с наложенной секцией
  /// `loc.<регион>` (для РФ — белые списки CDN-реестра провайдеров).
  /// Пусто → фаза 4 не запускается.
  List<String> _sniCandidates = const [];

  /// Сколько валидных резолверов отмечать по умолчанию (по RTT). Ничего не
  /// отмечать нельзя осмысленно: пользователь жмёт «применить» и ждёт, что
  /// выбранный DNS поедет в конфиг; два самых быстрых — разумный дефолт,
  /// который легко снять.
  static const _defaultDnsPicked = 2;

  /// §835 — живой список: адрес → вердикт. Обновляется из `onStatus` без
  /// setState (перерисовку даёт тикер 250 мс) — иначе 300 rebuild'ов за скан.
  final _statuses = <String, ScanEndpointStatus>{};

  @override
  void initState() {
    super.initState();
    _startScan();
  }

  @override
  void dispose() {
    _ticker?.cancel();
    _scanner.cancel();
    super.dispose();
  }

  Future<void> _startScan() async {
    setState(() {
      _scanning = true;
      _error = null;
      _result = null;
      _selected.clear();
      _statuses.clear();
      _log.clear();
      _phase1Done = 0;
      _phase1Total = 0;
      _phase2Done = 0;
      _phase2Total = 0;
      _phase4Done = 0;
      _phase4Total = 0;
      _selectedDns.clear();
      _selectedSni.clear();
      _note = '';
    });
    _ticker = Timer.periodic(const Duration(milliseconds: 250), (_) {
      if (mounted) setState(() {});
    });

    try {
      _log.i('ui', 'старт скана: загружаю пул адресов…');
      final endpoints = await _scanner.loadPools();
      if (!mounted) return;
      _log.i('ui', 'пул загружен: ${endpoints.length} адресов');
      // §834 — базовый bundled-пул (SNI/порты) для построения пула из выбранных.
      // §847 — кандидаты SNI берём из того же пула, но с наложенной секцией
      // `loc.<регион>` (§425): в сети РФ это белые списки CDN-реестра
      // провайдеров, вне её — корневой пул (секции нет → остаётся корень).
      _sniCandidates = const [];
      try {
        final raw = await rootBundle.loadString('assets/warp_endpoints.json');
        final region = await UsageRegion.effective();
        _basePool = ScanPool.fromFullJson(
          jsonDecode(raw) as Map<String, dynamic>,
          region: region,
        );
        _sniCandidates = sniScanCandidates(
          masque: _basePool?.masqueSniPool ?? const <String>[],
          wg: _basePool?.wgSniPool ?? const <String>[],
        );
        _log.i(
          'ui',
          'регион пула: ${region.isEmpty ? 'нет' : region}, '
          'SNI-кандидатов: ${_sniCandidates.length}',
        );
      } catch (e) {
        _basePool = null;
        _log.w('ui', 'бутафорский пул не прочитан: $e');
      }
      final result = await _scanner.scan(
        endpoints: endpoints,
        concurrency: widget.concurrency,
        timeout: widget.timeout,
        excludeColos: widget.excludeColos,
        log: _log,
        sniCandidates: _sniCandidates,
        onStatus: (s) => _statuses[s.endpoint] = s,
        onProgressPhase1: (d, t) {
          _phase1Done = d;
          _phase1Total = t;
        },
        onProgressPhase2: (d, t) {
          _phase2Done = d;
          _phase2Total = t;
        },
        onProgressPhase4: (d, t) {
          _phase4Done = d;
          _phase4Total = t;
        },
        onNote: (n) => _note = n,
      );
      if (!mounted) return;
      setState(() {
        _scanning = false;
        _result = result;
        _viaTcp = result.tcpFallbackUsed;
        _note = result.note;
        // Итоговые статусы перекрывают живые (там же гео и вердикт).
        for (final s in result.statuses) {
          _statuses[s.endpoint] = s;
        }
        _preselect(result);
      });
    } catch (e) {
      _log.e('ui', 'скан упал: $e');
      if (!mounted) return;
      setState(() {
        _scanning = false;
        _error = '$e';
      });
    } finally {
      _ticker?.cancel();
      _ticker = null;
      if (mounted) setState(() {});
    }
  }

  void _stopScan() {
    _scanner.cancel();
    _log.w('ui', 'остановлено пользователем');
    setState(() => _scanning = false);
  }

  int get _selectedEndpointCount {
    final r = _result;
    if (r == null) return 0;
    return r.groups
        .where((g) => _selected.contains(g.code))
        .fold(0, (s, g) => s + g.valid);
  }

  /// §847 — отобранные резолверы (в порядке фазы 3, не в порядке тапов).
  List<DnsServerResult> get _selectedDnsList {
    final r = _result;
    if (r == null) return const [];
    return [
      for (final d in _sortedValidDns(r))
        if (_selectedDns.contains(d.endpoint)) d,
    ];
  }

  /// §847 — отобранные SNI в порядке кандидатов.
  List<String> get _selectedSniList {
    final r = _result;
    if (r == null) return const [];
    return [
      for (final s in r.sni)
        if (_selectedSni.contains(s.sni)) s.sni,
    ];
  }

  /// Валидные резолверы по RTT (неизмеренный — в конец).
  List<DnsServerResult> _sortedValidDns(EndpointScanResult r) =>
      r.validDns..sort((a, b) {
        final x = a.rttMs == 0 ? 1 << 30 : a.rttMs;
        final y = b.rttMs == 0 ? 1 << 30 : b.rttMs;
        return x.compareTo(y);
      });

  /// §847 — отметки по умолчанию после скана: два самых быстрых валидных
  /// резолвера и ВСЕ прошедшие SNI. SNI иначе пришлось бы отмечать вручную по
  /// каждому из 16 доменов, а смысл шага именно в «что пропустили сегодня».
  void _preselect(EndpointScanResult r) {
    _selectedDns.addAll(
      _sortedValidDns(r).take(_defaultDnsPicked).map((d) => d.endpoint),
    );
    _selectedSni.addAll(r.validSni.map((s) => s.sni));
  }

  void _useSelected() {
    final r = _result;
    if (r == null) return;
    final eps = <String>[
      for (final g in r.groups)
        if (_selected.contains(g.code))
          for (final e in widget.perCountryLimit <= 0
              ? g.endpoints
              : g.endpoints.take(widget.perCountryLimit)) e.endpoint,
    ];
    final sni = _selectedSniList;
    // §834 — возвращаем пул (а не строки): генератор сразу соберёт конфиги
    // WARP/MASQUE на выбранных эндпоинтах через poolOverride.
    // §847 — [sniOverride] меняет SNI-пулы пула, поэтому Монте-Карло сеет
    // узлы только на проверенных доменах; DNS уходят в хранилище настроек.
    final pool = ScanPool.fromEndpoints(
      eps,
      base: _basePool,
      sniOverride: sni,
    );
    if (pool == null) return;
    Navigator.of(context).pop(
      EndpointScanSelection(pool: pool, dns: _selectedDnsList, sni: sni),
    );
  }

  // ───────────────────────── §835 — лог ─────────────────────────

  void _copyLog() {
    Clipboard.setData(ClipboardData(text: _log.text));
    showSnack(getLocalText.s('Log copied to clipboard'));
  }

  Future<void> _shareLog() async {
    try {
      await SharePlus.instance.share(
        ShareParams(text: _log.text, subject: 'LXBox endpoint scan log'),
      );
    } catch (e) {
      showSnack(getLocalText.s('Share failed: %s', '$e'));
    }
  }

  void _openLog() {
    showAppBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) {
        final cs = Theme.of(ctx).colorScheme;
        return DraggableScrollableSheet(
          expand: false,
          initialChildSize: 0.7,
          maxChildSize: 0.95,
          builder: (ctx2, scroll) => Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 8, 4),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        getLocalText.s('Scan log'),
                        style: Theme.of(ctx).textTheme.titleMedium,
                      ),
                    ),
                    IconButton(
                      tooltip: getLocalText.s('Copy'),
                      onPressed: _copyLog,
                      icon: const Icon(Icons.copy_all_outlined),
                    ),
                    IconButton(
                      tooltip: getLocalText.s('Share'),
                      onPressed: _shareLog,
                      icon: const Icon(Icons.ios_share),
                    ),
                  ],
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: _log.isEmpty
                    ? Center(
                        child: Text(
                          getLocalText.s('Log is empty'),
                          style: TextStyle(color: cs.onSurfaceVariant),
                        ),
                      )
                    : ListView.builder(
                        controller: scroll,
                        padding: const EdgeInsets.all(12)
                            .withSafeBottom(context),
                        itemCount: _log.lines.length,
                        itemBuilder: (_, i) {
                          final l = _log.lines[i];
                          return Padding(
                            padding: const EdgeInsets.only(bottom: 2),
                            child: Text(
                              ScanLog.formatLine(l),
                              style: TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 11,
                                color: _logColor(l.level, cs),
                              ),
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        );
      },
    );
  }

  Color _logColor(ScanLogLevel level, ColorScheme cs) => switch (level) {
        ScanLogLevel.debug => cs.onSurfaceVariant,
        ScanLogLevel.info => cs.onSurface,
        ScanLogLevel.warn => cs.tertiary,
        ScanLogLevel.error => cs.error,
      };

  // ───────────────────────── build ─────────────────────────

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: Text(getLocalText.s("Endpoint scanner")),
        actions: [
          IconButton(
            tooltip: getLocalText.s('Scan log'),
            onPressed: _openLog,
            icon: Badge(
              isLabelVisible: _log.length > 0,
              label: Text('${_log.length}'),
              child: const Icon(Icons.article_outlined),
            ),
          ),
          if (_scanning)
            TextButton(
              onPressed: _stopScan,
              child: Text(getLocalText.s("Stop")),
            )
          else
            TextButton(
              onPressed: _startScan,
              child: Text(getLocalText.s("Rescan")),
            ),
        ],
      ),
      body: Column(
        children: [
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Text(_error!, style: TextStyle(color: cs.error)),
            ),
          if (!_scanning && _note.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: Text(
                _note,
                style: TextStyle(color: cs.tertiary, fontSize: 12),
              ),
            ),
          _buildProgress(cs),
          Expanded(child: _buildBody(cs)),
          SafeArea(
            minimum: const EdgeInsets.all(16),
            child: Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: Text(getLocalText.s("Cancel")),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: _scanning || _selectedEndpointCount == 0
                        ? null
                        : _useSelected,
                    child: Text(
                      getLocalText.s(
                        "Apply selection: %1\$s endpoints · %2\$s DNS · %3\$s SNI",
                        '$_selectedEndpointCount',
                        '${_selectedDns.length}',
                        '${_selectedSni.length}',
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildProgress(ColorScheme cs) {
    final endpoints = _statuses.values.where((s) => s.phase < 3);
    final alive = endpoints.where((s) => s.alive).length;
    final dnsPhase = _statuses.values.any((s) => s.phase == 3);
    final sniPhase = _statuses.values.any((s) => s.phase == 4);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_scanning) ...[
            if (_phase1Total > 0)
              LinearProgressIndicator(value: _phase1Done / _phase1Total),
            const SizedBox(height: 4),
            Text(
              sniPhase
                  ? getLocalText.s(
                      "Phase 4: checking %1\$s SNI domains through live endpoints…",
                      '$_phase4Done/$_phase4Total',
                    )
                  : dnsPhase
                      ? getLocalText.s(
                          "Phase 3: checking known DNS resolvers…",
                        )
                      : _phase2Total > 0
                          ? getLocalText.s(
                              "Phase 2: determining country of %1\$s endpoints…",
                              '$_phase2Done/$_phase2Total',
                            )
                          : getLocalText.s(
                              "Phase 1: probing %1\$s endpoints…",
                              '$_phase1Done/$_phase1Total',
                            ),
              style: Theme.of(context).textTheme.bodySmall,
            ),
            if (_viaTcp)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  getLocalText.s(
                    "UDP blocked — using TCP fallback (443/8443)",
                  ),
                  style: TextStyle(color: cs.tertiary, fontSize: 12),
                ),
              ),
          ],
          const SizedBox(height: 4),
          Text(
            getLocalText.s(
              "Probed %1\$s · alive %2\$s",
              '${endpoints.length}',
              '$alive',
            ),
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: alive > 0 ? cs.primary : cs.onSurfaceVariant,
                  fontWeight: FontWeight.w600,
                ),
          ),
        ],
      ),
    );
  }

  Widget _buildBody(ColorScheme cs) {
    final r = _result;
    // Живой список адресов (по мере проверки) — основное, что хочет видеть
    // пользователь: что скан РАБОТАЕТ и что отвечает. Фаза 3 (DNS) показана
    // отдельным блоком ниже, поэтому здесь только P1/P2.
    final statuses = _statuses.values.where((s) => s.phase < 3).toList()
      ..sort((a, b) {
        // Живые выше мёртвых; внутри — по RTT.
        if (a.alive != b.alive) return a.alive ? -1 : 1;
        return (a.rttMs == 0 ? 1 << 30 : a.rttMs)
            .compareTo(b.rttMs == 0 ? 1 << 30 : b.rttMs);
      });

    final hasGroups = r != null && r.groups.isNotEmpty;
    final dns = r == null ? const <DnsServerResult>[] : _sortedValidDns(r);
    final sni = r?.sni ?? const <SniScanResult>[];

    return ListView(
      padding: const EdgeInsets.all(8).withSafeBottom(context),
      children: [
        if (hasGroups) ...[
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 8, 8, 4),
            child: Text(
              getLocalText.s('By country'),
              style: Theme.of(context).textTheme.titleSmall,
            ),
          ),
          for (final g in r.groups) _countryTile(g, cs),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 8, 8, 4),
            child: Text(
              getLocalText.s('All probed endpoints'),
              style: Theme.of(context).textTheme.titleSmall,
            ),
          ),
        ],
        if (!hasGroups && r != null && statuses.isEmpty)
          Padding(
            padding: const EdgeInsets.all(24),
            child: Text(
              getLocalText.s(
                "No endpoints found. All UDP is likely blocked on this network — try MASQUE (TCP) or a different network.",
              ),
              style: TextStyle(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
          ),
        if (r == null && statuses.isEmpty)
          const Padding(
            padding: EdgeInsets.all(24),
            child: Center(child: CircularProgressIndicator()),
          ),
        for (final s in statuses) _statusTile(s, cs),
        if (r != null && r.dns.isNotEmpty) ...[
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 8, 8, 4),
            child: Text(
              getLocalText.s('Valid DNS resolvers'),
              style: Theme.of(context).textTheme.titleSmall,
            ),
          ),
          if (dns.isEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 0, 8, 8),
              child: Text(
                getLocalText.s(
                  "No known DNS resolver answered our query correctly — DNS is intercepted or blocked.",
                ),
                style: TextStyle(color: cs.error, fontSize: 12),
              ),
            ),
          if (dns.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 0, 8, 4),
              child: Text(
                getLocalText.s(
                  "Picked resolvers go into DNS settings and the generated configs.",
                ),
                style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
              ),
            ),
          for (final d in dns) _dnsTile(d, cs),
        ],
        // §847 — шаг 4: SNI, прогнанные через живые эндпоинты. Непрошедшие
        // видны, но не выбираются: выбрать зарезанный домен — значит собрать
        // конфиг, который не поднимется.
        if (r != null && sni.isNotEmpty) ...[
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 8, 8, 4),
            child: Text(
              getLocalText.s('SNI domains (provider allow-list)'),
              style: Theme.of(context).textTheme.titleSmall,
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 0, 8, 4),
            child: Text(
              getLocalText.s(
                "Only domains that answered through a live endpoint can be picked.",
              ),
              style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
            ),
          ),
          for (final s in sni) _sniTile(s, cs),
        ],
      ],
    );
  }

  /// §845/§847 — строка валидного резолвера из фазы 3: адрес, провайдер, RTT,
  /// UDP/TCP 853 (DoT) и самоидентификация `id.server`; чекбокс — шаг выбора.
  Widget _dnsTile(DnsServerResult d, ColorScheme cs) {
    final subtitle = StringBuffer('${d.rttMs}ms');
    if (d.dotOpen) subtitle.write(' · TCP 853');
    if (d.identity.isNotEmpty) subtitle.write(' · ${d.identity}');
    return CheckboxListTile(
      value: _selectedDns.contains(d.endpoint),
      onChanged: (v) => setState(() {
        if (v == true) {
          _selectedDns.add(d.endpoint);
        } else {
          _selectedDns.remove(d.endpoint);
        }
      }),
      dense: true,
      visualDensity: VisualDensity.compact,
      controlAffinity: ListTileControlAffinity.leading,
      title: Text(
        d.endpoint,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
      ),
      subtitle: Text(
        '${d.label} · $subtitle',
        style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
      ),
    );
  }

  /// §847 — строка SNI-кандидата из фазы 4: домен, вердикт, на каком эндпоинте
  /// прогоняли и сколько эндпоинтов успели проверить.
  Widget _sniTile(SniScanResult s, ColorScheme cs) {
    final subtitle = StringBuffer(
      s.valid
          ? getLocalText.s("answered via %1\$s", s.endpoint)
          : getLocalText.s("blocked on this network"),
    );
    if (s.tried > 1) {
      subtitle.write(
        ' · ${getLocalText.s("%1\$s endpoints tried", '${s.tried}')}',
      );
    }
    return CheckboxListTile(
      value: _selectedSni.contains(s.sni),
      onChanged: s.valid
          ? (v) => setState(() {
              if (v == true) {
                _selectedSni.add(s.sni);
              } else {
                _selectedSni.remove(s.sni);
              }
            })
          : null,
      dense: true,
      visualDensity: VisualDensity.compact,
      controlAffinity: ListTileControlAffinity.leading,
      secondary: Icon(
        s.valid ? Icons.shield_outlined : Icons.block_outlined,
        color: s.valid ? cs.primary : cs.onSurfaceVariant,
        size: 20,
      ),
      title: Text(
        s.sni,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
      ),
      subtitle: Text(
        subtitle.toString(),
        style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
      ),
    );
  }

  Widget _countryTile(EndpointCountryGroup g, ColorScheme cs) {
    return CheckboxListTile(
      value: _selected.contains(g.code),
      onChanged: (v) => setState(() {
        if (v == true) {
          _selected.add(g.code);
        } else {
          _selected.remove(g.code);
        }
      }),
      title: Text(
        g.isUnknown
            ? getLocalText.s("Country not determined")
            : '${g.name} (${g.code})',
      ),
      subtitle: Text(
        getLocalText.s(
          "%1\$s found · %2\$s valid",
          '${g.found}',
          '${g.valid}',
        ),
      ),
      secondary: _countryFlag(g.code),
      dense: true,
    );
  }

  Widget _statusTile(ScanEndpointStatus s, ColorScheme cs) {
    final (icon, color) = _verdictIcon(s, cs);
    final subtitle = StringBuffer()
      ..write('P${s.phase} · ${s.verdict}');
    if (s.rttMs > 0) subtitle.write(' · ${s.rttMs}ms');
    if (s.country.isNotEmpty || s.colo.isNotEmpty) {
      subtitle.write(' · ${s.country}${s.colo.isEmpty ? '' : '/${s.colo}'}');
    }
    if (s.detail.isNotEmpty) subtitle.write('\n${s.detail}');
    return ListTile(
      dense: true,
      visualDensity: VisualDensity.compact,
      leading: Icon(icon, color: color, size: 20),
      title: Text(
        s.endpoint,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
      ),
      subtitle: Text(
        subtitle.toString(),
        style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
      ),
    );
  }

  (IconData, Color) _verdictIcon(ScanEndpointStatus s, ColorScheme cs) =>
      switch (s.verdict) {
        'alive' || 'geo-ok' => (Icons.check_circle, cs.primary),
        'cookie' => (Icons.check_circle_outline, cs.tertiary),
        'timeout' => (Icons.timer_off_outlined, cs.onSurfaceVariant),
        'junk' => (Icons.help_outline, cs.outline),
        'geo-fail' => (Icons.gps_off_outlined, cs.tertiary),
        'error' => (Icons.error_outline, cs.error),
        _ => (Icons.hourglass_empty, cs.onSurfaceVariant),
      };

  Widget _countryFlag(String code) {
    if (code.length != 2) {
      return const Icon(Icons.public);
    }
    // Региональные индикаторы: буквы A..Z → U+1F1E6..U+1F1FF.
    final cps = code.toUpperCase().codeUnits;
    if (cps.any((c) => c < 0x41 || c > 0x5A)) {
      return const Icon(Icons.public);
    }
    final flag = String.fromCharCodes(cps.map((c) => 0x1F1E6 + (c - 0x41)));
    return Text(flag, style: const TextStyle(fontSize: 22));
  }
}
