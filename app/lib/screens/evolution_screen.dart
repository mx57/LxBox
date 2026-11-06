// §848 — экран эволюции конфигов.
//
// Что здесь происходит физически: посев берётся из узлов экрана серверов
// (проходимые WARP-конфиги), движок мутирует 16 локусов и оценивает каждого
// кандидата живыми HTTP-пробами через поднятую probe-сессию ядра. Экран поэтому
// и показывает ВСЮ цену: бюджет измеряется в запросах, а не в «прогрессе».
//
// Три вещи, которые экран обязан говорить честно, а не прятать под «100 %»:
//   • HTTP-ответ через узел ≠ туннель держит нагрузку;
//   • вердикт DPI нестационарен, поэтому в архив славы особь попадает только
//     после подтверждений в разных кампаниях (настройка «Confirmations needed»);
//   • кандидатов с одной пробой нельзя сравнивать с кандидатом с шестью — отсюда
//     колонка «Probes» и shading ненадёжных значений.
//
// Ничего не сохраняется без нажатия: прогон пишет только в память экрана и в
// журнал. Папку с победителями создаёт явная кнопка (см. [SubscriptionController]
// .kEvolutionFolderName).
//
// Живые обновляются БЕЗ setState на каждое наблюдение (их сотни за кампанию):
// данные пишутся в поля, а перерисовку даёт тикер 250 мс — тот же приём, что у
// сканера эндпоинтов (§835).

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart'
    show Clipboard, ClipboardData, rootBundle;
import 'package:share_plus/share_plus.dart';

import '../controllers/subscription_controller.dart';
import '../models/dns_ref.dart';
import '../models/node_spec.dart';
import '../services/evolution/engine.dart';
import '../services/evolution/genome.dart';
import '../services/evolution/objectives.dart';
import '../services/evolution/pools.dart';
import '../services/evolution/probe_evaluator.dart';
import '../services/evolution/seeds.dart';
import '../services/evolution/settings.dart';
import '../services/l10n/locale_controller.dart';
import '../services/settings_storage.dart';
import '../services/ui_helpers.dart';
import '../services/usage_region.dart';
import '../services/warp/scan/endpoint_scanner.dart'
    show countryName, kGeoUrls;
import '../services/warp/scan/scan_log.dart';
import '../services/warp/scan/scan_pool.dart';
import '../widgets/app_bottom_sheet.dart';
import '../widgets/safe_bottom.dart';

/// Экран эволюции. [nodes] — узлы экрана серверов (посев); контроллер нужен
/// только для того, чтобы положить выбранных победителей в папку.
class EvolutionScreen extends StatefulWidget {
  const EvolutionScreen({
    super.key,
    required this.subController,
    this.nodes = const [],
  });

  final SubscriptionController subController;
  final List<NodeSpec> nodes;

  @override
  State<EvolutionScreen> createState() => _EvolutionScreenState();
}

class _EvolutionScreenState extends State<EvolutionScreen>
    with SnackHelper<EvolutionScreen> {
  final _log = ScanLog();

  EvolutionSettings _settings = const EvolutionSettings();
  SeedSet _seeds = SeedSet.empty;

  /// Штатный пул сканера (asset + секция региона): из него эволюция берёт
  /// адреса, порты и SNI-пул. Пустой = мутации некуда ехать, экран это скажет.
  ScanPool? _assetPool;
  List<DnsServerRef> _dnsRefs = const [];

  ProbeGenomeEvaluator? _evaluator;
  EvolutionEngine? _engine;

  bool _running = false;
  bool _paused = false;
  bool _preparing = false;
  int _generation = 0;
  int _requestsUsed = 0;
  List<GenerationSummary> _stats = const [];
  List<EvoRecord> _records = const [];
  List<Fitness> _hall = const [];
  EvolutionOutcome? _outcome;

  /// Фитнес ТЕКУЩЕГО поколения (ключ — [Genome.key]). Сбрасывается на первом
  /// наблюдении новой кампании — см. [_maybeRollover].
  final _live = <String, Fitness>{};
  int _liveGeneration = 0;

  /// Куда смотреть: 0 — живая таблица, 1 — архив славы.
  int _tab = 0;

  /// Отмеченные в архиве для экспорта.
  final _checked = <String>{};

  /// Страна выхода по адресу — накапливается из наблюдений и становится
  /// фильтром «Endpoint countries» для следующей кампании.
  final _countryByHost = <String, String>{};

  String _statusKey = '';
  String? _error;
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    unawaited(_loadContext());
  }

  @override
  void dispose() {
    _ticker?.cancel();
    _engine?.cancel();
    final ev = _evaluator;
    _evaluator = null;
    if (ev != null) unawaited(ev.dispose());
    super.dispose();
  }

  Future<void> _loadContext() async {
    _seeds = seedsFromNodes(widget.nodes);
    EvolutionSettings loaded;
    ScanPool? pool;
    List<DnsServerRef> dns = const [];
    try {
      loaded = await EvolutionSettings.load();
    } catch (_) {
      loaded = const EvolutionSettings();
    }
    try {
      final raw = await rootBundle.loadString('assets/warp_endpoints.json');
      final region = await UsageRegion.effective();
      pool = ScanPool.fromFullJson(
        jsonDecode(raw) as Map<String, dynamic>,
        region: region,
      );
    } catch (e) {
      _log.w('evo', 'endpoint pool unavailable: $e');
    }
    try {
      dns = await SettingsStorage.getDnsServers();
    } catch (e) {
      _log.w('evo', 'dns settings unavailable: $e');
    }
    if (!mounted) return;
    setState(() {
      _settings = loaded;
      _assetPool = pool;
      _dnsRefs = dns;
    });
  }

  // ───────────────────────── пулы мутаций ─────────────────────────

  /// Домен мутаций под текущие настройки. Страны берутся из [_countryByHost]:
  /// до первой кампании их нет, и фильтр обязан тихо отдавать весь пул, а не
  /// пустоту (иначе «выбери страну» обнулил бы поиск).
  EvolutionPools _basePools() {
    final byCountry = <String, List<String>>{};
    _countryByHost.forEach((host, country) {
      if (country.isEmpty) return;
      byCountry.putIfAbsent(country, () => []).add(host);
    });
    return EvolutionPools.fromScanPool(
      _assetPool,
      dnsTags: [for (final d in _dnsRefs.where((d) => d.enabled)) d.tag],
      endpointsByCountry: byCountry,
    );
  }

  int get _endpointCount =>
      _assetPool == null ? 0 : _basePools().endpoints.length;
  int get _sniCount => _assetPool == null ? 0 : _basePools().sni.length;
  int get _dnsCount => _dnsRefs.where((d) => d.enabled).length;

  List<String> get _countryOptions {
    final set = _countryByHost.values.where((c) => c.isNotEmpty).toSet()
      ..addAll(_settings.countries)
      ..addAll(_settings.targetCountry.isEmpty
          ? const <String>{}
          : {_settings.targetCountry});
    final out = set.toList()..sort();
    return out;
  }

  // ───────────────────────── прогон ─────────────────────────

  Future<void> _start() async {
    if (_running || _preparing) return;
    if (_seeds.genomes.isEmpty) {
      setState(() => _error = getLocalText.s(
          "There are no usable configs to evolve — generate or import WARP nodes first"));
      return;
    }
    _ticker?.cancel();
    setState(() {
      _running = true;
      _paused = false;
      _preparing = true;
      _error = null;
      _outcome = null;
      _stats = const [];
      _hall = const [];
      _generation = 0;
      _requestsUsed = 0;
      _live.clear();
      _liveGeneration = 0;
      _records = const [];
      _statusKey = 'preparing';
    });
    _log.clear();
    _log.i('evo',
        'campaign start: seeds=${_seeds.genomes.length} pop=${_settings.populationSize} '
        'gens=${_settings.maxGenerations} budget=${_settings.maxRequests} '
        'rungs=${_settings.rungAttempts.join(",")} eda=${_settings.useEda} '
        'seed=${_settings.seed}');

    final evaluator = _evaluator ??= ProbeGenomeEvaluator(
      log: _log,
      pool: _assetPool,
      wgKeepalive: _assetPool?.wgKeepalive ?? 0,
      timeout: _settings.requestTimeout,
    );
    final engine = EvolutionEngine(
      evaluator: evaluator,
      pools: _settings.poolsFor(_basePools()),
      settings: _settings,
      onGeneration: _onGeneration,
      onObservation: _onObservation,
      onNote: _onNote,
    );
    _engine = engine;
    _startTicker();

    EvolutionOutcome outcome;
    try {
      outcome = await engine.run(_seeds.genomes);
    } catch (e, s) {
      _log.e('evo', 'engine crashed: $e $s');
      outcome = EvolutionOutcome(
        hallOfFame: engine.hallOfFame,
        stats: engine.stats,
        requestsUsed: engine.requestsUsed,
        generations: engine.stats.length,
        error: '$e',
      );
    }
    if (!mounted) return;
    _ticker?.cancel();
    setState(() {
      _running = false;
      _preparing = false;
      _paused = false;
      _outcome = outcome;
      _stats = outcome.stats;
      _hall = outcome.hallOfFame;
      _records = engine.records;
      _requestsUsed = outcome.requestsUsed;
      _generation = outcome.generations;
      _error = outcome.error;
      _statusKey = outcome.cancelled
          ? 'stopped'
          : outcome.error != null
              ? 'failed'
              : 'finished';
      _checked
        ..clear()
        ..addAll(_hall.map((f) => f.genome.key));
    });
  }

  void _startTicker() {
    _ticker?.cancel();
    _ticker = Timer.periodic(const Duration(milliseconds: 250), (_) {
      if (mounted && _running) setState(() {});
    });
  }

  void _onGeneration(GenerationSummary s) {
    _stats = [..._stats, s];
    _records = _engine?.records ?? _records;
  }

  /// Запросы, потраченные НАСЧИТЛЯЮЩИЙ момент: движок считает их по рангам, а
  /// итог прогона известен только после `run()`.
  int get _spent =>
      _running ? (_engine?.requestsUsed ?? _requestsUsed) : _requestsUsed;

  void _onObservation(Genome g, Fitness f, int rung) {
    // Первая проба новой кампании — живая таблица начинается заново: движок
    // отдаёт сводку поколения ДО наблюдений следующего, поэтому счётчик
    // завершённых поколений надёжнее любых флагов внутри особей.
    final current = _stats.length + 1;
    if (current != _liveGeneration) {
      _liveGeneration = current;
      _live.clear();
    }
    _live[g.key] = f;
    if (!_paused && _statusKey != 'running') _statusKey = 'running';
    final c = f.country;
    if (c.isNotEmpty && g.endpoint.isNotEmpty) _countryByHost[g.endpoint] = c;
  }

  void _onNote(String message) => _log.i('evo', message);

  void _pause() {
    if (!_running || _paused) return;
    _engine?.pause();
    setState(() {
      _paused = true;
      _statusKey = 'paused';
    });
  }

  void _resume() {
    _engine?.resume();
    setState(() {
      _paused = false;
      _statusKey = 'running';
    });
  }

  void _stop() {
    _engine?.cancel();
    setState(() => _statusKey = 'stopping');
  }

  Future<void> _saveSelected() async {
    final evaluator = _evaluator;
    if (evaluator == null || _hall.isEmpty) return;
    final bodies = <String>[];
    final missing = <String>[];
    for (final f in _hall) {
      if (!_checked.contains(f.genome.key)) continue;
      final body = evaluator.exportFor(f.genome);
      if (body == null) {
        missing.add(f.genome.shortLabel);
      } else {
        bodies.add(body);
      }
    }
    if (bodies.isEmpty) {
      showSnack(getLocalText.s("Nothing to save — these configs could not be rebuilt"));
      return;
    }
    await widget.subController.addEvolutionFolder(bodies);
    if (!mounted) return;
    setState(() {});
    showSnack(getLocalText.s(
      "Saved %1\$s configs to folder %2\$s",
      '${bodies.length}',
      SubscriptionController.kEvolutionFolderName,
    ));
    if (missing.isNotEmpty) {
      showSnack(getLocalText.s(
        "%1\$s configs could not be rebuilt and were skipped",
        '${missing.length}',
      ));
    }
  }

  // ───────────────────────── шторки ─────────────────────────

  void _copyLog() {
    Clipboard.setData(ClipboardData(text: _log.text));
    showSnack(getLocalText.s('Log copied to clipboard'));
  }

  Future<void> _shareLog() async {
    try {
      await SharePlus.instance.share(
        ShareParams(text: _log.text, subject: 'LxBox evolution log'),
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
                        getLocalText.s("Evolution log"),
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
                        padding:
                            const EdgeInsets.all(12).withSafeBottom(ctx),
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

  Future<void> _openSettings() async {
    final next = await showAppBottomSheet<EvolutionSettings>(
      context: context,
      isScrollControlled: true,
      builder: (_) => _SettingsSheet(
        settings: _settings,
        countries: _countryOptions,
        endpoints: _endpointCount,
        sni: _sniCount,
        dns: _dnsCount,
        seeds: _seeds.genomes.length,
      ),
    );
    if (next == null || !mounted) return;
    await next.save();
    if (!mounted) return;
    setState(() {
      _settings = next;
      // Меняется всё, что зависит от домена мутаций.
      _evaluator = null;
    });
  }

  void _openCandidate(Fitness f) {
    final exported = _running ? null : _evaluator?.exportFor(f.genome);
    showAppBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => _CandidateSheet(
        fitness: f,
        settings: _settings,
        body: exported,
        records: _records,
      ),
    );
  }

  // ───────────────────────── build ─────────────────────────

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: Text(getLocalText.s("Config evolution")),
        actions: [
          IconButton(
            tooltip: getLocalText.s("Evolution log"),
            onPressed: _openLog,
            icon: Badge(
              isLabelVisible: _log.length > 0,
              label: Text('${_log.length}'),
              child: const Icon(Icons.article_outlined),
            ),
          ),
          IconButton(
            tooltip: getLocalText.s('Settings'),
            onPressed: _running ? null : _openSettings,
            icon: const Icon(Icons.tune),
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView(
              padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
              children: [
                _statusBanner(cs),
                _metricsStrip(cs),
                _failureReasonsCard(cs),
                const SizedBox(height: 10),
                _budgetBar(cs),
                const SizedBox(height: 10),
                _trendCard(cs),
                const SizedBox(height: 10),
                _seedsCard(cs),
                const SizedBox(height: 10),
                _honestyNote(cs),
                const SizedBox(height: 12),
                _tabs(cs),
                const SizedBox(height: 8),
                _tabBody(cs),
              ],
            ),
          ),
          _actions(cs),
        ],
      ),
    );
  }

  Widget _statusBanner(ColorScheme cs) {
    final error = _error;
    if (error != null) {
      return Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: cs.errorContainer,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Row(
          children: [
            Icon(Icons.error_outline, color: cs.onErrorContainer),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                error,
                style: TextStyle(color: cs.onErrorContainer),
              ),
            ),
          ],
        ),
      );
    }
    if (_statusKey.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          SizedBox(
            width: 14,
            height: 14,
            child: _running && !_paused
                ? CircularProgressIndicator(strokeWidth: 2, color: cs.primary)
                : Icon(_statusKey == 'finished'
                    ? Icons.verified_outlined
                    : Icons.radio_button_unchecked, size: 14, color: cs.primary),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              getLocalText.s(_statusLabel),
              style: TextStyle(
                color: cs.onSurfaceVariant,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }

  String get _statusLabel => switch (_statusKey) {
        'preparing' => "Preparing the probe session…",
        'running' => "Evolving…",
        'paused' => "Paused between probe rounds",
        'stopping' => "Stopping after the current probe…",
        'stopped' => "Stopped",
        'failed' => "Run failed",
        _ => "Run finished",
      };

  Widget _metricsStrip(ColorScheme cs) {
    final live = _live.values.toList();
    final passable = live
        .where((f) => f.attempts > 0 && f.passRate >= _settings.minPassRate)
        .length;
    final best = live.isEmpty
        ? null
        : live.reduce((a, b) => a.passRate >= b.passRate ? a : b);
    final last = _stats.isEmpty ? null : _stats.last;
    final cards = <Widget>[
      _MetricCard(
        value: '$_generation/${_settings.maxGenerations}',
        label: getLocalText.s("Generation"),
        icon: Icons.layers_outlined,
      ),
      _MetricCard(
        value: '$passable',
        label: getLocalText.s("Passable now"),
        icon: Icons.check_circle_outline,
      ),
      _MetricCard(
        value: best == null || best.attempts == 0
            ? '—'
            : '${(best.passRate * 100).round()} %',
        label: getLocalText.s("Best pass rate"),
        icon: Icons.trending_up,
      ),
      _MetricCard(
        value: '$_spent/${_settings.maxRequests}',
        label: getLocalText.s("Requests used"),
        icon: Icons.ssid_chart,
      ),
      _MetricCard(
        value: last == null
            ? '—'
            : '${(last.diversity * 100).round()} %',
        label: getLocalText.s("Diversity"),
        icon: Icons.category_outlined,
      ),
      _MetricCard(
        value: '${_hall.length}',
        label: getLocalText.s("Hall of fame"),
        icon: Icons.card_giftcard,
      ),
    ];
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: cards,
    );
  }

  /// «Проходимых 0» без причин неотличимо от «сеть режет всё»: движок несёт
  /// подписи отказов поколения, и одна и та же подпись у всех особей — это
  /// путь пробы (резолв цели, сессия), а не блокировка.
  Widget _failureReasonsCard(ColorScheme cs) {
    final last = _stats.isEmpty ? null : _stats.last;
    final reasons = last?.failureReasons ?? '';
    if (last == null || last.alive > 0 || reasons.isEmpty) {
      return const SizedBox.shrink();
    }
    return Container(
      margin: const EdgeInsets.only(top: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: cs.tertiary.withValues(alpha: 0.55)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.network_ping_outlined, size: 16, color: cs.tertiary),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  getLocalText.s("Nothing passed — probe failures"),
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: cs.onSurface,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          for (final reason in reasons.split('; '))
            Padding(
              padding: const EdgeInsets.only(bottom: 3),
              child: Text(
                '• $reason',
                style: TextStyle(
                  fontSize: 11,
                  color: cs.onSurface,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          const SizedBox(height: 4),
          Text(
            getLocalText.s(
                "One and the same reason for every candidate is a probe-path problem, not a block — check the DNS server and the target country, then rerun"),
            style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
          ),
        ],
      ),
    );
  }

  Widget _budgetBar(ColorScheme cs) {
    final est = estimateRequests(_settings);
    final spent = (_spent / _settings.maxRequests).clamp(0.0, 1.0);
    final over = est > _settings.maxRequests;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ClipRRect(
          borderRadius: BorderRadius.circular(6),
          child: LinearProgressIndicator(
            value: _running || _outcome != null ? spent : null,
            minHeight: 8,
            backgroundColor: cs.surfaceContainerHighest,
          ),
        ),
        const SizedBox(height: 6),
        Text(
          over
              ? getLocalText.s(
                  "Estimated %1\$s requests for the full run — budget %2\$s will cut it short",
                  '$est',
                  '${_settings.maxRequests}',
                )
              : getLocalText.s(
                  "Estimated %1\$s requests for the full run",
                  '$est',
                ),
          style: TextStyle(
            fontSize: 11,
            color: over ? cs.tertiary : cs.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  Widget _trendCard(ColorScheme cs) {
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 8),
      decoration: _card(cs),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  getLocalText.s("Pass rate and diversity by generation"),
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: cs.onSurfaceVariant,
                  ),
                ),
              ),
              _Legend(cs.primary, getLocalText.s("Pass rate")),
              const SizedBox(width: 10),
              _Legend(cs.tertiary, getLocalText.s("Diversity")),
            ],
          ),
          const SizedBox(height: 8),
          SizedBox(
            height: 132,
            width: double.infinity,
            child: CustomPaint(
              painter: _TrendPainter(
                stats: _stats,
                generations: _settings.maxGenerations,
                primary: cs.primary,
                secondary: cs.tertiary,
                grid: cs.outlineVariant,
                muted: cs.onSurfaceVariant,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _seedsCard(ColorScheme cs) {
    final s = _seeds;
    final skipped = [
      for (final e in s.skipped.entries)
        '${getLocalText.s(_skipLabel(e.key))} ${e.value}',
    ].join(' · ');
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
      decoration: _card(cs),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            getLocalText.s(
              "Seed from your servers: %1\$s of %2\$s configs",
              '${s.genomes.length}',
              '${s.total}',
            ),
            style: TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w600,
              color: cs.onSurface,
            ),
          ),
          if (skipped.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(
              skipped,
              style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
            ),
          ],
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 6,
            children: [
              _InfoChip(
                icon: Icons.lan_outlined,
                label: getLocalText.s("Endpoints available"),
                value: '$_endpointCount',
              ),
              _InfoChip(
                icon: Icons.lock_outline,
                label: "SNI",
                value: '$_sniCount',
              ),
              _InfoChip(
                icon: Icons.dns_outlined,
                label: "DNS",
                value: '$_dnsCount',
              ),
              _InfoChip(
                icon: Icons.public,
                label: getLocalText.s("Countries learned"),
                value: '${_countryOptions.length}',
              ),
            ],
          ),
          if (_endpointCount == 0) ...[
            const SizedBox(height: 6),
            Text(
              getLocalText.s(
                  "The endpoint pool is empty — run the endpoint scanner first"),
              style: TextStyle(fontSize: 11, color: cs.tertiary),
            ),
          ],
        ],
      ),
    );
  }

  String _skipLabel(SeedSkipReason r) => switch (r) {
        SeedSkipReason.notWarp => "Not WARP",
        SeedSkipReason.group => "Groups",
        SeedSkipReason.noAddress => "No address",
        SeedSkipReason.broken => "Unparsable",
      };

  Widget _honestyNote(ColorScheme cs) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            getLocalText.s(
                "A response through the node is not a load test — this optimises handshake passability"),
            style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
          ),
          const SizedBox(height: 2),
          Text(
            getLocalText.s(
                "DPI verdicts drift, so the hall of fame only lists configs confirmed in separate generations"),
            style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
          ),
        ],
      );

  Widget _tabs(ColorScheme cs) {
    Widget tab(int i, String label, IconData icon) {
      final on = _tab == i;
      return InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: () => setState(() => _tab = i),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          color: on ? cs.secondaryContainer : Colors.transparent,
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon,
                  size: 16,
                  color: on ? cs.onSecondaryContainer : cs.onSurfaceVariant),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: on ? FontWeight.w700 : FontWeight.w500,
                  color: on ? cs.onSecondaryContainer : cs.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
      );
    }

    return Row(
      children: [
        Expanded(
          child: tab(0, getLocalText.s("Candidates"), Icons.biotech_outlined),
        ),
        const SizedBox(width: 6),
        Expanded(
          child: tab(
              1, getLocalText.s("Hall of fame"), Icons.workspace_premium_outlined),
        ),
      ],
    );
  }

  Widget _tabBody(ColorScheme cs) =>
      _tab == 0 ? _candidates(cs) : _hallOfFame(cs);

  /// Живая таблица: особи текущего поколения в Парето-порядке.
  Widget _candidates(ColorScheme cs) {
    final all = _live.values.toList();
    if (all.isEmpty) {
      return _emptyHint(
        cs,
        _running
            ? getLocalText.s("First probes are still running")
            : getLocalText.s("Start a run to see candidates here"),
      );
    }
    final order =
        nsga2Order(all, targetCountry: _settings.targetCountry);
    final rows = [for (final i in order) all[i]];
    final visible = rows.take(24).toList(growable: false);
    // Сумма попыток всех рангов: «3 / 6» честнее голой тройки — кандидата,
    // отсечённого на втором ранге, ещё нельзя считать проверенным.
    final fullAttempts =
        _settings.rungAttempts.fold<int>(0, (a, b) => a + b);
    return Container(
      decoration: _card(cs),
      clipBehavior: Clip.antiAlias,
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: DataTable(
          showBottomBorder: true,
          columnSpacing: 18,
          headingRowHeight: 38,
          dataRowMinHeight: 46,
          dataRowMaxHeight: 56,
          dividerThickness: 0.4,
          headingTextStyle: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w700,
            color: cs.onSurfaceVariant,
          ),
          dataTextStyle: TextStyle(fontSize: 12, color: cs.onSurface),
          columns: [
            DataColumn(label: Text(getLocalText.s("Rank"))),
            DataColumn(label: Text(getLocalText.s("Candidate"))),
            DataColumn(label: Text(getLocalText.s("Pass rate"))),
            DataColumn(label: Text(getLocalText.s("Probes"))),
            DataColumn(label: Text(getLocalText.s("RTT"))),
            DataColumn(label: Text(getLocalText.s("Country"))),
            DataColumn(label: Text(getLocalText.s("Confirmed"))),
          ],
          rows: [
            for (final f in visible)
              DataRow(
                onSelectChanged: (_) => _openCandidate(f),
                cells: [
                  DataCell(Text(_rankOf(f, rows))),
                  DataCell(_candidateCell(f, cs)),
                  DataCell(_passBar(f, cs)),
                  DataCell(Text(f.attempts >= fullAttempts
                      ? '${f.attempts}'
                      : '${f.attempts} / $fullAttempts')),
                  DataCell(Text(f.medianRtt == null
                      ? '—'
                      : '${f.medianRtt} ms')), // l10n-exempt: latency value + unit
                  DataCell(_countryCell(f, cs)),
                  DataCell(Text('${f.confirmations}/${_settings.confirmationsNeeded}')),
                ],
              ),
          ],
        ),
      ),
    );
  }

  String _rankOf(Fitness f, List<Fitness> ordered) {
    final i = ordered.indexOf(f);
    return i < 0 ? '—' : '${i + 1}';
  }

  Widget _candidateCell(Fitness f, ColorScheme cs) {
    final g = f.genome;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            _TransportBadge(g.transport),
            const SizedBox(width: 6),
            ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 190),
              child: Text(
                '${g.endpoint}:${g.port}',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                    fontFamily: 'monospace', fontSize: 11.5),
              ),
            ),
          ],
        ),
        if (g.sni.isNotEmpty)
          Text(
            g.sni,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant),
          ),
      ],
    );
  }

  Widget _passBar(Fitness f, ColorScheme cs) {
    final confident = f.confidence >= 0.99;
    return SizedBox(
      width: 78,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            f.attempts == 0 ? '—' : '${(f.passRate * 100).round()} %',
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w700,
              color: f.passRate >= _settings.minPassRate
                  ? cs.primary
                  : cs.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 3),
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: LinearProgressIndicator(
              value: f.passRate,
              minHeight: 4,
              color: confident ? cs.primary : cs.primary.withValues(alpha: 0.45),
              backgroundColor: cs.surfaceContainerHighest,
            ),
          ),
        ],
      ),
    );
  }

  Widget _countryCell(Fitness f, ColorScheme cs) {
    final c = f.colo.isNotEmpty ? f.colo : f.country;
    if (c.isEmpty) return Text('—', style: TextStyle(color: cs.onSurfaceVariant));
    final hit = _settings.targetCountry.isNotEmpty &&
        f.country == _settings.targetCountry;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: hit ? cs.primaryContainer : cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        hit ? '${countryName(c)} ★' : countryName(c),
        style: TextStyle(
          fontSize: 10.5,
          fontWeight: FontWeight.w600,
          color: hit ? cs.onPrimaryContainer : cs.onSurfaceVariant,
        ),
      ),
    );
  }

  Widget _hallOfFame(ColorScheme cs) {
    if (_hall.isEmpty) {
      return _emptyHint(
        cs,
        getLocalText.s(
            "Empty until a config repeats its passability in %s separate generations",
            '${_settings.confirmationsNeeded}'),
      );
    }
    return Container(
      decoration: _card(cs),
      clipBehavior: Clip.antiAlias,
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 4, 8, 0),
            child: Row(
              children: [
                TextButton.icon(
                  onPressed: () => setState(() => _checked
                    ..clear()
                    ..addAll(_hall.map((f) => f.genome.key))),
                  icon: const Icon(Icons.select_all, size: 16),
                  label: Text(getLocalText.s('Select all')),
                ),
                const Spacer(),
                TextButton(
                  onPressed: () => setState(_checked.clear),
                  child: Text(getLocalText.s("Clear")),
                ),
              ],
            ),
          ),
          for (final f in _hall)
            CheckboxListTile(
              dense: true,
              controlAffinity: ListTileControlAffinity.leading,
              value: _checked.contains(f.genome.key),
              onChanged: (v) => setState(() {
                if (v == true) {
                  _checked.add(f.genome.key);
                } else {
                  _checked.remove(f.genome.key);
                }
              }),
              title: _candidateCell(f, cs),
              subtitle: Text(
                '${getLocalText.s("Pass rate")} ${(f.passRate * 100).round()} % · '
                '${f.attempts} ${getLocalText.s("probes")} · '
                '${f.confirmations} ${getLocalText.s("confirmations")}',
                style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
              ),
              secondary: IconButton(
                tooltip: getLocalText.s("Details"),
                onPressed: () => _openCandidate(f),
                icon: const Icon(Icons.insights_outlined, size: 20),
              ),
            ),
        ],
      ),
    );
  }

  Widget _emptyHint(ColorScheme cs, String text) => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(18),
        decoration: _card(cs),
        child: Text(
          text,
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
        ),
      );

  BoxDecoration _card(ColorScheme cs) => BoxDecoration(
        color: cs.surfaceContainerLow,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: cs.outlineVariant.withValues(alpha: 0.6)),
      );

  Widget _actions(ColorScheme cs) {
    Widget primary;
    VoidCallback? primaryAction;
    if (_running && !_paused) {
      primary = Text(getLocalText.s("Pause"));
      primaryAction = _pause;
    } else if (_running) {
      primary = Text(getLocalText.s("Resume"));
      primaryAction = _paused ? _resume : null;
    } else {
      primary = Text(getLocalText.s("Start evolution"));
      primaryAction = _preparing ? null : _start;
    }
    return SafeArea(
      minimum: const EdgeInsets.fromLTRB(12, 6, 12, 12),
      child: Row(
        children: [
          Expanded(
            child: FilledButton.icon(
              onPressed: primaryAction,
              icon: Icon(_running ? Icons.pause_rounded : Icons.play_arrow_rounded),
              label: primary,
            ),
          ),
          if (_running) ...[
            const SizedBox(width: 8),
            OutlinedButton(
              onPressed: _stop,
              child: Text(getLocalText.s('Stop')),
            ),
          ],
          if (!_running && _hall.isNotEmpty) ...[
            const SizedBox(width: 8),
            FilledButton.tonalIcon(
              onPressed: _checked.isEmpty ? null : _saveSelected,
              icon: const Icon(Icons.folder_open),
              label: Text(getLocalText.s(
                "Save %s",
                '${_checked.length}',
              )),
            ),
          ],
        ],
      ),
    );
  }
}

/// Ген, который пользователь Freeze-ом снять не может: `jitterMax` обязан
/// оставаться ≥ `jitterMin` (AWG-пара проверяется связью реестра, и «случайный»
/// максимум меньше минимума дал бы кандидат, который ядро отвергает целиком).
const _lockedLocus = EvoLocus.jitterMax;

/// Цена прогона в ЗАПРОСАХ (верхняя оценка): successive halving берёт
/// `attempts[i]` проб у `alive` особей, затем `alive = keepOf(alive)`. Одна
/// проба — это серия GET'ов по источникам гео (§844: мёртвый адрес стоит
/// `kGeoUrls.length` запросов, живой — один), поэтому вердикт умножается на их
/// число. Низкую цену показывать нельзя: пользователь выбирает бюджет по ней.
int estimateRequests(EvolutionSettings s) {
  if (s.rungAttempts.isEmpty) return 0;
  var perGeneration = 0;
  var alive = s.populationSize;
  for (final attempts in s.rungAttempts) {
    if (alive <= 0) break;
    perGeneration += attempts * alive;
    alive = s.keepOf(alive);
  }
  return perGeneration * s.maxGenerations * kGeoUrls.length;
}

// ───────────────────────── виджеты ─────────────────────────

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.value,
    required this.label,
    required this.icon,
  });

  final String value;
  final String label;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      width: 112,
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: cs.surfaceContainerLow,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: cs.outlineVariant.withValues(alpha: 0.6)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 13, color: cs.primary),
              const SizedBox(width: 5),
              Expanded(
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  alignment: Alignment.centerLeft,
                  child: Text(
                    value,
                    style: const TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w700),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 2),
          Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant),
          ),
        ],
      ),
    );
  }
}

class _Legend extends StatelessWidget {
  const _Legend(this.color, this.label);
  final Color color;
  final String label;

  @override
  Widget build(BuildContext context) => Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 10,
            height: 3,
            decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(2)),
          ),
          const SizedBox(width: 4),
          Text(label,
              style: TextStyle(
                  fontSize: 10, color: Theme.of(context).colorScheme.onSurfaceVariant)),
        ],
      );
}

class _InfoChip extends StatelessWidget {
  const _InfoChip({required this.icon, required this.label, required this.value});
  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(9),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: cs.onSurfaceVariant),
          const SizedBox(width: 5),
          Text(label,
              style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant)),
          const SizedBox(width: 4),
          Text(value,
              style: const TextStyle(
                  fontSize: 11, fontWeight: FontWeight.w700)),
        ],
      ),
    );
  }
}

class _TransportBadge extends StatelessWidget {
  const _TransportBadge(this.transport);
  final EvoTransport transport;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final color = switch (transport) {
      EvoTransport.awg => cs.primary,
      EvoTransport.masqueH3 => cs.tertiary,
      EvoTransport.masqueH2 => cs.secondary,
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        transport.wire.toUpperCase(),
        style: TextStyle(
            fontSize: 9.5, fontWeight: FontWeight.w800, color: color),
      ),
    );
  }
}

class _TrendPainter extends CustomPainter {
  _TrendPainter({
    required this.stats,
    required this.generations,
    required this.primary,
    required this.secondary,
    required this.grid,
    required this.muted,
  });

  final List<GenerationSummary> stats;
  final int generations;
  final Color primary;
  final Color secondary;
  final Color grid;
  final Color muted;

  @override
  void paint(Canvas canvas, Size size) {
    final axis = Paint()
      ..color = grid.withValues(alpha: 0.7)
      ..strokeWidth = 0.7;
    for (var i = 0; i <= 4; i++) {
      final y = size.height * i / 4;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), axis);
    }
    final n = generations <= 1 ? 1 : generations - 1;
    double x(int index) =>
        n == 0 ? size.width / 2 : size.width * index / n;
    double y(double value) => size.height * (1 - value.clamp(0.0, 1.0));

    void line(double Function(GenerationSummary) pick, Color color,
        {bool fill = false}) {
      if (stats.isEmpty) return;
      final path = Path();
      for (var i = 0; i < stats.length; i++) {
        final p = Offset(x(i), y(pick(stats[i])));
        i == 0 ? path.moveTo(p.dx, p.dy) : path.lineTo(p.dx, p.dy);
      }
      if (fill) {
        final under = Path.from(path)
          ..lineTo(x(stats.length - 1), size.height)
          ..lineTo(x(0), size.height)
          ..close();
        canvas.drawPath(under, Paint()..color = color.withValues(alpha: 0.12));
      }
      canvas.drawPath(
          path,
          Paint()
            ..color = color
            ..style = PaintingStyle.stroke
            ..strokeWidth = 2
            ..strokeJoin = StrokeJoin.round);
      final last = Offset(x(stats.length - 1), y(pick(stats.last)));
      canvas.drawCircle(last, 3.2, Paint()..color = color);
    }

    line((s) => s.bestPassRate, primary, fill: true);
    line((s) => s.diversity, secondary);

    if (stats.isEmpty) {
      final tp = TextPainter(
        text: TextSpan(
          text: '0 %',
          style: TextStyle(fontSize: 10, color: muted),
        ),
        textDirection: TextDirection.ltr,
      )..layout();
      tp.paint(canvas, Offset(size.width / 2 - tp.width / 2, size.height / 2));
      return;
    }
    // Подписи осей: по сколько поколений на экране.
    final label = TextPainter(
      text: TextSpan(
        text: '1',
        style: TextStyle(fontSize: 9, color: muted),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    label.paint(canvas, const Offset(1, 0));
    final label2 = TextPainter(
      text: TextSpan(
        text: '$generations',
        style: TextStyle(fontSize: 9, color: muted),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    label2.paint(canvas, Offset(size.width - label2.width, 0));
  }

  @override
  bool shouldRepaint(_TrendPainter old) =>
      old.stats.length != stats.length ||
      old.generations != generations ||
      old.primary != primary;
}

/// Шторка одной особи: все 16 генов + накопленные наблюдения + тело конфига.
class _CandidateSheet extends StatelessWidget {
  const _CandidateSheet({
    required this.fitness,
    required this.settings,
    required this.body,
    required this.records,
  });

  final Fitness fitness;
  final EvolutionSettings settings;
  final String? body;
  final List<EvoRecord> records;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tokens = fitness.genome.tokens();
    final errors = [
      for (final o in fitness.observations)
        if (!o.responded && o.error.isNotEmpty) o.error
    ];
    final record = records.where((r) => r.key == fitness.genome.key).toList();
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.75,
      maxChildSize: 0.95,
      builder: (ctx, scroll) => ListView(
        controller: scroll,
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
        children: [
          Row(
            children: [
              _TransportBadge(fitness.genome.transport),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  fitness.genome.shortLabel,
                  style: Theme.of(context).textTheme.titleMedium,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (body != null)
                IconButton(
                  tooltip: getLocalText.s("Copy config"),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: body!));
                  },
                  icon: const Icon(Icons.copy_all_outlined),
                ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 6,
            children: [
              _InfoChip(
                icon: Icons.check_circle_outline,
                label: getLocalText.s("Pass rate"),
                value: '${(fitness.passRate * 100).round()} %',
              ),
              _InfoChip(
                icon: Icons.timer_outlined,
                label: getLocalText.s("RTT"),
                value: fitness.medianRtt == null
                    ? '—'
                    : '${fitness.medianRtt} ms', // l10n-exempt: latency value + unit
              ),
              _InfoChip(
                icon: Icons.how_to_reg_outlined,
                label: getLocalText.s("Confirmed"),
                value: '${fitness.confirmations}/${settings.confirmationsNeeded}',
              ),
              _InfoChip(
                icon: Icons.network_ping_outlined,
                label: getLocalText.s("Requests"),
                value: '${fitness.requestsUsed}',
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            getLocalText.s("Genes"),
            style: TextStyle(
                fontSize: 12, fontWeight: FontWeight.w700, color: cs.onSurfaceVariant),
          ),
          const SizedBox(height: 4),
          for (final locus in EvoLocus.values)
            _GeneRow(
              label: getLocalText.s(locusUiKey(locus)),
              value: _displayValue(locus, tokens[locus] ?? ''),
              frozen: settings.disabledLoci.contains(locus),
            ),
          if (errors.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(
              getLocalText.s("Last failures"),
              style: TextStyle(
                  fontSize: 12, fontWeight: FontWeight.w700, color: cs.error),
            ),
            const SizedBox(height: 4),
            for (final e in errors.take(6))
              Padding(
                padding: const EdgeInsets.only(bottom: 2),
                child: Text(
                  e,
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 10.5),
                ),
              ),
          ],
          if (record.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(
              getLocalText.s("Lifetime over this campaign"),
              style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 4),
            Text(
              getLocalText.s(
                "%1\$s probes · %2\$s passed · deepest round %3\$s",
                '${record.first.lifetime.attempts}',
                '${record.first.lifetime.passes}',
                '${record.first.bestRung + 1}',
              ),
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
            ),
          ],
          if (body != null) ...[
            const SizedBox(height: 12),
            Text(
              getLocalText.s("Config body"),
              style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 4),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: cs.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(10),
              ),
              child: SelectableText(
                body!,
                style: const TextStyle(
                    fontFamily: 'monospace', fontSize: 10),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _GeneRow extends StatelessWidget {
  const _GeneRow(
      {required this.label, required this.value, required this.frozen});
  final String label;
  final String value;
  final bool frozen;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.5),
      child: Row(
        children: [
          SizedBox(
            width: 150,
            child: Text(
              label,
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
            ),
          ),
          Expanded(
            child: Text(
              value.isEmpty ? '—' : value,
              style: TextStyle(
                fontSize: 12,
                fontFamily: 'monospace',
                fontWeight: frozen ? FontWeight.w500 : FontWeight.w700,
              ),
            ),
          ),
          Icon(
            frozen ? Icons.lock_outline : Icons.shuffle,
            size: 13,
            color: frozen ? cs.tertiary : cs.primary.withValues(alpha: 0.6),
          ),
        ],
      ),
    );
  }
}

String _displayValue(EvoLocus locus, String raw) => switch (locus) {
      EvoLocus.fragment ||
      EvoLocus.recordFragment =>
        raw == '1' ? 'on' : 'off',
      EvoLocus.keepalive || EvoLocus.mtu => raw == '0' ? '' : raw,
      EvoLocus.sniCase => raw == '0' ? '' : '#$raw',
      _ => raw,
    };

/// Ключ l10n для подписи локуса (UI-тексты живут в словарях, сервис — нет).
String locusUiKey(EvoLocus locus) => switch (locus) {
      EvoLocus.transport => "Transport",
      EvoLocus.endpoint => "Endpoint",
      EvoLocus.port => "Port",
      EvoLocus.sni => "SNI domain",
      EvoLocus.keepalive => "Keepalive",
      EvoLocus.mtu => "MTU",
      EvoLocus.junkProto => "Decoy protocol",
      EvoLocus.junkBrowser => "Decoy browser",
      EvoLocus.junkDomain => "Decoy domain",
      EvoLocus.jc => "Decoy count",
      EvoLocus.jitterMin => "Decoy size min",
      EvoLocus.jitterMax => "Decoy size max",
      EvoLocus.fragment => "TLS fragmentation",
      EvoLocus.recordFragment => "Record fragmentation",
      EvoLocus.sniCase => "Mixed-case SNI",
      EvoLocus.dns => "DNS resolver",
    };

// ───────────────────────── шторка настроек ─────────────────────────

class _SettingsSheet extends StatefulWidget {
  const _SettingsSheet({
    required this.settings,
    required this.countries,
    required this.endpoints,
    required this.sni,
    required this.dns,
    required this.seeds,
  });

  final EvolutionSettings settings;
  final List<String> countries;
  final int endpoints;
  final int sni;
  final int dns;
  final int seeds;

  @override
  State<_SettingsSheet> createState() => _SettingsSheetState();
}

/// Публичный только внутри файла: шторка держит черновик настроек.
class _SettingsSheetState extends State<_SettingsSheet> {
  late EvolutionSettings _s = widget.settings;
  late final TextEditingController _seed =
      TextEditingController(text: '${widget.settings.seed}');

  @override
  void dispose() {
    _seed.dispose();
    super.dispose();
  }

  void _patch(EvolutionSettings Function(EvolutionSettings) f) =>
      setState(() => _s = f(_s));

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final cost = estimateRequests(_s);
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.9,
      maxChildSize: 0.95,
      builder: (ctx, scroll) => Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: Row(
              children: [
                Expanded(
                  child: Text(getLocalText.s('Settings'),
                      style: Theme.of(context).textTheme.titleMedium),
                ),
                TextButton(
                  onPressed: () => setState(() {
                    _s = const EvolutionSettings();
                    _seed.text = '0';
                  }),
                  child: Text(getLocalText.s("Reset defaults")),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: ListView(
              controller: scroll,
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
              children: [
                _section(cs, getLocalText.s("Search")),
                _slider(
                  cs,
                  label: getLocalText.s("Population"),
                  current: _s.populationSize.toDouble(),
                  value: '${_s.populationSize}',
                  min: EvolutionSettings.minPopulation.toDouble(),
                  max: EvolutionSettings.maxPopulation.toDouble(),
                  divisions: (EvolutionSettings.maxPopulation -
                          EvolutionSettings.minPopulation) ~/
                      2,
                  onChanged: (v) => _patch((s) =>
                      s.copyWith(populationSize: v.round())),
                  hint: getLocalText.s(
                      "Candidates evaluated per generation — each one costs live probes"),
                ),
                _slider(
                  cs,
                  label: getLocalText.s("Generations"),
                  current: _s.maxGenerations.toDouble(),
                  value: '${_s.maxGenerations}',
                  min: 1,
                  max: EvolutionSettings.maxGenerationsLimit.toDouble(),
                  divisions: EvolutionSettings.maxGenerationsLimit - 1,
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(maxGenerations: v.round())),
                ),
                _slider(
                  cs,
                  label: getLocalText.s("Request budget"),
                  current: _s.maxRequests.toDouble(),
                  value: '${_s.maxRequests}',
                  min: EvolutionSettings.minRequestBudget.toDouble(),
                  max: EvolutionSettings.maxRequestBudget.toDouble(),
                  divisions:
                      (EvolutionSettings.maxRequestBudget -
                              EvolutionSettings.minRequestBudget) ~/
                          30,
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(maxRequests: v.round())),
                  hint: getLocalText.s(
                      "Hard stop: every verdict costs up to 3 HTTP probes — the geo check rotates sources"),
                ),
                _costLine(cs, cost),
                _slider(
                  cs,
                  label: getLocalText.s("Elite fraction"),
                  current: _s.eliteFraction,
                  value: '${(_s.eliteFraction * 100).round()} %',
                  min: 0.1,
                  max: 0.6,
                  divisions: 10,
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(eliteFraction: v)),
                  hint: getLocalText.s(
                      "How many top configs feed the frequency model"),
                ),
                _slider(
                  cs,
                  label: getLocalText.s("Mutation rate"),
                  current: _s.mutationRate,
                  value: '${(_s.mutationRate * 100).round()} %',
                  min: 0.02,
                  max: 0.4,
                  divisions: 19,
                  onChanged: (v) => _patch((s) => s.copyWith(mutationRate: v)),
                ),
                _slider(
                  cs,
                  label: getLocalText.s("Immigrant fraction"),
                  current: _s.immigrantFraction,
                  value: '${(_s.immigrantFraction * 100).round()} %',
                  min: 0,
                  max: 0.4,
                  divisions: 8,
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(immigrantFraction: v)),
                  hint: getLocalText.s(
                      "Random newcomers keep the search from collapsing on one answer"),
                ),
                const SizedBox(height: 10),
                _section(cs, getLocalText.s("Probing")),
                _rungs(cs),
                _choice(cs,
                    label: getLocalText.s("Keep fraction per round"),
                    values: const ['0.35', '0.5', '0.7'],
                    selected: _s.rungKeepFraction.toString(),
                    onSelected: (v) => _patch(
                        (s) => s.copyWith(rungKeepFraction: double.parse(v)))),
                _stepper(
                  cs,
                  label: getLocalText.s("Hall of fame size"),
                  value: _s.hallOfFameSize,
                  min: 3,
                  max: 40,
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(hallOfFameSize: v)),
                ),
                _stepper(
                  cs,
                  label: getLocalText.s("Confirmations needed"),
                  value: _s.confirmationsNeeded,
                  min: 1,
                  max: 5,
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(confirmationsNeeded: v)),
                  hint: getLocalText.s(
                      "Separate generations a config must repeat to reach the hall of fame"),
                ),
                _slider(
                  cs,
                  label: getLocalText.s("Pass threshold"),
                  current: _s.minPassRate,
                  value: '${(_s.minPassRate * 100).round()} %',
                  min: 0.2,
                  max: 0.9,
                  divisions: 14,
                  onChanged: (v) => _patch((s) => s.copyWith(minPassRate: v)),
                ),
                _slider(
                  cs,
                  label: getLocalText.s("Request timeout"),
                  current: _s.requestTimeout.inMilliseconds / 1000,
                  value: '${_s.requestTimeout.inMilliseconds / 1000} s',
                  min: 3,
                  max: 20,
                  divisions: 17,
                  onChanged: (v) => _patch(
                      (s) => s.copyWith(
                          requestTimeout:
                              Duration(milliseconds: (v * 1000).round()))),
                ),
                const SizedBox(height: 10),
                _section(cs, getLocalText.s("Mutation space")),
                _choice(
                  cs,
                  label: getLocalText.s("Search operator"),
                  values: const ['eda', 'ga'],
                  selected: _s.useEda ? 'eda' : 'ga',
                  onSelected: (v) =>
                      _patch((s) => s.copyWith(useEda: v == 'eda')),
                  hint: getLocalText.s(
                      "EDA learns which values the winners share; GA recombines two parents"),
                ),
                _chips(cs,
                    label: getLocalText.s("Transports"),
                    all: [for (final t in EvoTransport.values) t.wire],
                    selected: {for (final t in _s.transports) t.wire},
                    captions: {
                      for (final t in EvoTransport.values)
                        t.wire: t.wire == 'awg' ? 'AWG' : t.wire.toUpperCase(),
                    },
                    onSelected: (set) => _patch((s) => s.copyWith(
                          transports: {
                            for (final w in set)
                              EvoTransport.values.firstWhere((t) => t.wire == w),
                          },
                        ))),
                _switch(cs,
                    label: getLocalText.s("TLS fragmentation"),
                    value: _s.allowFragment,
                    onChanged: (v) =>
                        _patch((s) => s.copyWith(allowFragment: v))),
                _switch(cs,
                    label: getLocalText.s("Record fragmentation"),
                    value: _s.allowRecordFragment,
                    onChanged: (v) => _patch(
                        (s) => s.copyWith(allowRecordFragment: v))),
                _chips(cs,
                    label: getLocalText.s("Frozen genes"),
                    all: [for (final l in EvoLocus.values) l.wire],
                    selected: {
                      for (final l in _s.disabledLoci) l.wire,
                      _lockedLocus.wire,
                    },
                    locked: {_lockedLocus.wire},
                    captions: {
                      for (final l in EvoLocus.values)
                        l.wire: getLocalText.s(locusUiKey(l)),
                    },
                    onSelected: (set) => _patch((s) => s.copyWith(
                          disabledLoci: {
                            for (final w in set)
                              EvoLocus.values.firstWhere((l) => l.wire == w),
                          },
                        ))),
                if (_s.countries.isNotEmpty)
                  Text(
                    getLocalText.s(
                      "Countries come from live probes, so the filter only narrows endpoints that are already classified",
                    ),
                    style: TextStyle(fontSize: 11, color: cs.tertiary),
                  ),
                _chips(cs,
                    label: getLocalText.s("Endpoint countries"),
                    all: widget.countries,
                    selected: _s.countries.toSet(),
                    emptyLabel: getLocalText.s("All countries"),
                    onSelected: (set) => _patch(
                        (s) => s.copyWith(countries: set.toList()..sort()))),
                _chips(cs,
                    label: getLocalText.s("Target exit country"),
                    all: widget.countries,
                    selected: _s.targetCountry.isEmpty
                        ? <String>{}
                        : {_s.targetCountry},
                    single: true,
                    emptyLabel: getLocalText.s("Any country"),
                    onSelected: (set) => _patch((s) => s.copyWith(
                        targetCountry: set.isEmpty ? '' : set.last))),
                const SizedBox(height: 10),
                _section(cs, getLocalText.s("Reproducibility")),
                TextField(
                  controller: _seed,
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(
                    labelText: getLocalText.s("Random seed"),
                    helperText: getLocalText.s(
                        "0 restarts randomly each run; a fixed number repeats the campaign"),
                    helperMaxLines: 2,
                    border: const OutlineInputBorder(),
                    isDense: true,
                  ),
                  onChanged: (v) =>
                      _patch((s) => s.copyWith(seed: int.tryParse(v) ?? 0)),
                ),
                const SizedBox(height: 10),
                _poolInventory(cs),
              ],
            ),
          ),
          SafeArea(
            minimum: const EdgeInsets.fromLTRB(16, 6, 16, 12),
            child: Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: Text(getLocalText.s('Cancel')),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: _s.transports.isEmpty ? null : () => Navigator.of(context).pop(_s),
                    child: Text(getLocalText.s('Apply')),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _poolInventory(ColorScheme cs) => Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: cs.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Wrap(
          spacing: 8,
          runSpacing: 6,
          children: [
            _InfoChip(
              icon: Icons.lan_outlined,
              label: getLocalText.s("Endpoints available"),
              value: '${widget.endpoints}',
            ),
            _InfoChip(icon: Icons.lock_outline, label: "SNI", value: '${widget.sni}'),
            _InfoChip(icon: Icons.dns_outlined, label: "DNS", value: '${widget.dns}'),
            _InfoChip(
              icon: Icons.eco,
              label: getLocalText.s("Seeds"),
              value: '${widget.seeds}',
            ),
          ],
        ),
      );

  Widget _costLine(ColorScheme cs, int cost) {
    final over = cost > _s.maxRequests;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Text(
        over
            ? getLocalText.s(
                "Estimated %1\$s requests for the full run — budget %2\$s will cut it short",
                '$cost',
                '${_s.maxRequests}',
              )
            : getLocalText.s(
                "Estimated %1\$s requests for the full run",
                '$cost',
              ),
        style: TextStyle(
            fontSize: 11,
            color: over ? cs.tertiary : cs.onSurfaceVariant),
      ),
    );
  }

  Widget _rungs(ColorScheme cs) {
    const presets = <List<int>>[
      [1],
      [1, 2],
      [1, 2, 3],
      [1, 2, 4],
    ];
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(getLocalText.s("Probe rounds (successive halving)"),
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
          const SizedBox(height: 4),
          Wrap(
            spacing: 6,
            children: [
              for (final p in presets)
                ChoiceChip(
                  label: Text(p.map((e) => '$e').join(' + ')),
                  selected: _s.rungAttempts.join(',') == p.join(','),
                  onSelected: (_) =>
                      _patch((s) => s.copyWith(rungAttempts: p)),
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _section(ColorScheme cs, String title) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(
          title,
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w800,
            letterSpacing: 0.4,
            color: cs.primary,
          ),
        ),
      );

  Widget _slider(
    ColorScheme cs, {
    required String label,
    required double current,
    required String value,
    required double min,
    required double max,
    required int divisions,
    required ValueChanged<double> onChanged,
    String? hint,
  }) =>
      Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(label,
                    style: TextStyle(fontSize: 12, color: cs.onSurface)),
              ),
              Text(value,
                  style: const TextStyle(
                      fontSize: 12, fontWeight: FontWeight.w700)),
            ],
          ),
          Slider(
            value: current.clamp(min, max),
            min: min,
            max: max,
            divisions: divisions < 1 ? null : divisions,
            label: value,
            onChanged: onChanged,
          ),
          if (hint != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Text(hint,
                  style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant)),
            ),
        ],
      );

  Widget _stepper(ColorScheme cs, {
    required String label,
    required int value,
    required int min,
    required int max,
    required ValueChanged<int> onChanged,
    String? hint,
  }) =>
      ListTile(
        dense: true,
        contentPadding: EdgeInsets.zero,
        title: Text(label, style: TextStyle(fontSize: 12)),
        subtitle: hint == null
            ? null
            : Text(hint,
                style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant)),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              onPressed: value > min ? () => onChanged(value - 1) : null,
              icon: const Icon(Icons.remove_circle_outline, size: 18),
            ),
            SizedBox(
              width: 28,
              child: Text('$value',
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontWeight: FontWeight.w700)),
            ),
            IconButton(
              onPressed: value < max ? () => onChanged(value + 1) : null,
              icon: const Icon(Icons.add_circle_outline, size: 18),
            ),
          ],
        ),
      );

  Widget _switch(ColorScheme cs,
          {required String label,
          required bool value,
          required ValueChanged<bool> onChanged}) =>
      SwitchListTile.adaptive(
        dense: true,
        contentPadding: EdgeInsets.zero,
        title: Text(label, style: const TextStyle(fontSize: 12)),
        value: value,
        onChanged: onChanged,
      );

  Widget _choice(ColorScheme cs, {
    required String label,
    required List<String> values,
    required String selected,
    required ValueChanged<String> onSelected,
    String? hint,
  }) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label,
                style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 4),
            Wrap(
              spacing: 6,
              children: [
                for (final v in values)
                  ChoiceChip(
                    label: Text(_choiceCaption(v)),
                    selected: selected == v,
                    onSelected: (_) => onSelected(v),
                  ),
              ],
            ),
            if (hint != null)
              Text(hint,
                  style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant)),
          ],
        ),
      );

  String _choiceCaption(String v) {
    if (v == 'eda') return getLocalText.s("EDA (UMDA)");
    if (v == 'ga') return getLocalText.s("Genetic algorithm");
    final asDouble = double.tryParse(v);
    if (asDouble != null) return '${(asDouble * 100).round()} %';
    return v;
  }

  Widget _chips(ColorScheme cs, {
    required String label,
    required List<String> all,
    required Set<String> selected,
    required ValueChanged<Set<String>> onSelected,
    Map<String, String> captions = const {},
    Set<String> locked = const {},
    String? emptyLabel,
    bool single = false,
  }) {
    if (all.isEmpty) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label,
                style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
            Text(
              emptyLabel ?? getLocalText.s("Nothing to choose from yet"),
              style: TextStyle(fontSize: 11, color: cs.tertiary),
            ),
          ],
        ),
      );
    }
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
          const SizedBox(height: 4),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              for (final v in all)
                FilterChip(
                  label: Text(captions[v] ?? v),
                  selected: selected.contains(v) || locked.contains(v),
                  onSelected: locked.contains(v)
                      ? null
                      : (on) {
                          final next = <String>{...selected};
                          if (single) {
                            next
                              ..clear()
                              ..addAll(on ? {v} : const <String>{});
                          } else if (on) {
                            next.add(v);
                          } else {
                            next.remove(v);
                          }
                          onSelected(next);
                        },
                ),
            ],
          ),
        ],
      ),
    );
  }
}
