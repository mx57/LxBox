// §848 — мутационные пулы (аллельные домены) эволюции.
//
// Это тот самый «выбор списков для мутаций» из настройки: эндпоинты по странам,
// SNI (белые списки провайдеров), DNS-резолверы, транспорты, тайминги. Модель
// аллелей умеет переписывать только ЗНАЧЕНИЯ ИЗ ПУЛА — пул поэтому и границы
// поиска, и гарантия, что эволюция не уедет в адрес, которого нет в asset'е.
//
// Всё приходит из уже существующих источников истины: [ScanPool] (asset +
// секция региона + результат скана), хранилище DNS, список SNI фазы 4. Новой
// копии данных здесь нет намеренно.

import 'dart:math';

import '../warp/scan/scan_pool.dart';
import 'genome.dart';

/// Домен значений одного локуса + выборка из него.
class Alleles {
  const Alleles(this.values);
  static const Alleles empty = Alleles(<String>[]);

  final List<String> values;

  bool get isEmpty => values.isEmpty;
  int get length => values.length;

  String pick(Random rng) =>
      values.isEmpty ? '' : values[rng.nextInt(values.length)];
}

/// То, откуда движок берёт аллели: настоящий пул или пул с выключенными
/// локусами ([RestrictedPools]). Вынесено в интерфейс именно из-за пустого
/// значения: «пустой домен = локус не мутируется» — единственный способ
/// пользователя зафиксировать параметр, не переписывая модель.
abstract class AlleleSource {
  Alleles alleles(EvoLocus locus, {Iterable<String> countries});
  Genome random(Random rng, {Iterable<String> countries});
  List<int> portsFor(EvoTransport t);
}

/// Набор пулов, из которых эволюция собирает и мутирует геномы.
class EvolutionPools implements AlleleSource {
  const EvolutionPools({
    this.transports = const {EvoTransport.awg, EvoTransport.masqueH3,
        EvoTransport.masqueH2},
    this.endpoints = const [],
    this.endpointsByCountry = const {},
    this.wgPorts = const [2408, 500, 1701, 4500],
    this.h3Ports = const [443, 4443, 8095],
    this.h2Ports = const [500, 4500, 8443],
    this.sni = const [],
    this.dnsTags = const [],
    this.junkProtocols = const ['quic', 'dns', 'stun', 'sip'],
    this.junkBrowsers = const ['chrome', 'firefox', 'curl'],
    this.keepalives = const [0, 15, 25, 30, 60],
    this.mtus = const [0, 1280, 1400, 1420],
    this.junkCounts = const [0, 2, 4, 6, 8],
    this.junkSizeMins = const [0, 20, 40, 64],
    this.junkSizeMaxs = const [40, 70, 128, 256],
    this.sniCaseSeeds = const [0, 1, 2, 3],
    this.fragment = true,
    this.recordFragment = true,
  });

  final Set<EvoTransport> transports;

  /// Все известные адреса (без порта). Дефолтный домен локуса `endpoint`.
  final List<String> endpoints;

  /// Код страны → адреса. Даёт фильтр «мутировать только по выбранным странам»;
  /// пустой ключ `''` — адреса, у которых страна не определена.
  final Map<String, List<String>> endpointsByCountry;

  final List<int> wgPorts;
  final List<int> h3Ports;
  final List<int> h2Ports;

  /// SNI-домены (для MASQUE — `tls.server_name`, для AWG — приманка `id`).
  final List<String> sni;

  /// Теги DNS-серверов из хранилища настроек; `''` (штатный local) всегда
  /// допустим как значение.
  final List<String> dnsTags;

  final List<String> junkProtocols;
  final List<String> junkBrowsers;
  final List<int> keepalives;
  final List<int> mtus;
  final List<int> junkCounts;
  final List<int> junkSizeMins;
  final List<int> junkSizeMaxs;

  /// Variants mixed-case SNI: 0 = выкл, остальные — seed'ы преобразования.
  final List<int> sniCaseSeeds;

  /// Разрешены ли мутации по фрагментации вообще (выключатель в настройках).
  final bool fragment;
  final bool recordFragment;

  /// Адреса, доступные при текущем выборе стран. Пустой [countries] = все.
  List<String> endpointsFor(Iterable<String> countries) {
    if (countries.isEmpty) return endpoints;
    final out = <String>[];
    final seen = <String>{};
    for (final c in countries) {
      for (final e in endpointsByCountry[c] ?? const <String>[]) {
        if (seen.add(e)) out.add(e);
      }
    }
    return out.isEmpty ? endpoints : out;
  }

  @override
  List<int> portsFor(EvoTransport t) => switch (t) {
        EvoTransport.awg => wgPorts,
        EvoTransport.masqueH3 => h3Ports,
        EvoTransport.masqueH2 => h2Ports,
      };

  /// Домен значений локуса с учётом текущих ограничений (транспорты, страны).
  /// Пустой список означает «локус не мутируется» — вызывающий тогда оставляет
  /// прежнее значение.
  @override
  Alleles alleles(EvoLocus locus, {Iterable<String> countries = const []}) {
    switch (locus) {
      case EvoLocus.transport:
        // Пустое поле = «не ограничивать» — так же, как в [random].
        final t = (transports.isEmpty ? EvoTransport.values : transports).toList();
        return Alleles([for (final x in t) x.wire]);
      case EvoLocus.endpoint:
        final eps = endpointsFor(countries);
        return eps.isEmpty ? Alleles.empty : Alleles(eps);
      case EvoLocus.port:
        final all = <int>{...wgPorts, ...h3Ports, ...h2Ports};
        return all.isEmpty
            ? const Alleles(['443'])
            : Alleles([for (final p in all) '$p']);
      case EvoLocus.sni:
        return sni.isEmpty ? Alleles.empty : Alleles(sni);
      case EvoLocus.keepalive:
        return Alleles([for (final v in keepalives) '$v']);
      case EvoLocus.mtu:
        return Alleles([for (final v in mtus) '$v']);
      case EvoLocus.junkProto:
        return Alleles(junkProtocols);
      case EvoLocus.junkBrowser:
        return Alleles(junkBrowsers);
      case EvoLocus.junkDomain:
        return sni.isEmpty ? const Alleles(['']) : Alleles(sni);
      case EvoLocus.jc:
        return Alleles([for (final v in junkCounts) '$v']);
      case EvoLocus.jitterMin:
        return Alleles([for (final v in junkSizeMins) '$v']);
      case EvoLocus.jitterMax:
        return Alleles([for (final v in junkSizeMaxs) '$v']);
      case EvoLocus.fragment:
        return Alleles(fragment ? const ['0', '1'] : const ['0']);
      case EvoLocus.recordFragment:
        return Alleles(recordFragment ? const ['0', '1'] : const ['0']);
      case EvoLocus.sniCase:
        return Alleles([for (final v in sniCaseSeeds) '$v']);
      case EvoLocus.dns:
        return Alleles(['', ...dnsTags]);
    }
  }

  /// Случайный геном (иммигрант / посев). Локусы, у которых пул пуст, остаются
  /// на значениях по умолчанию — это честнее, чем выдумывать адрес.
  @override
  Genome random(Random rng, {Iterable<String> countries = const []}) {
    final trList = (transports.isEmpty ? EvoTransport.values : transports)
        .toList();
    final transport = trList[rng.nextInt(trList.length)];
    final eps = endpointsFor(countries);
    final ports = portsFor(transport);
    String v(EvoLocus l) => alleles(l, countries: countries).pick(rng);
    return Genome(
      transport: transport,
      endpoint: eps.isEmpty
          ? ''
          : eps[rng.nextInt(eps.length)],
      port: ports.isEmpty ? 443 : ports[rng.nextInt(ports.length)],
      sni: v(EvoLocus.sni),
      keepalive: int.tryParse(v(EvoLocus.keepalive)) ?? 0,
      mtu: int.tryParse(v(EvoLocus.mtu)) ?? 0,
      junkProto: v(EvoLocus.junkProto),
      junkBrowser: v(EvoLocus.junkBrowser),
      junkDomain: '',
      jc: int.tryParse(v(EvoLocus.jc)) ?? 4,
      jitterMin: int.tryParse(v(EvoLocus.jitterMin)) ?? 40,
      jitterMax: int.tryParse(v(EvoLocus.jitterMax)) ?? 70,
      fragment: v(EvoLocus.fragment) == '1',
      recordFragment: v(EvoLocus.recordFragment) == '1',
      sniCase: int.tryParse(v(EvoLocus.sniCase)) ?? 0,
      dnsTag: v(EvoLocus.dns),
    );
  }

  /// Пул из штатного [ScanPool] (asset + регион + результат скана). SNI и DNS
  /// приходят отдельными аргументами: их выбирает пользователь на экране
  /// сканера (§847), и здесь они просто становятся доменом мутаций.
  static EvolutionPools fromScanPool(
    ScanPool? pool, {
    List<String> sniOverride = const [],
    List<String> dnsTags = const [],
    Map<String, List<String>> endpointsByCountry = const {},
    Set<EvoTransport> transports = const {
      EvoTransport.awg,
      EvoTransport.masqueH3,
      EvoTransport.masqueH2,
    },
  }) {
    final sniPool = <String>{
      ...sniOverride,
      if (pool != null) ...pool.wgSniPool,
      if (pool != null) ...pool.masqueSniPool,
    }.toList();
    final endpoints = <String>{
      ...endpointsByCountry.values.expand((e) => e),
      if (pool != null) ...pool.wgEndpointsPreset.map(endpointHost),
      if (pool != null) ...pool.masqueHostsPreset,
      ...?pool?.wgV4Cidr.map(_blockHost),
    }.where((e) => e.isNotEmpty).toList();
    return EvolutionPools(
      transports: transports,
      endpoints: endpoints,
      endpointsByCountry: endpointsByCountry,
      wgPorts: pool != null && pool.wgPorts.isNotEmpty
          ? [...pool.wgPorts, ...pool.wgPortsExtra]
          : const [2408, 500, 1701, 4500],
      h3Ports: pool?.masquePortsH3.isNotEmpty ?? false
          ? pool!.masquePortsH3
          : const [443, 4443, 8095],
      h2Ports: pool?.masquePortsH2.isNotEmpty ?? false
          ? pool!.masquePortsH2
          : const [500, 4500, 8443],
      sni: sniPool,
      dnsTags: dnsTags,
    );
  }

  /// CIDR → «первый адрес блока» как маркер пула: сам по себе он не кандидат
  /// (адреса эволюция берёт из `endpointsByCountry`), нужен, чтобы при пустом
  /// скане хоть что-то осталось в домене локуса.
  static String _blockHost(String cidr) {
    final slash = cidr.indexOf('/');
    return slash < 0 ? cidr : cidr.substring(0, slash);
  }
}

/// Пул с выключенными локусами: «зафиксировать параметр» = вернуть пустой
/// домен, и [mutate]/[AlleleModel.sample] оставляют прежнее значение. Никакого
/// второго механизма заморозки в движке нет специально.
class RestrictedPools implements AlleleSource {
  const RestrictedPools(
    this.base, {
    this.transports = const {},
    this.disabledLoci = const {},
    this.fragment = true,
    this.recordFragment = true,
  });

  final EvolutionPools base;

  /// Разрешённые транспорты; пустое множество = «не ограничивать» (домен берётся
  /// из [base]). Фильтр здесь, а не только при сборке [base], потому что
  /// настройки меняются после пула: экран строит пул из asset'а один раз, а
  /// галки транспортов пользователь крутит на каждой кампании.
  final Set<EvoTransport> transports;

  final Set<EvoLocus> disabledLoci;

  /// Выключатель мутаций фрагментации (у MASQUE-h3 он и так снимается
  /// реестром, здесь — воля пользователя).
  final bool fragment;
  final bool recordFragment;

  @override
  Alleles alleles(EvoLocus locus, {Iterable<String> countries = const []}) {
    if (disabledLoci.contains(locus)) return Alleles.empty;
    switch (locus) {
      case EvoLocus.transport:
        if (transports.isEmpty) {
          return base.alleles(locus, countries: countries);
        }
        final baseWires = base.alleles(locus, countries: countries).values;
        final allowed = [
          for (final t in transports)
            if (baseWires.isEmpty || baseWires.contains(t.wire)) t.wire,
        ];
        // Пустой домен локуса означал бы «не мутировать», а транспорт обязан
        // иметь значение: пересечение пустое (база закрыта другим фильтром) —
        // берем то, что разрешил пользователь, а не первое пришедшее: домен
        // обязан оставаться подмножеством выбора экрана, иначе мутация «уведёт»
        // особь в транспорт, который снят галкой.
        return Alleles(
            allowed.isEmpty ? [for (final t in transports) t.wire] : allowed);
      case EvoLocus.fragment:
        return Alleles(fragment ? const ['0', '1'] : const ['0']);
      case EvoLocus.recordFragment:
        return Alleles(recordFragment ? const ['0', '1'] : const ['0']);
      default:
        return base.alleles(locus, countries: countries);
    }
  }

  @override
  Genome random(Random rng, {Iterable<String> countries = const []}) {
    var g = base.random(rng, countries: countries);
    // Иммигрант обязан быть в разрешённом транспорте, иначе галки «только h2»
    // означали бы «15 % популяции вне поиска». Порт пересемплируем под новый
    // транспорт — у MASQUE и WG свои диапазоны.
    if (transports.isNotEmpty && !transports.contains(g.transport)) {
      final list = transports.toList();
      final t = list[rng.nextInt(list.length)];
      final ports = base.portsFor(t);
      g = g.copyWith(
        transport: t,
        port: ports.isEmpty ? g.port : ports[rng.nextInt(ports.length)],
      );
    }
    // Замороженный локус не должен получать значение и из посева: берём
    // дефолт генома (это же значение, что «ключ не писать в тело»).
    for (final l in disabledLoci) {
      g = switch (l) {
        EvoLocus.fragment => g.copyWith(fragment: false),
        EvoLocus.recordFragment => g.copyWith(recordFragment: false),
        EvoLocus.sniCase => g.copyWith(sniCase: 0),
        EvoLocus.dns => g.copyWith(dnsTag: ''),
        EvoLocus.mtu => g.copyWith(mtu: 0),
        EvoLocus.keepalive => g.copyWith(keepalive: 0),
        EvoLocus.jc => g.copyWith(jc: 0),
        EvoLocus.jitterMin => g.copyWith(jitterMin: 0),
        EvoLocus.jitterMax => g.copyWith(jitterMax: 0),
        _ => g,
      };
    }
    if (!fragment) g = g.copyWith(fragment: false);
    if (!recordFragment) g = g.copyWith(recordFragment: false);
    return g;
  }

  @override
  List<int> portsFor(EvoTransport t) => base.portsFor(t);
}

/// `host:port` → host (IPv6 в скобках). Повтор крошечной логики из scan-слоя,
/// чтобы не тянуть в эволюцию весь `scan_pool` ради одной функции.
String endpointHost(String hostPort) {
  final s = hostPort.trim();
  if (s.startsWith('[')) {
    final close = s.indexOf(']');
    return close < 0 ? s : s.substring(1, close);
  }
  final i = s.lastIndexOf(':');
  if (i <= 0) return s;
  return int.tryParse(s.substring(i + 1)) == null ? s : s.substring(0, i);
}
