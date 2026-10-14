// §848 — геном конфигa для эволюционного подбора проходимости.
//
// Геном = набор КАТЕГОРИАЛЬНЫХ локусов: каждый locus принимает значение из
// конечного пула (эндпоинты, порты, SNI, DNS, приманки AWG, тайминги). Это
// осознанный выбор, а не упрощение: пространство обхода DPI — комбинации
// дискретных настроек, и именно поэтому здесь работает EDA (оценка частот
// аллелей по элите), а не CMA-ES, который заточен под непрерывные параметры.
//
// Второе следствие: геном не хранит «своё» представление конфига. Единственный
// источник истины — штатный эмиттер (`ScanNodeBuilder` → URI → `parseLinkViaPipeline`
// → `NodeSpec.emit`), а геном описывает только ТО, что в этом теле меняется
// ([Genome.applyTo]). Значит, про эволюцию нельзя сказать «соберёт конфиг
// минуя валидацию»: патч уходит в `patchedJson`, то есть через тот же гард
// реестра и те же post-steps, что и боевая сборка (см. probe_config.dart).
//
// Третье: мутация может сделать тело негодным (например `tls.fragment` на
// MASQUE-h3, где связь `conflicts` реестра его снимает). Поэтому [applyTo]
// спрашивает годность поля у реестра ([fieldAllowedOn]), а не держит список
// разрешений здесь.

import 'dart:convert';
import 'dart:math';

import '../../models/node_spec.dart' show deepCopyJson;
import '../contract/body_sanitizer.dart' show fieldAllowedOn;
import '../warp/scan/scan_models.dart';

/// Транспорт узла в терминах эволюции. Совпадает с [ScanProtocol]: AWG =
/// WireGuard + AmneziaWG-обфускация (голый WG DPI режет охотнее).
enum EvoTransport {
  awg('awg'),
  masqueH3('h3'),
  masqueH2('h2');

  const EvoTransport(this.wire);
  final String wire;

  bool get isMasque => this != EvoTransport.awg;

  ScanProtocol get scanProtocol => switch (this) {
        EvoTransport.awg => ScanProtocol.awg,
        EvoTransport.masqueH3 => ScanProtocol.masqueH3,
        EvoTransport.masqueH2 => ScanProtocol.masqueH2,
      };

  static EvoTransport fromWire(String w) => EvoTransport.values.firstWhere(
        (t) => t.wire == w,
        orElse: () => EvoTransport.awg,
      );
}

/// Локусы генома. Порядок — порядок обхода в модели аллелей и в [Genome.tokens].
enum EvoLocus {
  transport,
  endpoint,
  port,
  sni,
  keepalive,
  mtu,
  junkProto,
  junkBrowser,
  junkDomain,
  jc,
  jitterMin,
  jitterMax,
  fragment,
  recordFragment,
  sniCase,
  dns;

  String get wire => name;
}

/// Значения локусов как строки — единый язык для частотной модели (EDA),
/// сравнения «на сколько геномы различаются» и сериализации. Типизированные
/// поля [Genome] остаются для сборки конфига.
typedef GeneTokens = Map<EvoLocus, String>;

/// Один кандидат в выходные точки.
///
/// Все поля — значения, которые реально пишутся в тело узла; `0`/`''` означает
/// «ключ не писать» (ядро тогда берёт своё умолчание), это же и значение гена
/// «по умолчанию».
class Genome {
  const Genome({
    required this.transport,
    required this.endpoint,
    required this.port,
    this.sni = '',
    this.keepalive = 0,
    this.mtu = 0,
    this.junkProto = 'quic',
    this.junkBrowser = 'chrome',
    this.junkDomain = '',
    this.jc = 4,
    this.jitterMin = 40,
    this.jitterMax = 70,
    this.fragment = false,
    this.recordFragment = false,
    this.sniCase = 0,
    this.dnsTag = '',
  });

  final EvoTransport transport;

  /// Хост без порта (IP-литерал или домен).
  final String endpoint;
  final int port;

  /// SNI/MASQUE `tls.server_name` (для AWG — приманка `id`).
  final String sni;

  /// WG/AWG: `peers[].persistent_keepalive_interval`, сек. MASQUE:
  /// `keep_alive_period` (сек). `0` — не писать.
  final int keepalive;

  /// `mtu` интерфейса. `0` — не писать (у MASQUE билдер пишет 1280).
  final int mtu;

  // ── AWG-обфускация (только [EvoTransport.awg]) ──────────────────────────
  /// `ip` — протокол приманки: `quic` | `dns` | `stun` | `sip`.
  final String junkProto;

  /// `ib` — браузер приманки (осмысленно только при `junkProto == quic`).
  final String junkBrowser;

  /// `id` — домен маскировки; пустой → берётся [sni].
  final String junkDomain;

  /// `jc` — сколько junk-пакетов перед handshake.
  final int jc;

  /// `jmin`/`jmax` — размер junk-пакетов.
  final int jitterMin;
  final int jitterMax;

  // ── TLS-трансформы (только там, где реестр их разрешает) ────────────────
  final bool fragment;
  final bool recordFragment;

  /// Смешанный регистр SNI (ломает exact-match DPI; RFC 6066 — SNI не
  /// чувствителен к регистру). `0` = выкл, иначе — детерминированный seed:
  /// один и тот же геном всегда даёт один и тот же вариант регистра, иначе
  /// фитнес был бы невоспроизводим.
  final int sniCase;

  /// Тег DNS-резолвера из хранилища настроек; `''` = штатный local-резолвер.
  final String dnsTag;

  // ── идентичность ────────────────────────────────────────────────────────

  /// Каноническая строка особи. Ею сопоставляются повторные наблюдения одного
  /// и того же кандидата между поколениями (гистерезис архива) и снимается
  /// дублирование посева.
  String get key => tokens().entries.map((e) => '${e.key.wire}=${e.value}').join('|');

  /// Значения всех локусов в строковой форме.
  GeneTokens tokens() => {
        EvoLocus.transport: transport.wire,
        EvoLocus.endpoint: endpoint,
        EvoLocus.port: '$port',
        EvoLocus.sni: sni,
        EvoLocus.keepalive: '$keepalive',
        EvoLocus.mtu: '$mtu',
        EvoLocus.junkProto: junkProto,
        EvoLocus.junkBrowser: junkBrowser,
        EvoLocus.junkDomain: junkDomain,
        EvoLocus.jc: '$jc',
        EvoLocus.jitterMin: '$jitterMin',
        EvoLocus.jitterMax: '$jitterMax',
        EvoLocus.fragment: fragment ? '1' : '0',
        EvoLocus.recordFragment: recordFragment ? '1' : '0',
        EvoLocus.sniCase: '$sniCase',
        EvoLocus.dns: dnsTag,
      };

  static Genome fromTokens(GeneTokens t) => Genome(
        transport: EvoTransport.fromWire(t[EvoLocus.transport] ?? 'awg'),
        endpoint: t[EvoLocus.endpoint] ?? '',
        port: int.tryParse(t[EvoLocus.port] ?? '') ?? 2408,
        sni: t[EvoLocus.sni] ?? '',
        keepalive: int.tryParse(t[EvoLocus.keepalive] ?? '') ?? 0,
        mtu: int.tryParse(t[EvoLocus.mtu] ?? '') ?? 0,
        junkProto: t[EvoLocus.junkProto] ?? 'quic',
        junkBrowser: t[EvoLocus.junkBrowser] ?? 'chrome',
        junkDomain: t[EvoLocus.junkDomain] ?? '',
        jc: int.tryParse(t[EvoLocus.jc] ?? '') ?? 4,
        jitterMin: int.tryParse(t[EvoLocus.jitterMin] ?? '') ?? 40,
        jitterMax: int.tryParse(t[EvoLocus.jitterMax] ?? '') ?? 70,
        fragment: t[EvoLocus.fragment] == '1',
        recordFragment: t[EvoLocus.recordFragment] == '1',
        sniCase: int.tryParse(t[EvoLocus.sniCase] ?? '') ?? 0,
        dnsTag: t[EvoLocus.dns] ?? '',
      );

  Genome copyWith({
    EvoTransport? transport,
    String? endpoint,
    int? port,
    String? sni,
    int? keepalive,
    int? mtu,
    String? junkProto,
    String? junkBrowser,
    String? junkDomain,
    int? jc,
    int? jitterMin,
    int? jitterMax,
    bool? fragment,
    bool? recordFragment,
    int? sniCase,
    String? dnsTag,
  }) =>
      Genome(
        transport: transport ?? this.transport,
        endpoint: endpoint ?? this.endpoint,
        port: port ?? this.port,
        sni: sni ?? this.sni,
        keepalive: keepalive ?? this.keepalive,
        mtu: mtu ?? this.mtu,
        junkProto: junkProto ?? this.junkProto,
        junkBrowser: junkBrowser ?? this.junkBrowser,
        junkDomain: junkDomain ?? this.junkDomain,
        jc: jc ?? this.jc,
        jitterMin: jitterMin ?? this.jitterMin,
        jitterMax: jitterMax ?? this.jitterMax,
        fragment: fragment ?? this.fragment,
        recordFragment: recordFragment ?? this.recordFragment,
        sniCase: sniCase ?? this.sniCase,
        dnsTag: dnsTag ?? this.dnsTag,
      );

  Map<String, dynamic> toJson() => {'key': key, ..._typed()};

  Map<String, Object> _typed() => {
        'transport': transport.wire,
        'endpoint': endpoint,
        'port': port,
        'sni': sni,
        'keepalive': keepalive,
        'mtu': mtu,
        'junkProto': junkProto,
        'junkBrowser': junkBrowser,
        'junkDomain': junkDomain,
        'jc': jc,
        'jitterMin': jitterMin,
        'jitterMax': jitterMax,
        'fragment': fragment,
        'recordFragment': recordFragment,
        'sniCase': sniCase,
        'dnsTag': dnsTag,
      };

  static Genome fromJson(Map<String, dynamic> j) => Genome(
        transport: EvoTransport.fromWire('${j['transport'] ?? 'awg'}'),
        endpoint: '${j['endpoint'] ?? ''}',
        port: (j['port'] as num?)?.toInt() ?? 2408,
        sni: '${j['sni'] ?? ''}',
        keepalive: (j['keepalive'] as num?)?.toInt() ?? 0,
        mtu: (j['mtu'] as num?)?.toInt() ?? 0,
        junkProto: '${j['junkProto'] ?? 'quic'}',
        junkBrowser: '${j['junkBrowser'] ?? 'chrome'}',
        junkDomain: '${j['junkDomain'] ?? ''}',
        jc: (j['jc'] as num?)?.toInt() ?? 4,
        jitterMin: (j['jitterMin'] as num?)?.toInt() ?? 40,
        jitterMax: (j['jitterMax'] as num?)?.toInt() ?? 70,
        fragment: j['fragment'] == true,
        recordFragment: j['recordFragment'] == true,
        sniCase: (j['sniCase'] as num?)?.toInt() ?? 0,
        dnsTag: '${j['dnsTag'] ?? ''}',
      );

  String get json => jsonEncode(_typed());

  /// Доля локусов, которые различаются (0..1). Нужна не для отбора, а для
  /// честной картинки в UI: «популяция разошлась по X из 16 параметров».
  double distanceTo(Genome other) {
    final a = tokens();
    final b = other.tokens();
    var diff = 0;
    for (final l in EvoLocus.values) {
      if (a[l] != b[l]) diff++;
    }
    return diff / EvoLocus.values.length;
  }

  /// Человек-readable подпись особи для таблицы: `h2 · 162.159.198.2:8443 · cdg01`.
  String get shortLabel {
    final host = endpoint.isEmpty ? '—' : endpoint;
    final tail = sni.isEmpty ? '' : ' · $sni';
    return '${transport.wire} · $host:$port$tail';
  }

  // ── сборка тела ─────────────────────────────────────────────────────────

  /// `host:port` (IPv6 в скобках) — как в [ScanCandidate.endpoint].
  String get endpointHostPort =>
      endpoint.contains(':') ? '[$endpoint]:$port' : '$endpoint:$port';

  /// Кандидат для штатного билдера узлов.
  ScanCandidate toCandidate() => ScanCandidate(
        ip: endpoint,
        port: port,
        protocol: transport.scanProtocol,
        sni: transport == EvoTransport.awg
            ? (junkDomain.isNotEmpty ? junkDomain : sni)
            : sni,
        awgParams: transport == EvoTransport.awg
            ? AwgParams(
                ip: junkProto,
                jc: jc,
                jmin: jitterMin,
                jmax: jitterMax,
              )
            : null,
      );

  /// Превращает ЭМИТИРОВАННОЕ тело узла (result of `NodeSpec.emit`) в тело этого
  /// генома. Возвращает новый map; вход не мутируется.
  ///
  /// Пишутся только те поля, которые реестр считает годными для данного тела
  /// ([fieldAllowedOn]) — иначе ядро отвергло бы весь probe-конфиг из-за одной
  /// мутации, и эволюция теряла бы кандидатов на ровном месте.
  Map<String, dynamic> applyTo(Map<String, dynamic> base) {
    final body = deepCopyJson(base) as Map<String, dynamic>;
    final isMasque = body['type'] == 'masque';
    if (isMasque) {
      body['server'] = endpoint;
      body['server_port'] = port;
      body['vhttp'] = transport == EvoTransport.masqueH3 ? 'h3' : 'h2';
      if (keepalive > 0) {
        body['keep_alive_period'] = '${keepalive}s';
      } else {
        body.remove('keep_alive_period');
      }
      if (mtu > 0 && fieldAllowedOn(body, 'mtu')) body['mtu'] = mtu;
      final tls = _tlsBlock(body);
      final name = sniCase > 0 && sni.isNotEmpty
          ? caseShuffle(sni, sniCase)
          : sni;
      if (name.isEmpty) {
        tls.remove('server_name');
      } else {
        tls['server_name'] = name;
      }
      _applyFragment(body, tls);
      if (tls.isEmpty) {
        body.remove('tls');
      } else {
        body['tls'] = tls;
      }
      return body;
    }
    // WireGuard/AmneziaWG: endpoint-запись, адреса пиров в `peers[]`.
    final peers = (body['peers'] as List?)?.cast<Map<String, dynamic>>() ??
        <Map<String, dynamic>>[];
    for (final p in peers) {
      p['address'] = endpoint;
      p['port'] = port;
      if (keepalive > 0) {
        p['persistent_keepalive_interval'] = keepalive;
      } else {
        p.remove('persistent_keepalive_interval');
      }
    }
    if (mtu > 0 && fieldAllowedOn(body, 'mtu')) {
      body['mtu'] = mtu;
    } else if (mtu == 0) {
      body.remove('mtu');
    }
    // AWG-поля живут в корне endpoint'а (Awg.writeInto). Голый WG (без `jc`)
    // мутация приманки не касается: добавлять их к WG-узлу нельзя.
    if (body.containsKey('jc') || body.containsKey('ip')) {
      body['ip'] = junkProto;
      body['id'] = junkDomain.isNotEmpty ? junkDomain : sni;
      if (junkProto == 'quic') {
        body['ib'] = junkBrowser;
      } else {
        body.remove('ib');
      }
      body['jc'] = jc;
      body['jmin'] = jitterMin;
      body['jmax'] = jitterMax;
    }
    return body;
  }

  /// `tls.fragment`/`record_fragment` + `fragment_fallback_delay`. Годность
  /// спрашивается у реестра ПОСЛЕ того, как в тело уже лег `vhttp` (связь
  /// `conflicts` у фрагментации именно с `vhttp: h3`).
  void _applyFragment(Map<String, dynamic> body, Map<String, dynamic> tls) {
    final canFragment = fragment && fieldAllowedOn(body, 'tls.fragment');
    final canRecord =
        recordFragment && fieldAllowedOn(body, 'tls.record_fragment');
    if (!canFragment && !canRecord) {
      tls.remove('fragment');
      tls.remove('record_fragment');
      tls.remove('fragment_fallback_delay');
      return;
    }
    if (canFragment) tls['fragment'] = true;
    if (canRecord) tls['record_fragment'] = true;
    tls['fragment_fallback_delay'] = '500ms';
  }

  Map<String, dynamic> _tlsBlock(Map<String, dynamic> body) {
    final t = body['tls'];
    return t is Map<String, dynamic>
        ? Map<String, dynamic>.from(t)
        : <String, dynamic>{};
  }
}

/// Смешанный регистр хоста по детерминированному seed (тот же алгоритм, что у
/// post-step'а `tls_mixed_case_sni`: Punycode-метки `xn--` не трогаем — там
/// регистр значим).
String caseShuffle(String host, int seed) {
  if (seed == 0) return host;
  final rng = Random(seed);
  final labels = host.split('.');
  for (var i = 0; i < labels.length; i++) {
    final label = labels[i];
    if (label.startsWith('xn--')) continue;
    final buf = StringBuffer();
    for (final cu in label.codeUnits) {
      final isUpper = cu >= 0x41 && cu <= 0x5A;
      final isLower = cu >= 0x61 && cu <= 0x7A;
      if (isUpper || isLower) {
        buf.writeCharCode(rng.nextBool() ? (cu | 0x20) : (cu & ~0x20));
      } else {
        buf.writeCharCode(cu);
      }
    }
    labels[i] = buf.toString();
  }
  return labels.join('.');
}
