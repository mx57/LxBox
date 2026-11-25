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

import '../../models/node_spec.dart' show Awg, deepCopyJson;
import '../contract/body_sanitizer.dart' show fieldAllowedOn;
import '../warp/awg_profile.dart';
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
  awgProfile,
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
    this.awgProfile = AwgProfile.warp15,
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

  static Object normalizeKeepalive(Object? value, {required bool allowRange}) {
    final Object? parsed;
    if (value is int) {
      parsed = value;
    } else if (value is double) {
      if (!value.isFinite) return 0;
      parsed = value.toInt();
    } else if (value is String) {
      parsed = Awg.parseAwg3Range(value);
    } else {
      return 0;
    }
    if (parsed is int) return parsed > 0 ? parsed : 0;
    return allowRange && parsed is String ? parsed : 0;
  }

  final EvoTransport transport;

  bool get isVerbatim => false;

  /// §740 — профиль WARP-декоя. Для MASQUE не влияет на тело.
  final AwgProfile awgProfile;

  /// Хост без порта (IP-литерал или домен).
  final String endpoint;
  final int port;

  /// SNI/MASQUE `tls.server_name` (для AWG — приманка `id`).
  final String sni;

  /// WG/AWG: `peers[].persistent_keepalive_interval`, сек. — положительное
  /// число или AWG3-диапазон `"N-M"`. MASQUE: `keep_alive_period`, только
  /// положительное число. `0` — не писать.
  final Object keepalive;

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
  String get key =>
      tokens().entries.map((e) => '${e.key.wire}=${e.value}').join('|');

  /// Значения всех локусов в строковой форме.
  GeneTokens tokens() => {
        EvoLocus.transport: transport.wire,
        EvoLocus.awgProfile: awgProfile.wire,
        EvoLocus.endpoint: endpoint,
        EvoLocus.port: '$port',
        EvoLocus.sni: sni,
        EvoLocus.keepalive:
            '${normalizeKeepalive(keepalive, allowRange: !transport.isMasque)}',
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

  static Genome fromTokens(GeneTokens t) {
    final transport = EvoTransport.fromWire(t[EvoLocus.transport] ?? 'awg');
    return Genome(
      transport: transport,
      awgProfile: AwgProfile.fromWire(t[EvoLocus.awgProfile]),
      endpoint: t[EvoLocus.endpoint] ?? '',
      port: int.tryParse(t[EvoLocus.port] ?? '') ?? 2408,
      sni: t[EvoLocus.sni] ?? '',
      keepalive: normalizeKeepalive(
        t[EvoLocus.keepalive],
        allowRange: !transport.isMasque,
      ),
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
  }

  Genome copyWith({
    EvoTransport? transport,
    AwgProfile? awgProfile,
    String? endpoint,
    int? port,
    String? sni,
    Object? keepalive,
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
  }) {
    final nextTransport = transport ?? this.transport;
    return Genome(
      transport: nextTransport,
      awgProfile: awgProfile ?? this.awgProfile,
      endpoint: endpoint ?? this.endpoint,
      port: port ?? this.port,
      sni: sni ?? this.sni,
      keepalive: normalizeKeepalive(
        keepalive ?? this.keepalive,
        allowRange: !nextTransport.isMasque,
      ),
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
  }

  Map<String, dynamic> toJson() => {'key': key, ..._typed()};

  Map<String, Object> _typed() => {
        'transport': transport.wire,
        'awgProfile': awgProfile.wire,
        'endpoint': endpoint,
        'port': port,
        'sni': sni,
        'keepalive':
            normalizeKeepalive(keepalive, allowRange: !transport.isMasque),
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

  static Genome fromJson(Map<String, dynamic> j) {
    final transport = EvoTransport.fromWire('${j['transport'] ?? 'awg'}');
    return Genome(
      transport: transport,
      awgProfile: AwgProfile.fromWire(j['awgProfile'] as String?),
      endpoint: '${j['endpoint'] ?? ''}',
      port: (j['port'] as num?)?.toInt() ?? 2408,
      sni: '${j['sni'] ?? ''}',
      keepalive: normalizeKeepalive(
        j['keepalive'],
        allowRange: !transport.isMasque,
      ),
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
  }

  String get json => jsonEncode(_typed());

  /// Доля локусов, которые различаются (0..1). Нужна не для отбора, а для
  /// честной картинки в UI: «популяция разошлась по X параметров».
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
    final profile =
        transport == EvoTransport.awg ? ' · ${awgProfile.wire}' : '';
    return '${transport.wire}$profile · $host:$port$tail';
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
                profile: awgProfile,
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
    final ka = normalizeKeepalive(keepalive, allowRange: !isMasque);
    if (isMasque) {
      body['server'] = endpoint;
      body['server_port'] = port;
      body['vhttp'] = transport == EvoTransport.masqueH3 ? 'h3' : 'h2';
      if (ka is int && ka > 0) {
        body['keep_alive_period'] = '${ka}s';
      } else {
        body.remove('keep_alive_period');
      }
      if (mtu > 0 && fieldAllowedOn(body, 'mtu')) body['mtu'] = mtu;
      final tls = _tlsBlock(body);
      final name =
          sniCase > 0 && sni.isNotEmpty ? caseShuffle(sni, sniCase) : sni;
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
      if (ka != 0) {
        p['persistent_keepalive_interval'] = ka;
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
      if (!body.containsKey('i1')) {
        final proto = _masqueradeValue(junkProto, body['ip']);
        final domain = _masqueradeValue(
          junkDomain.isNotEmpty ? junkDomain : sni,
          body['id'],
        );
        if (proto != null) {
          body['ip'] = proto;
        } else {
          body.remove('ip');
        }
        if (domain != null) {
          body['id'] = domain;
        } else {
          body.remove('id');
        }
        if (proto == 'quic') {
          final browser = _masqueradeValue(junkBrowser, body['ib']);
          if (browser != null) {
            body['ib'] = browser;
          } else {
            body.remove('ib');
          }
        } else {
          body.remove('ib');
        }
      }
      body['jc'] = jc;
      body['jmin'] = jitterMin;
      body['jmax'] = jitterMax;
      for (final key in const ['i2', 'i3', 'i4', 'i5']) {
        body.remove(key);
      }
      if (awgProfile == AwgProfile.warpCps) {
        body.addAll(awgProfile.extraFieldsFor(junkProto));
      }
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

  String? _masqueradeValue(String gene, Object? base) {
    final value = gene.isNotEmpty ? gene : base;
    return value is String && value.isNotEmpty ? value : null;
  }

  Map<String, dynamic> _tlsBlock(Map<String, dynamic> body) {
    final t = body['tls'];
    return t is Map<String, dynamic>
        ? Map<String, dynamic>.from(t)
        : <String, dynamic>{};
  }
}

/// Приватный WG/AWG: исходное тело сохраняется дословно, поиск меняет только
/// MTU, keepalive и DNS. Креды и AWG3-параметры никогда не подменяются WARP.
class GenomeVerbatim extends Genome {
  GenomeVerbatim._({
    required this.tag,
    required Map<String, dynamic> baseBody,
    required super.endpoint,
    required super.port,
    super.keepalive,
    super.mtu,
    super.dnsTag,
  }) : _baseBody = deepCopyJson(baseBody) as Map<String, dynamic>,
       super(transport: EvoTransport.awg);

  static GenomeVerbatim? fromBody(
    String tag,
    Map<String, dynamic> baseBody,
  ) {
    if (baseBody['type'] != 'wireguard') return null;
    final detour = baseBody['detour'];
    if (detour != null && (detour is! String || detour.trim().isNotEmpty)) {
      return null;
    }
    final addresses = baseBody['address'];
    if (addresses is! List || addresses.isEmpty) return null;
    final peers = (baseBody['peers'] as List?)?.cast<Map<String, dynamic>>() ??
        const <Map<String, dynamic>>[];
    if (peers.isEmpty) return null;
    final endpoint = '${peers.first['address'] ?? ''}';
    final port = (peers.first['port'] as num?)?.toInt() ?? 0;
    if (endpoint.isEmpty || port <= 0) return null;
    return GenomeVerbatim._(
      tag: tag,
      endpoint: endpoint,
      port: port,
      baseBody: baseBody,
      keepalive: Genome.normalizeKeepalive(
        peers.first['persistent_keepalive_interval'],
        allowRange: true,
      ),
      mtu: (baseBody['mtu'] as num?)?.toInt() ?? 0,
    );
  }

  final String tag;
  final Map<String, dynamic> _baseBody;

  Map<String, dynamic> get baseBody =>
      deepCopyJson(_baseBody) as Map<String, dynamic>;

  @override
  bool get isVerbatim => true;

  @override
  GeneTokens tokens() => {
        EvoLocus.mtu: '$mtu',
        EvoLocus.keepalive:
            '${Genome.normalizeKeepalive(keepalive, allowRange: true)}',
        EvoLocus.dns: dnsTag,
      };

  @override
  String get key => 'verbatim:${tag.length}:$tag|'
      '${tokens().entries.map((e) => '${e.key.wire}=${e.value}').join('|')}';

  @override
  GenomeVerbatim copyWith({
    EvoTransport? transport,
    AwgProfile? awgProfile,
    String? endpoint,
    int? port,
    String? sni,
    Object? keepalive,
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
      GenomeVerbatim._(
        tag: tag,
        endpoint: this.endpoint,
        port: this.port,
        baseBody: _baseBody,
        keepalive: keepalive ?? this.keepalive,
        mtu: mtu ?? this.mtu,
        dnsTag: dnsTag ?? this.dnsTag,
      );

  @override
  Map<String, dynamic> applyTo(Map<String, dynamic> base) {
    final body = deepCopyJson(_baseBody) as Map<String, dynamic>;
    if (mtu > 0) {
      body['mtu'] = mtu;
    } else {
      body.remove('mtu');
    }
    final ka = Genome.normalizeKeepalive(keepalive, allowRange: true);
    final peers = (body['peers'] as List?)?.cast<Map<String, dynamic>>() ??
        const <Map<String, dynamic>>[];
    for (final peer in peers) {
      if (ka == 0) {
        peer.remove('persistent_keepalive_interval');
      } else {
        peer['persistent_keepalive_interval'] = ka;
      }
    }
    return body;
  }

  @override
  Map<String, dynamic> toJson() => {
        'key': key,
        'mode': 'verbatim',
        'tag': tag,
        'endpoint': endpoint,
        'port': port,
        'keepalive': Genome.normalizeKeepalive(keepalive, allowRange: true),
        'mtu': mtu,
        'dnsTag': dnsTag,
      };

  @override
  String get json => jsonEncode(toJson());

  @override
  String get shortLabel => 'private · $tag · $endpoint:$port';

  @override
  double distanceTo(Genome other) {
    if (other is! GenomeVerbatim || other.tag != tag) return 1;
    final a = tokens();
    final b = other.tokens();
    var diff = 0;
    for (final locus in a.keys) {
      if (a[locus] != b[locus]) diff++;
    }
    return diff / a.length;
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
