// §845 — сканер известных публичных DNS-резолверов (фаза 3 эндпоинт-сканера).
//
// Зачем отдельный шаг: WARP/MASQUE-эндпоинт может быть жив, но приложение всё
// равно не поднимется, если DNS зарезан — резолв доменов правил/схем уходит в
// пустоту, и пользователь видит «не подключается». Операторы в РФ режут
// 8.8.8.8/1.1.1.1 и одновременно ОТВЕЧАют на 53-м порту сами (transparent DNS),
// поэтому «порт открыт» — ничего не доказывает. Критерий отбора здесь —
// корректный DNS-ответ НА НАШ запрос (см. dns_probe.dart):
//   • A-запрос на `.invalid`-имя → честный резолвер обязан отдать NXDOMAIN;
//   • CH/TXT `id.server` (RFC 4832) → резолвер называется, если хочет.
//
// Результат — список адресов с вердиктами и RTT; «валидными» считаются те, что
// ответили корректно и не похожи на подмену.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../../../models/dns_ref.dart';
import 'dns_probe.dart';
import 'scan_log.dart';
import 'scan_wg_probe.dart' show probeTcpOpen;

/// Один известный резолвер из справочника [kKnownDnsServers].
class KnownDnsServer {
  const KnownDnsServer({
    required this.ip,
    required this.label,
  });

  final String ip;
  final String label;
}

/// Справочник «всех известных DNS-адресов»: публичные anycast-резолверы,
/// которые реально используют для обхода блокировок. IPv4 + IPv6; порядок —
/// по предпочтению (первые идут в первую очередь проверок).
const List<KnownDnsServer> kKnownDnsServers = [
  KnownDnsServer(ip: '1.1.1.1', label: 'Cloudflare'),
  KnownDnsServer(ip: '1.0.0.1', label: 'Cloudflare Secondary'),
  KnownDnsServer(ip: '8.8.8.8', label: 'Google'),
  KnownDnsServer(ip: '8.8.4.4', label: 'Google Secondary'),
  KnownDnsServer(ip: '9.9.9.9', label: 'Quad9'),
  KnownDnsServer(ip: '149.112.112.112', label: 'Quad9 Secondary'),
  KnownDnsServer(ip: '94.140.14.14', label: 'AdGuard DNS'),
  KnownDnsServer(ip: '94.140.14.15', label: 'AdGuard Family'),
  KnownDnsServer(ip: '208.67.222.222', label: 'OpenDNS'),
  KnownDnsServer(ip: '208.67.220.220', label: 'OpenDNS Secondary'),
  KnownDnsServer(ip: '77.88.8.8', label: 'Yandex Basic'),
  KnownDnsServer(ip: '77.88.8.7', label: 'Yandex Safe'),
  KnownDnsServer(ip: '185.222.222.222', label: 'DNS.SB'),
  KnownDnsServer(ip: '45.66.33.62', label: 'DNS.SB Secondary'),
  KnownDnsServer(ip: '94.100.177.19', label: 'Comss'),
  KnownDnsServer(ip: '94.100.177.18', label: 'Comss Secondary'),
  KnownDnsServer(ip: '185.228.168.9', label: 'CleanBrowsing Family'),
  KnownDnsServer(ip: '185.228.168.10', label: 'CleanBrowsing Security'),
  KnownDnsServer(ip: '209.244.0.3', label: 'Level3'),
  KnownDnsServer(ip: '209.244.0.4', label: 'Level3 Secondary'),
  KnownDnsServer(ip: '205.171.3.25', label: 'CenturyLink'),
  KnownDnsServer(ip: '2606:4700:4700::1111', label: 'Cloudflare (v6)'),
  KnownDnsServer(ip: '2606:4700:4700::1001', label: 'Cloudflare Secondary (v6)'),
  KnownDnsServer(ip: '2001:4860:4860::8888', label: 'Google (v6)'),
  KnownDnsServer(ip: '2001:4860:4860::8844', label: 'Google Secondary (v6)'),
  KnownDnsServer(ip: '2620:fe::fe', label: 'Quad9 (v6)'),
  KnownDnsServer(ip: '2a10:50c0::ad1:ff', label: 'AdGuard (v6)'),
  KnownDnsServer(ip: '2a02:6b8::feed:0ff', label: 'Yandex (v6)'),
  KnownDnsServer(ip: '2620:0:2d0:200::222', label: 'OpenDNS (v6)'),
];

/// Вердикты фазы 3 (совпадают с `ScanEndpointStatus.verdict`, чтобы живой список
/// сканера показывал их без новых строк).
const String kDnsVerdictOk = 'dns-ok';
const String kDnsVerdictSpoofed = 'dns-spoofed';
const String kDnsVerdictTimeout = 'dns-timeout';
const String kDnsVerdictRefused = 'dns-refused';
const String kDnsVerdictError = 'dns-error';

/// Итог проверки одного резолвера.
class DnsServerResult {
  const DnsServerResult({
    required this.ip,
    required this.label,
    required this.verdict,
    this.rttMs = 0,
    this.dotOpen = false,
    this.identity = '',
    this.detail = '',
  });

  final String ip;
  final String label;
  final String verdict;

  /// RTT канареечного UDP-запроса.
  final int rttMs;

  /// TCP 853 открывается — можно строить DoT- outbound, если UDP режут.
  final bool dotOpen;

  /// Ответ `id.server` (RFC 4832), если резолвер представился.
  final String identity;
  final String detail;

  /// «Валиден» = ответил корректно на НАШ запрос (не подмена, не отказ).
  bool get valid => verdict == kDnsVerdictOk;

  /// `ip:53` — адрес в том виде, в каком его принимает настройка DNS.
  String get endpoint =>
      ip.contains(':') ? '[$ip]:53' : '$ip:53';
}

/// Движок фазы 3. Сеть трогает только UDP:53/UDP:853-подобные запросы и один
/// TCP-connect на 853; ядро и VPN не задействуются — работает и при включённом
/// туннеле (тогда ответы идут через него, что честно помечается в журнале).
class DnsScanner {
  DnsScanner({
    this.timeout = const Duration(milliseconds: 1500),
    this.concurrency = 8,
    this.checkDot = true,
    bool Function()? cancelled,
  }) : _cancelled = cancelled ?? (() => false);

  final Duration timeout;
  final int concurrency;

  /// Проверять доступность TCP 853 (DoT) — один connect на адрес.
  final bool checkDot;
  final bool Function() _cancelled;

  int _salt = 0x100000;

  Future<List<DnsServerResult>> scan({
    List<KnownDnsServer>? servers,
    ScanLog? log,
    void Function(DnsServerResult result)? onResult,
  }) async {
    final list = servers ?? kKnownDnsServers;
    log?.i(
      'dns',
      'фаза 3: проверяю ${list.length} DNS-резолверов '
      '(UDP:53, ждём ${timeout.inMilliseconds}мс)',
    );
    final out = <DnsServerResult>[];
    for (var i = 0; i < list.length; i += concurrency) {
      if (_cancelled()) break;
      final chunk = list.skip(i).take(concurrency);
      final part = await Future.wait(chunk.map((s) async {
        if (_cancelled()) return null;
        final r = await _check(s, log);
        onResult?.call(r);
        return r;
      }));
      out.addAll(part.whereType<DnsServerResult>());
    }
    final valid = out.where((r) => r.valid).length;
    log?.i('dns', 'фаза 3: валидных $valid из ${out.length}');
    return out;
  }

  Future<DnsServerResult> _check(KnownDnsServer s, ScanLog? log) async {
    try {
      final canary = canaryName(_salt++);
      final probe = await _query(
        s.ip,
        canary,
        DnsQueryKind.a,
        sentId: _idFor(canary),
      );
      final verdict = classifyDnsProbe(
        sentId: _idFor(canary),
        sentName: canary,
        kind: DnsQueryKind.a,
        packet: probe.packet,
        timedOut: probe.timedOut,
      );
      var identity = '';
      // §845 — представление по id.server только для отвечавших: это второй
      // пакет на том же адресе, и он ничего не решает (отказ = normal для
      // Cloudflare), но в журнале отличает настоящий сервис от «отвечает кто-то».
      if (verdict.ok && !_cancelled()) {
        final name = kDnsIdServerName;
        final idProbe = await _query(
          s.ip,
          name,
          DnsQueryKind.idServerTxt,
          sentId: _idFor(name),
        );
        final cls = classifyDnsProbe(
          sentId: _idFor(name),
          sentName: name,
          kind: DnsQueryKind.idServerTxt,
          packet: idProbe.packet,
          timedOut: idProbe.timedOut,
        );
        identity = cls.identity;
      }
      final dot = checkDot && !_cancelled()
          ? (await probeTcpOpen(s.ip, 853, timeout: timeout)).open
          : false;

      final res = DnsServerResult(
        ip: s.ip,
        label: s.label,
        verdict: switch (verdict.verdict) {
          'ok' || 'identified' || 'nodata' || 'truncated' => kDnsVerdictOk,
          'spoofed' => kDnsVerdictSpoofed,
          'timeout' => kDnsVerdictTimeout,
          'refused' => kDnsVerdictRefused,
          _ => kDnsVerdictError,
        },
        rttMs: probe.rttMs,
        dotOpen: dot,
        identity: identity,
        detail: [
          verdict.detail,
          if (verdict.proven) 'NXDOMAIN подтверждён',
          if (identity.isNotEmpty) 'id.server=$identity',
          if (dot) 'TCP 853 открыт',
        ].join(', '),
      );
      if (res.valid) {
        log?.i('dns', '${res.endpoint} ${s.label} → ${res.verdict} '
            '${res.rttMs}мс · ${res.detail}');
      } else {
        log?.w('dns', '${res.endpoint} ${s.label} → ${res.verdict} '
            '${res.rttMs}мс · ${res.detail}');
      }
      return res;
    } catch (e) {
      log?.e('dns', '${s.ip} сбой проверки: $e');
      return DnsServerResult(
        ip: s.ip,
        label: s.label,
        verdict: kDnsVerdictError,
        detail: '$e',
      );
    }
  }

  int _idFor(String name) =>
      0x1000 + (name.codeUnits.fold<int>(0, (a, b) => (a * 31 + b) & 0xffff)) %
          0xefff;

  /// Один UDP DNS-обмен с [ip]:53: ждём первый пакет не дольше [timeout].
  /// Отвечает чужой процесс (перехватчик) — это разберёт [classifyDnsProbe].
  Future<({DnsPacket? packet, bool timedOut, int rttMs})> _query(
    String ip,
    String name,
    DnsQueryKind kind, {
    required int sentId,
  }) async {
    final query = buildDnsQuery(name, id: sentId, kind: kind);
    final isV6 = ip.contains(':');
    final RawDatagramSocket sock;
    try {
      sock = await RawDatagramSocket.bind(
        isV6 ? InternetAddress.anyIPv6 : InternetAddress.anyIPv4,
        0,
      );
    } catch (_) {
      // Нет IPv6-маршрута/интерфейса — не ошибка резолвера, а отсутствие
      // transport'а на устройстве: помечаем таймаутом с внятной деталью.
      return (packet: null, timedOut: true, rttMs: 0);
    }
    final sw = Stopwatch()..start();
    final completer = Completer<DnsPacket?>();
    Timer? timer;
    try {
      sock.listen((event) {
        if (event != RawSocketEvent.read || completer.isCompleted) return;
        final dg = sock.receive();
        if (dg == null) return;
        final packet = parseDnsPacket(Uint8List.fromList(dg.data));
        // Первый разобранный ответ по нашему ID — решающий; чужие пакеты
        // (другой ID) тоже отдаём наружу: classifyDnsProbe квалифицирует это как
        // подмену, а молчать о нём нельзя.
        if (packet != null) completer.complete(packet);
      }, onError: (Object _) {
        if (!completer.isCompleted) completer.complete(null);
      });
      timer = Timer(timeout, () {
        if (!completer.isCompleted) completer.complete(null);
      });
      sock.send(query, InternetAddress(ip), 53);
      final packet = await completer.future;
      sw.stop();
      return (
        packet: packet,
        timedOut: packet == null,
        rttMs: packet == null ? 0 : sw.elapsedMilliseconds,
      );
    } finally {
      timer?.cancel();
      sock.close();
    }
  }
}

// ─── §847 — выбранные резолверы → запись DNS хранения ─────────────────────

/// Тег для записи хранения из результата скана: метка справочника + адрес.
/// Детерминирован (повторный скан обновляет ту же запись, а не плодит дубли) и
/// держится допустимого для sing-box `tag` алфавита `[A-Za-z0-9_-]`.
String scannedDnsTag(DnsServerResult d) {
  final slug = (d.label.isEmpty ? d.ip : d.label)
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), '_')
      .replaceAll(RegExp(r'^_+|_+$'), '');
  final host = d.ip.replaceAll(RegExp(r'[^a-z0-9]+'), '');
  return 'scan${slug.isEmpty ? '' : '_$slug'}_$host';
}

/// §847 — выбор пользователя из фазы 3 → inline-серверы, которые пост-шаг
/// `dns_servers.dart` эмитит в `dns.servers[]` собранного конфига. Это и есть
/// «DNS подставляется в генератор так же, как эндпоинты»: отсканированные
/// адреса попадают в ту же систему записей, что и ручной выбор в DNS-настройках.
///
/// Невалидные (подмена/таймаут) отбрасываются молча: их выбор — ошибка UI, а не
/// повод писать в конфиг заведомо мёртвый резолвер.
List<DnsServerInline> scannedDnsRecords(List<DnsServerResult> picked) {
  final out = <DnsServerInline>[];
  final seen = <String>{};
  for (final d in picked) {
    if (!d.valid) continue;
    final tag = scannedDnsTag(d);
    if (!seen.add(tag)) continue;
    out.add(
      DnsServerInline(
        enabled: true,
        tag: tag,
        description: d.label.isEmpty ? d.ip : d.label,
        // Проба шла по UDP:53 — порт не пишем, это дефолт sing-box.
        body: {'type': 'udp', 'server': d.ip},
      ),
    );
  }
  return out;
}
