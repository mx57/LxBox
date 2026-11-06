// §845 — минимальный DNS-кодек (RFC 1035) для сканера резолверов.
//
// Только то, что нужно проверке: заголовок, один вопрос, разбор A/TXT. Файл
// ЧИСТЫЙ (без сокетов и async): вся сверка пришённого пакета с посланным
// покрывается тестами на подготовленных байтах, сеть не трогаем.
//
// Зачем свой кодек: публичный резолвер «валиден» не тогда, когда порт открыт
// (на 53/853 оператор-перехватчик отвечает сам), а когда ОТВЕТ сошёлся с
// ЗАПРОСОМ — наш ID, наш вопрос, правдоподобный rcode. Это и есть способ
// отличить настоящий сервис от DPI-подмены.

import 'dart:convert';
import 'dart:typed_data';

/// Тип запроса. `idServerTxt` — CH-class TXT на `id.server` (RFC 4832):
/// «честные» резолверы отвечают своей версией/именем.
enum DnsQueryKind { a, idServerTxt }

/// Имя-канарейка: `.invalid` (RFC 6761 — не делегируется вообще), поэтому
/// настоящий резолвер обязан ответить NXDOMAIN. NOERROR с адресом на `.invalid`
/// и есть подпись перехватчика, который обслуживает запрос сам.
String canaryName(int salt) =>
    'lxscan${salt.toRadixString(16).padLeft(6, '0')}.invalid';

const String kDnsIdServerName = 'id.server';

/// Байты DNS-запроса: ID, RD, ровно один вопрос.
Uint8List buildDnsQuery(
  String name, {
  required int id,
  DnsQueryKind kind = DnsQueryKind.a,
}) {
  final labels = kind == DnsQueryKind.idServerTxt
      ? kDnsIdServerName.split('.')
      : name.split('.').where((s) => s.isNotEmpty).toList();
  final type = kind == DnsQueryKind.idServerTxt ? 16 : 1; // TXT / A
  final klass = kind == DnsQueryKind.idServerTxt ? 3 : 1; // CH / IN

  final bb = BytesBuilder(copy: false);
  void u16(int v) {
    bb.addByte((v >> 8) & 0xff);
    bb.addByte(v & 0xff);
  }

  u16(id); // ID
  u16(0x0100); // flags: RD=1
  u16(1); // QDCOUNT
  u16(0); // ANCOUNT
  u16(0); // NSCOUNT
  u16(0); // ARCOUNT
  for (final label in labels) {
    final bytes = const Utf8Encoder().convert(label);
    bb.addByte(bytes.length);
    bb.add(bytes);
  }
  bb.addByte(0); // корневая метка
  u16(type);
  u16(klass);
  return bb.toBytes();
}

/// Синтетический ОТВЕТ — только для тестов: заголовок с `rcode`, тот же вопрос
/// (`question`), затем A-записи [ips] и TXT-записи [texts].
Uint8List buildDnsResponse(
  String question, {
  required int id,
  DnsQueryKind kind = DnsQueryKind.a,
  int rcode = 0,
  bool truncated = false,
  bool response = true,
  List<String> ips = const [],
  List<String> texts = const [],
}) {
  final bb = BytesBuilder(copy: false);
  void u16(int v) {
    bb.addByte((v >> 8) & 0xff);
    bb.addByte(v & 0xff);
  }

  var flags = 0x8180; // QR=1, RD=1, RA=1
  if (!response) flags &= ~0x8000;
  if (truncated) flags |= 0x0200;
  flags |= rcode & 0xf;

  u16(id);
  u16(flags);
  u16(1);
  u16(ips.length + texts.length);
  u16(0);
  u16(0);

  void writeName(String name) {
    for (final label in name.split('.').where((s) => s.isNotEmpty)) {
      final bytes = const Utf8Encoder().convert(label);
      bb.addByte(bytes.length);
      bb.add(bytes);
    }
    bb.addByte(0);
  }

  final qType = kind == DnsQueryKind.idServerTxt ? 16 : 1;
  final qClass = kind == DnsQueryKind.idServerTxt ? 3 : 1;
  writeName(question);
  u16(qType);
  u16(qClass);

  for (final ip in ips) {
    writeName(question);
    u16(1); // A
    u16(1); // IN
    _u32(bb, 60); // TTL
    u16(4);
    for (final part in ip.split('.')) {
      bb.addByte(int.parse(part));
    }
  }
  for (final t in texts) {
    writeName(question);
    u16(16); // TXT
    u16(kind == DnsQueryKind.idServerTxt ? 3 : 1);
    _u32(bb, 60);
    final bytes = const Utf8Encoder().convert(t);
    u16(bytes.length + 1);
    bb.addByte(bytes.length);
    bb.add(bytes);
  }
  return bb.toBytes();
}

void _u32(BytesBuilder bb, int v) {
  bb.addByte((v >> 24) & 0xff);
  bb.addByte((v >> 16) & 0xff);
  bb.addByte((v >> 8) & 0xff);
  bb.addByte(v & 0xff);
}

final _utf8 = const Utf8Decoder(allowMalformed: true);

/// Разобранный DNS-пакет.
class DnsPacket {
  DnsPacket({
    required this.id,
    required this.isResponse,
    required this.truncated,
    required this.rcode,
    required this.question,
    required this.answerCount,
    required this.ips,
    required this.texts,
  });

  final int id;
  final bool isResponse;
  final bool truncated;
  final int rcode;

  /// Имя из вопроса (указатели раскрыты), нижний регистр, без точек на конце.
  final String question;
  final int answerCount;

  /// A-адреса из ответов.
  final List<String> ips;

  /// TXT-строки из ответов.
  final List<String> texts;

  bool get noError => rcode == 0;
  bool get nxDomain => rcode == 3;
  bool get refused => rcode == 5;
}

/// null — пакет не разborчивается (короткий, битый заголовок/вопрос, вылет за
/// границы, цикл указателя): на вход приходят данные чужих рук, включая
/// DPI-подмену, поэтому ронять скан нельзя.
DnsPacket? parseDnsPacket(Uint8List data) {
  if (data.length < 12) return null;
  final id = (data[0] << 8) | data[1];
  final flags = (data[2] << 8) | data[3];
  if (((data[4] << 8) | data[5]) != 1) return null; // сканер шлёт ровно один вопрос
  final anCount = (data[6] << 8) | data[7];

  final r = _Reader(data)..offset = 12;
  final question = r.readName();
  if (question == null) return null;
  if (r.u16() == null || r.u16() == null) return null; // qtype/qclass

  final ips = <String>[];
  final texts = <String>[];
  for (var i = 0; i < anCount; i++) {
    if (r.readName() == null) break;
    final type = r.u16();
    final klass = r.u16();
    if (r.u32() == null) break; // TTL
    final rdLen = r.u16();
    if (type == null || klass == null || rdLen == null) break;
    final rdata = r.take(rdLen);
    if (rdata == null) break;
    if (type == 1 && klass == 1 && rdata.length == 4) {
      ips.add(rdata.map((b) => b.toString()).join('.'));
    } else if (type == 16) {
      final t = _readTxt(rdata);
      if (t.isNotEmpty) texts.add(t);
    }
  }

  return DnsPacket(
    id: id,
    isResponse: (flags & 0x8000) != 0,
    truncated: (flags & 0x0200) != 0,
    rcode: flags & 0xf,
    question: question,
    answerCount: anCount,
    ips: ips,
    texts: texts,
  );
}

/// TXT RDATA: цепочка `<len><bytes>` character-string'ов.
String _readTxt(Uint8List rdata) {
  final parts = <String>[];
  var i = 0;
  while (i < rdata.length) {
    final len = rdata[i];
    if (len == 0 || i + 1 + len > rdata.length) break;
    parts.add(_utf8.convert(rdata.sublist(i + 1, i + 1 + len)));
    i += 1 + len;
  }
  return parts.join(' ').trim();
}

/// Результат одной пробы резолвера.
({String verdict, bool ok, bool proven, bool identified, String identity, String detail})
    classifyDnsProbe({
  required int sentId,
  required String sentName,
  required DnsQueryKind kind,
  required DnsPacket? packet,
  required bool timedOut,
}) {
  if (timedOut) {
    return (
      verdict: 'timeout',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'нет ответа',
    );
  }
  if (packet == null) {
    return (
      verdict: 'malformed',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'не разобрано как DNS',
    );
  }
  if (!packet.isResponse) {
    return (
      verdict: 'malformed',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'QR=0 — пришёл запрос, а не ответ',
    );
  }
  if (packet.id != sentId) {
    return (
      verdict: 'spoofed',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'ID ответа ${packet.id} != ID запроса $sentId',
    );
  }
  if (packet.question != sentName.toLowerCase()) {
    return (
      verdict: 'spoofed',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'вопрос "${packet.question}" != "$sentName"',
    );
  }

  if (kind == DnsQueryKind.idServerTxt) {
    final identity = packet.texts.isEmpty ? '' : packet.texts.first;
    return (
      verdict: identity.isEmpty ? 'nodata' : 'identified',
      ok: true,
      proven: false,
      identified: identity.isNotEmpty,
      identity: identity,
      detail:
          identity.isEmpty ? 'rcode=${packet.rcode}, TXT пусто' : '"$identity"',
    );
  }

  if (packet.nxDomain) {
    return (
      verdict: 'ok',
      ok: true,
      proven: true,
      identified: false,
      identity: '',
      detail: 'NXDOMAIN по .invalid',
    );
  }
  if (packet.noError && packet.ips.isNotEmpty) {
    return (
      verdict: 'spoofed',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'адрес ${packet.ips.first} по .invalid — перехват',
    );
  }
  if (packet.refused) {
    return (
      verdict: 'refused',
      ok: false,
      proven: false,
      identified: false,
      identity: '',
      detail: 'REFUSED',
    );
  }
  return (
    verdict: packet.truncated ? 'truncated' : 'ok',
    ok: true,
    proven: false,
    identified: false,
    identity: '',
    detail: packet.truncated ? 'TC=1 — ответ обрезан, нужен TCP' : 'rcode=${packet.rcode}',
  );
}

/// Читатель DNS-пакета с контролем границ.
class _Reader {
  _Reader(this.data);

  final Uint8List data;
  int offset = 0;

  int? u16() {
    if (offset + 2 > data.length) return null;
    final v = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    return v;
  }

  int? u32() {
    if (offset + 4 > data.length) return null;
    var v = 0;
    for (var i = 0; i < 4; i++) {
      v = (v << 8) | data[offset + i];
    }
    offset += 4;
    return v;
  }

  Uint8List? take(int n) {
    if (n < 0 || offset + n > data.length) return null;
    final out = data.sublist(offset, offset + n);
    offset += n;
    return out;
  }

  /// Имя с раскрытием сжатых указателей (0b11). Нижним регистром, без хвостовой
  /// точки; null — вылет за границы или цикл указателя.
  String? readName() {
    final parts = <String>[];
    var jumps = 0;
    var at = offset;
    var endAfter = -1;
    while (true) {
      if (at >= data.length) return null;
      final len = data[at];
      if ((len & 0xc0) == 0xc0) {
        if (at + 1 >= data.length) return null;
        if (endAfter < 0) endAfter = at + 2;
        final ptr = ((len & 0x3f) << 8) | data[at + 1];
        if (++jumps > 32 || ptr >= data.length || ptr == at) return null;
        at = ptr;
        continue;
      }
      if (len == 0) {
        if (endAfter < 0) endAfter = at + 1;
        break;
      }
      if (at + 1 + len > data.length) return null;
      parts.add(_utf8.convert(data.sublist(at + 1, at + 1 + len)));
      at += 1 + len;
      if (parts.length > 128) return null;
    }
    offset = endAfter;
    return parts.join('.').toLowerCase();
  }
}
