// §834 — WARP endpoint scanner: движок двухфазного скана (warpscout-inspired).
//
// Phase 1 — живость: WG-handshake по UDP (реальный Noise_IKpsk2-пакет,
// scan_wire.dart). Живым считается эндпоинт, ответивший type-2 (92 Б) или
// type-3 cookie (64 Б) — это единственный признак, отличающий «порт открыт»
// от «эндпоинт реально отвечает WARP».
//
// Phase 2 — страна/нода + подтверждение: через ШТАТНУЮ headless probe-сессию
// ядра (probeStart → probeGetUrl → probeStop, как в NodeDiagnosticsRunner и
// ProbeRunner). Запрос идёт по `https://1.1.1.1/cdn-cgi/trace`: строка `loc=`
// отдаёт страну (ISO-3166 alpha-2, верхний регистр), `colo=` — IATA-код узла.
// Без поднятой сессии probeGetUrl не работает вовсе — прежняя версия звала его
// с фиктивным тегом, из-за чего страна всегда была «??», а `valid` — 0.
//
// Если egress UDP режется (типично для РФ), WG-фаза не даёт живых. Тогда идём
// путём MASQUE: MASQUE-кандидаты (h3/h2) подтверждаются реальным GET через
// probe-сессию — открытый TCP 443 сам по себе «живостью» НЕ считается (CF-edge
// отвечает на 443 почти всегда, это ложный сигнал).
//
// §838 — ПЕРЕД probe-сессией h2-кандидаты проходят дешёвый TCP-preflight
// (системный стек Dart, без ядра): адрес/порт, до которого TCP зарезан,
// отсекается за секунды с ЯВНЫМ вердиктом в журнале (`tcp-closed`), а не висит
// 8с × N кандидатов в `context deadline exceeded` — снаружи это выглядело как
// «сканер 4 минуты молчит и не находит живых». Живой порт подбирается по пулу
// (443 → 500 → … → 8095): если 443 зарезан, а 8443 нет, кандидат переезжает.
//
// §839 — четыре правки по аудиту (все подтверждены на коде и тестах):
//  1. закрытый TCP ≠ выброшенный адрес: h2-кандидат уходит на h3/QUIC.
//     Живое доказательство из журнала: ответ `http3: parsing frame failed:
//     PROTOCOL_VIOLATION (remote)` означает, что UDP-пакеты до Cloudflare
//     ДОШЛИ — путь жив, и терять его нельзя (раньше такие адреса молча
//     «пропускались»);
//  2. переезд на другой порт ЗАМЕНЯЕТ кандидата на месте, а не добавляет дубль,
//     и переносит уже измеренный RTT;
//  3. отмена скана прерывает и preflight (иначе кнопка «Отмена» ждала все
//     таймауты — до 7 портов × 3с на адрес);
//  4. MASQUE-SNI ротируется по пулу (`rotateMasqueSni`): пул начинается с
//     родного `consumer-masque.cloudflareclient.com`, и до §839 ВСЕ кандидаты до
//     32 шли под этим доменом — одна узнаваемая подпись на весь батч. Плюс
//     гейт `kProbeMaxMasquePerConfig` (probe_config.dart) не даёт 32 MASQUE-
//     узлам стартовать в одном probe-конфиге и задушить друг друга (в журнале
//     это выглядело как 31 × `context deadline exceeded`).
//
// §840 — повторные попытки по не ответившим MASQUE-адресам. Замер рабочего
// эталона (warpscout `masqueDefaultAttempts = 3`) на фильтрующей сети: одна
// попытка дала 1–3 живых из 14, три — 11–13. То есть одна неудача не значит
// ничего: адрес «флапает» (QUIC-хендшейк проходит, а CONNECT-IP/GET не
// отвечает, и наоборот). Без повторов скан массово даёт ложно-мёртвые адреса —
// «живых 0» при живых 11. Повтор дешёвый (ещё один probeGetUrl в уже поднятой
// сессии) и прозрачный (в журнале видна попытка).
//
// §845/§847 — после группировки по странам идут ещё два шага, оба дают
// пользователю СПИСОК НА ВЫБОР (не просто журнал):
//   3 — известные публичные DNS-резолверы (`dns_scanner.dart`): честный ответ
//       на `.invalid`-канарейку + `id.server`. Отобранные адреса прокидываются
//       в сборщик конфигов (DNS-запись хранения), потому что живой эндпоинт с
//       перехваченным DNS подключения не даёт.
//   4 — SNI-кандидаты (`sni_scanner.dart`), включая белые списки РФ: каждый
//       домен собирается узлом поверх подтверждённого эндпоинта и проверяется
//       одним ответом через туннель. Годны только прошедшие: список в asset'е
//       ≠ пропуск в DPI сегодня.
//
// Результат — список живых эндпоинтов с (страна, нода, RTT), готовый к
// группировке по странам (UI с чекбоксами) и к генерации конфигов.

import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart' show rootBundle;

import '../../../models/node_spec.dart';
import '../../../models/tunnel_status.dart';
import '../../../services/l10n/locale_controller.dart';
import '../../../services/parser/mappers/uri_pipeline.dart'
    show parseLinkViaPipeline;
import '../../../vpn/box_vpn_client.dart';
import '../../../vpn/cc_channel.dart';
import '../../builder/core_chain_capability.dart';
import '../../probe/probe_config.dart';
import '../../settings_storage.dart';
import '../masque_account.dart';
import '../warp_account.dart';
import '../warp_client.dart';
import 'dns_scanner.dart';
import 'scan_awg_probe.dart';
import 'scan_models.dart';
import 'scan_log.dart';
import 'scan_i1.dart';
import 'scan_node_builder.dart';
import 'scan_pool.dart';
import 'scan_wg_probe.dart';
import 'scan_wire.dart';
import 'sni_scanner.dart';

/// Один валидный эндпоинт с гео-метаданными.
class EndpointResult {
  const EndpointResult({
    required this.endpoint,
    required this.country,
    required this.colo,
    required this.rttMs,
    required this.alive,
  });

  final String endpoint;
  final String country;
  final String colo;
  final int rttMs;
  final bool alive;
}

/// Группа по стране: список эндпоинтов + счётчики.
class EndpointCountryGroup {
  const EndpointCountryGroup({
    required this.code,
    required this.name,
    required this.endpoints,
  });

  /// ISO-3166 alpha-2 (верхний регистр) либо `''` — страна не определена
  /// (probe-сессия не дала `loc=`, напр. UDP-фаза прошла, а гео-фаза — нет).
  final String code;

  final String name;
  final List<EndpointResult> endpoints;

  int get found => endpoints.length;
  int get valid => endpoints.where((e) => e.alive).length;

  /// §834 — группа «страна не определена» (пустой код). UI рендерит её
  /// отдельной подписью, а не «()».
  bool get isUnknown => code.isEmpty;
}

/// Результат скана: группы по странам (отсортированы по valid desc).
class EndpointScanResult {
  const EndpointScanResult({
    required this.groups,
    required this.scanAt,
    required this.scanDurationMs,
    required this.failedCount,
    this.tcpFallbackUsed = false,
    this.note = '',
    this.statuses = const [],
    this.dns = const [],
    this.sni = const [],
  });

  final List<EndpointCountryGroup> groups;
  final DateTime scanAt;
  final int scanDurationMs;
  final int failedCount;

  /// Был ли задействован путь MASQUE (UDP-фаза не дала живых).
  final bool tcpFallbackUsed;

  /// §834 — замечание для UI (напр. почему гео-фаза не отработала).
  final String note;

  /// §835 — вердикт по КАЖДОМУ проверенному адресу (и живым, и мёртвым).
  /// UI показывает его живым списком; сводные счётчики — из [groups].
  final List<ScanEndpointStatus> statuses;

  /// §845 — фаза 3: проверка известных DNS-резолверов (после группировки по
  /// странам). Пусто, если шаг был выключен или отменён.
  final List<DnsServerResult> dns;

  /// Валидные резолверы — те, что корректно ответили на наш запрос.
  List<DnsServerResult> get validDns => dns.where((d) => d.valid).toList();

  /// §847 — фаза 4: SNI-кандидаты (белые списки РФ), прогнанные через живые
  /// эндпоинты. Пусто, если шаг выключен, отменён или probe-сессия недоступна.
  final List<SniScanResult> sni;

  /// Годные SNI — те, что хотя бы на одном эндпоинте дали ответ.
  List<SniScanResult> get validSni => sni.where((s) => s.valid).toList();

  int get totalFound => groups.fold(0, (s, g) => s + g.endpoints.length);
  int get totalValid => groups.fold(0, (s, g) => s + g.valid);

  /// §835 — сколько адресов реально проверено (для строки «проверено N»).
  /// Фазу 3 (DNS-резолверы) не считаем: это не эндпоинты.
  int get totalProbed => statuses.where((s) => s.phase < 3).length;

  /// §835 — сколько из проверенных оказались живыми на уровне живости.
  int get totalAlive => statuses.where((s) => s.alive).length;
}

/// Статический справочник стран (ISO 3166-1 alpha-2 → русские имена).
const Map<String, String> _countryNames = {
  'US': 'США',
  'DE': 'Германия',
  'NL': 'Нидерланды',
  'GB': 'Великобритания',
  'FR': 'Франция',
  'FI': 'Финляндия',
  'SE': 'Швеция',
  'PL': 'Польша',
  'CZ': 'Чехия',
  'EE': 'Эстония',
  'LV': 'Латвия',
  'LT': 'Литва',
  'UA': 'Украина',
  'BY': 'Беларусь',
  'KZ': 'Казахстан',
  'RU': 'Россия',
  'TR': 'Турция',
  'IL': 'Израиль',
  'AE': 'ОАЭ',
  'SG': 'Сингапур',
  'JP': 'Япония',
  'HK': 'Гонконг',
  'KR': 'Южная Корея',
  'IN': 'Индия',
  'BR': 'Бразилия',
  'CA': 'Канада',
  'AU': 'Австралия',
  'IT': 'Италия',
  'ES': 'Испания',
  'CH': 'Швейцария',
  'AT': 'Австрия',
  'BE': 'Бельгия',
  'IE': 'Ирландия',
  'NO': 'Норвегия',
  'DK': 'Дания',
  'RO': 'Румыния',
  'BG': 'Болгария',
  'GR': 'Греция',
  'PT': 'Португалия',
  'HU': 'Венгрия',
  'SK': 'Словакия',
  'SI': 'Словения',
  'HR': 'Хорватия',
  'RS': 'Сербия',
  'MD': 'Молдова',
  'GE': 'Грузия',
  'AM': 'Армения',
  'AZ': 'Азербайджан',
  'UZ': 'Узбекистан',
  'PH': 'Филиппины',
  'ID': 'Индонезия',
  'MY': 'Малайзия',
  'TH': 'Таиланд',
  'VN': 'Вьетнам',
  'TW': 'Тайвань',
  'MX': 'Мексика',
  'AR': 'Аргентина',
  'CL': 'Чили',
  'CO': 'Колумбия',
  'PE': 'Перу',
  'ZA': 'ЮАР',
  'NG': 'Нигерия',
  'EG': 'Египет',
  'SA': 'Саудовская Аравия',
  // §846 — страны, до которых теперь доходит группировка через colo.
  'LU': 'Люксембург',
  'UY': 'Уругвай',
  'PA': 'Панама',
  'CR': 'Коста-Рика',
  'JM': 'Ямайка',
  'DO': 'Доминиканская Республика',
  'TT': 'Тринидад и Тобаго',
  'NZ': 'Новая Зеландия',
  'MO': 'Макао',
  'MN': 'Монголия',
  'PK': 'Пакистан',
  'BD': 'Бангладеш',
  'LK': 'Шри-Ланка',
  'IS': 'Исландия',
  'MT': 'Мальта',
  'CY': 'Кипр',
  'JO': 'Иордания',
  'LB': 'Ливан',
  'IQ': 'Ирак',
  'QA': 'Катар',
  'KW': 'Кувейт',
  'OM': 'Оман',
  'MA': 'Марокко',
  'TN': 'Тунис',
  'DZ': 'Алжир',
  'SN': 'Сенегал',
  'CI': 'Кот-д’Ивуар',
  'GH': 'Гана',
  'ET': 'Эфиопия',
  'KE': 'Кения',
  'UG': 'Уганда',
  'TZ': 'Танзания',
  'RW': 'Руанда',
  'CD': 'ДР Конго',
  'MG': 'Мадагаскар',
  'MU': 'Маврикий',
  // §848 — страны, которые таблица colo начала отдавать после расширения.
  'AL': 'Албания',
  'BA': 'Босния и Герцеговина',
  'BH': 'Бахрейн',
  'BS': 'Багамы',
  'EC': 'Эквадор',
  'GP': 'Гваделупа',
  'GT': 'Гватемала',
  'GU': 'Гуам',
  'HN': 'Гондурас',
  'KG': 'Киргизия',
  'MK': 'Северная Македония',
  'NP': 'Непал',
  'PR': 'Пуэрто-Рико',
  'PY': 'Парагвай',
  'RE': 'Реюньон',
  'SV': 'Сальвадор',
};

String countryName(String code) =>
    _countryNames[code.toUpperCase()] ?? code.toUpperCase();

/// §834 — транспорт, которым эндпоинт подтверждён. Определяет, каким узлом
/// (WG/AWG или MASQUE h3/h2) его подтверждает гео-фаза.
enum EndpointTransport { wg, masqueH3, masqueH2 }

/// §847 — одна цель probe-сессии: адрес + SNI внешнего handshake + транспорт.
///
/// SNI — часть цели, а не деталь сборки узла, потому что фаза 4 прогоняет ОДИН
/// адрес с разными доменами: ключом результата служит индекс цели в списке
/// (карта `endpoint → гео` такие повторы схлопнула бы).
typedef ScanProbeTarget = ({
  String endpoint,
  String sni,
  EndpointTransport transport,
});

/// §844 — псевдо-коды в `loc`, которые CF/MaxMind отдают ВМЕСТО страны: `XX`
/// («неизвестно»), `A1`/`A2` (анонимный прокси / Tor из GeoLite классификатора),
/// `T1` (тестовый). Как страна бесполезны, а в группировку дали бы фантомную
/// группу «XX», которую пользователь прочтёт как «вот такая страна».
const kGeoPseudoCountries = {'XX', 'A1', 'A2', 'T1'};

/// ISO-3166 alpha-2 в трактовке CF: ровно две латинские буквы и не псевдо-код.
bool isPlausibleCountry(String code) {
  if (code.length != 2) return false;
  final cps = code.toUpperCase().codeUnits;
  if (cps.any((c) => c < 0x41 || c > 0x5A)) return false;
  return !kGeoPseudoCountries.contains(code.toUpperCase());
}

/// §846 — IATA-код cloudflare-узла (`colo`) → ISO-3166-1 alpha-2.
///
/// Почему это вообще нужно: `colo` CF отдаёт почти всегда, а `loc` — нет. У
/// хостинговых и анонимизированных IP GeoLite возвращает `loc=T1`/`A1`/`XX`
/// (замер: `www.cloudflare.com/cdn-cgi/trace` → `colo=DFW loc=T1`,
/// `1.1.1.1/cdn-cgi/trace` → `colo=EWR loc=T1`, а `speed.cloudflare.com/meta` —
/// `{}`). До §846 такой эндпоинт попадал в группу «не определена», хотя узел с
/// страной виден прямо в логе скана.
///
/// Узел — это датацентр: его страна — факт размещения, а не вывод из
/// классификатора IP, поэтому с §848 это И основной источник страны эндпоинта
/// (см. [parseGeoBody]): `loc` описывает клиента, а не точку выхода.
///
/// Таблица — просто «этому IATA какая страна принадлежит»; неполнота безопасна:
/// неизвестный код даёт '' и эндпоинт честно остаётся неопределённым. Но теперь
/// каждый пропущенный код стоит пользователю целую группу, расширять таблицу
/// выгоднее, чем придумывать эвристики для `loc`.
const Map<String, String> kColoCountries = {
  // Северная Америка
  'ATL': 'US', 'AUS': 'US', 'BNA': 'US', 'BOS': 'US', 'BWI': 'US',
  'CLT': 'US', 'CMH': 'US', 'CVG': 'US', 'DAL': 'US', 'DFW': 'US',
  'DEN': 'US', 'DTW': 'US', 'EWR': 'US', 'FLL': 'US', 'GEG': 'US',
  'HNL': 'US', 'IAD': 'US', 'ICT': 'US', 'IND': 'US', 'JFK': 'US',
  'LAS': 'US', 'LAX': 'US', 'MCI': 'US', 'MEM': 'US', 'MHT': 'US',
  'MIA': 'US', 'MKE': 'US', 'MSP': 'US', 'MSY': 'US', 'ORD': 'US',
  'PDX': 'US', 'PHL': 'US', 'PHX': 'US', 'RDU': 'US',
  'SAT': 'US', 'SEA': 'US', 'SJC': 'US', 'SLC': 'US',
  'SMF': 'US', 'SRQ': 'US', 'TPA': 'US', 'TUS': 'US', 'XNA': 'US',
  // Аляска, Гавайи и заморские территории США.
  'ANC': 'US', 'ITO': 'US', 'KOA': 'US', 'GUM': 'GU',
  // Карибы, Центральная Америка и заморские территории
  'GUA': 'GT', 'KIN': 'JM', 'NAS': 'BS', 'PSE': 'PR', 'PTP': 'GP',
  'PTY': 'PA', 'PUJ': 'DO', 'SAL': 'SV', 'SDQ': 'DO', 'SJO': 'CR',
  'SJU': 'PR', 'TGU': 'HN', 'POS': 'TT',
  'YHM': 'CA', 'YQB': 'CA', 'YUL': 'CA', 'YOW': 'CA', 'YXE': 'CA',
  'YYC': 'CA', 'YYG': 'CA', 'YYJ': 'CA', 'YYT': 'CA', 'YYZ': 'CA',
  'BJX': 'MX', 'CUN': 'MX', 'GDL': 'MX', 'MEX': 'MX', 'QRO': 'MX',
  'SLP': 'MX',
  // Южная Америка
  'ASU': 'PY', 'BEL': 'BR', 'BOG': 'CO', 'BSB': 'BR', 'COR': 'AR',
  'CWB': 'BR', 'EZE': 'AR', 'FOR': 'BR', 'GIG': 'BR', 'GRU': 'BR',
  'GYE': 'EC', 'LIM': 'PE', 'MAO': 'BR', 'MDE': 'CO', 'MVD': 'UY',
  'POA': 'BR', 'REC': 'BR', 'ROS': 'AR', 'SCL': 'CL', 'SSA': 'BR',
  'UIO': 'EC', 'VCP': 'BR',
  // Западная/Северная Европа
  'AGP': 'ES', 'AMS': 'NL', 'ARN': 'SE', 'AST': 'ES', 'BEG': 'RS',
  'BER': 'DE', 'BGO': 'NO', 'BHX': 'GB', 'BCN': 'ES', 'BOD': 'FR',
  'BRS': 'GB', 'BRU': 'BE', 'BVA': 'FR', 'CDG': 'FR', 'CFU': 'GR',
  'CPH': 'DK', 'CTA': 'IT', 'DUB': 'IE', 'DUS': 'DE', 'EDI': 'GB',
  'FRA': 'DE', 'FCO': 'IT', 'FNC': 'PT', 'FUE': 'ES', 'GVA': 'CH',
  'HAM': 'DE', 'HEL': 'FI', 'HER': 'GR', 'IBZ': 'ES', 'INI': 'RS',
  'KEF': 'IS', 'KRK': 'PL', 'LCA': 'CY', 'LHR': 'GB', 'LGW': 'GB',
  'LIS': 'PT', 'LIN': 'IT', 'LPA': 'ES', 'LYS': 'FR', 'LUX': 'LU',
  'MAD': 'ES', 'MAN': 'GB', 'MLA': 'MT', 'MLP': 'IT', 'MRS': 'FR',
  'MUC': 'DE', 'MXP': 'IT', 'NAP': 'IT', 'NCE': 'FR',
  'NCL': 'GB', 'NTE': 'FR', 'NUE': 'DE', 'OPO': 'PT', 'OSL': 'NO',
  'PMI': 'ES', 'PMO': 'IT', 'PRG': 'CZ', 'PDL': 'PT', 'SVG': 'NO',
  'SVQ': 'ES', 'STN': 'GB', 'TLS': 'FR', 'TLN': 'FR', 'TRN': 'IT',
  'VLC': 'ES', 'WAW': 'PL', 'ZAG': 'HR', 'ZRH': 'CH',
  'BLE': 'SE', 'GOT': 'SE', 'MMX': 'SE', 'STO': 'SE', 'STR': 'DE',
  'LEJ': 'DE',
  // Восточная/Южная Европа + CIS
  'ATH': 'GR', 'SKG': 'GR', 'BTS': 'SK', 'BRQ': 'CZ',
  'BUD': 'HU', 'CIY': 'IT', 'VRN': 'IT', 'DEB': 'HU', 'OTP': 'RO',
  'CLJ': 'RO', 'SOF': 'BG', 'PLO': 'BG', 'VAR': 'BG', 'BOJ': 'BG',
  'TLL': 'EE', 'RIX': 'LV', 'VNO': 'LT', 'MSQ': 'BY', 'KBP': 'UA',
  'IEV': 'UA', 'DNN': 'UA', 'OZH': 'UA', 'LWO': 'UA', 'ODS': 'UA',
  'HRK': 'UA', 'KIV': 'MD', 'RNV': 'MD', 'DME': 'RU', 'LED': 'RU',
  'TBS': 'GE', 'EVN': 'AM', 'GYD': 'AZ', 'ALA': 'KZ', 'TAS': 'UZ',
  // Скандинавия/Балтия-запас и Балканы, которые CF отдаёт часто.
  'LJU': 'SI', 'SPU': 'HR', 'RIJ': 'HR', 'OSI': 'HR', 'TIA': 'AL',
  'SKP': 'MK', 'SJJ': 'BA', 'OSR': 'CZ', 'TMP': 'FI', 'OUL': 'FI',
  'GDN': 'PL', 'KTW': 'PL', 'POZ': 'PL', 'WRO': 'PL', 'BZG': 'PL',
  'RZE': 'PL', 'SZZ': 'PL',
  // Россия: узлы CF и крупные IATA — после §848 это основной источник страны.
  'AER': 'RU', 'GOJ': 'RU', 'KZN': 'RU', 'KRR': 'RU', 'ROV': 'RU',
  'SVX': 'RU', 'OVB': 'RU', 'KJA': 'RU', 'UFA': 'RU', 'VVO': 'RU',
  'SVO': 'RU',
  // Ближний Восток
  'ADB': 'TR', 'AMM': 'JO', 'BEY': 'LB', 'BGW': 'IQ', 'CAI': 'EG',
  'DKR': 'SN', 'DOH': 'QA', 'DWC': 'AE', 'DXB': 'AE', 'ESB': 'TR',
  'IST': 'TR', 'JED': 'SA', 'RUH': 'SA', 'DMM': 'SA', 'KWI': 'KW',
  'BAH': 'BH', 'MCT': 'OM', 'TLV': 'IL',
  // Африка
  'ABJ': 'CI', 'ACC': 'GH', 'ADD': 'ET', 'ALG': 'DZ', 'CPT': 'ZA',
  'EBB': 'UG', 'FIH': 'CD', 'JNB': 'ZA', 'DUR': 'ZA', 'JRO': 'TZ',
  'KGL': 'RW', 'LOS': 'NG', 'MRU': 'MU', 'NBO': 'KE', 'RBA': 'MA',
  'TNR': 'MG', 'TUN': 'TN', 'RUN': 'RE',
  // Азия и Океания
  'AKL': 'NZ', 'WLG': 'NZ', 'CHC': 'NZ', 'ZQN': 'NZ',
  'AUH': 'AE', 'BKK': 'TH', 'BLR': 'IN', 'BOM': 'IN', 'BBI': 'IN',
  'COK': 'IN', 'MAA': 'IN', 'CCU': 'IN', 'CGK': 'ID', 'DPS': 'ID',
  'CMB': 'LK', 'CNX': 'TH', 'DAC': 'BD', 'DEL': 'IN', 'FRU': 'KG',
  'FUK': 'JP', 'KTM': 'NP', 'HAN': 'VN', 'DAD': 'VN', 'PQC': 'VN',
  'SGN': 'VN', 'HKG': 'HK', 'HYD': 'IN', 'ICN': 'KR', 'ISB': 'PK',
  'KHI': 'PK', 'KIX': 'JP', 'CTS': 'JP', 'NGO': 'JP',
  'MEL': 'AU', 'BNE': 'AU', 'ADL': 'AU', 'CNS': 'AU', 'DRW': 'AU',
  'PER': 'AU', 'SYD': 'AU', 'MFM': 'MO', 'MNL': 'PH', 'CEB': 'PH',
  'CRK': 'PH', 'DVO': 'PH', 'NRT': 'JP', 'PNQ': 'IN', 'SIN': 'SG',
  'SUB': 'ID', 'TPE': 'TW', 'ULN': 'MN', 'NQZ': 'KZ',
};

/// §846 — страна узла по IATA-коду; '' при неизвестном коде.
String countryFromColo(String colo) =>
    kColoCountries[colo.toUpperCase().trim()] ?? '';

/// Тело `cdn-cgi/trace` (построчные `key=value`) → (код страны, IATA-узел).
/// Пусто/битый ответ → ('' , ''). Чистая функция — покрыта тестом.
({String country, String colo}) parseCloudflareTrace(String body) {
  var country = '';
  var colo = '';
  for (final line in const LineSplitter().convert(body)) {
    final i = line.indexOf('=');
    if (i <= 0) continue;
    final k = line.substring(0, i).trim();
    final v = line.substring(i + 1).trim();
    if (k == 'loc') {
      country = v.toUpperCase();
    } else if (k == 'colo') {
      colo = v.toUpperCase();
    }
  }
  // trace может отдать `loc=` пустым или псевдо-кодом (у CF это «неизвестно») —
  // тогда страну считаем неопределённой.
  if (!isPlausibleCountry(country)) country = '';
  return (country: country, colo: colo);
}

/// §844 — тело `speed.cloudflare.com/meta` (JSON: `{"colo":"AMS",
/// "country":"NL",...}`) → тот же кортеж. Второй источник гео: он отдаёт страну
/// там, где `cdn-cgi/trace` подменён перехватом (HTML вместо key=value) или
/// молчит по `loc`. Битый/не-JSON ответ — ('', ''), кидаться не должен: тело
/// приходит из чужих рук (DPI/captive portal).
({String country, String colo}) parseCloudflareMeta(String body) {
  Object? decoded;
  try {
    decoded = jsonDecode(body);
  } catch (_) {
    return (country: '', colo: '');
  }
  if (decoded is! Map) return (country: '', colo: '');
  final country = '${decoded['country'] ?? ''}'.toUpperCase().trim();
  final colo = '${decoded['colo'] ?? ''}'.toUpperCase().trim();
  return (country: isPlausibleCountry(country) ? country : '', colo: colo);
}

/// §844/§848 — тело geo-ответа → (СТРАНА УЗЛА, узел) независимо от формата.
///
/// §848 меняет приоритет: гео-запрос идёт через сам узел (probe-сессия роутит
/// его теги), поэтому в ответе CF разводят два разных объекта:
///
/// * `colo` — IATA-код датацентра, который обработал запрос, то есть **наша
///   выходная точка**; у CF он есть практически всегда;
/// * `loc` (trace) и `country` (meta) — страна, которую GeoLite приписало
///   **источнику запроса**. Это не свойство эндпоинта: хостинговые и anycast
///   диапазоны GeoLite кладёт в `T1`/`A1`/`XX`, а адреса, из которых узел
///   выходит в свою же сеть, — в страну пользователя.
///
/// Замер с этой машины (без туннеля, два разных anycast-адреса):
/// `www.cloudflare.com/cdn-cgi/trace` → `colo=LED loc=RU`,
/// `1.1.1.1/cdn-cgi/trace` → `colo=HEL loc=RU` — один и тот же `loc` при разных
/// узлах. До §848 «верим loc» означало, что весь скан группировался в `RU`
/// (страна клиента), а всё, где GeoLite не угадал, уезжало в «не определена»
/// при видимом в журнале `colo=FRA`/`HEL`.
///
/// Поэтому: есть `colo` → страна берётся ТОЛЬКО из него (нет в таблице —
/// честная «не определена», клиентскую страну подставлять нельзя); `loc`/
/// `country` остаются запасным вариантом только для ответов вообще без `colo`.
({String country, String colo}) parseGeoBody(String body) {
  final trace = parseCloudflareTrace(body);
  final meta = parseCloudflareMeta(body);
  final colo = trace.colo.isNotEmpty ? trace.colo : meta.colo;
  if (colo.isNotEmpty) {
    return (country: countryFromColo(colo), colo: colo);
  }
  // colo нет вообще (перехваченный/неполный ответ) — тогда хоть что-то лучше,
  // чем пустая группа: берём страну из loc, затем из meta.
  if (trace.country.isNotEmpty) return (country: trace.country, colo: colo);
  if (meta.country.isNotEmpty) return (country: meta.country, colo: colo);
  return (country: '', colo: colo);
}

/// §844 — что именно пришло в ответе, для журнала: первая строка/заголовок
/// вразрезку, без переносов и без дампа на 4 КБ. По ней видно, чей это ответ —
/// CF-trace, JSON meta, перехваченный HTML или редирект.
String geoBodyHint(String body) {
  final flat = body.replaceAll(RegExp(r'\s+'), ' ').trim();
  if (flat.isEmpty) return 'пустое тело';
  return flat.length <= 60 ? flat : '${flat.substring(0, 60)}…';
}

/// §839 — SNI для i-го MASQUE-кандидата: РОТАЦИЯ по пулу, а не всегда первый.
///
/// Пул начинается с родного `consumer-masque.cloudflareclient.com` (он же
/// `recommended_sni` в `assets/warp_endpoints.json`): до §839 сканер брал
/// `masqueSniPool.first` на ВСЕ узлы батча, то есть до 32 кандидатов шли с одним
/// и тем же доменом. DPI, знающий эту подпись, режет по ней весь батч сразу —
/// и скан отдаёт «живых 0», хотя адреса могут быть живы. Ротация разносит
/// кандидатов по пулу (10 доменов: родной + приманки), так что батч проверяет
/// не одну подпись, а десять.
String rotateMasqueSni(List<String> pool, int index) {
  if (pool.isEmpty) return '';
  return pool[index % pool.length];
}

/// §840 — сколько раз перепроверять НЕ ответивший MASQUE-адрес, прежде чем
/// объявить его мёртвым.
///
/// Замер рабочей реализации ([warpscout] `masqueDefaultAttempts = 3`) на
/// фильтрующей сети, ОДНИ И ТЕ ЖЕ адреса и тот же SNI: одна попытка дала 1–3
/// живых из 14, три попытки — 11–13. То есть одна неудача не значит ничего:
/// адрес «флапает» (QUIC-хендшейк проходит, а CONNECT-IP/GET не отвечает — и
/// наоборот). Без повторов скан массово даёт ложно-мёртвые адреса, что и
/// выглядит как «живых 0». Повтор дешёвый: адрес уже в поднятой probe-сессии,
/// это ещё один probeGetUrl (3 с вместо 8 с).
const kScanMasqueAttempts = 3;

/// §840 — одна попытка GET'а по узлу, приведённая к тому, что решает скан:
/// «получено ли гео». Ошибка (`err`) и ответ без `loc=`/`colo=` одинаково
/// означают «этот заход не удался» — их и стоит повторить. Ветку `loc=`
/// разбирает вызывающий ([parseCloudflareTrace]) и только для успешных
/// заходов, поэтому здесь она лишь передаётся наружу как есть.
({bool ok, String content}) probeGeoAttempt(CcGetUrlResult r) {
  // §843 — trace иногда не отдаёт loc, но HTTP 2xx подтверждает доступ.
  // Мягкий критерий: считаем geo-ok, если ответ валидный (HTTP 2xx).
  final hasOk = r.ok && (r.status == 200 || r.status == 301 || r.status == 302);
  return (ok: hasOk, content: r.content.isNotEmpty ? r.content : '');
}

/// §844 — Источники гео через проверяемый узел, по предпочтению.
///
/// Раньше был один `https://1.1.1.1/cdn-cgi/trace`: запрос к чистому IP без SNI
/// — самая удобная мишень для перехвата (DPI/captive portal отдают свой HTML с
/// HTTP 200, и §843 считал такой ответ «гео получен», хотя страны в нём нет).
/// `speed.cloudflare.com/meta` отдаёт JSON с `country`, `www.cloudflare.com` —
/// trace с нормальным SNI; оба живут на домене CF, поэтому подмена их ответа
/// ломает и обычный браузер (перехватчики так не делают). IP-версия оставлена
/// последней — она работает там, где DNS-имена зарезаны.
const List<String> kGeoUrls = [
  'https://speed.cloudflare.com/meta',
  'https://www.cloudflare.com/cdn-cgi/trace',
  'https://1.1.1.1/cdn-cgi/trace',
];

/// §844 — потолок GET'ов на один эндпоинт в поисках страны. Повтор (§840) теперь
/// мотивирован НЕ «любым 2xx», а отсутствием СТРАНЫ, поэтому без лимита мёртвый
/// адрес стоил бы 3×8 с, а не 3×8.
const int kGeoMaxRequestsPerEndpoint = 4;

/// Результат серии повторов по одному узлу.
class GeoAttemptResult {
  const GeoAttemptResult({
    required this.result,
    required this.attempts,
  });

  /// ПОСЛЕДНИЙ ответ сервера (для журнала важен он: именно его увидит
  /// разработчик). null — попыток не было.
  final CcGetUrlResult? result;
  final int attempts;
}

/// Движок сканера. Не хранит состояние UI; отдаёт результаты по мере готовности.
class EndpointScanner {
  EndpointScanner({
    CcChannel? cc,
    BoxVpnClient? vpn,
    WarpClient? warpClient,
  })  : _cc = cc ?? CcChannel.instance,
        _vpn = vpn ?? BoxVpnClient(),
        _injectedWarp = warpClient;

  final CcChannel _cc;
  final BoxVpnClient _vpn;
  final WarpClient? _injectedWarp;

  bool _cancelled = false;

  void cancel() => _cancelled = true;

  bool get cancelled => _cancelled;

  /// Максимум кандидатов за один скан (стратифицированная выборка по блокам):
  /// полный перебор /22×4 = 1280 адресов на телефоне бессмысленно долог.
  static const int maxCandidates = 256;

  /// Сколько эндпоинтов максимум подтверждаем/геолоцируем через probe-сессию.
  /// Каждая probe-сессия поднимает ядро (WG-endpoint'ы предвыделяют пулы,
  /// §523), поэтому фаза ограничена и по числу, и по батчам.
  ///
  /// §844 — 32 → 48: всё, что не попало в лимит, живёт в группе «страна не
  /// определена» без какой-то проверки — при 100+ живых адресах это и выглядело
  /// как «страны не определяются».
  static const int maxGeoLookups = 48;

  /// Источники адресов: официальные CF-блоки WARP (WG) + MASQUE-пулы из asset.
  /// Возвращает `ip` (порт подставляется фазой) и `ip:port` (MASQUE).
  ///
  /// §835 — asset не прочитан → берётся встроенный [_fallbackScanPool]:
  /// раньше отсутствие asset'а оставляло только 12 WG-адресов и ВЫКЛЮЧАЛО
  /// MASQUE-путь — а он единственный рабочий в сетях, режущих UDP (РФ).
  Future<List<String>> loadPools() async {
    final pool = await loadPool() ?? _fallbackScanPool();
    // v4-блоки WG (v6-разворот здесь не делаем: expandCidrV4 работает по v4).
    final wg = _sampleIps(pool.wgV4Cidr, maxCandidates);
    final out = <String>[...wg];
    // MASQUE-кандидаты: h3-хосты + стратифицированная выборка h2-блока.
    final masqueSeen = <String>{};
    for (final h in pool.masqueH3Hosts) {
      if (masqueSeen.add(h)) out.add(h);
    }
    for (final ip in _sampleIps(pool.masqueV4Cidr, 32)) {
      if (pool.masqueH2Exclude.contains(ip)) continue;
      if (masqueSeen.add(ip)) out.add(ip);
    }
    return out.isEmpty ? _fallbackPools() : out;
  }

  /// §835 — встроенный резервный пул (asset недоступен/битый). Держит и
  /// WG-блоки, и MASQUE-хосты/блок, чтобы скан не терял второй транспорт.
  /// Структура статична и валидна → null здесь невозможен.
  static ScanPool _fallbackScanPool() =>
      ScanPool.fromFullJson(_fallbackJson)!;

  static const Map<String, dynamic> _fallbackJson = {
    'wireguard': {
      'v4_cidr': [
        '162.159.192.0/24',
        '162.159.193.0/24',
        '162.159.195.0/24',
        '162.159.204.0/24',
        '188.114.96.0/22',
      ],
      'v6_cidr': [
        '2606:4700:d0::/64',
        '2606:4700:d1::/64',
        '2606:4700:100::/64',
      ],
      'ports': [2408, 500, 1701, 4500],
      'keepalive': 25,
      'sni_pool': ['www.google.com', 'www.microsoft.com', 'www.bing.com'],
    },
    'masque': {
      'hosts_preset': [
        '162.159.198.2',
        '162.159.199.2',
        '162.159.197.3',
        '162.159.197.4',
      ],
      'h3': {
        'hosts_extra': ['162.159.198.1', '162.159.199.1'],
        'ports': [443, 8443, 8095],
      },
      'h2': {
        'v4_cidr': [
          '162.159.198.0/24',
          '162.159.199.0/24',
          '162.159.197.0/24',
        ],
        'exclude': ['162.159.198.1', '162.159.199.1'],
        'ports': [443, 8443, 8095],
      },
      'sni_pool': ['consumer-masque.cloudflareclient.com', 'www.google.com'],
    },
  };

  /// Пул из bundled asset (root-секция; регион здесь не важен — сканируем
  /// физические адреса CF, а не региональные списки SNI).
  Future<ScanPool?> loadPool() async {
    try {
      final raw = await rootBundle.loadString('assets/warp_endpoints.json');
      return ScanPool.fromFullJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  List<String> _fallbackPools() {
    // Проверенные CF-адреса (см. docs/§834 notes): WARP anycast + h3/h2 MASQUE.
    return const [
      '162.159.192.1',
      '162.159.192.2',
      '162.159.193.1',
      '162.159.195.1',
      '188.114.96.1',
      '188.114.97.1',
      '188.114.98.1',
      '188.114.99.1',
      '162.159.204.1',
      '162.159.204.2',
      '162.159.197.3',
      '162.159.197.4',
      '162.159.198.1',
      '162.159.198.2',
      '162.159.199.1',
      '162.159.199.2',
    ];
  }

  /// Запускает трёхфазный скан. [endpoints] — адреса (IP или `host:port`;
  /// пустой порт → WG 2408). [excludeColos] — IATA-коды узлов (например `DME`),
  /// которые исключаются из результатов (как `-exclude-node` в warpscout).
  /// [scanDns] — фаза 3: прогон известных DNS-резолверов после группировки по
  /// странам (см. §845, [DnsScanner]).
  Future<EndpointScanResult> scan({
    required List<String> endpoints,
    int concurrency = 16,
    Duration timeout = const Duration(seconds: 3),
    bool tcpFallback = true,
    Set<String> excludeColos = const {},
    int maxGeoLookups = EndpointScanner.maxGeoLookups,
    bool scanDns = true,
    // §847 — фаза 4: прогон SNI-кандидатов (белые списки РФ) через
    // подтверждённые эндпоинты. [sniCandidates] пусто → фаза не идёт (не чего
    // проверять), независимо от флага.
    bool scanSni = true,
    List<String> sniCandidates = const [],
    void Function(int done, int total)? onProgressPhase1,
    void Function(int done, int total)? onProgressPhase2,
    void Function(int done, int total)? onProgressPhase4,
    void Function(String note)? onNote,
    ScanLog? log,
    void Function(ScanEndpointStatus status)? onStatus,
  }) async {
    _cancelled = false;
    final sw = Stopwatch()..start();
    var note = '';
    final statuses = <String, ScanEndpointStatus>{};
    void emit(ScanEndpointStatus s) {
      statuses[s.endpoint] = s;
      onStatus?.call(s);
    }

    log?.i(
      'scan',
      'старт: адресов=${endpoints.length} потоков=$concurrency '
      'таймаут=${timeout.inMilliseconds}мс максимум-гео=$maxGeoLookups '
      'MASQUE-фолбэк=$tcpFallback',
    );

    // §835 — самопроверка сети: на телефоне UDP наружу может быть зарезан
    // целиком, и в журнале надо отличить «нет интернета» от «режут UDP».
    unawaited(_netSelfCheck(log));

    // ── Phase 1 — UDP WG-проба ────────────────────────────────────────────
    // Кандидаты WG — те, у кого нет не-WG порта; MASQUE-адреса (h3-хосты и
    // h2-блок) в WG-фазу не идут: они не отвечают на WG-handshake.
    final loadedPool = await loadPool();
    final pool = loadedPool ?? _fallbackScanPool();
    final wgPorts = <int>{
      2408,
      ...pool.wgPorts,
    }.toList();
    if (loadedPool == null) {
      log?.w(
        'pool',
        'asset не прочитан → встроенный резервный пул (WG + MASQUE); '
        'проверьте assets/warp_endpoints.json',
      );
    } else {
      log?.i(
        'pool',
        'asset ок: wgV4=${pool.wgV4Cidr} порты=$wgPorts '
        'masqueH3=${pool.masqueH3Hosts} masqueH2=${pool.masqueV4Cidr}',
      );
    }

    final byTransport = <String, EndpointTransport>{};
    final wgCandidates = <String>[];
    final masqueCandidates = <String>[];
    for (final ep in endpoints) {
      if (_isMasqueEndpoint(ep, pool)) {
        masqueCandidates.add(ep);
        byTransport[ep] = _masqueTransport(ep, pool);
      } else {
        wgCandidates.add(ep);
      }
    }
    log?.i(
      'plan',
      'раскладка: WG=${wgCandidates.length} MASQUE=${masqueCandidates.length}',
    );

    final alive = <String, WgProbeResult>{};
    final aliveTransport = <String, EndpointTransport>{};
    final failed = <String>[];

    // §841 — КОРЕНЬ «нет живых» на фильтрующих сетях (МегаФон/Орёл):
    //   1) фаза 1 слала ГОЛЫЙ WG-init со СЛУЧАЙНЫМ ключом. WARP-эндпоинт
    //      отвечает на handshake только от ЗАРЕГИСТРИРОВАННОГО пира: со
    //      случайным ключом сервер молчит (проверено: аккаунтный ключ → 92 Б
    //      type-2, случайный → timeout).
    //   2) DPI режет одиночный WG-init по сигнатуре; пробивает только
    //      обфусцированный залп AmneziaWG: [I1] + [junk × jc] + [init].
    //      Замер на той же сети: голый init → timeout, junk+init → 92 Б
    //      type-2, I1+junk+init → 92 Б type-2.
    // Поэтому ключ аккаунта достаём ДО скана (кеш → регистрация), а пробу
    // шлём залпом. Если аккаунта нет и зарегистрировать не удалось —
    // деградируем к прежнему голому WG-зонду (лучше, чем ничего).
    // §842 — деградация к голому WG делается ГРОМКОЙ: раньше сбой получения
    // ключа аккаунта молча давал «живых 0» по всем адресам и выглядел как
    // «сканер не работает». Теперь причина видна и в журнале, и в заметке.
    String? awgDegradedReason;
    List<int>? warpPrivRaw;
    try {
      var acc = await SettingsStorage.getWarpAccount();
      if (acc == null) {
        log?.i('p1', 'WARP-аккаунта нет — регистрирую для пробы живости…');
        Object? lastErr;
        for (var attempt = 1; attempt <= 2 && acc == null; attempt++) {
          final regClient = _injectedWarp ?? WarpClient();
          try {
            acc = await regClient.register(
              endpoint: WarpAccount.defaultEndpoint,
              nowIso8601: DateTime.now().toUtc().toIso8601String(),
            );
            await SettingsStorage.setWarpAccount(acc);
          } catch (e) {
            lastErr = e;
            log?.w('p1', 'регистрация (попытка $attempt/2) не удалась: $e');
          } finally {
            if (_injectedWarp == null) regClient.close();
          }
        }
        if (acc == null) throw lastErr ?? 'registration returned null';
      }
      warpPrivRaw = base64Decode(acc.privKey);
      log?.i(
        'p1',
        'обфускация AWG: I1(${renderI1Chain(kI1DefaultChain).length}Б)'
        '+junk(jc=6,j10..50)+init, ключ аккаунта ок (${warpPrivRaw.length}Б)',
      );
    } catch (e) {
      awgDegradedReason = 'ключ аккаунта не получен';
      log?.e(
        'p1',
        'КЛЮЧ АККАУНТА НЕ ПОЛУЧЕН ($e) → голый WG-init. На сетях, режущих '
        'UDP, это даст 0 живых: WARP отвечает только на handshake от ключа '
        'ЗАРЕГИСТРИРОВАННОГО пира. Проверьте интернет и повторите скан.',
      );
    }

    Future<void> wgPass(List<int> ports) async {
      final cand = <String>[
        for (final ip in wgCandidates)
          for (final p in ports) ip.contains(':') ? ip : '$ip:$p',
      ];
      void onP1(String ep, WgProbeResult r) {
        log?.add(
          r.alive ? ScanLogLevel.info : ScanLogLevel.debug,
          'p1',
          '$ep → ${r.kind.name} rtt=${r.rttMs}мс ${r.detail}',
        );
        emit(ScanEndpointStatus(
          endpoint: ep,
          phase: 1,
          verdict: r.alive
              ? (r.kind == WgProbeKind.cookie ? 'cookie' : 'alive')
              : r.kind.name,
          rttMs: r.rttMs,
          detail: r.detail,
        ));
      }
      final awgMode = warpPrivRaw != null;
      log?.i(
        'p1',
        awgMode
            ? 'UDP-проба AWG-залпом (обфусцированно): ${cand.length} адресов, '
                'порты=$ports'
            : 'UDP-проба голым WG-init: ${cand.length} адресов, порты=$ports',
      );
      final batch = await (warpPrivRaw != null
          ? scanAwgBatch(
              endpoints: cand,
              staticPrivRaw: warpPrivRaw,
              concurrency: concurrency,
              timeout: timeout,
              onProgress: onProgressPhase1,
              onProbe: onP1,
              cancelled: () => _cancelled,
            )
          : scanWgBatch(
              endpoints: cand,
              concurrency: concurrency,
              timeout: timeout,
              onProgress: onProgressPhase1,
              onProbe: onP1,
              cancelled: () => _cancelled,
            ));
      batch.forEach((ep, r) {
        if (r.alive) {
          alive[ep] = r;
          aliveTransport[ep] = EndpointTransport.wg;
        }
      });
    }

    if (wgCandidates.isNotEmpty && !_cancelled) {
      await wgPass([2408]);
      // Другие WG-порты — только если канонический ничего не дал: операторы
      // режут 2408, но пропускают 500/1701/4500.
      if (!_cancelled && alive.isEmpty && wgPorts.isNotEmpty) {
        final rest = wgPorts.where((p) => p != 2408).toList();
        if (rest.isNotEmpty) {
          log?.i('p1', 'порт 2408 молчит — пробуем другие WG-порты: $rest');
          await wgPass(rest);
        }
      }
    }
    failed.addAll(wgCandidates.where((ip) => !alive.keys.any(
          (a) => a == ip || a.startsWith('$ip:'),
        )));
    log?.i(
      'p1',
      'итог фазы 1: живых=${alive.length} без ответа=${failed.length}',
    );

    // §842 — если ключ аккаунта не получен, проба шла голым WG: на сети,
    // режущей UDP, это 0 живых. Поднимаем причину в заметку под итогом скана,
    // чтобы пользователь видел не только «0», но и ЧТО сломано.
    if (awgDegradedReason != null && alive.isEmpty) {
      note = '$awgDegradedReason — проба шла без обфускации. '
          'Проверьте интернет и повторите скан.';
    }

    // ── Phase 1b — MASQUE-путь, если UDP не дал живых ─────────────────────
    // Открытый TCP 443 НЕ считаем живостью (CF-edge отвечает почти всегда):
    // кандидаты MASQUE подтверждаются реальным GET через probe-сессию ниже.
    var usedMasque = false;
    if (tcpFallback && !_cancelled && alive.isEmpty && masqueCandidates.isNotEmpty) {
      usedMasque = true;
      log?.w('p1b', 'UDP не дал живых → идём MASQUE-путём (h2/TCP 443)');
    }

    // ── Phase 2 — подтверждение + гео через probe-сессию ядра ─────────────
    final geoMeta = <String, ({String country, String colo})>{};
    final ordered = <String>[
      ...alive.keys,
      if (usedMasque) ...masqueCandidates,
    ];
    // Сначала самые «перспективные» (WG-ответ прошёл быстрее) — по RTT.
    final orderedSorted = [...ordered]
      ..sort((a, b) =>
          (alive[a]?.rttMs ?? 1 << 30).compareTo(alive[b]?.rttMs ?? 1 << 30));
    final geoList = orderedSorted.take(maxGeoLookups).toList();

    log?.i(
      'p2',
      'фаза 2 (гео через ядро): кандидатов=${geoList.length} '
      'из ${ordered.length} (лимит $maxGeoLookups)',
    );

    // ── §838 — TCP-preflight MASQUE-h2 ────────────────────────────────────
    // В сетях РФ оператор часто режет не только UDP/WG, но и ТСР до
    // MASQUE-адресов. Probe-сессия ядра на мёртвом адресе висит ~8с и отдаёт
    // `context deadline exceeded`: 32 таких подряд = 4+ минуты «молчания», а
    // пользователь видит «живых 0» без причины. Дешёвая TCP-проверка
    // (системный стек Dart, БЕЗ ядра) за секунды отделяет «адрес/порт закрыт»
    // от «ядро не смогло» и даёт в журнал ЯВНЫЙ вердикт. У выживших порты
    // пула пробуются по очереди: 443 зарезан, а 8443 нет — кандидат
    // переезжает на рабочий порт. h3 (QUIC/UDP) preflight не подлежит.
    var effective = [...geoList];
    if (!_cancelled) {
      final h2 = <String>[
        for (final ep in geoList)
          if (byTransport[ep] == EndpointTransport.masqueH2) ep,
      ];
      if (h2.isNotEmpty) {
        final ports = pool.masquePortsH2.isNotEmpty
            ? pool.masquePortsH2
            : const <int>[443, 8443];
        log?.i(
          'p2',
          'TCP-preflight MASQUE-h2: ${h2.length} адресов, порты=$ports',
        );
        final probes = await Future.wait(h2.map((ep) async {
          final ip = ep.contains(':') ? ep.split(':').first : ep;
          for (final p in ports) {
            // §839 — отмена должна прерывать и preflight: иначе «Отмена»
            // ждёт все таймауты (до 7 портов × 3с) по всем адресам.
            if (_cancelled) {
              return (ep: ep, ip: ip, port: 0, detail: 'отменено');
            }
            final r = await probeTcpOpen(
              ip,
              p,
              timeout: const Duration(seconds: 3),
            );
            if (r.open) return (ep: ep, ip: ip, port: p, detail: r.detail);
          }
          return (ep: ep, ip: ip, port: 0, detail: 'tcp: порты $ports закрыты');
        }));
        for (final r in probes) {
          if (_cancelled) break;
          if (r.port == 0) {
            // §839 — TCP закрыт, НО UDP:443 (QUIC) может проходить: у РФ-операторов
            // это частый случай. Не выбрасываем адрес, а пробуем его же через
            // MASQUE-h3. Прямое доказательство из журнала пользователя: ответ
            // `http3: parsing frame failed: PROTOCOL_VIOLATION (remote)` означает,
            // что QUIC-пакеты до Cloudflare ДОШЛИ и сервер ответил — то есть путь
            // существует, и отбрасывать его нельзя.
            byTransport[r.ep] = EndpointTransport.masqueH3;
            log?.w(
              'p2',
              '${r.ep} ${r.detail} → fallback на MASQUE-h3 (QUIC/UDP:443)',
            );
            emit(ScanEndpointStatus(
              endpoint: r.ep,
              phase: 2,
              verdict: 'tcp-closed',
              detail: '${r.detail} → пробую h3/QUIC',
            ));
            continue;
          }
          final key = '${r.ip}:${r.port}';
          if (key != r.ep) {
            // 443 не открылся, а другой порт пула — да: переезжаем на него,
            // ЗАМЕНЯЯ кандидата на месте (не добавляя дубль) и перенося RTT.
            final idx = ordered.indexOf(r.ep);
            if (idx >= 0) {
              ordered[idx] = key;
            } else {
              ordered.add(key);
            }
            final prev = alive.remove(r.ep);
            if (prev != null) alive[key] = prev;
            byTransport[key] = EndpointTransport.masqueH2;
            final ei = effective.indexOf(r.ep);
            if (ei >= 0) {
              effective[ei] = key;
            } else {
              effective.add(key);
            }
            log?.i('p2', '${r.ep} ${r.detail} → кандидат на $key');
          } else {
            log?.i('p2', '${r.ep} ${r.detail} → TCP открыт, подтверждаю');
          }
        }
        log?.i(
          'p2',
          'после preflight: к подтверждению ${effective.length} '
          'из ${geoList.length}',
        );
      }
    }

    if (!_cancelled && effective.isNotEmpty) {
      // §847 — цели фазы 2: адрес + SNI (ротация по пулу). Индекс цели =
      // позиция в [effective], поэтому результаты разбираются обратно по индексу.
      final targets = [
        for (var i = 0; i < effective.length; i++)
          (
            endpoint: effective[i],
            transport: byTransport[effective[i]] ?? EndpointTransport.wg,
            sni: _sniForCandidate(
              byTransport[effective[i]] ?? EndpointTransport.wg,
              i,
              pool,
            ),
          ),
      ];
      try {
        final res = await _probeTargets(
          targets,
          pool: pool,
          onProgress: onProgressPhase2,
          log: log,
          onResult: (i, t, geo, detail) {
            emit(ScanEndpointStatus(
              endpoint: t.endpoint,
              phase: 2,
              verdict: geo != null ? 'geo-ok' : 'geo-fail',
              rttMs: alive[t.endpoint]?.rttMs ?? 0,
              country: geo?.country ?? '',
              colo: geo?.colo ?? '',
              detail: detail,
            ));
          },
        );
        for (final e in res.geoByIndex.entries) {
          geoMeta[effective[e.key]] = e.value;
        }
        // §844 — MASQUE-кандидаты становятся живыми по факту ответа через узел,
        // а не по наличию страны: иначе строгий критерий гео молча убивал бы
        // проходимые адреса («живых 0» при работающем туннеле).
        for (final i in res.respondedIndex) {
          final ep = effective[i];
          if (!alive.containsKey(ep)) {
            alive[ep] = const WgProbeResult(WgProbeKind.response,
                rttMs: 0); // подтверждён probe-GET (MASQUE)
            aliveTransport[ep] = byTransport[ep] ?? EndpointTransport.masqueH3;
          }
        }
        if (res.error != null && res.error!.isNotEmpty) {
          note = res.error!;
          log?.e('p2', 'ошибка фазы 2: ${res.error}');
        }
      } catch (e) {
        note = 'probe: $e';
        log?.e('p2', 'исключение фазы 2: $e');
      }
    }

    // ── Сборка результата ────────────────────────────────────────────────
    final byCountry = <String, List<EndpointResult>>{};
    for (final ep in ordered) {
      if (!alive.containsKey(ep)) continue;
      final meta = geoMeta[ep];
      final country = meta?.country ?? '';
      final colo = meta?.colo ?? '';
      if (colo.isNotEmpty && excludeColos.contains(colo)) {
        log?.i('build', '$ep исключён по узлу $colo');
        continue;
      }
      final r = EndpointResult(
        endpoint: ep,
        country: country,
        colo: colo,
        rttMs: alive[ep]?.rttMs ?? 0,
        alive: true,
      );
      byCountry.putIfAbsent(country, () => []).add(r);
    }

    final groups = [
      for (final e in byCountry.entries)
        EndpointCountryGroup(
          code: e.key,
          name: countryName(e.key),
          endpoints: e.value,
        ),
    ]..sort((a, b) {
        // Известные страны — выше; «не определена» — в конце.
        if (a.isUnknown != b.isUnknown) return a.isUnknown ? 1 : -1;
        return b.valid.compareTo(a.valid);
      });

    // ── Фаза 3 — известные DNS-резолверы ─────────────────────────────────
    // Идёт ПОСЛЕ группировки по странам: сначала сами эндпоинты и их гео,
    // потом инфраструктура резолвинга. Отбор — только корректно ответившие адреса.
    var dns = const <DnsServerResult>[];
    if (scanDns && !_cancelled) {
      try {
        dns = await DnsScanner(
          cancelled: () => _cancelled,
        ).scan(
          log: log,
          onResult: (r) => emit(ScanEndpointStatus(
            endpoint: r.endpoint,
            phase: 3,
            verdict: r.verdict,
            rttMs: r.rttMs,
            detail: '${r.label}${r.detail.isEmpty ? '' : ' · ${r.detail}'}',
          )),
        );
      } catch (e) {
        log?.e('dns', 'фаза 3 не завершилась: $e');
        note = 'dns: $e';
      }
    }

    // ── Фаза 4 — SNI (белые списки РФ) ───────────────────────────────────
    // Идёт ПОСЛЕ эндпоинтов и DNS: проверяем домены уже рабочими адресами,
    // поэтому кандидаты — пул RU-списка, а эндпоинты — живые, по RTT.
    var sni = const <SniScanResult>[];
    if (scanSni && sniCandidates.isNotEmpty && !_cancelled) {
      final probeable = <String>[
        for (final ep in ordered)
          if (alive.containsKey(ep)) ep,
      ]..sort(
          (a, b) => _rttOf(alive[a]!.rttMs).compareTo(_rttOf(alive[b]!.rttMs)),
        );
      final cands = sniScanCandidates(
        masque: sniCandidates,
        wg: pool.wgSniPool,
        max: kSniScanPerEndpoint,
      );
      if (cands.isNotEmpty) {
        try {
          sni = await _probeSni(
            endpoints: probeable,
            byTransport: aliveTransport,
            candidates: cands,
            pool: pool,
            log: log,
            onProgress: onProgressPhase4,
            onAttempt: (a) => emit(ScanEndpointStatus(
              endpoint: '${a.sni} @${a.endpoint}',
              phase: 4,
              verdict: a.responded ? kSniVerdictOk : kSniVerdictBlocked,
              detail: a.detail,
            )),
            onResult: (r) => emit(ScanEndpointStatus(
              endpoint: '${r.sni} @${r.endpoint}',
              phase: 4,
              verdict: r.verdict,
              rttMs: r.rttMs,
              detail: r.detail,
            )),
          );
        } catch (e) {
          log?.e('sni', 'фаза 4 не завершилась: $e');
          note = 'sni: $e';
        }
      }
    }

    log?.i(
      'done',
      'финиш: групп=${groups.length} живых=${alive.length} '
      'без ответа=${failed.length} dns-валидных='
      '${dns.where((d) => d.valid).length} sni-годных='
      '${sni.where((s) => s.valid).length} за ${sw.elapsedMilliseconds}мс',
    );

    return EndpointScanResult(
      groups: groups,
      scanAt: DateTime.now().toUtc(),
      scanDurationMs: sw.elapsedMilliseconds,
      failedCount: failed.length,
      tcpFallbackUsed: usedMasque && groups.isNotEmpty,
      note: note,
      statuses: statuses.values.toList(),
      dns: dns,
      sni: sni,
    );
  }

  /// §847 — порядок по RTT: 0 («не измерен») — в конец.
  static int _rttOf(int rttMs) => rttMs == 0 ? 1 << 30 : rttMs;

  /// §835 — самопроверка сети для журнала: TCP-коннект к `1.1.1.1:443`.
  /// Отличает «нет интернета» (пользователю надо чинить сеть) от «интернет
  /// есть, но режут UDP/WG» (тогда скан обязан идти MASQUE-путём).
  Future<void> _netSelfCheck(ScanLog? log) async {
    if (log == null) return;
    try {
      final r = await probeTcpReachable('1.1.1.1', 443);
      if (r.reachable) {
        log.i('net', 'интернет есть: ${r.detail}');
      } else {
        log.w('net', 'интернет НЕ подтверждён: ${r.detail}');
      }
    } catch (e) {
      log.w('net', 'самопроверка сети не удалась: $e');
    }
  }

  /// MASQUE-ли это адрес (h3-хост блока или адрес h2-блока).
  bool _isMasqueEndpoint(String ep, ScanPool? pool) {
    if (pool == null) return false;
    final host = ep.contains(':') ? ep.split(':').first : ep;
    if (pool.masqueH3Hosts.contains(host)) return true;
    return _ipInCidrs(host, pool.masqueV4Cidr);
  }

  EndpointTransport _masqueTransport(String ep, ScanPool? pool) {
    final host = ep.contains(':') ? ep.split(':').first : ep;
    if (pool == null) return EndpointTransport.masqueH3;
    // В сетях, режущих UDP (РФ), рабочий транспорт — h2 (TCP): h3 — это QUIC
    // поверх UDP. Поэтому адрес, живущий и в h2-блоке (не из exclude), ведём
    // как h2; на h3 остаются только h3-only хосты.
    final inH2 = _ipInCidrs(host, pool.masqueV4Cidr) &&
        !pool.masqueH2Exclude.contains(host);
    return inH2 ? EndpointTransport.masqueH2 : EndpointTransport.masqueH3;
  }

  /// Подтверждение + гео через probe-сессию. Возвращает карту `endpoint →
  /// (страна, узел)` по тем, через кого GET прошёл; эндпоинты, не прошедшие
  /// пробу, в карту не попадают.
  /// §844 — GET'ы по одному узлу пробы до полученной СТРАНЫ.
  ///
  /// До §844 цикл останавливался на первом HTTP 2xx (критерий [probeGeoAttempt]
  /// из §843) и парсил `cdn-cgi/trace`. На перехваченной сети это давало ровно
  /// то, что наблюдал пользователь: вердикт «geo-ok» при пустой стране — чужой
  /// HTML/редирект проходит как 2xx, а `loc=` в нём нет. Поэтому: критерий успеха
  /// — непустая страна, источник чередуется по [kGeoUrls], всего запросов не
  /// больше [kGeoMaxRequestsPerEndpoint] (мёртвый адрес не должен стоить минут).
  Future<
      ({
        String country,
        String colo,
        bool responded,
        int requests,
        String url,
        CcGetUrlResult? last,
      })> _fetchGeo(
    String tag,
    ScanLog? log,
    String ep, {
    int rounds = kScanMasqueAttempts,
    int maxRequests = kGeoMaxRequestsPerEndpoint,
    // §847 — прогон SNI решает «прошёл/не прошёл», страна ему не нужна:
    // первый же ответ закрывает заход (иначе мёртвый SNI стоил бы 4 запроса).
    bool stopAtResponse = false,
  }) async {
    var colo = '';
    var requests = 0;
    var responded = false;
    var usedUrl = kGeoUrls.first;
    CcGetUrlResult? last;
    for (var round = 0; round < rounds; round++) {
      for (final url in kGeoUrls) {
        if (_cancelled || requests >= maxRequests) break;
        usedUrl = url;
        final r = await _cc.probeGetUrl(
          tag,
          link: url,
          timeoutMs: 8000,
          maxBytes: 4096,
        );
        last = r;
        requests++;
        final parsed = probeGeoAttempt(r);
        if (!parsed.ok) continue;
        // Ответ через узел получен — это доказательство проходимости независимо
        // от того, есть ли в теле страна (§844: живость и гео разведены).
        responded = true;
        final g = parseGeoBody(parsed.content);
        if (g.colo.isNotEmpty) colo = g.colo;
        if (g.country.isNotEmpty || stopAtResponse) {
          return (
            country: g.country,
            colo: g.colo.isNotEmpty ? g.colo : colo,
            responded: true,
            requests: requests,
            url: url,
            last: r,
          );
        }
        log?.d('p2', '$ep $url HTTP ${r.status} — ответ есть, страны нет');
      }
      if (_cancelled || requests >= maxRequests) break;
    }
    return (
      country: '',
      colo: colo,
      responded: responded,
      requests: requests,
      url: usedUrl,
      last: last,
    );
  }

  Future<
      ({
        Map<int, ({String country, String colo})> geoByIndex,
        Set<int> respondedIndex,
        String? error,
      })> _probeTargets(
    List<ScanProbeTarget> targets, {
    required ScanPool? pool,
    int rounds = kScanMasqueAttempts,
    int maxRequests = kGeoMaxRequestsPerEndpoint,
    bool stopAtResponse = false,
    void Function(int done, int total)? onProgress,
    ScanLog? log,
    void Function(
      int index,
      ScanProbeTarget target,
      ({String country, String colo})? geo,
      String detail,
    )? onResult,
  }) async {
    final out = <int, ({String country, String colo})>{};
    // §844 — «узел донёс наш запрос» отдельно от «узел дал страну»: MASQUE-
    // кандидаты становятся живыми по первому, а вердикт гео — по второй.
    final responded = <int>{};
    if (targets.isEmpty) {
      return (geoByIndex: out, respondedIndex: responded, error: null);
    }

    // VPN активен → probe-сессию не поднять (два CommandServer на процесс
    // невозможны, §236). Скан от этого не рушится: живость из фазы 1 остаётся.
    try {
      final status = await _vpn.getVpnStatus();
      log?.i('p2', 'статус VPN: $status');
      if (status != TunnelStatus.disconnected) {
        log?.w(
          'p2',
          'VPN включён → probe-сессию поднять нельзя, гео пропущено. '
          'Выключите VPN и перезапустите скан.',
        );
        return (
          geoByIndex: out,
          respondedIndex: responded,
          error: getLocalText.s('VPN active — geo phase skipped'),
        );
      }
    } catch (e) {
      // Состояние VPN не спросилось — пробуем всё равно.
      log?.w('p2', 'статус VPN не спросился ($e) — пробуем поднять сессию');
    }

    // Аккаунты: кеш → регистрация. Для WG нужен WarpAccount, для MASQUE —
    // MasqueAccount (обфускация/SNI — из пула).
    final client = _injectedWarp ?? WarpClient();
    WarpAccount? warpAcc;
    MasqueAccount? masqueAcc;
    String? regError;
    try {
      final now = DateTime.now().toUtc().toIso8601String();
      warpAcc = await SettingsStorage.getWarpAccount();
      masqueAcc = await SettingsStorage.getMasqueAccount();
      log?.i(
        'p2',
        'аккаунты: WARP=${warpAcc != null ? 'есть' : 'нет'} '
        'MASQUE=${masqueAcc != null ? 'есть' : 'нет'}',
      );
      if (targets.any((t) => t.transport == EndpointTransport.wg) &&
          warpAcc == null) {
        try {
          log?.i('p2', 'регистрирую WARP-аккаунт…');
          warpAcc = await client.register(
            endpoint: WarpAccount.defaultEndpoint,
            nowIso8601: now,
          );
          await SettingsStorage.setWarpAccount(warpAcc);
          log?.i('p2', 'WARP-аккаунт зарегистрирован');
        } catch (e) {
          regError ??= 'WARP register failed: $e';
          log?.e('p2', 'WARP register failed: $e');
        }
      }
      if (targets.any((t) => t.transport != EndpointTransport.wg) &&
          masqueAcc == null) {
        try {
          log?.i('p2', 'регистрирую MASQUE-аккаунт…');
          masqueAcc = await client.registerMasque(nowIso8601: now);
          await SettingsStorage.setMasqueAccount(masqueAcc);
          log?.i('p2', 'MASQUE-аккаунт зарегистрирован');
        } catch (e) {
          regError ??= 'MASQUE register failed: $e';
          log?.e('p2', 'MASQUE register failed: $e');
        }
      }
    } finally {
      if (_injectedWarp == null) client.close();
    }

    final builder = ScanNodeBuilder(
      warp: warpAcc,
      masque: masqueAcc,
      wgKeepalive: pool?.wgKeepalive ?? 0,
    );

    // Узлы строятся в порядке [targets] (null — не собирается; индекс
    // сохраняется, `buildProbeBatches` вернёт его в `brokenByIndex`).
    // §839 — SNI цели уже задан вызывающим: в фазе 2 его ротирует
    // [_sniForCandidate] (один «паливный» домен на весь батч DPI режет целиком),
    // в фазе 4 (§847) цель и есть проверяемый SNI.
    final nodes = <NodeSpec?>[];
    for (var i = 0; i < targets.length; i++) {
      final t = targets[i];
      final node = _buildNodeFor(t.endpoint, t.transport, builder, pool, t.sni);
      if (node == null) {
        log?.w(
          'p2',
          '${t.endpoint} (${t.transport.name} sni=${t.sni}): '
          'узел не собрался (нет аккаунта/кред)',
        );
        onResult?.call(i, t, null, 'node build failed: no account');
      } else {
        log?.d(
          'p2',
          '${t.endpoint} (${t.transport.name}) sni=${t.sni} → узел собран',
        );
      }
      nodes.add(node);
    }

    final coreVersion = await CoreVersionCache.ensure(
      () => _vpn.getCoreVersion(),
    );
    final vars = await loadProbeVars();
    final batches = buildProbeBatches(
      nodes,
      coreVersion: coreVersion,
      vars: vars,
    );
    log?.i(
      'p2',
      'probe-конфигов=${batches.length} ядро=$coreVersion '
      'собрано узлов=${nodes.whereType<NodeSpec>().length}/${targets.length}',
    );

    var done = 0;
    for (final cfg in batches) {
      if (_cancelled) break;
      if (cfg.configJson == null) {
        log?.w('p2', 'батч пуст (нет тестируемых узлов)');
        continue;
      }
      log?.i(
        'p2',
        'probeStart: тегов=${cfg.tagByIndex.length} '
        'конфиг=${cfg.configJson!.length}B битых=${cfg.brokenByIndex.length}',
      );
      final err = await _cc.probeStart(cfg.configJson!);
      if (err.isNotEmpty) {
        log?.e('p2', 'probeStart не поднялся: $err');
        return (geoByIndex: out, respondedIndex: responded, error: err);
      }
      log?.i('p2', 'probe-сессия ядра поднята');
      try {
        for (final entry in cfg.tagByIndex.entries) {
          if (_cancelled) break;
          final t = targets[entry.key];
          final ep = t.endpoint;
          try {
            // §840/§844 — MASQUE «флапает» (замер эталона: 1 попытка → 1–3 живых
            // из 14, 3 попытки → 11–13), но повторяем теперь до СТРАНЫ, а не до
            // «любого 2xx», и чередуем источники гео. §847 (прогон SNI) —
            // наоборот: первый ответ и есть вердикт, страну там не ищем.
            final g = await _fetchGeo(
              entry.value,
              log,
              ep,
              rounds: rounds,
              maxRequests: maxRequests,
              stopAtResponse: stopAtResponse,
            );
            final r = g.last;
            final ok = g.responded && (stopAtResponse || g.country.isNotEmpty);
            if (g.responded) responded.add(entry.key);
            if (ok) {
              final geo = (country: g.country, colo: g.colo);
              out[entry.key] = geo;
              log?.i(
                'p2',
                '$ep sni=${t.sni} ${stopAtResponse ? 'прошёл' : 'country=${geo.country}'} '
                'colo=${geo.colo} HTTP ${r?.status} remote=${r?.remoteAddr} '
                '${r?.elapsedMs ?? 0}мс (${g.requests} з-сов, ${g.url})',
              );
              onResult?.call(
                entry.key,
                t,
                geo,
                'HTTP ${r?.status} ${r?.remoteAddr} '
                '${r?.elapsedMs ?? 0}мс',
              );
            } else {
              // Узел мог отдать colo без страны — помечаем: excludeColos и
              // подпись в UI по нему работают, а вердикт остаётся geo-fail.
              if (g.colo.isNotEmpty) {
                out[entry.key] = (country: '', colo: g.colo);
              }
              final why = r == null
                  ? 'нет ответа'
                  : r.error.isNotEmpty
                      ? 'err=${r.error}'
                      : 'HTTP ${r.status} без country/loc (${geoBodyHint(r.content)})';
              log?.w(
                'p2',
                '$ep sni=${t.sni} гео не получено: ${g.requests} запросов по '
                '${kGeoUrls.length} источникам — $why remote=${r?.remoteAddr}',
              );
              onResult?.call(entry.key, t, null, why);
            }
          } catch (e) {
            // Один узел не ответил — не валим весь батч.
            log?.w('p2', '$ep probeGetUrl исключение: $e');
            onResult?.call(entry.key, t, null, 'exception: $e');
          }
          done++;
          onProgress?.call(done, targets.length);
        }
      } finally {
        await _cc.probeStop();
        log?.i('p2', 'probe-сессия ядра погашена');
      }
    }
    return (geoByIndex: out, respondedIndex: responded, error: regError);
  }

  /// §839 — SNI i-го кандидата фазы 2. WG-приманка берёт первый домен своего
  /// пула (у AWG набор подписей короче), MASQUE — ротирует по пулу: раньше все
  /// узлы батча шли с `masqueSniPool.first` (родной
  /// `consumer-masque.cloudflareclient.com`), и DPI, знающий эту подпись, резал
  /// батч целиком — «живых 0» при живых адресах.
  String _sniForCandidate(
    EndpointTransport transport,
    int index,
    ScanPool? pool,
  ) {
    final isWg = transport == EndpointTransport.wg;
    final sniPool = isWg
        ? (pool?.wgSniPool ?? const <String>[])
        : (pool?.masqueSniPool ?? const <String>[]);
    return isWg
        ? (sniPool.isEmpty ? '' : sniPool.first)
        : rotateMasqueSni(sniPool, index);
  }

  /// §847 — фаза 4: прогон SNI-кандидатов (белые списки РФ) через
  /// подтверждённые эндпоинты.
  ///
  /// Каждый кандидат собирается отдельной целью `(эндпоинт, SNI)` и проверяется
  /// ОДНИМ ответом через туннель: прошёл — домен живёт в DPI сегодня, не прошёл
  /// — в генератор не попадает. Эндпоинтов берём не больше
  /// [kSniScanEndpoints] (по RTT, живо подтверждённые гео), кандидатов — не
  /// больше [kSniScanPerEndpoint] в порядке пула.
  ///
  /// Возвращает пусто, если probe-сессия невозможна (VPN включён, нет
  /// аккаунтов) — тогда UI просто не показывает шаг.
  Future<List<SniScanResult>> _probeSni({
    required List<String> endpoints,
    required Map<String, EndpointTransport> byTransport,
    required List<String> candidates,
    required ScanPool? pool,
    ScanLog? log,
    void Function(int done, int total)? onProgress,
    void Function(SniAttempt attempt)? onAttempt,
    void Function(SniScanResult result)? onResult,
  }) async {
    if (endpoints.isEmpty || candidates.isEmpty) return const [];
    final targets = <ScanProbeTarget>[];
    for (final ep in endpoints.take(kSniScanEndpoints)) {
      for (final sni in candidates) {
        targets.add((endpoint: ep, sni: sni,
            transport: byTransport[ep] ?? EndpointTransport.masqueH3));
      }
    }
    log?.i(
      'sni',
      'фаза 4: ${candidates.length} SNI × ${endpoints.take(kSniScanEndpoints).length} '
      'эндпоинтов = ${targets.length} узлов',
    );
    final attempts = <SniAttempt>[];
    final res = await _probeTargets(
      targets,
      pool: pool,
      rounds: 1,
      maxRequests: kSniScanRequestsPerPair,
      stopAtResponse: true,
      log: log,
      onProgress: onProgress,
      onResult: (i, t, geo, detail) {
        final a = (
          sni: t.sni,
          endpoint: t.endpoint,
          responded: geo != null,
          rttMs: 0,
          detail: detail,
        );
        attempts.add(a);
        onAttempt?.call(a);
      },
    );
    if (res.error != null && res.error!.isNotEmpty) {
      log?.w('sni', 'фаза 4 не дошла до прогона: ${res.error}');
    }
    final summary = summariseSniAttempts(attempts);
    for (final s in summary) {
      log?.i(
        'sni',
        '${s.sni} → ${s.verdict} на ${s.endpoint} '
        '(${s.tried} эндпоинт(ов), ${s.detail})',
      );
      onResult?.call(s);
    }
    return summary;
  }

  /// Строит узел-кандидат для probe-сессии под конкретный эндпоинт.
  /// [sni] (§839) выбирает вызывающий: SNI ротируется по кандидатам, чтобы весь
  /// батч не шёл с одним «паливным» доменом.
  NodeSpec? _buildNodeFor(
    String ep,
    EndpointTransport transport,
    ScanNodeBuilder builder,
    ScanPool? pool,
    String sni,
  ) {
    final parts = ep.split(':');
    final ip = parts[0];
    final explicitPort =
        parts.length > 1 ? int.tryParse(parts[1]) : null;
    switch (transport) {
      case EndpointTransport.wg:
        final c = ScanCandidate(
          ip: ip,
          port: explicitPort ?? 2408,
          protocol: ScanProtocol.awg,
          sni: sni,
          awgParams: const AwgParams(ip: 'quic', jc: 4, jmin: 40, jmax: 70),
        );
        final uri = builder.uriFor(c);
        return uri == null ? null : parseLinkViaPipeline(uri);
      case EndpointTransport.masqueH3:
      case EndpointTransport.masqueH2:
        final isH3 = transport == EndpointTransport.masqueH3;
        final ports = isH3 ? pool?.masquePortsH3 : pool?.masquePortsH2;
        final c = ScanCandidate(
          ip: ip,
          port: explicitPort ??
              ((ports?.isNotEmpty ?? false) ? ports!.first : 443),
          protocol: isH3 ? ScanProtocol.masqueH3 : ScanProtocol.masqueH2,
          sni: sni,
        );
        final uri = builder.uriFor(c);
        return uri == null ? null : parseLinkViaPipeline(uri);
    }
  }
}

/// Стратифицированная выборка IP из списка CIDR: /22 разбиваем на /24 (иначе
/// [expandCidrV4] их не разворачивает), затем берём не более [max] адресов,
/// равномерно по всем блокам.
List<String> _sampleIps(List<String> cidrs, int max) {
  final all = <String>[];
  for (final cidr in cidrs) {
    for (final c24 in _toSlash24(cidr)) {
      all.addAll(expandCidrV4(c24));
    }
  }
  if (all.length <= max) return all;
  final step = all.length / max;
  final out = <String>[];
  for (var i = 0; i < max; i++) {
    out.add(all[(i * step).floor()]);
  }
  return out;
}

/// CIDR → список /24-блоков (для /24 — он сам; для широких — под-блоки; для
/// /32 — сам адрес).
List<String> _toSlash24(String cidr) {
  final slash = cidr.indexOf('/');
  if (slash < 0) return [cidr];
  final mask = int.tryParse(cidr.substring(slash + 1));
  if (mask == null || mask > 32) return const [];
  if (mask >= 24) return [cidr];
  final parts = cidr.substring(0, slash).split('.').map(int.tryParse).toList();
  if (parts.length != 4 || parts.any((p) => p == null)) return const [];
  final base = (parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!;
  final mask24 = 24;
  final hostBits = mask24 - mask;
  final count = 1 << hostBits;
  final netBase = base & (~((1 << (32 - mask)) - 1) & 0xFFFFFFFF);
  return [
    for (var i = 0; i < count; i++)
      '${(netBase + (i << 8)) >> 24 & 0xFF}.'
          '${(netBase + (i << 8)) >> 16 & 0xFF}.'
          '${(netBase + (i << 8)) >> 8 & 0xFF}.0/24',
  ];
}

/// Адрес входит в любой из CIDR (сравнение по сети/хосту, v4).
bool _ipInCidrs(String ip, List<String> cidrs) {
  final addr = _ipv4ToInt(ip);
  if (addr == null) return false;
  for (final c in cidrs) {
    final slash = c.indexOf('/');
    if (slash < 0) continue;
    final net = _ipv4ToInt(c.substring(0, slash));
    final mask = int.tryParse(c.substring(slash + 1));
    if (net == null || mask == null || mask < 0 || mask > 32) continue;
    final m = mask == 0 ? 0 : (~((1 << (32 - mask)) - 1) & 0xFFFFFFFF);
    if ((addr & m) == (net & m)) return true;
  }
  return false;
}

int? _ipv4ToInt(String ip) {
  final parts = ip.split('.');
  if (parts.length != 4) return null;
  var v = 0;
  for (final p in parts) {
    final n = int.tryParse(p);
    if (n == null || n < 0 || n > 255) return null;
    v = (v << 8) | n;
  }
  return v;
}
