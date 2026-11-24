import '../../models/node_spec.dart';

/// §740 — клиентские профили WARP-обфускации. Cloudflare остаётся plain WG,
/// поэтому все профили сохраняют стандартный handshake; меняется только junk.
enum AwgProfile {
  warp15('warp15'),
  warpCps('warp-cps');

  const AwgProfile(this.wire);

  final String wire;

  static AwgProfile fromWire(String? value) => switch (value) {
        'warp-cps' => AwgProfile.warpCps,
        _ => AwgProfile.warp15,
      };

  /// Дополнительные CPS-декои. Ядро рандомизирует `<r>` при сборке пакета.
  /// `I1` не задаём: он идёт через `id/ip/ib` и не может сосуществовать с `i1`.
  Map<String, Object> extraFieldsFor(String ip) => switch (this) {
        AwgProfile.warp15 => const {},
        AwgProfile.warpCps => {
            if (ip != 'sip') 'i2': '<t><r 28>',
            'i3': '<r 32>',
            'i4': '<r 32>',
            'i5': '<r 32>',
          },
      };

  Awg build({
    required String ip,
    required String id,
    required String ib,
    required int jc,
    required int jmin,
    required int jmax,
  }) =>
      Awg({
        ...amneziaWarpHandshakeFields(jc: jc, jmin: jmin, jmax: jmax),
        'ip': ip,
        'id': id,
        if (ip == 'quic') 'ib': ib,
        ...extraFieldsFor(ip),
      });
}

/// Общий безопасный handshake для любого WARP-профиля.
Map<String, Object> amneziaWarpHandshakeFields({
  required int jc,
  required int jmin,
  required int jmax,
}) =>
    {
      'jc': jc,
      'jmin': jmin,
      'jmax': jmax,
      's1': 0,
      's2': 0,
      'h1': 1,
      'h2': 2,
      'h3': 3,
      'h4': 4,
    };
