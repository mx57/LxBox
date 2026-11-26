@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:lxbox/models/node_spec.dart';
import 'package:lxbox/models/template_vars.dart';
import 'package:lxbox/services/parser/drop_verdict.dart';
import 'package:lxbox/services/parser/ini_parser.dart';

import '../parser/engine_test_setup.dart';

const _syntheticPrivate = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=';
const _syntheticPublic = 'ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=';
const _syntheticPsk = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=';
const _syntheticHeader = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4A=';

const _safeAwgFields = <String, Object>{
  'jc': 4,
  'jmin': 40,
  'jmax': 70,
  's1': 16,
  's2': 24,
  's3': 32,
  's4': 40,
  'h1': '100000-110000',
  'h2': '200000-210000',
  'h3': '300000-310000',
  'h4': '400000-410000',
  'i1': '<b 0x01020304><r 16>',
  'i2': '<r 24>',
  'i3': '<rc 32>',
  'i4': '<t>',
  'i5': '<b 0xaabb>',
  'content_padding_addition': '8-24',
  'rekey_after_time': '120-180',
  'rekey_timeout': '5-10',
  'reject_after_time': '180-240',
  'keepalive_timeout': '10-20',
  'max_handshake_attempts': '18-24',
  'random_trailers': true,
  'disable_cookies': true,
};

final _root = Directory('..').absolute.path;
final _compose = File('$_root/ops/awg3/docker-compose.yml').absolute.path;
final _fixture = File(
  '$_root/app/test/fixtures/wireguard/awg3_docker.conf',
).absolute.path;
final _runtime = Directory('$_root/app/build/awg3-stand').absolute;

void main() {
  setUpAll(loadEngineSections);
  tearDownAll(unloadEngineSections);

  test('full AWG3 fixture survives the application emitter', () {
    var source = File(_fixture).readAsStringSync();
    source = source.replaceAll('__CLIENT_PRIVATE_KEY__', _syntheticPrivate);
    source = source.replaceAll('__SERVER_PUBLIC_KEY__', _syntheticPublic);
    source = source.replaceAll('__PRE_SHARED_KEY__', _syntheticPsk);
    source = source.replaceAll('__HEADER_PROTECTION_KEY__', _syntheticHeader);
    final dropped = XrayDropVerdict();
    final node = parseWireguardIni(
      source,
      nameHint: 'awg3-stand',
      dropped: dropped,
    );
    expect(
      node,
      isA<WireguardSpec>(),
      reason: '${dropped.reason?.code} at ${dropped.reason?.path}',
    );
    final endpoint = node!.emitRaw(TemplateVars.empty).map;
    _expectSafeEndpoint(endpoint);
    expect(endpoint['header_protection_key'], _syntheticHeader);
    final config = _standConfig(endpoint);
    expect(config['endpoints'], [endpoint]);
    expect(
      (config['outbounds'] as List).single,
      {'type': 'direct', 'tag': 'direct'},
    );
    expect((config['route'] as Map)['final'], endpoint['tag']);
  });

  test('stand log redacts secrets split across output chunks', () {
    final log = _StandLog({'synthetic-secret'});
    log.add('left synthetic-');
    expect(log.text, isEmpty);
    log.add('secret right\nnext synthetic-');
    expect(log.text, 'left [REDACTED] right\n');
    log.add('secret');
    log.finish();
    expect(log.text, 'left [REDACTED] right\nnext [REDACTED]\n');
  });

  final enabled = Platform.environment['LX_AWG3_DOCKER'] == '1';
  test(
    'pinned AWG3 server accepts the emitted endpoint and carries HTTP',
    () async {
      final client = File('${_runtime.path}/client.conf');
      final server = File('${_runtime.path}/server.conf');
      final core = File('${_runtime.path}/sing-box');
      for (final file in [client, server, core, File(_compose)]) {
        expect(
          file.existsSync(),
          isTrue,
          reason: 'Run ops/awg3/setup.sh before enabling LX_AWG3_DOCKER',
        );
      }

      final secrets = _standSecrets(client, server);
      final serverSource = server.readAsStringSync();
      expect(serverSource, startsWith('[Interface]\n'));
      expect(
        RegExp(r'^\[Interface\]$', multiLine: true).allMatches(serverSource),
        hasLength(1),
      );
      expect(
        RegExp(r'=\s*(true|false)\s*$', multiLine: true).hasMatch(serverSource),
        isFalse,
        reason: 'awg-tools accepts on/off or 0/1, not JSON booleans',
      );
      final log = _StandLog(secrets);
      Process? singbox;
      var singboxStreams = <Future<void>>[];
      try {
        final dropped = XrayDropVerdict();
        final node = parseWireguardIni(
          client.readAsStringSync(),
          nameHint: 'awg3-stand',
          dropped: dropped,
        );
        expect(
          node,
          isA<WireguardSpec>(),
          reason: '${dropped.reason?.code} at ${dropped.reason?.path}',
        );
        final endpoint = node!.emitRaw(TemplateVars.empty).map;
        _expectSafeEndpoint(endpoint);
        final config = File('${_runtime.path}/client.sing-box.json');
        config.writeAsStringSync(
          const JsonEncoder.withIndent('  ').convert(_standConfig(endpoint)),
        );
        final chmod = await _run(['chmod', '600', config.path]);
        log.add(chmod.stderr.toString());
        expect(chmod.exitCode, 0);

        final checked = await _run([core.path, 'check', '-c', config.path]);
        log.add(checked.stdout.toString());
        log.add(checked.stderr.toString());
        expect(
          checked.exitCode,
          0,
          reason: 'Pinned sing-box rejected the application-emitted endpoint',
        );

        final up = await _run([
          'docker',
          'compose',
          '-f',
          _compose,
          'up',
          '-d',
          '--wait',
        ]);
        log.add(up.stdout.toString());
        log.add(up.stderr.toString());
        expect(up.exitCode, 0);

        final published = await _run([
          'docker',
          'compose',
          '-f',
          _compose,
          'port',
          'echo',
          '8080',
        ]);
        log.add(published.stdout.toString());
        log.add(published.stderr.toString());
        expect(published.exitCode, 0);
        expect(
          published.stdout.toString().trim(),
          isEmpty,
          reason: 'The echo service must not be published to the host',
        );

        singbox = await Process.start(core.path, ['run', '-c', config.path]);
        int? singboxExitCode;
        unawaited(singbox.exitCode.then((code) => singboxExitCode = code));
        singboxStreams = [
          singbox.stdout.transform(utf8.decoder).forEach(log.add),
          singbox.stderr.transform(utf8.decoder).forEach(log.add),
        ];

        final clientPublic = _iniValue(client.readAsStringSync(), 'PublicKey');
        await _waitForHandshake(
          _compose,
          clientPublic,
          () => singboxExitCode,
          log,
        );
        await _expectEcho(log);
      } finally {
        if (singbox != null) {
          singbox.kill();
          try {
            await singbox.exitCode.timeout(const Duration(seconds: 10));
          } on TimeoutException {
            singbox.kill(ProcessSignal.sigkill);
            await singbox.exitCode;
          }
        }
        try {
          await Future.wait(singboxStreams).timeout(const Duration(seconds: 5));
        } catch (_) {
          log.add('sing-box output could not be fully collected\n');
        }
        try {
          final logs = await _run([
            'docker',
            'compose',
            '-f',
            _compose,
            'logs',
            '--no-color',
          ]);
          log.add(logs.stdout.toString());
          log.add(logs.stderr.toString());
        } catch (error) {
          log.add('Compose logs unavailable: $error\n');
        }
        try {
          final down = await _run([
            'docker',
            'compose',
            '-f',
            _compose,
            'down',
            '-v',
            '--remove-orphans',
          ]);
          log.add(down.stdout.toString());
          log.add(down.stderr.toString());
        } catch (error) {
          log.add('Compose teardown failed: $error\n');
        }
        log.finish();
        File('${_runtime.path}/stand.log').writeAsStringSync(log.text);
      }
    },
    skip: !enabled
        ? 'Set LX_AWG3_DOCKER=1 after ops/awg3/setup.sh to run the live stand'
        : false,
    timeout: const Timeout(Duration(minutes: 10)),
  );
}

Map<String, Object> _standConfig(Map<String, dynamic> endpoint) => {
  'log': {'level': 'warn'},
  'inbounds': [
    {
      'type': 'mixed',
      'tag': 'stand-in',
      'listen': '127.0.0.1',
      'listen_port': 18080,
    },
  ],
  'outbounds': [
    {'type': 'direct', 'tag': 'direct'},
  ],
  'endpoints': [endpoint],
  'route': {
    'final': endpoint['tag'],
    'rules': <Map<String, Object>>[],
  },
};

void _expectSafeEndpoint(Map<String, dynamic> endpoint) {
  expect(endpoint['type'], 'wireguard');
  expect(endpoint['tag'], 'awg3-stand');
  expect(endpoint['mtu'], 1280);
  expect(endpoint['address'], ['10.8.3.2/32']);
  for (final entry in _safeAwgFields.entries) {
    expect(
      endpoint[entry.key],
      entry.value,
      reason: 'Lost AWG field ${entry.key}',
    );
  }
  expect(endpoint['header_protection_key'] is String, isTrue);
  final peers = endpoint['peers'];
  expect(peers, isA<List>());
  final peer = (peers! as List).single as Map;
  expect(peer['address'], '127.0.0.1');
  expect(peer['port'], 51820);
  expect(peer['allowed_ips'], ['0.0.0.0/0']);
  expect(peer['persistent_keepalive_interval'], '25-35');
}

Set<String> _standSecrets(File client, File server) {
  final values = <String>{};
  for (final file in [client, server]) {
    for (final key in const [
      'PrivateKey',
      'PublicKey',
      'PreSharedKey',
      'HeaderProtectionKey',
    ]) {
      final value = _iniValue(file.readAsStringSync(), key);
      if (value.isNotEmpty) values.add(value);
    }
  }
  return values;
}

String _iniValue(String source, String key) {
  for (final line in const LineSplitter().convert(source)) {
    final separator = line.indexOf('=');
    if (separator < 0) continue;
    if (line.substring(0, separator).trim() == key) {
      return line.substring(separator + 1).trim();
    }
  }
  return '';
}

Future<void> _waitForHandshake(
  String compose,
  String clientPublic,
  int? Function() exitCode,
  _StandLog log,
) async {
  for (var attempt = 0; attempt < 120; attempt++) {
    final exited = exitCode();
    if (exited != null) {
      fail('sing-box exited before the handshake (exit $exited)');
    }
    final result = await _run([
      'docker',
      'compose',
      '-f',
      compose,
      'exec',
      '-T',
      'awg',
      'awg',
      'show',
      'wg0',
      'latest-handshakes',
    ]);
    log.add(result.stdout.toString());
    log.add(result.stderr.toString());
    if (result.exitCode == 0) {
      for (final line in const LineSplitter().convert(
        result.stdout.toString(),
      )) {
        final fields = line.trim().split(RegExp(r'\s+'));
        final handshake = fields.length == 2 ? int.tryParse(fields[1]) : null;
        if (fields.length == 2 &&
            fields.first == clientPublic &&
            handshake != null &&
            handshake != 0) {
          return;
        }
      }
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }
  fail('AWG3 handshake did not complete within 60 seconds');
}

Future<void> _expectEcho(_StandLog log) async {
  String? lastError;
  for (var attempt = 0; attempt < 30; attempt++) {
    final result = await _run([
      'curl',
      '--fail',
      '--silent',
      '--show-error',
      '--max-time',
      '5',
      '--noproxy',
      '*',
      '--socks5-hostname',
      '127.0.0.1:18080',
      'http://10.8.3.1:8080/',
    ]);
    log.add(result.stdout.toString());
    log.add(result.stderr.toString());
    if (result.exitCode == 0) {
      expect(result.stdout.toString().trim(), 'awg3-ok');
      return;
    }
    lastError = result.stderr.toString().trim();
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }
  fail(
    'HTTP echo through AWG3 failed: ${log.redact(lastError ?? 'unknown error')}',
  );
}

Future<ProcessResult> _run(List<String> command) async {
  final process = await Process.start(command.first, command.skip(1).toList());
  final stdout = process.stdout.transform(utf8.decoder).join();
  final stderr = process.stderr.transform(utf8.decoder).join();
  try {
    final exited = await process.exitCode.timeout(const Duration(minutes: 2));
    return ProcessResult(process.pid, exited, await stdout, await stderr);
  } on TimeoutException {
    process.kill();
    await process.exitCode;
    rethrow;
  }
}

class _StandLog {
  _StandLog(this._secrets);

  final Set<String> _secrets;
  final StringBuffer _complete = StringBuffer();
  String _pending = '';

  String get text => _complete.toString();

  String redact(String text) {
    var clean = text;
    for (final secret in _secrets) {
      clean = clean.replaceAll(secret, '[REDACTED]');
    }
    return clean;
  }

  void add(String chunk) {
    _pending += chunk;
    var newline = _pending.indexOf('\n');
    while (newline >= 0) {
      _complete.writeln(redact(_pending.substring(0, newline)));
      _pending = _pending.substring(newline + 1);
      newline = _pending.indexOf('\n');
    }
  }

  void finish() {
    if (_pending.isNotEmpty) _complete.writeln(redact(_pending));
    _pending = '';
  }
}
