import 'dart:async';

import 'package:flutter/services.dart';

/// §669 — Dart-двойник `ProbeSession.kt`: до двух независимых сессий, stale-id
/// no-op и отмена начатых замеров только своего runId.
class FakeProbeSession {
  FakeProbeSession({this.capacity = 2});

  final int capacity;
  final calls = <MethodCall>[];

  int _nextId = 0;
  final _sessions = <int, _FakeSession>{};

  List<int> get liveRunIds => _sessions.keys.toList();
  int? get live => liveRunIds.lastOrNull;

  /// Замер живой сессии висит, пока его не отпустят.
  bool holdUrlTests = true;
  final _pending = <int, List<Completer<Map<String, Object>>>>{};
  int get pendingCount =>
      _pending.values.fold(0, (count, list) => count + list.length);

  /// Не-null — `probeStop` своей сессии ждёт его (долгий `closeService`).
  Completer<void>? stopGate;

  int callsOf(String method) => calls.where((c) => c.method == method).length;

  List<int> runIdsOf(String method) => [
        for (final c in calls)
          if (c.method == method) (c.arguments as Map)['runId'] as int,
      ];

  /// Отпустить висящие замеры успехом.
  void releaseOk({int delay = 50}) =>
      _releaseAll({'delay': delay, 'error': ''});

  Future<Object?> handle(MethodCall call) async {
    calls.add(call);
    final args = (call.arguments as Map?) ?? const {};
    final runId = (args['runId'] as int?) ?? 0;
    switch (call.method) {
      case 'probeStart':
        if (_sessions.length >= capacity) {
          return {'error': 'probe session capacity reached', 'runId': 0};
        }
        final id = ++_nextId;
        _sessions[id] = _FakeSession();
        return {'error': '', 'runId': id};
      case 'probeUrlTest':
        final session = _sessions[runId];
        if (session == null) return {'delay': 0, 'error': 'stale run'};
        if (session.cancelled) {
          return {'delay': 0, 'error': 'probe run cancelled'};
        }
        if (!holdUrlTests) return {'delay': 50, 'error': ''};
        final c = Completer<Map<String, Object>>();
        _pending.putIfAbsent(runId, () => []).add(c);
        return c.future;
      case 'probeCancel':
        final session = _sessions[runId];
        if (session != null) {
          session.cancelled = true;
          _releaseRun(runId, {'delay': 0, 'error': 'context canceled'});
        }
        return null;
      case 'probeStop':
        final session = _sessions.remove(runId);
        if (session == null) return null;
        final gate = stopGate;
        if (gate != null) await gate.future;
        _releaseRun(runId, {'delay': 0, 'error': 'probe session closed'});
        return null;
    }
    return null;
  }

  void _releaseAll(Map<String, Object> result) {
    final ids = _pending.keys.toList();
    for (final id in ids) {
      _releaseRun(id, result);
    }
  }

  void _releaseRun(int runId, Map<String, Object> result) {
    final list = _pending.remove(runId) ?? const [];
    for (final c in list) {
      c.complete(result);
    }
  }
}

class _FakeSession {
  bool cancelled = false;
}
