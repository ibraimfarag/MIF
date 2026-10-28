// JSON-RPC 2.0 client for the MI CS engine.
//
// Transport (v1, see docs/DECISIONS.md D-006): Windows named pipe
// `\\.\pipe\mics_engine`, served by `mics-engine --service`.
//
// Behaviour that matters to the product:
//  * the engine is a **single** long-lived process per machine. The UI attaches
//    to it if it is already running, otherwise it starts it detached and
//    attaches. Quitting the UI never kills the engine;
//  * a dropped connection is retried with 1→2→5→10 s backoff and a `ping`
//    heartbeat every 15 s;
//  * the engine's push traffic (`progress`, `event`) is exposed as streams, so
//    screens never have to poll for scan progress.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'pipe_client.dart';

class EngineIpc {
  PipeConnection? _pipe;
  int _nextId = 1;
  final Map<int, Completer<dynamic>> _pending = {};
  final _statusController = StreamController<EngineState>.broadcast();
  final _eventController = StreamController<Map<String, dynamic>>.broadcast();
  final _progressController =
      StreamController<Map<String, dynamic>>.broadcast();

  /// Engine-pushed events (guard/canary/job_finished).
  Stream<Map<String, dynamic>> get eventStream => _eventController.stream;

  /// Engine-pushed scan progress notifications.
  Stream<Map<String, dynamic>> get progressStream => _progressController.stream;

  Timer? _restartTimer;
  Timer? _heartbeat;
  int _restartBackoffSeconds = 1;
  bool _disposed = false;
  Future<bool>? _connecting;

  Stream<EngineState> get statusStream => _statusController.stream;
  EngineState _state = EngineState.stopped;
  EngineState get state => _state;

  /// Extra environment applied when *this* app has to start the engine.
  Map<String, String> spawnEnv = {};

  void _setState(EngineState s) {
    _state = s;
    if (!_statusController.isClosed) _statusController.add(s);
  }

  /// Locates the engine executable: explicit env override, side-by-side with
  /// the app binary (packaged layout), then the dev repo layout.
  String resolveEnginePath() {
    final env = Platform.environment['MICS_ENGINE_PATH'];
    if (env != null && File(env).existsSync()) return env;

    final exeDir = File(Platform.resolvedExecutable).parent;
    final beside = exeDir.uri.resolve('mics-engine.exe').toFilePath();
    if (File(beside).existsSync()) return beside;

    // Dev layout: walk up from the app binary to the repo root and try
    // engine/target/release. Covers "flutter run/build" from any cwd.
    var dir = exeDir.parent;
    for (var i = 0; i < 6; i++) {
      final candidate =
          dir.uri.resolve('engine/target/release/mics-engine.exe').toFilePath();
      if (File(candidate).existsSync()) return candidate;
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
    return beside;
  }

  /// Connects to the engine, starting it if needed. Safe to call repeatedly:
  /// concurrent callers share the same in-flight attempt.
  Future<bool> ensureRunning() {
    if (_pipe != null) return Future.value(true);
    return _connecting ??= _connect().whenComplete(() => _connecting = null);
  }

  Future<bool> _connect() async {
    // 1) An engine may already be running (autostart, previous app session).
    final existing = await PipeConnection.tryConnect(
      timeout: const Duration(milliseconds: 900),
    );    if (existing != null) {
      _attach(existing);
      return true;
    }

    // 2) Start it detached. The single-instance mutex inside the engine makes
    //    a duplicate start harmless: the loser exits immediately.
    final path = resolveEnginePath();
    if (!File(path).existsSync()) {
      _setState(EngineState.engineMissing);
      return false;
    }
    try {
      await Process.start(
        path,
        const ['service'],
        environment: spawnEnv.isEmpty ? null : spawnEnv,
        mode: ProcessStartMode.detached,
      );
    } catch (_) {
      _setState(EngineState.engineMissing);
      _scheduleRestart();
      return false;
    }

    // 3) Wait for the pipe to come up.
    final started = await PipeConnection.tryConnect(
      timeout: const Duration(seconds: 8),
    );
    if (started != null) {
      _attach(started);
      return true;
    }
    _setState(EngineState.engineMissing);
    _scheduleRestart();
    return false;
  }

  void _attach(PipeConnection conn) {
    _pipe = conn;
    conn.lines.listen(_handleLine);
    conn.onClosed.listen((reason) => _handleDisconnect(reason));
    _restartBackoffSeconds = 1;
    _setState(EngineState.running);
    _startHeartbeat();
  }

  void _handleLine(String line) {
    final trimmed = line.trim();
    if (trimmed.isEmpty) return;
    try {
      final msg = jsonDecode(trimmed) as Map<String, dynamic>;
      final id = msg['id'];
      if (id == null && msg['method'] == 'event') {
        final params = (msg['params'] as Map?)?.cast<String, dynamic>() ?? {};
        if (!_eventController.isClosed) _eventController.add(params);
        return;
      }
      if (id == null && msg['method'] == 'progress') {
        final params = (msg['params'] as Map?)?.cast<String, dynamic>() ?? {};
        if (!_progressController.isClosed) _progressController.add(params);
        return;
      }
      if (id is int && _pending.containsKey(id)) {
        final completer = _pending.remove(id)!;
        final error = msg['error'];
        if (error != null) {
          completer.completeError(EngineException(
              error['message']?.toString() ?? 'engine error',
              code: error['code'] as int? ?? -1));
        } else {
          completer.complete(msg['result']);
        }
      }
    } catch (_) {
      // Non-JSON line from the engine — ignore.
    }
  }

  void _handleDisconnect(String reason) {
    _pipe?.close();
    _pipe = null;
    for (final c in _pending.values) {
      if (!c.isCompleted) {
        c.completeError(EngineException('engine connection lost: $reason'));
      }
    }
    _pending.clear();
    _heartbeat?.cancel();
    if (!_disposed) {
      _setState(EngineState.reconnecting);
      _scheduleRestart();
    }
  }

  void _scheduleRestart() {
    _restartTimer?.cancel();
    _restartTimer = Timer(Duration(seconds: _restartBackoffSeconds), () async {
      if (_disposed) return;
      await ensureRunning();
      _restartBackoffSeconds = (_restartBackoffSeconds * 2).clamp(1, 10);
    });
  }

  /// Spec: heartbeat `ping` every 15 s — a missed reply triggers reconnect.
  void _startHeartbeat() {
    _heartbeat?.cancel();
    _heartbeat = Timer.periodic(const Duration(seconds: 15), (_) async {
      if (_pipe == null || _disposed) return;
      try {
        final res = await request('ping').timeout(const Duration(seconds: 5));
        if (res != 'pong') _handleDisconnect('heartbeat lost');
      } catch (_) {
        _handleDisconnect('heartbeat failed');
      }
    });
  }

  /// Sends a whitelisted JSON-RPC command and awaits the matching response.
  Future<dynamic> request(String method, [Map<String, dynamic>? params]) async {
    final ok = await ensureRunning();
    if (!ok) throw EngineException('engine not running');
    final pipe = _pipe;
    if (pipe == null) throw EngineException('engine connection lost');
    final id = _nextId++;
    final completer = Completer<dynamic>();
    _pending[id] = completer;
    final body = <String, dynamic>{
      'jsonrpc': '2.0',
      'id': id,
      'method': method,
    };
    if (params != null) body['params'] = params;
    pipe.send(jsonEncode(body));
    try {
      return await completer.future.timeout(const Duration(seconds: 120));
    } on TimeoutException {
      _pending.remove(id);
      throw EngineException('engine request timed out: $method');
    } catch (e) {
      _pending.remove(id);
      rethrow;
    }
  }

  void dispose() {
    _disposed = true;
    _heartbeat?.cancel();
    _restartTimer?.cancel();
    _pipe?.close();
    _pipe = null;
    _statusController.close();
    _eventController.close();
    _progressController.close();
  }
}

class EngineException implements Exception {
  final String message;
  final int code;
  EngineException(this.message, {this.code = -1});
  @override
  String toString() => 'EngineException($code): $message';
}

enum EngineState { stopped, running, reconnecting, engineMissing }

final engineIpcProvider = Provider<EngineIpc>((ref) {
  final ipc = EngineIpc();
  ref.onDispose(ipc.dispose);
  return ipc;
});
