import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

/// JSON-RPC 2.0 client for the MI CS engine.
///
/// Transport (v1): spawns `mics_engine.exe --serve` and speaks JSON-Lines over
/// stdio. This keeps the architecture rule "the UI never touches OS APIs" —
/// every OS query still happens inside the engine process. The named-pipe
/// transport plugs into the same interface when service mode lands (Phase 7).
class EngineIpc {
  Process? _process;
  int _nextId = 1;
  final Map<int, Completer<dynamic>> _pending = {};
  final _statusController = StreamController<EngineState>.broadcast();
  final _eventController = StreamController<Map<String, dynamic>>.broadcast();

  /// Pushed engine events (guard/canary notifications).
  Stream<Map<String, dynamic>> get eventStream => _eventController.stream;
  Timer? _restartTimer;
  int _restartBackoffSeconds = 1;
  bool _disposed = false;

  Stream<EngineState> get statusStream => _statusController.stream;
  EngineState _state = EngineState.stopped;
  EngineState get state => _state;

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
    for (final root in [Directory.current.path]) {
      final dev = '$root\\engine\\target\\release\\mics-engine.exe';
      if (File(dev).existsSync()) return dev;
    }
    return beside;
  }

  /// Extra environment (VT key, LM Studio URL, ...) applied at spawn — set
  /// from the advanced settings screen before first launch.
  Map<String, String> spawnEnv = {};

  Future<bool> ensureRunning() async {
    if (_process != null) return true;
    final path = resolveEnginePath();
    if (!File(path).existsSync()) {
      _setState(EngineState.engineMissing);
      return false;
    }
    try {
      final proc = await Process.start(path, ['serve'],
          environment: spawnEnv, mode: ProcessStartMode.normal);
      _process = proc;
      _setState(EngineState.running);
      _restartBackoffSeconds = 1;

      proc.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen(_handleLine, onDone: _handleExit);
      proc.stderr.drain<void>();
      proc.exitCode.then((_) => _handleExit());
      _startHeartbeat();
      return true;
    } catch (_) {
      _setState(EngineState.engineMissing);
      _scheduleRestart();
      return false;
    }
  }

  void _handleLine(String line) {
    final trimmed = line.trim();
    if (trimmed.isEmpty) return;
    try {
      final msg = jsonDecode(trimmed) as Map<String, dynamic>;
      final id = msg['id'];
      if (id == null && msg['method'] == 'event') {
        // JSON-RPC notification: engine-pushed event (guard/canary).
        if (!_eventController.isClosed) {
          _eventController.add(
              (msg['params'] as Map?)?.cast<String, dynamic>() ?? {});
        }
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

  void _handleExit() {
    _process = null;
    for (final c in _pending.values) {
      if (!c.isCompleted) c.completeError(EngineException('engine exited'));
    }
    _pending.clear();
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

  Timer? _heartbeat;

  /// Spec: heartbeat `ping` every 15 s — a missed reply triggers reconnect.
  void _startHeartbeat() {
    _heartbeat?.cancel();
    _heartbeat = Timer.periodic(const Duration(seconds: 15), (_) async {
      if (_process == null || _disposed) return;
      try {
        final res = await request('ping').timeout(const Duration(seconds: 5));
        if (res != 'pong') _handleExit();
      } catch (_) {
        _handleExit();
      }
    });
  }

  /// Sends a whitelisted JSON-RPC command and awaits the matching response.
  Future<dynamic> request(String method, [Map<String, dynamic>? params]) async {
    final ok = await ensureRunning();
    if (!ok) throw EngineException('engine not running');
    final id = _nextId++;
    final completer = Completer<dynamic>();
    _pending[id] = completer;
    final body = <String, dynamic>{
      'jsonrpc': '2.0',
      'id': id,
      'method': method,
    };
    if (params != null) body['params'] = params;
    final req = jsonEncode(body);
    try {
      _process!.stdin.writeln(req);
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
    _process?.kill();
    _statusController.close();
    _eventController.close();
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
