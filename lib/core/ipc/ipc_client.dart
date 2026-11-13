// JSON-RPC 2.0 client for the MI CS engine.
//
// Transport (v1, see docs/DECISIONS.md D-006): Windows named pipe
// `\\.\pipe\mics_engine`, served by `mics-engine --service`.
//
// Behaviour that matters to the product:
//  * the engine is a **single** long-lived process per machine. The UI attaches
//    to it if it is already running, otherwise it starts it — passing this app's
//    own pid as `--parent` — and attaches. The engine that *this* app started
//    stops when this app does: `stopOwnEngine()` asks it to stop on the way out,
//    and the engine also holds a handle to us, so a quit that never gets an
//    answer (a crash, Task Manager) still takes it with us (D-039);
//  * an engine this app only *attached* to belongs to whoever started it and is
//    left alone: closing MI CS must not stop a protection engine that another
//    instance — or the autostart entry — is running;
//  * a dropped connection is retried with 1→2→5→10 s backoff and a `ping`
//    heartbeat every 15 s, except while we are deliberately stopping;
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
  final _alertController = StreamController<Map<String, dynamic>>.broadcast();

  /// Engine-pushed events (guard/canary/job_finished).
  Stream<Map<String, dynamic>> get eventStream => _eventController.stream;

  /// Engine-pushed scan progress notifications.
  Stream<Map<String, dynamic>> get progressStream => _progressController.stream;

  /// In-app alert cards the engine's gate decided to surface (D-024). A
  /// separate stream on purpose: these are cards, not guard events, and the
  /// Guard screen must not grow a row for each one.
  Stream<Map<String, dynamic>> get alertStream => _alertController.stream;

  Timer? _restartTimer;
  Timer? _heartbeat;
  int _restartBackoffSeconds = 1;
  bool _disposed = false;
  Future<bool>? _connecting;

  /// The pid of the engine process this app started, when it started one. It is
  /// the only thing that makes this app the engine's owner: a start that loses
  /// the engine's single-instance race exits at once, and `status.pid` then
  /// names somebody else's process (D-039).
  int? _spawnedPid;
  bool _ownershipChecked = false;

  /// True when the engine this app is talking to is the one it started, and
  /// therefore the one it may stop when it quits.
  bool _ownsEngine = false;
  bool get ownsEngine => _ownsEngine;

  /// Set while this app is deliberately stopping the engine, so the disconnect
  /// that follows is not mistaken for a crash worth reconnecting to.
  bool _stopping = false;

  Stream<EngineState> get statusStream => _statusController.stream;
  EngineState _state = EngineState.stopped;
  EngineState get state => _state;

  /// Why the last start attempt failed, in the engine's own words when it had
  /// any. The engine is started detached, so a refusal like "started from a
  /// Low-integrity location" is written to a stderr nobody reads; without this
  /// the user sees "engine missing" and a retry that cannot succeed.
  String? _lastFailure;
  String? get lastFailure => _lastFailure;

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
  ///
  /// The first successful connect also settles *ownership* — whether the engine
  /// behind the pipe is the process this app started — because that is what
  /// decides if quitting may stop it.
  Future<bool> ensureRunning() async {
    if (_pipe != null) return true;
    final pending = _connecting ??= _connect().whenComplete(() {
      _connecting = null;
    });
    final ok = await pending;
    if (ok && !_ownershipChecked) {
      _ownershipChecked = true;
      await _claimOwnership();
    }
    return ok;
  }

  /// Did the engine we are talking to turn out to be the process we started?
  ///
  /// `status.pid` answers it: when this app's start lost the single-instance
  /// race the loser exited immediately and the pipe belongs to the engine that
  /// was already running — an engine this app must not stop when it quits.
  Future<void> _claimOwnership() async {
    final spawned = _spawnedPid;
    if (spawned == null) {
      _ownsEngine = false;
      return;
    }
    try {
      final status = await request('status', null, const Duration(seconds: 5));
      _ownsEngine =
          status is Map && (status['pid'] as num?)?.toInt() == spawned;
    } catch (_) {
      // No answer, no claim: leaving somebody else's engine running is the
      // harmless direction to be wrong in.
      _ownsEngine = false;
    }
  }

  /// Asks the engine **this app started** to stop, and gives it a bounded
  /// moment to close the pipe — the engine's own proof that it exited.
  ///
  /// A no-op when this app only attached to an engine somebody else owns: that
  /// engine outlives us on purpose. Bounded on purpose too: the engine holds a
  /// handle to this process, so a shutdown that never answers still ends when
  /// we do.
  ///
  /// The reconnect timers are cancelled **before** the ownership test (D-053):
  /// a quit is final regardless of who owns the engine, and a restart armed
  /// earlier must not survive it to start an engine while the window goes away.
  Future<void> stopOwnEngine(
      {Duration timeout = const Duration(seconds: 3)}) async {
    _restartTimer?.cancel();
    _heartbeat?.cancel();
    if (!_ownsEngine || _pipe == null || _stopping) {
      _ownsEngine = false;
      return;
    }
    _stopping = true;
    try {
      await request('shutdown', null, const Duration(seconds: 2));
    } catch (e) {
      // The engine is stopping either way; whether it answered is not something
      // the user needs to see while the window is closing.
      stderr.writeln('shutdown request got no answer ($e) — the engine still exits with the app');
    }
    final deadline = DateTime.now().add(timeout);
    while (_pipe != null && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    _ownsEngine = false;
  }

  Future<bool> _connect() async {
    // 1) An engine may already be running (autostart, previous app session).
    final existing = await PipeConnection.tryConnect(
      timeout: const Duration(milliseconds: 900),
    );
    if (existing != null) {
      // Somebody else's engine: attach, and leave its lifetime alone.
      _spawnedPid = null;
      _ownsEngine = false;
      _ownershipChecked = true;
      _attach(existing);
      return true;
    }

    // 2) Start it detached — detached so that a crash of *this* process does not
    //    kill protection mid-operation; tying it to us is the parent watch's job
    //    (D-039), which is deliberate and reports itself. The single-instance
    //    mutex inside the engine makes a duplicate start harmless: the loser
    //    exits immediately, and `status.pid` below decides who owns the pipe.
    final path = resolveEnginePath();
    if (!File(path).existsSync()) {
      _lastFailure = 'mics-engine.exe is not at $path';
      _setState(EngineState.engineMissing);
      return false;
    }
    try {
      final spawned = await Process.start(
        path,
        ['service', '--parent', '$pid'],
        // Dart replaces the whole environment when `environment` is given, so
        // it must be merged with the current one: dropping it would lose
        // PROGRAMDATA (state/data path) and PATH (netsh, taskkill, reg).
        environment: spawnEnv.isEmpty
            ? null
            : {...Platform.environment, ...spawnEnv},
        mode: ProcessStartMode.detached,
      );
      _spawnedPid = spawned.pid;
      _ownsEngine = false;
      _ownershipChecked = false;
    } catch (e) {
      _spawnedPid = null;
      _lastFailure = 'the engine could not be started ($e)';
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
    // Nothing is serving the pipe. What the engine said on the way down is the
    // only thing that makes this actionable, and the detached spawn discarded
    // it — so ask once more, with stderr piped. The probe is bounded and runs at
    // most once per failure episode: `_lastFailure` is cleared by `_attach`.
    if (_lastFailure == null) {
      final probed = await _probeStartFailure(path);
      if (probed.connection != null) {
        _attach(probed.connection!);
        return true;
      }
      _lastFailure = probed.reason;
    }
    _setState(EngineState.engineMissing);
    _scheduleRestart();
    return false;
  }

  /// One bounded second start whose only purpose is to hear *why* the first one
  /// did not answer.
  ///
  /// `_connect` starts the engine detached, which discards its stdio; the
  /// refusals worth showing the user — a Low-integrity folder, a command line
  /// the engine will not take — are printed to stderr and nothing else. This
  /// runs the same command once with stderr piped and keeps the last lines.
  ///
  /// Safe to run whenever the pipe is silent: the engine's single-instance mutex
  /// makes a duplicate harmless (the loser exits at once), and if *this* copy is
  /// the one that ends up serving the pipe, it is attached to and owned rather
  /// than reported as a failure.
  Future<({PipeConnection? connection, String? reason})> _probeStartFailure(
      String path) async {
    final Process probe;
    try {
      probe = await Process.start(
        path,
        ['service', '--parent', '$pid'],
        environment: spawnEnv.isEmpty
            ? null
            : {...Platform.environment, ...spawnEnv},
      );
    } catch (e) {
      return (connection: null, reason: 'the engine could not be started ($e)');
    }

    final tail = <String>[];
    final stderrDrain = keepTail(probe.stderr, tail);
    // stdout is drained too: a child must never block on a full pipe.
    final stdoutDrain = probe.stdout.drain<void>();

    // A refusal exits at once, and the exit *is* the answer; a healthy start
    // keeps running and gets the pipe wait instead.
    int? exitCode;
    try {
      exitCode = await probe.exitCode
          .timeout(const Duration(milliseconds: 800));
    } on TimeoutException {
      exitCode = null;
    }
    if (exitCode != null) {
      await stderrDrain.cancel();
      unawaited(stdoutDrain.catchError((Object _) {}));
      return (
        connection: null,
        reason: tail.isNotEmpty
            ? tail.join('\n')
            : 'the engine exited at once with code $exitCode',
      );
    }

    final connection = await PipeConnection.tryConnect(
      timeout: const Duration(milliseconds: 2500),
    );
    if (connection != null) {
      // This copy is the engine now. Keep draining its stderr — an unread pipe
      // would eventually block it — and let ownership see the pid we started.
      _spawnedPid = probe.pid;
      return (connection: connection, reason: null);
    }
    probe.kill();
    await probe.exitCode.timeout(const Duration(seconds: 1), onTimeout: () => -1);
    await stderrDrain.cancel();
    unawaited(stdoutDrain.catchError((Object _) {}));
    return (
      connection: null,
      reason: tail.isNotEmpty
          ? tail.join('\n')
          : 'the engine started but never answered on the pipe',
    );
  }

  void _attach(PipeConnection conn) {
    _pipe = conn;
    conn.lines.listen(_handleLine);
    conn.onClosed.listen((reason) => _handleDisconnect(reason));
    _restartBackoffSeconds = 1;
    _lastFailure = null;
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
      if (id == null && msg['method'] == 'alert') {
        final params = (msg['params'] as Map?)?.cast<String, dynamic>() ?? {};
        if (!_alertController.isClosed) _alertController.add(params);
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
    // A deliberate stop is not a lost engine: nothing to reconnect to, and
    // restarting what we just asked to end would leave the process behind that
    // D-039 exists to prevent.
    if (!_disposed && !_stopping) {
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
  ///
  /// Only probed when nothing else is in flight: a vulnerability scan or an
  /// update download legitimately keeps the engine busy for minutes, and a
  /// ping stuck behind it is not proof the engine died. Killing the connection
  /// there is what surfaced as `engine connection lost: heartbeat failed` on
  /// the Vulnerabilities screen.
  void _startHeartbeat() {
    _heartbeat?.cancel();
    _heartbeat = Timer.periodic(const Duration(seconds: 15), (_) async {
      if (_pipe == null || _disposed) return;
      if (_pending.isNotEmpty) return;
      try {
        final res = await request('ping').timeout(const Duration(seconds: 5));
        if (res != 'pong') _handleDisconnect('heartbeat lost');
      } catch (_) {
        _handleDisconnect('heartbeat failed');
      }
    });
  }

  /// Sends a whitelisted JSON-RPC command and awaits the matching response.
  ///
  /// [timeout] is per call because a few commands are slow by design (a cold
  /// NVD vulnerability scan spends ~6.5 s per application on the public rate
  /// limit); everything else keeps the 120 s default.
  Future<dynamic> request(String method,
      [Map<String, dynamic>? params,
      Duration timeout = const Duration(seconds: 120)]) async {
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
      return await completer.future.timeout(timeout);
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
    _alertController.close();
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

/// The shape of the engine's last refusal, so a screen can say it in the user's
/// language instead of echoing the engine's English sentence.
enum EngineFailureKind {
  /// Windows gives a process the integrity label of the folder its image sits
  /// in. From a Low-labelled folder — a web root, a sandbox output — the engine
  /// cannot write its state database or reach the privileged helper, so it
  /// refuses to run at all.
  lowIntegrity,

  /// The engine ran but its data directory is not writable.
  dataDirUnwritable,

  /// No `mics-engine.exe` where the app expects it.
  engineMissing,

  /// The process could not be created at all.
  spawnFailed,
}

/// Classifies [reason] — the client's `lastFailure`, which is either the
/// engine's own stderr tail or a line this app wrote — into something the UI can
/// translate. Null means "nothing to add", and the caller keeps whatever message
/// it already had.
EngineFailureKind? classifyEngineFailure(String? reason) {
  if (reason == null || reason.isEmpty) return null;
  final r = reason.toLowerCase();
  // The Low-integrity refusal also quotes "readonly database", so it has to be
  // recognised before the data-dir case.
  if (r.contains('low-integrity') || r.contains('low integrity')) {
    return EngineFailureKind.lowIntegrity;
  }
  if (r.contains('not writable') || r.contains('readonly database')) {
    return EngineFailureKind.dataDirUnwritable;
  }
  if (r.contains('is not at')) return EngineFailureKind.engineMissing;
  if (r.contains('could not be started')) return EngineFailureKind.spawnFailed;
  return null;
}

/// Keeps the last [keep] non-empty lines of [stream] in [into].
///
/// A refusal is a sentence at the *end* of whatever the engine printed on its
/// way down, so the tail is the part worth showing the user and the buffer is
/// bounded — an engine that died mid-scan can print a great deal. The
/// subscription comes back because the caller decides when to stop listening: a
/// process that is still running has to keep being drained or it blocks.
StreamSubscription<String> keepTail(
  Stream<List<int>> stream,
  List<String> into, {
  int keep = 12,
}) {
  return stream
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .listen((line) {
    final text = line.trim();
    if (text.isEmpty) return;
    into.add(text);
    if (into.length > keep) into.removeAt(0);
  }, onError: (Object _) {});
}

final engineIpcProvider = Provider<EngineIpc>((ref) {
  final ipc = EngineIpc();
  ref.onDispose(ipc.dispose);
  return ipc;
});
