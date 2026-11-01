// Starts a real `mics-engine --service` against a throw-away sandbox.
//
// Every isolation hook AGENTS.md names is set here, and nothing else is: the
// harness must exercise the shipped code path, not a mock of it. The engine is
// killed in a `finally`, so a failed case cannot leave a service behind on the
// developer's machine.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

class EngineHost {
  EngineHost._(this.process, this.pipeName, this.sandbox);

  final Process process;
  final String pipeName;
  final Directory sandbox;

  final StringBuffer _stdout = StringBuffer();
  final StringBuffer _stderr = StringBuffer();

  static Future<EngineHost> start({
    required String enginePath,
    required Directory sandbox,
    required String pipeName,
  }) async {
    final dataDir = Directory('${sandbox.path}${Platform.pathSeparator}data')
      ..createSync(recursive: true);
    final programData =
        Directory('${sandbox.path}${Platform.pathSeparator}programdata')
          ..createSync(recursive: true);

    final environment = <String, String>{
      // Isolation hooks (AGENTS.md rule 5). Anything that writes must land in
      // the sandbox: the data dir, or PROGRAMDATA for the code paths that read
      // it directly. The pipe hook gets the full path: `pipe_path` accepts both
      // spellings, and the full one also works on an engine built before that
      // helper existed (a bare name produced Win32 error 123 there).
      'MICS_PIPE_NAME': r'\\.\pipe\' + pipeName,
      'MICS_DATA_DIR': dataDir.path,
      'PROGRAMDATA': programData.path,
      'MICS_NO_SINGLETON': '1',
      'MICS_NO_GUARD': '1',
      'MICS_NO_AUTO_RESUME': '1',
      // Keep the engine's own logging quiet and text-only for the report.
      'RUST_BACKTRACE': '1',
    };

    final process = await Process.start(
      enginePath,
      const ['service'],
      environment: environment,
      // The engine shells out (netsh, sc, powershell) through ToolCall, so it
      // needs the real PATH; every process-wide hook above still wins over the
      // inherited value because it is passed explicitly.
      includeParentEnvironment: true,
      workingDirectory: sandbox.path,
      runInShell: false,
    );

    final host = EngineHost._(process, pipeName, sandbox);
    process.stdout.transform(utf8.decoder).listen(host._stdout.write);
    process.stderr.transform(utf8.decoder).listen(host._stderr.write);
    return host;
  }

  /// True when the engine died before the harness finished with it.
  bool get exited => _exitCode != null;
  int? _exitCode;

  /// Waits (briefly) for the process to exit, so "it refused to start" is
  /// reported as that, not as a pipe timeout.
  Future<int?> exitCodeWithin(Duration timeout) async {
    try {
      _exitCode = await process.exitCode.timeout(timeout);
    } on TimeoutException {
      return null;
    }
    return _exitCode;
  }

  String get diagnostics {
    String tail(StringBuffer buffer, int lines) {
      final all = buffer.toString().trimRight().split('\n');
      if (all.length <= lines) return all.join('\n');
      return all.sublist(all.length - lines).join('\n');
    }

    final parts = <String>[];
    final out = tail(_stdout, 20);
    final err = tail(_stderr, 20);
    if (out.isNotEmpty) parts.add('stdout:\n$out');
    if (err.isNotEmpty) parts.add('stderr:\n$err');
    return parts.join('\n');
  }

  Future<void> stop() async {
    try {
      process.kill();
    } catch (_) {
      // already gone
    }
    await exitCodeWithin(const Duration(seconds: 5));
    // A service engine can survive the first signal while a worker thread is
    // busy; the second one is not optional inside a test run.
    if (_exitCode == null) {
      try {
        Process.killPid(process.pid, ProcessSignal.sigkill);
      } catch (_) {
        // already gone
      }
      await exitCodeWithin(const Duration(seconds: 5));
    }
  }
}