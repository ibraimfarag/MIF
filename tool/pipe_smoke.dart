// ignore_for_file: avoid_print
//
// Smoke test for the production pipe client used by the Flutter app.
//
//   dart run tool/pipe_smoke.dart
//
// Unlike tool/pipe_probe.dart (a hand-written client), this imports
// `lib/core/ipc/pipe_client.dart` — the exact class EngineIpc uses — so a
// regression in the isolate/FFI framing is caught here without launching the
// GUI. Expects an engine already listening on \\.\pipe\mics_engine.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:mics_app/core/ipc/pipe_client.dart';

Future<void> main() async {
  final conn = await PipeConnection.tryConnect(
    timeout: const Duration(seconds: 5),
  );
  if (conn == null) {
    stderr.writeln('FAIL: could not connect to the pipe');
    exit(1);
  }
  print('PASS: connected (production PipeConnection)');

  final lines = <String>[];
  final subscription = conn.lines.listen(lines.add);
  final closed = Completer<String>();
  conn.onClosed.listen((reason) {
    print('connection closed: $reason');
    if (!closed.isCompleted) closed.complete(reason);
  });

  conn.send(jsonEncode({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}));

  // Wait up to 5 s for the pong.
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (DateTime.now().isBefore(deadline)) {
    final pong = lines.any((l) => l.contains('"pong"'));
    if (pong) break;
    if (closed.isCompleted) break;
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }

  final ok = lines.any((l) => l.contains('"pong"'));
  print(ok ? 'PASS: ping -> pong over pipe' : 'FAIL: no pong (${lines.join(' | ')})');

  // Framing check: two requests back to back must both get answered.
  conn.send(jsonEncode({'jsonrpc': '2.0', 'id': 2, 'method': 'status'}));
  conn.send(jsonEncode({'jsonrpc': '2.0', 'id': 3, 'method': 'job.list', 'params': {'limit': 2}}));
  await Future<void>.delayed(const Duration(seconds: 2));
  final gotStatus = lines.any((l) => l.contains('"id":2'));
  final gotJobs = lines.any((l) => l.contains('"id":3'));
  print(gotStatus ? 'PASS: status replied' : 'FAIL: status unanswered');
  print(gotJobs ? 'PASS: job.list replied' : 'FAIL: job.list unanswered');

  await subscription.cancel();
  conn.close();
  print(ok && gotStatus && gotJobs ? 'ALL PASS' : 'FAILURES PRESENT');
  exit(ok && gotStatus && gotJobs ? 0 : 2);
}
