// ignore_for_file: avoid_print
//
// The contract harness: every JSON-RPC method the engine answers, against a real
// `mics-engine --service` in a throw-away sandbox.
//
//   dart run qa/contract.dart [--engine <path>] [--only <method>] [--keep]
//
// Why a separate process instead of `cargo test`: the dispatcher's table is the
// product's whole public surface (the UI only speaks JSON-RPC, D-006), and the
// unit tests call the handlers directly. This runs the transport too ? pipe
// framing, ids, error codes, notification traffic mixed into the replies.
//
// What it refuses to do is as important as what it does: a `mutating`, `network`
// or `desktop` method never runs its happy path (see qa/methods.json), because
// this harness must be safe on the machine that is being protected. Those rows
// still have to exist, so the surface is complete and countable: 62 methods, of
// which the run reports how many answered for real and how many were classified
// with a reason.

import 'dart:convert';
import 'dart:io';

import 'support/engine_host.dart';
import 'support/pipe.dart';

const _defaultTimeout = Duration(seconds: 30);
const _longTimeout = Duration(seconds: 180);

/// Methods that really do take their time on a cold machine.
const _slowMethods = <String>{
  'audit.run',
  'net.connections',
  'helper.status',
  'fw.rules.list',
  'scan.start',
};

EngineHost? _engine;

final _results = <Map<String, dynamic>>[];
final _skipped = <Map<String, dynamic>>[];

Future<void> main(List<String> args) async {
  final options = _Options.parse(args);
  final repo = _repoRoot();
  final registryFile = File('${repo.path}${Platform.pathSeparator}qa'
      '${Platform.pathSeparator}methods.json');
  if (!registryFile.existsSync()) {
    _die('registry not found: ${registryFile.path}');
  }
  final registry =
      (jsonDecode(registryFile.readAsStringSync()) as Map).cast<String, dynamic>();
  final methods = (registry['methods'] as List)
      .map((e) => (e as Map).cast<String, dynamic>())
      .toList();

  final enginePath = _resolveEngine(repo, options.engine);
  final sandbox = Directory.systemTemp.createTempSync('mics-qa-');
  final emptyDir = Directory('${sandbox.path}${Platform.pathSeparator}empty')
    ..createSync();
  final pipeName =
      'mics_qa_${pid}_${DateTime.now().millisecondsSinceEpoch % 100000}';

  print('MI CS contract harness');
  print('  engine   $enginePath');
  print('  sandbox  ${sandbox.path}');
  print('  pipe     $pipeName');
  print('  methods  ${methods.length}');
  print('');

  EngineHost? host;
  PipeClient? pipe;
  var ok = true;
  try {
    host = await EngineHost.start(
        enginePath: enginePath, sandbox: sandbox, pipeName: pipeName);
    _engine = host;
    final early = await host.exitCodeWithin(const Duration(seconds: 2));
    if (early != null) {
      print(host.diagnostics);
      _die('the engine exited with $early before it served the pipe');
    }
    pipe = PipeClient.connect(pipeName, timeout: const Duration(seconds: 20));

    // A method that is not registered must not be answered as if it were.
    final unknown = await pipe.call('qa.definitely.not.a.method');
    ok &= _record('qa.definitely.not.a.method', 'unknown-method', unknown,
        expect: 'error', wantCode: -32601);

    for (final entry in methods) {
      final method = entry['method'] as String;
      if (options.only != null && !options.only!.contains(method)) continue;
      ok &= await _runEntry(pipe, entry, sandbox, emptyDir);
    }

    if (options.only == null) {
      ok &= await _scanScenario(pipe, emptyDir);
      ok &= await _settingsScenario(pipe);
      ok &= await _crashScenario(enginePath, sandbox, pipeName);
    }

    // The engine has to survive every case: a handler that kills the process
    // would otherwise look like one failed method.
    final alive = await pipe.call('ping');
    ok &= _record('ping', 'still-alive', alive, expect: 'string');
    if (!alive.ok) await _drain(pipe);
    final exit = await host.exitCodeWithin(const Duration(milliseconds: 500));
    print('  engine at end: ${exit == null ? 'alive' : 'exited ($exit)'}');
  } on Object catch (error, stack) {
    ok = false;
    print('HARNESS FAILURE: $error');
    print(stack);
    final diagnostics = host?.diagnostics ?? '';
    if (diagnostics.isNotEmpty) print(diagnostics);
  } finally {
    pipe?.close();
    await host?.stop();
    if (options.keep) {
      print('sandbox kept at ${sandbox.path}');
    } else {
      try {
        sandbox.deleteSync(recursive: true);
      } catch (_) {
        // A lock left by the engine's log file is not a harness failure.
      }
    }
  }

  _writeReport(repo, enginePath, ok);
  _printSummary(ok);
  if (!ok) {
    // A failed case is usually the engine telling us something on its own log;
    // without it the report says "timeout" and nothing else.
    final diagnostics = host?.diagnostics ?? '';
    if (diagnostics.trim().isNotEmpty) {
      print('');
      print('--- engine stderr (tail) ---');
      final lines = const LineSplitter().convert(diagnostics);
      for (final line in lines.length > 40
          ? lines.sublist(lines.length - 40)
          : lines) {
        print('  $line');
      }
    }
  }
  exit(ok ? 0 : 1);
}

// ------------------------------------------------------------------- one row

Future<bool> _runEntry(PipeClient pipe, Map<String, dynamic> entry,
    Directory sandbox, Directory empty) async {
  final method = entry['method'] as String;
  final params = entry['params'];
  final expect = entry['expect'] as String?;
  final timeout = _slowMethods.contains(method) ? _longTimeout : _defaultTimeout;
  var ok = true;

  if (expect != null) {
    final reply = await pipe.call(method,
        params: _substitute(params, sandbox, empty), timeout: timeout);
    ok &= _record(method, 'call', reply,
        expect: expect,
        want: (entry['want'] as Map?)?.cast<String, dynamic>());
    if (reply.timedOut) await _drain(pipe);
  }

  if (entry['missing'] == true) {
    final reply = await pipe.call(method,
        params: const <String, dynamic>{}, timeout: timeout);
    ok &= _record(method, 'missing-params', reply, expect: 'error');
    if (reply.timedOut) await _drain(pipe);
  }

  final invalid = entry['invalid'];
  if (invalid != null) {
    final reply = await pipe.call(method,
        params: _substitute(invalid, sandbox, empty), timeout: timeout);
    ok &= _record(method, 'invalid-params', reply, expect: 'error');
    if (reply.timedOut) await _drain(pipe);
  }

  // Named extra cases: a method's contract is not always "one call, one shape".
  // `quarantine.delete` is the example that forced this: deleting a blob that is
  // already gone answers success on purpose, so the unknown id cannot live under
  // `invalid` (which means "must be refused").
  final extras = entry['extra'];
  if (extras is List) {
    for (final extra in extras) {
      final item = (extra as Map).cast<String, dynamic>();
      final reply = await pipe.call(method,
          params: _substitute(item['params'], sandbox, empty),
          timeout: timeout);
      ok &= _record(method, '${item['case']}', reply,
          expect: '${item['expect']}');
      if (reply.timedOut) await _drain(pipe);
    }
  }

  if (expect == null &&
      entry['missing'] != true &&
      invalid == null &&
      extras == null) {
    _skipped.add({
      'method': method,
      'class': entry['class'],
      'reason': entry['skip'] ?? 'not executable here',
    });
  }
  return ok;
}

bool _record(String method, String kind, RpcReply reply,
    {required String expect, int? wantCode, Map<String, dynamic>? want}) {
  var pass = true;
  final detail = reply.short;

  if (wantCode != null) {
    pass = !reply.ok && reply.code == wantCode;
  } else if (expect == 'error') {
    pass = !reply.ok && !reply.timedOut;
  } else {
    pass = reply.ok && _shape(expect, reply.result);
  }

  // `want` pins the values that make a shape meaningful: an object with
  // `status: not_resumable` is a different answer from one saying `resumed`.
  String? wrongField;
  if (pass && want != null && reply.result is Map) {
    final result = reply.result as Map;
    for (final entry in want.entries) {
      if ('${result[entry.key]}' != '${entry.value}') {
        pass = false;
        wrongField = '${entry.key}: wanted ${entry.value}, '
            'got ${result[entry.key]}';
        break;
      }
    }
  }

  _results.add({
    'method': method,
    'case': kind,
    'ok': pass,
    'detail': detail,
  });

  final tag = pass ? 'PASS' : 'FAIL';
  print('  $tag  ${method.padRight(26)} ${kind.padRight(15)} $detail');
  if (!pass) {
    if (wrongField != null) {
      print('        $wrongField');
    } else if (!reply.ok && reply.message != null) {
      print('        ${reply.message}');
    } else if (reply.ok) {
      print('        expected $expect, got ${reply.result.runtimeType}');
    }
  }
  return pass;
}

/// Prints what was waiting on the pipe after a timeout, so a missed reply is
/// evidence instead of a mystery.
Future<void> _drain(PipeClient pipe) async {
  final stale = await pipe.drain();
  if (stale.isEmpty) {
    print('        (nothing was waiting on the pipe)');
  }
  for (final line in stale.take(5)) {
    print('        stale: '
        '${line.length > 120 ? line.substring(0, 120) : line}');
  }
  await _reportEngineState();
}

/// "Timeout" covers three different bugs: a stuck handler, a dead process, and
/// a reply that was written but never matched. Say which one it was.
Future<void> _reportEngineState() async {
  final engine = _engine;
  if (engine == null) return;
  final exit = await engine.exitCodeWithin(const Duration(milliseconds: 250));
  if (exit != null) {
    print('        the engine process exited with $exit');
  } else if (engine.exited) {
    print('        the engine process was already gone');
  }
}

bool _shape(String expect, dynamic result) {
  switch (expect) {
    case 'string':
      return result is String;
    case 'object':
      return result is Map;
    case 'array':
      return result is List;
    case 'any':
      return result != null;
    case 'error':
      return false; // handled by the caller: an error result was expected
    default:
      return false;
  }
}

/// Replaces `@sandbox/...` placeholders with real paths, so the registry stays a
/// document rather than a list of machine-specific strings.
dynamic _substitute(dynamic value, Directory sandbox, Directory empty) {
  if (value is String) {
    if (value == '@sandbox/empty') return empty.path;
    if (value.startsWith('@sandbox/')) {
      final name = value.substring('@sandbox/'.length);
      return '${sandbox.path}${Platform.pathSeparator}$name';
    }
    return value;
  }
  if (value is Map) {
    return value.map((k, v) => MapEntry('$k', _substitute(v, sandbox, empty)));
  }
  if (value is List) {
    return value.map((v) => _substitute(v, sandbox, empty)).toList();
  }
  return value;
}

// --------------------------------------------------------------- scenarios

/// The scan path end to end: start a job, watch it finish, read it back, list
/// it, and prove a finished job cannot be cancelled.
Future<bool> _scanScenario(PipeClient pipe, Directory empty) async {
  var ok = true;
  final start = await pipe.call('scan.start',
      params: {'path': empty.path, 'quarantine': false},
      timeout: _longTimeout);
  ok &= _record('scan.start', 'scenario', start, expect: 'object');
  if (!start.ok || start.result is! Map) return false;

  final jobId = '${(start.result as Map)['job_id']}';
  if (jobId.isEmpty || jobId == 'null') {
    print('  FAIL  scan.start returned no job id');
    return false;
  }

  var state = 'running';
  final deadline = DateTime.now().add(const Duration(seconds: 120));
  while (DateTime.now().isBefore(deadline)) {
    final got = await pipe.call('job.get', params: {'job_id': jobId});
    if (!got.ok || got.result is! Map) {
      print('  FAIL  job.get for $jobId: ${got.short}');
      return false;
    }
    final job = (got.result as Map)['job'];
    state = '${job is Map ? job['state'] : ''}';
    if (state != 'running') break;
    sleep(const Duration(milliseconds: 250));
  }
  _results.add({
    'method': 'scan',
    'case': 'job-finished',
    'ok': state == 'done',
    'detail': 'state=$state',
  });
  print('  ${state == 'done' ? 'PASS' : 'FAIL'}  '
      'scan job finished        state=$state');
  ok &= state == 'done';

  final list = await pipe.call('job.list', params: {'limit': 20});
  final listed = list.ok &&
      list.result is List &&
      (list.result as List).any((e) => e is Map && '${e['job_id']}' == jobId);
  _results.add({
    'method': 'job.list',
    'case': 'contains-the-new-job',
    'ok': listed,
    'detail': listed ? jobId : 'job $jobId not listed',
  });
  print('  ${listed ? 'PASS' : 'FAIL'}  job.list contains the scan job');
  ok &= listed;

  final cancel = await pipe.call('job.cancel', params: {'job_id': jobId});
  final refused = cancel.ok &&
      cancel.result is Map &&
      (cancel.result as Map)['cancelled'] == false;
  _results.add({
    'method': 'job.cancel',
    'case': 'finished-job',
    'ok': refused,
    'detail': refused ? 'cancelled=false' : cancel.short,
  });
  print('  ${refused ? 'PASS' : 'FAIL'}  '
      'a finished job is not cancellable');
  return ok && refused;
}

/// Settings are the engine's document (D-008): a write must be readable back,
/// and a refused value must leave the previous one in place.
///
/// The refused value is `english`, not `xx`: a language tag the UI has no pack
/// for is *accepted* (the UI owns the packs, the engine only owns the shape), so
/// the refusal case has to be something that is not a tag at all.
Future<bool> _settingsScenario(PipeClient pipe) async {
  var ok = true;
  final toEnglish = await pipe.call('settings.set', params: {'lang': 'en'});
  ok &= toEnglish.ok;
  final readBack = await pipe.call('settings.get');
  ok &= readBack.ok && readBack.result is Map && readBack.result['lang'] == 'en';
  final refused = await pipe.call('settings.set', params: {'lang': 'english'});
  ok &= !refused.ok;
  final unchanged = await pipe.call('settings.get');
  ok &= unchanged.ok && unchanged.result is Map &&
      unchanged.result['lang'] == 'en';
  // A tag for a language nobody has shipped yet is stored, not rejected: the
  // next language must not need an engine release.
  final future = await pipe.call('settings.set', params: {'lang': 'de'});
  ok &= future.ok && future.result is Map && future.result['lang'] == 'de';
  final restored = await pipe.call('settings.set', params: {'lang': 'ar'});
  ok &= restored.ok;

  _results.add({
    'method': 'settings',
    'case': 'round-trip',
    'ok': ok,
    'detail':
        ok ? 'en persisted, "english" refused, de stored, ar restored' : 'see above',
  });
  print('  ${ok ? 'PASS' : 'FAIL'}  settings round-trip '
      '(en -> refused "english" -> de -> ar)');
  return ok;
}

// ------------------------------------------------------------------- crash

/// The crash report loop, proved on the real binary without making it panic.
///
/// A run that is killed leaves its session marker unclosed; the next run has to
/// notice that exactly once, write a report that says who died and when, and let
/// it be read and removed. The panic path itself is covered by the engine's own
/// unit tests (the hook writes the bundle before `panic = "abort"` ends the
/// process), and this scenario is the half that only exists across two
/// processes.
Future<bool> _crashScenario(
    String enginePath, Directory sandbox, String pipeName) async {
  final scratch = Directory('${sandbox.path}${Platform.pathSeparator}crash')
    ..createSync(recursive: true);
  EngineHost? first;
  EngineHost? second;
  var ok = true;
  try {
    // A fresh data dir: starting with no marker means nothing to report.
    first = await EngineHost.start(
        enginePath: enginePath, sandbox: scratch, pipeName: '${pipeName}c1');
    var pipe = PipeClient.connect('${pipeName}c1',
        timeout: const Duration(seconds: 20));
    final clean = await pipe.call('crash.list');
    final cleanList = clean.result as List? ?? const [];
    final cleanOk = clean.ok && cleanList.isEmpty;
    ok &= cleanOk;
    _results.add({
      'method': 'crash',
      'case': 'first-start-has-no-reports',
      'ok': cleanOk,
      'detail': clean.short,
    });
    print('  ${cleanOk ? 'PASS' : 'FAIL'}  crash  first start files nothing '
        '(${clean.short})');

    // Kill it: no goodbye, which is what a crash, a power cut or Task Manager
    // looks like from the inside.
    final deadPid = first.process.pid;
    await first.stop();
    first = null;

    second = await EngineHost.start(
        enginePath: enginePath, sandbox: scratch, pipeName: '${pipeName}c2');
    pipe = PipeClient.connect('${pipeName}c2',
        timeout: const Duration(seconds: 20));
    final after = await pipe.call('crash.list');
    final afterList = after.result as List? ?? const [];
    final reportedOk =
        after.ok && afterList.length == 1 && afterList.first['kind'] == 'unclean-exit';
    ok &= reportedOk;
    _results.add({
      'method': 'crash',
      'case': 'a-killed-run-is-reported-once',
      'ok': reportedOk,
      'detail': after.short,
    });
    print('  ${reportedOk ? 'PASS' : 'FAIL'}  crash  a killed run is reported '
        'once (${after.short})');

    if (afterList.isEmpty) return ok;
    final bugId = '${afterList.first['bug_id']}';
    final shapeOk = RegExp(r'^MICS-\d{8}-[0-9a-f]{6}$').hasMatch(bugId);
    ok &= shapeOk;
    _results.add({
      'method': 'crash',
      'case': 'the-bug-id-has-the-documented-shape',
      'ok': shapeOk,
      'detail': bugId,
    });
    print('  ${shapeOk ? 'PASS' : 'FAIL'}  crash  bug id $bugId');

    final report = await pipe.call('crash.get', params: {'bug_id': bugId});
    final sessionPid = (report.result as Map?)?['session'] is Map
        ? ((report.result as Map)['session'] as Map)['pid']
        : null;
    final readOk = report.ok &&
        (report.result as Map?)?['bug_id'] == bugId &&
        sessionPid == deadPid;
    ok &= readOk;
    _results.add({
      'method': 'crash',
      'case': 'the-report-names-the-process-that-died',
      'ok': readOk,
      'detail': 'session pid $sessionPid, killed $deadPid',
    });
    print('  ${readOk ? 'PASS' : 'FAIL'}  crash  the report names the process '
        'that died (session pid $sessionPid, killed $deadPid)');

    // The id comes from a pipe client, so it must never be able to name a file
    // outside the reports directory.
    final traversal =
        await pipe.call('crash.get', params: {'bug_id': r'..\..\settings.json'});
    final traversalOk = !traversal.ok;
    ok &= traversalOk;
    _results.add({
      'method': 'crash',
      'case': 'a-path-is-not-a-bug-id',
      'ok': traversalOk,
      'detail': traversal.short,
    });
    print('  ${traversalOk ? 'PASS' : 'FAIL'}  crash  a path is not a bug id '
        '(${traversal.short})');

    final removed = await pipe.call('crash.delete', params: {'bug_id': bugId});
    final deleteOk =
        removed.ok && (removed.result as Map?)?['deleted'] == true;
    final empty = await pipe.call('crash.list');
    final emptyOk = (empty.result as List? ?? const []).isEmpty;
    ok &= deleteOk && emptyOk;
    _results.add({
      'method': 'crash',
      'case': 'a-report-can-be-removed',
      'ok': deleteOk && emptyOk,
      'detail': removed.short,
    });
    print('  ${deleteOk && emptyOk ? 'PASS' : 'FAIL'}  crash  a report can be '
        'removed');
  } finally {
    await first?.stop();
    await second?.stop();
  }
  return ok;
}

// ------------------------------------------------------------------- output

void _writeReport(Directory repo, String enginePath, bool ok) {
  final reportDir = Directory('${repo.path}${Platform.pathSeparator}build');
  if (!reportDir.existsSync()) reportDir.createSync(recursive: true);
  final report = <String, dynamic>{
    'ok': ok,
    'when': DateTime.now().toIso8601String(),
    'engine': enginePath,
    'executed': _results.length,
    'skipped': _skipped.length,
    'cases': _results,
  };
  final file = File(
      '${reportDir.path}${Platform.pathSeparator}qa-contract.json');
  file.writeAsStringSync(
      const JsonEncoder.withIndent('  ').convert(report));
  print('');
  print('report: ${file.path}');
}

void _printSummary(bool ok) {
  final failed = _results.where((r) => r['ok'] != true).length;
  print('');
  print('RESULT: ${ok ? 'PASS' : 'FAIL'} - ${_results.length} case(s), '
      '$failed failed, ${_skipped.length} method(s) classified not-to-run');
  if (_skipped.isNotEmpty) {
    print('Not executed here (each with its reason, all still registered):');
    for (final skip in _skipped) {
      print('  - ${skip['method']} (${skip['class']}): ${skip['reason']}');
    }
  }
}

// ------------------------------------------------------------------ helpers

Directory _repoRoot() {
  final fromScript = File.fromUri(Platform.script).parent.parent;
  if (File('${fromScript.path}${Platform.pathSeparator}qa'
            '${Platform.pathSeparator}methods.json')
        .existsSync()) {
    return fromScript;
  }
  return Directory.current;
}

String _resolveEngine(Directory repo, String? explicit) {
  if (explicit != null) {
    if (!File(explicit).existsSync()) _die('no engine at $explicit');
    return explicit;
  }
  final fromEnv = Platform.environment['MICS_ENGINE_PATH'];
  if (fromEnv != null && File(fromEnv).existsSync()) return fromEnv;

  final target = Platform.environment['CARGO_TARGET_DIR'];
  final candidates = <String>[
    if (target != null) '$target${Platform.pathSeparator}release'
        '${Platform.pathSeparator}mics-engine.exe',
    if (target != null) '$target${Platform.pathSeparator}debug'
        '${Platform.pathSeparator}mics-engine.exe',
    '${repo.path}${Platform.pathSeparator}engine${Platform.pathSeparator}target'
        '${Platform.pathSeparator}release${Platform.pathSeparator}mics-engine.exe',
    '${repo.path}${Platform.pathSeparator}engine${Platform.pathSeparator}target'
        '${Platform.pathSeparator}debug${Platform.pathSeparator}mics-engine.exe',
  ];
  for (final candidate in candidates) {
    if (File(candidate).existsSync()) return candidate;
  }
  _die('no engine binary found. Build one (`cargo build`), or pass --engine, '
      'or set MICS_ENGINE_PATH.');
}

Never _die(String message) {
  print('FAIL: $message');
  exit(2);
}

class _Options {
  _Options({this.engine, this.only, this.keep = false});

  final String? engine;
  final Set<String>? only;
  final bool keep;

  static _Options parse(List<String> args) {
    String? engine;
    String? only;
    var keep = false;
    for (var i = 0; i < args.length; i++) {
      switch (args[i]) {
        case '--engine':
          i++;
          if (i >= args.length) _die('--engine needs a path');
          engine = args[i];
          break;
        case '--only':
          i++;
          if (i >= args.length) _die('--only needs a method name');
          only = args[i];
          break;
        case '--keep':
          keep = true;
          break;
        default:
          _die('unknown option ${args[i]}\n'
              'usage: dart run qa/contract.dart [--engine <path>] '
              '[--only <method>] [--keep]');
      }
    }
    return _Options(engine: engine, only: only?.split(',').toSet(), keep: keep);
  }
}