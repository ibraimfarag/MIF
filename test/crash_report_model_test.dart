// The two shapes the engine sends for crash reports (`crash.list` /
// `crash.get`) and the text the bug-id surface copies out of them (ز2-ج).
//
// The engine owns the file format; these tests pin the reading of it, so a
// field the UI shows cannot quietly become a default.

import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/models/crash_models.dart';

void main() {
  test('a list row is read as the engine sends it', () {
    final rows = CrashSummary.listFrom([
      {
        'bug_id': 'MICS-20261102-0d9743',
        'kind': 'hang',
        'created': '2026-11-02T00:15:40Z',
        'last_seen': '2026-11-02T00:20:11Z',
        'occurrences': 2,
        'message': "no heartbeat for 20.4 s, last request: scan.start",
        'location': null,
      },
      // A row the engine would never send is skipped, not thrown at the screen.
      'not a report',
    ]);

    expect(rows, hasLength(1));
    final row = rows.single;
    expect(row.bugId, 'MICS-20261102-0d9743');
    expect(row.kind, 'hang');
    expect(row.occurrences, 2);
    expect(row.lastSeen, '2026-11-02T00:20:11Z');
    expect(row.message, contains('scan.start'));
  });

  test('the text the user copies starts with the bug id', () {
    final report = CrashReport.fromJson({
      'bug_id': 'MICS-20261102-0d9743',
      'kind': 'hang',
      'created': '2026-11-02T00:15:40Z',
      'last_seen': '2026-11-02T00:20:11Z',
      'occurrences': 2,
      'version': '0.1.0',
      'message': 'no heartbeat for 20.4 s, last request: scan.start',
      'location': null,
      'session': {
        'pid': 4242,
        'mode': 'service',
        'started': '2026-11-02T00:00:00Z',
      },
      'log_tail': ['line one', 'line two'],
    });

    final text = report.pasteText;
    expect(text.split('\n').first, 'MICS-20261102-0d9743',
        reason: 'the first line has to be the id on its own');
    expect(text, contains('kind      : hang'));
    // The repeat is counted, and the newest duration is what the report shows.
    expect(text, contains('2 time(s)'));
    expect(text, contains('session   : service pid 4242'));
    expect(text, contains('what happened:'));
    expect(text, contains('last request: scan.start'));
    expect(text, contains('last 2 engine log lines (oldest first):'));
    expect(text, endsWith('line two\n'));
  });

  test('a report the runtime knows nothing about still renders', () {
    // A hang has no call site and no session need be there: the text must not
    // grow an empty `where`/`session` line or lose its first line.
    final report = CrashReport.fromJson({
      'bug_id': 'MICS-20261101-abc123',
      'kind': 'panic',
      'created': '2026-11-01T10:00:00Z',
      'last_seen': '2026-11-01T10:00:00Z',
      'occurrences': 1,
      'version': '0.1.0',
      'message': 'panicked at src/main.rs:12:5',
      'location': null,
      'session': null,
      'log_tail': <dynamic>[],
    });

    final text = report.pasteText;
    expect(text.split('\n').first, 'MICS-20261101-abc123');
    expect(text, isNot(contains('where')));
    expect(text, isNot(contains('session')));
    expect(text, isNot(contains('time(s)')));
    expect(text, contains('last 0 engine log lines (oldest first):'));
  });
}
