// The opsec allowlist (`qa/opsec-baseline.json`) is data, and data an agent can
// edit without thinking is how a fingerprint becomes permanent. This test guards
// the file itself:
//
//  * every allowlisted marker has a reason a human wrote - that is the whole
//    point of an allowlist, as opposed to a list of numbers;
//  * the file never stores the account path the probe forbids: the probe
//    computes that at run time from the machine it runs on, so committing it
//    would leak exactly what the probe exists to remove;
//  * the marker list in the file is the marker list in
//    `scripts/verify-opsec.ps1`, the way `test/qa_registry_test.dart` keeps
//    `qa/methods.json` equal to the dispatcher.
//
// The counts themselves are measured against a built package by
// `scripts/verify-opsec.ps1`; a committed baseline cannot measure a binary that
// is not in the repository, which is why the ratchet runs on the artifact (from
// `make-release.ps1`, and from `-Tier release` once ط3 wires it there).

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const _markers = ['flutter', 'dart', 'cargo', 'rustc', 'pubspec'];

void main() {
  late String raw;
  late Map<String, dynamic> baseline;

  setUpAll(() {
    raw = File('qa/opsec-baseline.json').readAsStringSync();
    baseline = (jsonDecode(raw) as Map).cast<String, dynamic>();
  });

  test('the allowlist says what it measured and where', () {
    expect(baseline['artifact'], 'dist/MICS-portable',
        reason: 'a baseline that does not name its package measures nothing');
    expect(baseline['measured'], matches(RegExp(r'^\d{4}-\d{2}-\d{2}$')),
        reason: 'the measurement needs a date, so a stale one is visible');
    expect(baseline['definition'], contains('ISO-8859-1'),
        reason: 'the counting definition is what makes two measurements '
            'comparable, so it belongs in the file');
    final policy = (baseline['policy'] as Map).cast<String, dynamic>();
    expect(policy['forbidden'], contains('profile path'),
        reason: 'the forbidden string is computed, not stored: say so');
    expect(policy['ratchet'], contains('fall'));
  });

  test('the counted markers are the probe\'s own markers', () {
    final policy = (baseline['policy'] as Map).cast<String, dynamic>();
    expect((policy['counted'] as List).cast<String>(), _markers,
        reason: 'the probe would measure one list and compare another');

    // The probe's list, read out of the script, so the two cannot drift apart.
    final script = File('scripts/verify-opsec.ps1').readAsStringSync();
    final declared = RegExp(r'\$Counted = @\(([^)]*)\)').firstMatch(script);
    expect(declared, isNotNull,
        reason: 'scripts/verify-opsec.ps1 no longer declares \$Counted');
    final probeMarkers = RegExp(r'"([^"]+)"')
        .allMatches(declared!.group(1)!)
        .map((m) => m.group(1))
        .toList();
    expect(probeMarkers, _markers,
        reason: 'the probe measures $probeMarkers, the baseline lists '
            '${policy['counted']}');
  });

  test('every allowlisted marker is a positive count with a written reason',
      () {
    final files = (baseline['files'] as Map).cast<String, dynamic>();
    expect(files, isNotEmpty);
    for (final entry in files.entries) {
      final file = (entry.value as Map).cast<String, dynamic>();
      expect(file.keys, ['counts'],
          reason: '${entry.key} carries more than its counts');
      final counts = (file['counts'] as Map).cast<String, dynamic>();
      expect(counts, isNotEmpty,
          reason: '${entry.key} has no marker: a zero row is noise, drop it');
      for (final marker in counts.entries) {
        expect(_markers, contains(marker.key),
            reason: '${entry.key} lists "${marker.key}", which the probe never '
                'counts');
        final row = (marker.value as Map).cast<String, dynamic>();
        expect(row['count'], isA<int>(),
            reason: '${entry.key}/${marker.key} needs a whole count');
        expect(row['count'] as int, greaterThan(0),
            reason: '${entry.key}/${marker.key} is zero; the probe only records '
                'hits that exist');
        final reason = (row['reason'] as String?) ?? '';
        expect(reason.trim().length, greaterThanOrEqualTo(20),
            reason: '${entry.key}/${marker.key} is allowlisted without a '
                'reason: why is this string allowed to ship?');
      }
    }
  });

  test('the file is ordered, so the next measurement diffs cleanly', () {
    final names = (baseline['files'] as Map).keys.cast<String>().toList();
    final sorted = [...names]..sort();
    expect(names, sorted);
  });

  test('the baseline never stores the account path the probe forbids', () {
    // The probe forbids the profile path of the account that runs it, so the
    // path itself must not be in the repository: it would be the leak with a
    // commit message. Any Windows user path is refused, not just this machine's.
    expect(raw, isNot(contains(r'C:\Users\')));
    expect(raw.toLowerCase(), isNot(contains('userprofile')));
    expect(raw, isNot(contains(Platform.environment['USERNAME'] ?? '@@none@@')),
        reason: 'the file names the account that measured it');
  });
}