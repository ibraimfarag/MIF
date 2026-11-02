// The QA report: what is registered, what proves it, and what runs where.
//
// Two committed files come out of here - `qa/report.md` and `qa/report.html` -
// and they are built from committed files only: no clock, no machine path, no
// run timing, no hash. That is what lets `test/qa_report_test.dart` compare them
// byte for byte and fail the fast tier (and so CI, which runs the fast tier
// inside `-Tier full`) when the surface moved and the report did not.
// Regenerating is deliberate:
//
//   $env:QA_REPORT_WRITE = "1"; dart run qa\report.dart
//
// and the diff is the thing to read, the same way `qa/ui/ledger.json` works.
//
// It is the *registered* surface, not a run. What executed, what was refused and
// how long it took is in `build/qa-contract.json` (the contract) and
// `build/pipeline-<tier>.json` (the steps); CI uploads both.
//
// Plain Dart on purpose: the report has to be writable without Flutter.

import 'dart:convert';
import 'dart:io';

import 'registry.dart';

const markdownPath = 'qa/report.md';
const htmlPath = 'qa/report.html';

/// Every file the report names. A rename must break this, not quietly produce a
/// report pointing at something that is gone.
const namedFiles = <String>[
  '.github/workflows/ci.yml',
  'assets/i18n/README.md',
  'engine/src/dispatcher.rs',
  'qa/contract.dart',
  'qa/methods.json',
  'qa/opsec-baseline.json',
  'qa/registry.dart',
  'qa/report.dart',
  'qa/ui/fixtures.json',
  'qa/ui/harness.dart',
  'qa/ui/ledger.dart',
  'qa/ui/ledger.json',
  'scripts/pipeline.ps1',
  'scripts/verify-opsec.ps1',
  'test/i18n_parity_test.dart',
  'test/lang_registry_test.dart',
  'test/opsec_baseline_test.dart',
  'test/qa_registry_test.dart',
  'test/qa_report_test.dart',
  'test/ui_screens_test.dart',
  'test/ui_shell_test.dart',
];

void main(List<String> args) {
  final report = buildReport();
  if (Platform.environment['QA_REPORT_WRITE'] == '1') {
    File(markdownPath).writeAsStringSync(report.markdown);
    File(htmlPath).writeAsStringSync(report.html);
    stdout.writeln('wrote $markdownPath and $htmlPath '
        '(${report.methodCount} methods, ${report.controlsCount} controls)');
    return;
  }

  var stale = 0;
  final pairs = <List<String>>[
    [markdownPath, report.markdown],
    [htmlPath, report.html],
  ];
  for (final pair in pairs) {
    final file = File(pair[0]);
    final onDisk = file.existsSync() ? file.readAsStringSync() : '';
    if (normaliseEol(onDisk) == normaliseEol(pair[1])) {
      stdout.writeln('OK    ${pair[0]}');
    } else {
      stale += 1;
      stdout.writeln('STALE ${pair[0]}');
    }
  }
  if (stale > 0) {
    stdout.writeln(
        r'regenerate: $env:QA_REPORT_WRITE = "1"; dart run qa\report.dart');
    exit(1);
  }
  stdout.writeln('$markdownPath and $htmlPath match the registries');
}

/// Line endings are the one difference a checkout is allowed to make
/// (`core.autocrlf`), so a byte comparison has to normalise them first.
String normaliseEol(String text) => text.replaceAll('\r\n', '\n');

/// The report, computed once and rendered twice.
QaReport buildReport() {
  for (final path in namedFiles) {
    if (!File(path).existsSync() && !Directory(path).existsSync()) {
      throw QaRegistryException('the report names $path, which does not exist');
    }
  }

  // ------------------------------------------------------------- the pipe
  final registry = readJsonMap(methodsPath);
  final dispatcherSource = registry['engine'] as String;
  final rows = methodRows(methodsPath);
  final dispatched = dispatchedMethods(dispatcherSource);

  int casesOf(Map<String, dynamic> row) => <bool>[
        row['expect'] != null,
        row['missing'] == true,
        row['invalid'] != null,
        row['extra'] is List && (row['extra'] as List).isNotEmpty,
      ].where((present) => present).length;

  final classes = <String, _ClassBucket>{};
  final methods = <_MethodRow>[];
  final notRun = <NotRun>[];
  var declaredCases = 0;
  for (final row in rows) {
    final name = row['method'] as String;
    final cls = row['class'] as String;
    final skip = row['skip'] as String?;
    final cases = casesOf(row);
    declaredCases += cases;
    final bucket = classes.putIfAbsent(cls, () => _ClassBucket());
    bucket.methods += 1;
    if (cases > 0) bucket.withCases += 1;
    if (skip != null) {
      bucket.notRun += 1;
      notRun.add(NotRun(name, cls, skip));
    }
    methods.add(_MethodRow(name, cls, cases, skip != null));
  }
  methods.sort((a, b) => a.name.compareTo(b.name));
  notRun.sort((a, b) => a.method.compareTo(b.method));
  final classNames = classes.keys.toList()..sort();

  // ----------------------------------------------------------- the screens
  final ledger = readJsonMap(ledgerPath);
  final entries = (ledger['entries'] as Map).cast<String, dynamic>();
  final screens = <String, int>{};
  var shellControls = 0;
  for (final entry in entries.entries) {
    final count = (entry.value as List).length;
    if (entry.key == 'shell') {
      shellControls = count;
    } else {
      screens[entry.key] = count;
    }
  }
  final screenNames = screens.keys.toList()..sort();
  final controls =
      screens.values.fold<int>(0, (sum, count) => sum + count) + shellControls;

  // --------------------------------------------------------- the languages
  final languages = <String, int>{};
  for (final entity in Directory('assets/i18n').listSync()) {
    if (entity is! Directory) continue;
    final code = entity.path.replaceAll('\\', '/').split('/').last;
    languages[code] = jsonFileNames('assets/i18n/$code').length;
  }
  final languageNames = languages.keys.toList()..sort();
  final bundled = RegExp(r'^\s*-\s+assets/i18n/([A-Za-z0-9_-]+)/\s*$',
          multiLine: true)
      .allMatches(File('pubspec.yaml').readAsStringSync())
      .map((match) => match.group(1)!)
      .toSet();

  // ----------------------------------------------------- the shipped files
  final opsec = readJsonMap(opsecPath);
  final policy = (opsec['policy'] as Map).cast<String, dynamic>();
  final markers = (policy['counted'] as List).cast<String>();
  final shippedRows = (opsec['files'] as Map).cast<String, dynamic>();
  final shipped = shippedRows.keys.toList()..sort();
  final countRows = <List<String>>[
    for (final name in shipped)
      [
        '`$name`',
        for (final marker in markers) '${countOf(shippedRows[name], marker)}',
        totalOf(shippedRows[name], markers),
      ],
  ];
  final reasonRows = <List<String>>[];
  for (final name in shipped) {
    for (final marker in markers) {
      final reason = reasonOf(shippedRows[name], marker);
      if (reason == null) continue;
      reasonRows.add(['`$name`', '`$marker`', reason]);
    }
  }

  // ------------------------------------------------------------ the tests
  final dartTests = <String, int>{};
  for (final file in Directory('test').listSync().whereType<File>()) {
    final path = file.path.replaceAll('\\', '/');
    if (!path.endsWith('_test.dart')) continue;
    dartTests[path] =
        declared(file.readAsStringSync(), RegExp(r'^[ \t]*(?:test|testWidgets)\(',
            multiLine: true));
  }
  final dartTestNames = dartTests.keys.toList()..sort();
  final dartCases = dartTests.values.fold<int>(0, (sum, n) => sum + n);

  final engineTests = <String, int>{};
  void walk(Directory dir) {
    for (final entity in dir.listSync()) {
      if (entity is Directory) {
        walk(entity);
      } else if (entity is File && entity.path.endsWith('.rs')) {
        final count = declared(
            entity.readAsStringSync(), RegExp(r'#\[(?:tokio::)?test\]'));
        if (count > 0) {
          engineTests[entity.path.replaceAll('\\', '/')] = count;
        }
      }
    }
  }

  walk(Directory('engine/src'));
  final engineTestNames = engineTests.keys.toList()..sort();
  final engineCases = engineTests.values.fold<int>(0, (sum, n) => sum + n);

  // -------------------------------------------------------- what runs where
  final steps = pipelineSteps(File('scripts/pipeline.ps1').readAsStringSync());
  const tiers = <String>['fast', 'full', 'release'];
  final markerText = markers.map((marker) => '`$marker`').join(', ');
  final packCount = languages.values.fold<int>(0, (sum, n) => sum + n);

  final blocks = <Block>[
    const Heading(1, 'MI CS - QA surface and gates'),
    const Para(
        'Generated by `qa/report.dart` from committed files only: no clock, no '
        'machine path, no run timing, no hash. That is what lets '
        '`test/qa_report_test.dart` compare these two files byte for byte and fail '
        'the fast tier - and so CI, which runs the fast tier inside `-Tier full` - '
        'when the surface moved and the report did not.'),
    const Para(r'Regenerate deliberately and read the diff: '
        r'`$env:QA_REPORT_WRITE = "1"; dart run qa\report.dart`.'),
    const Para(
        'This is the **registered** surface, not a run. What executed, what was '
        'refused and how long it took is in `build/qa-contract.json` (the contract) '
        'and `build/pipeline-<tier>.json` (the steps); CI uploads both next to this '
        'report.'),
    const Heading(2, 'The gates'),
    const Para(
        'One row per surface the QA harness covers: what registers it, what proves '
        'it, and the file that fails the build when the two disagree. A feature that '
        'is not registered fails the fast tier in both directions - something new '
        'with no registry entry, and a registry entry whose subject is gone.'),
    Table(
      const ['Surface', 'Registered', 'Proven by', 'Enforced by'],
      [
        [
          'JSON-RPC methods',
          '${rows.length} rows in `qa/methods.json`',
          '${dispatched.length} dispatched by `$dispatcherSource`',
          '`test/qa_registry_test.dart`',
        ],
        [
          'Contract cases',
          '$declaredCases declared in the registry, ${notRun.length} classified not to run',
          'every method has a case that runs here, or a recorded reason; the harness adds its own scenarios',
          '`engine.contract`, `qa/contract.dart`',
        ],
        [
          'Screens',
          '${screenNames.length} screens and the shell',
          'every screen swept, `qa/ui/ledger.json` agrees',
          '`test/ui_screens_test.dart`',
        ],
        [
          'Controls',
          '$controls in the ledger',
          'the sweep fails when a control appears or disappears unannounced',
          '`qa/ui/harness.dart`, `qa/ui/ledger.dart`',
        ],
        [
          'Languages',
          '${languageNames.length} languages, $packCount packs',
          'each language is bundled and parity-checked against the others',
          '`test/lang_registry_test.dart`, `test/i18n_parity_test.dart`',
        ],
        [
          'Shipped files',
          '${shipped.length} binaries in `qa/opsec-baseline.json`',
          'every count carries a written reason, and may only fall',
          '`scripts/verify-opsec.ps1`, `test/opsec_baseline_test.dart`',
        ],
        [
          'Dart tests',
          '${dartTestNames.length} files',
          '$dartCases declared cases (a floor: loops add more at run time)',
          '`flutter.test` step',
        ],
        [
          'Engine tests',
          '${engineTestNames.length} modules',
          '$engineCases declared cases',
          '`engine.test` step',
        ],
        [
          'Pipeline steps',
          '${steps.length} across ${tiers.length} tiers',
          'the same script a human runs and CI runs',
          '`scripts/pipeline.ps1`, `.github/workflows/ci.yml`',
        ],
        [
          'This report',
          '2 files',
          'rebuilt from the registries above and compared byte for byte',
          '`test/qa_report_test.dart`',
        ],
      ],
    ),
    Heading(2, 'The pipe: ${rows.length} methods'),
    const Para(
        'The UI speaks JSON-RPC and nothing else, so this is the product\'s whole '
        'public surface. Cases are the rows of `qa/methods.json` that make the '
        'harness call the engine; a method with none must carry a recorded reason '
        'instead.'),
    Table(
      const ['Class', 'Methods', 'With a case', 'Classified not to run'],
      [
        for (final name in classNames)
          [
            '`$name`',
            '${classes[name]!.methods}',
            '${classes[name]!.withCases}',
            '${classes[name]!.notRun}',
          ],
      ],
    ),
    const Heading(3, 'Every method'),
    Table(
      const ['Method', 'Class', 'Cases', 'Classified not to run'],
      [
        for (final method in methods)
          [
            '`${method.name}`',
            '`${method.cls}`',
            '${method.cases}',
            method.notRun ? 'yes' : '',
          ],
      ],
    ),
    Heading(3, 'The ${notRun.length} methods that are classified not to run'),
    const Para(
        'Each of these is a recorded decision, not a gap: the class decides what '
        'the harness may do on the machine it is protecting, and the reason says '
        'what would have to change for the row to run. The report test refuses a '
        'reason shorter than 20 characters, so "n/a" cannot pass as one.'),
    Table(
      const ['Method', 'Class', 'Why'],
      [
        for (final row in notRun) ['`${row.method}`', '`${row.cls}`', row.why],
      ],
    ),
    Heading(
        2,
        'The screens: ${screenNames.length} screens and the shell, '
            '${plural(controls, 'control')}'),
    const Para(
        'The sweep mounts each screen the way the router does, taps every control '
        'once against the fake engine, and compares what it found with '
        '`qa/ui/ledger.json`. The ledger is a ratchet in both directions.'),
    Bullets([
      for (final name in screenNames)
        '`$name` - ${plural(screens[name]!, 'control')}',
      '`shell` - ${plural(shellControls, 'control')} (rail, window buttons, '
          'command box)',
    ]),
    Heading(2, 'The languages: ${languageNames.length}'),
    Table(
      const ['Language', 'Packs', 'Bundled in pubspec.yaml'],
      [
        for (final code in languageNames)
          [
            '`$code`',
            '${languages[code]}',
            bundled.contains(code) ? 'yes' : 'no',
          ],
      ],
    ),
    const Para(
        'The direction of a language, and its name in its own script, live in '
        '`lib/core/i18n/app_i18n.dart`, which the registry test reads; this table is '
        'the packs on disk. A language directory that is not listed under '
        '`assets:` is not shipped, so the report test fails when the two sets '
        'disagree.'),
    Heading(2, 'The shipped files: ${shipped.length} binaries'),
    Para(
        'Five markers are counted, case-insensitively, over the ISO-8859-1 bytes of '
        'every binary in a package: $markerText. The baseline is an allowance that '
        'may only fall; the build account\'s profile path - computed on the machine '
        'that runs the probe, never stored in the repository - must appear zero '
        'times.'),
    Table(
      ['File', ...markers, 'Total'],
      countRows,
    ),
    Heading(3, 'Why each count is allowed to exist'),
    const Para(
        'This is the allowlist: the reason column is what separates a measured '
        'fingerprint from an accident. Raising a count needs a new reason here, '
        'which is a decision a human records.'),
    Table(const ['File', 'Marker', 'Why'], reasonRows),
    const Heading(2, 'The tests'),
    const Para(
        'Declared cases per file, counted in the source. A loop over fixtures adds '
        'cases at run time, so these are floors; the run prints the real numbers and '
        '`build/pipeline-fast.json` records how many seconds each step took.'),
    const Heading(3, 'Dart: the test/ directory'),
    Table(
      const ['Test file', 'Declared cases'],
      [
        for (final path in dartTestNames) ['`$path`', '${dartTests[path]}'],
        ['**total**', '**$dartCases** in ${dartTestNames.length} files'],
      ],
    ),
    const Heading(3, 'Engine: the modules under engine/src with tests'),
    Table(
      const ['Module', 'Declared cases'],
      [
        for (final path in engineTestNames)
          ['`$path`', '${engineTests[path]}'],
        ['**total**', '**$engineCases** in ${engineTestNames.length} modules'],
      ],
    ),
    const Heading(2, 'What runs where'),
    const Para(
        'Parsed from `scripts/pipeline.ps1`, so this table cannot drift from the '
        'script a human runs and CI runs. `fast` is the four checks; `full` adds the '
        'release builds, the smoke and the contract; `release` adds the artifact '
        'verifiers, one per slice as they land.'),
    Table(
      const ['Tier', 'Step', 'What'],
      [
        for (final tier in tiers)
          for (final step in steps.where((step) => step.tier == tier))
            ['`$tier`', '`${step.id}`', step.what],
      ],
    ),
    const Heading(2, 'What this report does not claim'),
    const Bullets([
      'It is not a run: it says what is registered and who enforces it, never that '
          'today\'s run passed.',
      'It names no machine: no user path, no account name, no pid, no hash. The '
          'report test fails if one appears.',
      'Its counts are declarations in committed files, so a test that failed still '
          'counts as declared. The gates on *results* are `engine.contract` and the '
          'two test steps, not this file.',
      'Coverage of a registry is not correctness of the product: this says every '
          'registered surface has a harness, not that the harness is right.',
    ]),
  ];

  return QaReport(
    markdown: renderMarkdown(blocks),
    html: renderHtml(blocks),
    methodCount: rows.length,
    dispatchedCount: dispatched.length,
    declaredCases: declaredCases,
    screensCount: screenNames.length,
    controlsCount: controls,
    languages: languages,
    bundledLanguages: bundled,
    shippedFiles: shipped.length,
    dartTestFiles: dartTestNames.length,
    dartCases: dartCases,
    engineTestFiles: engineTestNames.length,
    engineCases: engineCases,
    pipelineStepCount: steps.length,
    pipelineStepIds: steps.map((step) => step.id).toList(growable: false),
    pipelineTiers: tiers,
    notRun: notRun,
  );
}

int declared(String source, RegExp pattern) => pattern.allMatches(source).length;

/// `1 control`, `8 controls`: a count with the noun it counts.
String plural(int count, String noun) => '$count $noun${count == 1 ? '' : 's'}';

/// The count recorded for [marker] in one `files.<name>` entry, or 0 when the
/// marker is not listed there (which the probe would have failed on already).
int countOf(Object? row, String marker) {
  final counts = (row as Map)['counts'] as Map;
  final cell = counts[marker];
  if (cell is Map && cell['count'] is int) return cell['count'] as int;
  return 0;
}

/// The written reason for [marker] in one `files.<name>` entry.
String? reasonOf(Object? row, String marker) {
  final counts = (row as Map)['counts'] as Map;
  final cell = counts[marker];
  if (cell is Map && cell['reason'] is String) {
    return (cell['reason'] as String).trim();
  }
  return null;
}

/// The sum of the counted markers for one file, as text.
String totalOf(Object? row, List<String> markers) {
  var total = 0;
  for (final marker in markers) {
    total += countOf(row, marker);
  }
  return '$total';
}

/// The steps of `scripts/pipeline.ps1`: `Id`, `Tier` and `What` per block.
///
/// Read by hand rather than by running PowerShell, because the report must be
/// writable anywhere Dart is. `What` is looked for only up to the next `Id`, so a
/// step without one cannot steal the next step's description.
List<Step> pipelineSteps(String source) {
  final steps = <Step>[];
  final id = RegExp(r"Id\s*=\s*'([^']+)'\s*\r?\n\s*Tier\s*=\s*'([^']+)'");
  final nextId = RegExp(r"\n\s*Id\s*=");
  final what = RegExp(r"What\s*=\s*'([^']*)'");
  for (final match in id.allMatches(source)) {
    final rest = source.substring(match.end);
    final next = nextId.firstMatch(rest);
    final window = next == null ? rest : rest.substring(0, next.start);
    steps.add(Step(
      match.group(1)!,
      match.group(2)!,
      what.firstMatch(window)?.group(1) ?? '',
    ));
  }
  if (steps.isEmpty) {
    throw QaRegistryException('no pipeline steps were parsed from '
        'scripts/pipeline.ps1; the step shape changed');
  }
  return steps;
}

/// The report and the numbers the gates assert, in one object.
class QaReport {
  const QaReport({
    required this.markdown,
    required this.html,
    required this.methodCount,
    required this.dispatchedCount,
    required this.declaredCases,
    required this.screensCount,
    required this.controlsCount,
    required this.languages,
    required this.bundledLanguages,
    required this.shippedFiles,
    required this.dartTestFiles,
    required this.dartCases,
    required this.engineTestFiles,
    required this.engineCases,
    required this.pipelineStepCount,
    required this.pipelineStepIds,
    required this.pipelineTiers,
    required this.notRun,
  });

  final String markdown;
  final String html;
  final int methodCount;
  final int dispatchedCount;
  final int declaredCases;
  final int screensCount;
  final int controlsCount;
  final Map<String, int> languages;
  final Set<String> bundledLanguages;
  final int shippedFiles;
  final int dartTestFiles;
  final int dartCases;
  final int engineTestFiles;
  final int engineCases;
  final int pipelineStepCount;
  final List<String> pipelineStepIds;
  final List<String> pipelineTiers;

  /// The rows that do not run, with the reason a human recorded for each.
  final List<NotRun> notRun;
}

/// A method with a recorded decision not to exercise it here.
class NotRun {
  const NotRun(this.method, this.cls, this.why);

  final String method;
  final String cls;
  final String why;
}

/// One method row, as the report needs it.
class _MethodRow {
  const _MethodRow(this.name, this.cls, this.cases, this.notRun);

  final String name;
  final String cls;
  final int cases;
  final bool notRun;
}

class _ClassBucket {
  int methods = 0;
  int withCases = 0;
  int notRun = 0;
}

/// One `-Tier` step of the pipeline.
class Step {
  const Step(this.id, this.tier, this.what);

  final String id;
  final String tier;
  final String what;
}

/// A section of the report. One shape renders to markdown and to HTML, so the
/// two files cannot say different things.
sealed class Block {
  const Block();
}

class Heading extends Block {
  const Heading(this.level, this.text);

  final int level;
  final String text;
}

class Para extends Block {
  const Para(this.text);

  final String text;
}

class Bullets extends Block {
  const Bullets(this.items);

  final List<String> items;
}

class Table extends Block {
  const Table(this.head, this.rows);

  final List<String> head;
  final List<List<String>> rows;
}

String renderMarkdown(List<Block> blocks) {
  final out = StringBuffer();
  for (final block in blocks) {
    switch (block) {
      case Heading(:final level, :final text):
        out.writeln('${'#' * level} $text\n');
      case Para(:final text):
        out.writeln('$text\n');
      case Bullets(:final items):
        for (final item in items) {
          out.writeln('- $item');
        }
        out.writeln();
      case Table(:final head, :final rows):
        out.writeln('| ${head.map(cell).join(' | ')} |');
        out.writeln('|${head.map((_) => '---').join('|')}|');
        for (final row in rows) {
          out.writeln('| ${row.map(cell).join(' | ')} |');
        }
        out.writeln();
    }
  }
  return out.toString();
}

String renderHtml(List<Block> blocks) {
  final body = StringBuffer();
  for (final block in blocks) {
    switch (block) {
      case Heading(:final level, :final text):
        body.writeln('<h$level>${inline(text)}</h$level>');
      case Para(:final text):
        body.writeln('<p>${inline(text)}</p>');
      case Bullets(:final items):
        body.writeln('<ul>');
        for (final item in items) {
          body.writeln('  <li>${inline(item)}</li>');
        }
        body.writeln('</ul>');
      case Table(:final head, :final rows):
        final numeric = <bool>[
          for (var column = 0; column < head.length; column++)
            rows.isNotEmpty &&
                rows.every((row) =>
                    column < row.length &&
                    RegExp(r'^\*{0,2}\d+\*{0,2}$').hasMatch(row[column])),
        ];
        body.writeln('<table>');
        body.writeln('  <thead><tr>');
        for (var column = 0; column < head.length; column++) {
          body.writeln('    <th>${inline(head[column])}</th>');
        }
        body.writeln('  </tr></thead>');
        body.writeln('  <tbody>');
        for (final row in rows) {
          body.writeln('    <tr>');
          for (var column = 0; column < row.length; column++) {
            final attr = numeric[column] ? ' class="num"' : '';
            body.writeln('      <td$attr>${inline(row[column])}</td>');
          }
          body.writeln('    </tr>');
        }
        body.writeln('  </tbody>');
        body.writeln('</table>');
    }
  }

  return '''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MI CS - QA surface and gates</title>
<style>
:root { color-scheme: light dark; }
body { font-family: "Segoe UI", system-ui, sans-serif; max-width: 72rem;
       margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
h1 { font-size: 1.6rem; margin-bottom: .2rem; }
h2 { font-size: 1.25rem; margin-top: 2rem; border-bottom: 1px solid #8883;
     padding-bottom: .2rem; }
h3 { font-size: 1.05rem; margin-top: 1.5rem; }
p, li { font-size: .95rem; }
table { border-collapse: collapse; width: 100%; margin: .6rem 0 1.4rem;
        font-size: .9rem; }
th, td { text-align: left; vertical-align: top; padding: .3rem .5rem;
         border-bottom: 1px solid #8883; }
th { background: #8881; font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
code { font-family: Consolas, ui-monospace, monospace; font-size: .88em; }
</style>
</head>
<body>
$body</body>
</html>
''';
}

/// A markdown table cell: one line, and a literal `|` cannot split the row.
String cell(String text) =>
    text.replaceAll(RegExp(r'\r?\n'), ' ').replaceAll('|', r'\|');

/// A HTML cell or title: escaped, with `backticks` turned into code spans.
String inline(String text) {
  final escaped = const HtmlEscape().convert(text);
  return escaped.replaceAllMapped(
      RegExp(r'`([^`]+)`'), (match) => '<code>${match.group(1)}</code>');
}
