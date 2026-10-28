// One-off helper: splits the flat assets/i18n/<lang>.json files into
// per-module files under assets/i18n/<lang>/<module>.json.
//
//   dart run tool/split_i18n.dart
//
// Kept in the repo because it documents the module assignment rule; running it
// again is harmless (it rewrites the same files from the current flat files).

import 'dart:convert';
import 'dart:io';

/// Longest prefix wins; anything unmatched falls into `common`.
const _rules = <String, String>{
  'app.': 'app',
  'lang.': 'app',
  'nav.': 'nav',
  'state.': 'engine',
  'engine.': 'engine',
  'score.': 'dashboard',
  'dashboard.': 'dashboard',
  'audit.': 'audit',
  'settings.': 'settings',
  'common.': 'common',
  'status.': 'common',
  'soon.': 'common',
};

String moduleFor(String key) => _rules.entries
    .firstWhere((e) => key.startsWith(e.key),
        orElse: () => const MapEntry('', 'common'))
    .value;

void main() {
  for (final lang in ['ar', 'en']) {
    final source = File('assets/i18n/$lang.json');
    if (!source.existsSync()) {
      stderr.writeln('skip $lang (no flat file)');
      continue;
    }
    final flat = (jsonDecode(source.readAsStringSync()) as Map)
        .cast<String, dynamic>();
    final modules = <String, Map<String, String>>{};
    flat.forEach((key, value) {
      modules.putIfAbsent(moduleFor(key), () => {})[key] = '$value';
    });
    final dir = Directory('assets/i18n/$lang')..createSync(recursive: true);
    for (final entry in modules.entries) {
      final target = File('${dir.path}/${entry.key}.json');
      final sorted = Map.fromEntries(
          entry.value.entries.toList()..sort((a, b) => a.key.compareTo(b.key)));
      target.writeAsStringSync(
          '${const JsonEncoder.withIndent('  ').convert(sorted)}\n');
      stdout.writeln('${target.path}  ${sorted.length} keys');
    }
  }
}
