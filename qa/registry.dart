// The committed registries the QA surface is built from, read in one place.
//
// `qa/report.dart` says what is registered and `test/qa_registry_test.dart`
// fails when the engine grows a method the registries do not describe. The two
// have to agree on what "registered" means, so the reading lives here and both
// import it - a second parser is a second answer.
//
// Nothing here touches Flutter: `dart run qa\report.dart` has to work without
// the framework, and the report is written by a plain Dart process.

import 'dart:convert';
import 'dart:io';

/// One row per JSON-RPC method the dispatcher answers.
const methodsPath = 'qa/methods.json';

/// What each screen (and the shell) exposed the last time a human agreed.
const ledgerPath = 'qa/ui/ledger.json';

/// What each method returns when a screen needs something to show.
const fixturesPath = 'qa/ui/fixtures.json';

/// What the shipped bytes are allowed to say about the machine that built them.
const opsecPath = 'qa/opsec-baseline.json';

/// [path] as a JSON object. A missing or malformed registry is the interesting
/// failure, so it is named in the message instead of surfacing as a cast error
/// three frames later.
Map<String, dynamic> readJsonMap(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    throw QaRegistryException('the registry is missing: $path');
  }
  final Object? decoded;
  try {
    decoded = jsonDecode(file.readAsStringSync());
  } on FormatException catch (error) {
    throw QaRegistryException('$path is not JSON: ${error.message}');
  }
  if (decoded is! Map<String, dynamic>) {
    throw QaRegistryException('$path must hold a JSON object');
  }
  return decoded;
}

/// The method rows of [path], in file order.
List<Map<String, dynamic>> methodRows(String path) {
  final rows = readJsonMap(path)['methods'];
  if (rows is! List || rows.isEmpty) {
    throw QaRegistryException('$path has no "methods" list');
  }
  return rows
      .map((row) => (row as Map).cast<String, dynamic>())
      .toList(growable: false);
}

/// The method names the engine actually dispatches, read out of [dispatcherPath].
///
/// Matching on the arm indentation (twelve spaces) is what keeps handler-internal
/// `match` arms from being counted: they sit deeper. If the dispatcher is ever
/// reformatted this returns fewer names - loud, because the caller compares it
/// with a table of the same size, instead of quietly matching nothing.
Set<String> dispatchedMethods(String dispatcherPath) {
  final file = File(dispatcherPath);
  if (!file.existsSync()) {
    throw QaRegistryException('the dispatcher source is missing: $dispatcherPath');
  }
  final arm = RegExp(r'^ {12}"([a-z0-9_.]+)" =>', multiLine: true);
  return arm
      .allMatches(file.readAsStringSync())
      .map((match) => match.group(1)!)
      .toSet();
}

/// The JSON files directly under [directory], sorted by name.
List<String> jsonFileNames(String directory) {
  final dir = Directory(directory);
  if (!dir.existsSync()) {
    throw QaRegistryException('the directory is missing: $directory');
  }
  final names = dir
      .listSync()
      .whereType<File>()
      .map((file) => file.uri.pathSegments.last)
      .where((name) => name.endsWith('.json'))
      .toList()
    ..sort();
  return names;
}

/// A registry that cannot be read. One type, so a caller can say "the QA files
/// are broken" without matching six exception kinds.
class QaRegistryException implements Exception {
  QaRegistryException(this.message);

  final String message;

  @override
  String toString() => 'qa registry: $message';
}
