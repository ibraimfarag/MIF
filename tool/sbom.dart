// ignore_for_file: avoid_print
//
// Builds the shipped third-party inventory: `sbom.cdx.json` (CycloneDX 1.6) and
// `THIRD-PARTY-NOTICES`.
//
//   dart run tool/sbom.dart                   # regenerate both files at the repo root
//   dart run tool/sbom.dart --check           # exit 1 if the committed files are stale
//   dart run tool/sbom.dart --out <dir>       # write into another directory
//   dart run tool/sbom.dart --version 0.1.0   # the release version to record
//   dart run tool/sbom.dart --verbose         # list what is excluded, and the gaps
//
// Where the data comes from, all of it measured rather than assumed:
//
//   * `cargo metadata --locked --offline` - every crate in the engine's lockfile
//     with the SPDX expression it *declares*, its checksum and its source
//     directory, so the license text is the crate's own LICENSE file, plus the
//     resolve graph that says which crates the binary actually links;
//   * `pubspec.lock` - every Dart package with the sha256 pub recorded for it,
//     and `dart pub deps --json` for the two things the lockfile does not carry:
//     the package graph (which packages are dev-only) and the SDK versions. pub
//     does not store a license, so the id is concluded from the LICENSE file in
//     the pub cache and reproduced verbatim in the notices;
//   * the Flutter SDK's own `LICENSE` for the packages pub calls `sdk`;
//   * `assets/fonts/*.ttf` - the two OFL fonts whose copyright lines are read out
//     of the font binaries' `name` tables, and `assets/fonts/OFL-1.1.txt` for the
//     license text no font file carries;
//   * a short explicit list of things no lockfile mentions (the Flutter engine
//     DLL, the Visual C++ runtime the app needs but does not ship).
//
// The output is deterministic on purpose: no timestamp, and the BOM serial number
// is derived from the component set instead of random, so two runs over the same
// lockfiles give byte-identical files and a diff means a real dependency change.
// That is what makes the committed copies checkable in CI.

import 'dart:convert';
import 'dart:io';

/// Component ecosystems this inventory knows about.
const String ecosystemCargo = 'cargo';
const String ecosystemPub = 'pub';
const String ecosystemFlutter = 'flutter';
const String ecosystemFont = 'font';
const String ecosystemRuntime = 'runtime';

/// License ids we accept as permissive. Anything not here and not in
/// [_copyleftIds] is reported as unclassified and fails the audit, so a new
/// dependency with an unfamiliar license stops the build instead of shipping.
const Set<String> _permissiveIds = {
  '0BSD',
  'Apache-2.0',
  'BSD-1-Clause',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'BSL-1.0',
  'CC0-1.0',
  'CC-BY-4.0',
  'CDLA-Permissive-2.0',
  'ISC',
  'MIT',
  'MIT-0',
  'OFL-1.1',
  'Unicode-3.0',
  'Unlicense',
  'Zlib',
};

/// Ids that would oblige us to do something GPL-3.0-or-later does not already do.
/// They are reported, never silently accepted; a disjunction that offers a
/// permissive option (for example `MIT OR Apache-2.0 OR LGPL-2.1-or-later`) is
/// not copyleft, because we take the permissive option and it is named.
const Set<String> _copyleftIds = {
  'AGPL-3.0-only',
  'AGPL-3.0-or-later',
  'CC-BY-SA-4.0',
  'CDDL-1.0',
  'EPL-2.0',
  'GPL-2.0-only',
  'GPL-2.0-or-later',
  'GPL-3.0-only',
  'GPL-3.0-or-later',
  'LGPL-2.1-only',
  'LGPL-2.1-or-later',
  'LGPL-3.0-only',
  'LGPL-3.0-or-later',
  'MPL-2.0',
  'SSPL-1.0',
};

/// Which permissive option to take when a component offers a choice. Preference,
/// not preference-by-order: `MIT OR Apache-2.0` and `Apache-2.0 OR MIT` both
/// conclude MIT, so the notices do not depend on how a crate happened to spell
/// its expression.
const List<String> _preferredIds = [
  'MIT',
  'Apache-2.0',
  'BSD-3-Clause',
  'BSD-2-Clause',
  'ISC',
  '0BSD',
  'BSD-1-Clause',
  'Zlib',
  'Unlicense',
  'Unicode-3.0',
  'BSL-1.0',
  'CDLA-Permissive-2.0',
  'OFL-1.1',
  'CC0-1.0',
  'MIT-0',
];

/// The audit's answer for one license expression.
enum LicenseVerdict { permissive, copyleft, unknown }

/// One third-party component as it will be written to the SBOM.
class Component {
  Component({
    required this.name,
    required this.version,
    required this.ecosystem,
    this.declaredLicense,
    this.sha256,
    this.type = 'library',
    this.scope = 'required',
    this.note,
    this.copyrightNotice,
  }) {
    // A component that states its own license is assessed right away; for the
    // Dart packages, which state none, the id is concluded from the license text
    // later.
    if (declaredLicense != null) assessment = assess(declaredLicense!);
  }

  final String name;
  final String version;
  final String ecosystem;

  /// The SPDX expression as the component itself states it. For Dart packages pub
  /// never records one, so it stays null and the id is concluded from the text.
  final String? declaredLicense;

  /// The lockfile's own hash, when it has one.
  final String? sha256;

  final String type;
  final String scope;
  final String? note;

  /// A copyright line no license file carries: the shipped fonts state theirs in
  /// the TrueType `name` table, read from the .ttf itself.
  final String? copyrightNotice;

  /// Filled in by the license pass.
  LicenseAssessment? assessment;
  String? licenseText;
  String? copyright;

  String get purl {
    final encoded = Uri.encodeComponent(name);
    final v = Uri.encodeComponent(version);
    switch (ecosystem) {
      case ecosystemCargo:
        return 'pkg:cargo/$encoded@$v';
      case ecosystemPub:
        return 'pkg:pub/$encoded@$v';
      default:
        return 'pkg:generic/$encoded@$v';
    }
  }

  String get coordinates => '$name@$version';
}

/// The parsed expression plus what we concluded from it.
class LicenseAssessment {
  LicenseAssessment(this.expression, this.options, this.concluded, this.verdict);

  final String expression;
  final List<String> options;
  final String? concluded;
  final LicenseVerdict verdict;
}

/// Everything the notices' audit section reports.
///
/// The audit covers only what ships. A crate or package that exists in the
/// lockfile but is reachable only through a dev or build edge never lands in the
/// artifact a user receives, so its license is not a distribution obligation of
/// this product - it stays in the inventory (scope `excluded`) because a scanner
/// should still be able to see it.
class LicenseAudit {
  LicenseAudit(this.components);

  final List<Component> components;

  Iterable<Component> get shipped =>
      components.where((c) => c.scope == 'required');

  Iterable<Component> get excluded =>
      components.where((c) => c.scope != 'required');

  Iterable<Component> get copyleft => shipped.where(
    (c) => c.assessment?.verdict == LicenseVerdict.copyleft,
  );
  Iterable<Component> get unknown => shipped.where(
    (c) => c.assessment == null || c.assessment!.verdict == LicenseVerdict.unknown,
  );
  Iterable<Component> get permissive => shipped.where(
    (c) => c.assessment?.verdict == LicenseVerdict.permissive,
  );

  /// Ids we rely on, biggest first, over the whole inventory.
  Map<String, int> get byConcludedId {
    final out = <String, int>{};
    for (final c in components) {
      final id = c.assessment?.concluded;
      if (id != null) out[id] = (out[id] ?? 0) + 1;
    }
    final keys = out.keys.toList()..sort();
    return {for (final k in keys) k: out[k]!};
  }

  /// Shipped components whose own source tree carries no license text we could
  /// use. Informational: the notices quote the text of the id from the first
  /// component that did supply one, and MIT/Apache-2.0/BSD-3-Clause texts are
  /// identical across components apart from the copyright line. Most of these are
  /// crates the Windows build never compiles (macOS- and wasm-only dependencies),
  /// so their sources were never extracted into the cargo registry cache.
  List<Component> get componentsMissingText =>
      shipped
          .where((c) => c.assessment?.concluded != null && c.licenseText == null)
          .toList()
        ..sort((a, b) => a.coordinates.compareTo(b.coordinates));

  /// Ids the shipped artifact relies on with no text anywhere to quote - a
  /// release blocker, because the notices are supposed to carry the text of every
  /// license we rely on.
  List<String> get missingTexts {
    final needed = <String>{
      for (final c in shipped)
        if (c.assessment?.concluded != null) c.assessment!.concluded!,
    };
    final have = <String>{
      for (final c in shipped)
        if (c.licenseText != null) c.assessment!.concluded!,
    };
    final out = needed.difference(have).toList()..sort();
    return out;
  }

  bool get isClean =>
      copyleft.isEmpty && unknown.isEmpty && missingTexts.isEmpty;
}

// ---------------------------------------------------------------------------
// SPDX expressions
// ---------------------------------------------------------------------------

/// Evaluates an SPDX expression: `OR` offers a choice, `AND` requires all of its
/// operands, `WITH` narrows the id on its left, and parentheses group.
LicenseVerdict evaluateExpression(String expression) =>
    _evaluate(_parseExpression(expression));

/// Every id mentioned anywhere in the expression, in the order they appear.
List<String> expressionIds(String expression) {
  final out = <String>[];
  void walk(_Expr e) {
    switch (e) {
      case _IdExpr(:final id):
        if (!out.contains(id)) out.add(id);
      case _WithExpr(:final base, :final exception):
        walk(base);
        if (!out.contains(exception)) out.add(exception);
      case _BinaryExpr(:final left, :final right):
        walk(left);
        walk(right);
    }
  }

  walk(_parseExpression(expression));
  return out;
}

/// The permissive option we rely on, or null when the expression offers none.
String? concludedId(String expression) {
  if (evaluateExpression(expression) != LicenseVerdict.permissive) return null;
  final ids = expressionIds(expression);
  for (final preferred in _preferredIds) {
    if (ids.contains(preferred)) return preferred;
  }
  for (final id in ids) {
    if (_permissiveIds.contains(id)) return id;
  }
  return null;
}

LicenseAssessment assess(String expression) => LicenseAssessment(
  expression,
  expressionIds(expression),
  concludedId(expression),
  evaluateExpression(expression),
);

LicenseVerdict _evaluate(_Expr e) => switch (e) {
  _IdExpr(:final id) => _idVerdict(id),
  // `Apache-2.0 WITH LLVM-exception` stays permissive; a copyleft id with an
  // exception stays copyleft, because the exception narrows duties we cannot
  // audit from here and being conservative is the safe direction.
  _WithExpr(:final base) => _evaluate(base),
  _BinaryExpr(:final op, :final left, :final right) => switch (op) {
    'OR' => _or(_evaluate(left), _evaluate(right)),
    _ => _and(_evaluate(left), _evaluate(right)),
  },
};

LicenseVerdict _idVerdict(String id) {
  if (_permissiveIds.contains(id)) return LicenseVerdict.permissive;
  if (_copyleftIds.contains(id)) return LicenseVerdict.copyleft;
  return LicenseVerdict.unknown;
}

/// A disjunction is usable when either side is: that is the whole point of the
/// `OR`, and the notices name the option we took.
LicenseVerdict _or(LicenseVerdict a, LicenseVerdict b) {
  if (a == LicenseVerdict.permissive || b == LicenseVerdict.permissive) {
    return LicenseVerdict.permissive;
  }
  if (a == LicenseVerdict.copyleft || b == LicenseVerdict.copyleft) {
    return LicenseVerdict.copyleft;
  }
  return LicenseVerdict.unknown;
}

/// A conjunction is usable only when both sides are; an unknown side makes the
/// whole thing unknown, which the audit reports rather than assumes away.
LicenseVerdict _and(LicenseVerdict a, LicenseVerdict b) {
  if (a == LicenseVerdict.copyleft || b == LicenseVerdict.copyleft) {
    return LicenseVerdict.copyleft;
  }
  if (a == LicenseVerdict.unknown || b == LicenseVerdict.unknown) {
    return LicenseVerdict.unknown;
  }
  return LicenseVerdict.permissive;
}

sealed class _Expr {}

class _IdExpr extends _Expr {
  _IdExpr(this.id);
  final String id;
}

class _WithExpr extends _Expr {
  _WithExpr(this.base, this.exception);
  final _Expr base;
  final String exception;
}

class _BinaryExpr extends _Expr {
  _BinaryExpr(this.op, this.left, this.right);
  final String op;
  final _Expr left;
  final _Expr right;
}

/// Old crates spelled a choice `MIT/Apache-2.0`; SPDX spells it `MIT OR
/// Apache-2.0`. Normalise the slash rather than special-case it everywhere.
String normalizeExpression(String raw) {
  var expr = raw.trim();
  if (expr.contains('/') && !expr.contains('://')) {
    expr = expr.replaceAll('/', ' OR ');
  }
  return expr.replaceAll(RegExp(r'\s+'), ' ').trim();
}

/// Recursive-descent parser for the SPDX expression grammar this repo meets:
/// `OR` binds loosest, then `AND`, then `WITH`, with parentheses for grouping.
/// A class rather than nested functions because the levels call each other.
class _ExpressionParser {
  _ExpressionParser(this.raw)
    : tokens = normalizeExpression(raw)
          .replaceAll('(', ' ( ')
          .replaceAll(')', ' ) ')
          .split(RegExp(r'\s+'))
          .where((t) => t.isNotEmpty)
          .toList() {
    if (tokens.isEmpty) {
      throw FormatException('empty license expression: "$raw"');
    }
  }

  final String raw;
  final List<String> tokens;
  int index = 0;

  _Expr parse() {
    final expr = _parseOr();
    if (index != tokens.length) {
      throw FormatException('trailing "${tokens[index]}" in "$raw"');
    }
    return expr;
  }

  _Expr _parseOr() {
    var left = _parseAnd();
    while (index < tokens.length && tokens[index] == 'OR') {
      index++;
      left = _BinaryExpr('OR', left, _parseAnd());
    }
    return left;
  }

  _Expr _parseAnd() {
    var left = _parseWith();
    while (index < tokens.length && tokens[index] == 'AND') {
      index++;
      left = _BinaryExpr('AND', left, _parseWith());
    }
    return left;
  }

  _Expr _parseWith() {
    final base = _parsePrimary();
    if (index < tokens.length && tokens[index] == 'WITH') {
      index++;
      if (index >= tokens.length) {
        throw FormatException('WITH without an exception in "$raw"');
      }
      return _WithExpr(base, tokens[index++]);
    }
    return base;
  }

  _Expr _parsePrimary() {
    if (index >= tokens.length) {
      throw FormatException('license expression ends too early: "$raw"');
    }
    final token = tokens[index++];
    if (token == '(') {
      final inner = _parseOr();
      if (index >= tokens.length || tokens[index] != ')') {
        throw FormatException('unbalanced parentheses in "$raw"');
      }
      index++;
      return inner;
    }
    if (token == ')' || token == 'AND' || token == 'OR' || token == 'WITH') {
      throw FormatException('unexpected "$token" in "$raw"');
    }
    return _IdExpr(token);
  }
}

_Expr _parseExpression(String raw) => _ExpressionParser(raw).parse();

// ---------------------------------------------------------------------------
// License text recognition
// ---------------------------------------------------------------------------

/// The SPDX id a license file's own text states, or null when the text is not
/// one this tool recognises. Every id this returns has to be in [_permissiveIds]
/// or [_copyleftIds], otherwise the audit reports it as unclassified - the
/// point is to stop on the unfamiliar, not to guess.
String? detectLicenseId(String text) {
  final head = text.replaceAll('\r\n', '\n');
  bool has(String needle) => head.contains(needle);

  // Most specific first: several of these share phrases.
  if (has('SIL OPEN FONT LICENSE')) return 'OFL-1.1';
  // Both spellings occur: the full text, and the short notice a crate writes as
  // its LICENSE-APACHE ("Licensed under the Apache License, Version 2.0 (the
  // "License"); you may not use this file except in compliance with the License").
  if (RegExp(r'Apache License,?\s*\n?\s*Version 2\.0').hasMatch(head)) {
    return 'Apache-2.0';
  }
  if (has('Mozilla Public License Version 2.0')) return 'MPL-2.0';
  if (has('GNU LESSER GENERAL PUBLIC LICENSE')) {
    return has('Version 3') ? 'LGPL-3.0-only' : 'LGPL-2.1-only';
  }
  if (has('GNU AFFERO GENERAL PUBLIC LICENSE')) return 'AGPL-3.0-only';
  if (has('GNU GENERAL PUBLIC LICENSE')) {
    return has('Version 3') ? 'GPL-3.0-only' : 'GPL-2.0-only';
  }
  if (has('UNICODE LICENSE V3') ||
      has('UNICODE, INC. LICENSE AGREEMENT - DATA FILES AND SOFTWARE')) {
    return 'Unicode-3.0';
  }
  if (has('Community Data License Agreement')) return 'CDLA-Permissive-2.0';
  if (has('Boost Software License - Version 1.0')) return 'BSL-1.0';
  if (has('This is free and unencumbered software released into the public')) {
    return 'Unlicense';
  }
  if (has('MIT No Attribution')) return 'MIT-0';
  if (has('Permission is hereby granted, free of charge')) return 'MIT';
  if (has('Redistribution and use in source and binary forms')) {
    if (has('Neither the name of')) return 'BSD-3-Clause';
    if (has('All advertising materials mentioning features')) return 'BSD-4-Clause';
    return 'BSD-2-Clause';
  }
  // ISC and 0BSD open with the same sentence; the disclaimer's wording is what
  // separates them ("THE AUTHOR DISCLAIMS" is 0BSD's, ISC names the copyright
  // holder's obligation instead).
  if (has('Permission to use, copy, modify, and/or distribute this software')) {
    if (has('THE AUTHOR DISCLAIMS ALL WARRANTIES')) return '0BSD';
    return 'ISC';
  }
  // The zlib text: "This software is provided 'as-is', without any express or
  // implied warranty" - zlib-rs ships exactly this, and nothing else in the
  // registry does.
  if (has("This software is provided 'as-is'")) return 'Zlib';
  if (has('altered source versions must be plainly marked as such')) return 'Zlib';
  if (has('zlib License')) return 'Zlib';
  return null;
}

/// The copyright line a license file carries, when it carries one at all. MIT and
/// BSD files put it first; the Apache text does not have one.
String? copyrightLineOf(String text) {
  final lines = text.replaceAll('\r\n', '\n').split('\n');
  final marker = RegExp(r'^(copyright|\(c\)|©)', caseSensitive: false);
  for (var i = 0; i < lines.length && i < 15; i++) {
    final line = lines[i].trim();
    if (line.isEmpty) continue;
    if (!marker.hasMatch(line)) continue;
    final parts = <String>[line];
    for (var j = i + 1; j < lines.length && j < i + 4; j++) {
      final next = lines[j].trim();
      if (!marker.hasMatch(next)) break;
      parts.add(next);
    }
    return parts.join(' ').replaceAll(RegExp(r'\s+'), ' ').trim();
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lockfiles and metadata
// ---------------------------------------------------------------------------

/// Every package `pubspec.lock` pins, in the file's own order.
///
/// The lockfile is YAML, but it is generated by pub and this parser only accepts
/// the shape pub writes: a `packages:` block of two-space-indented names, then
/// four- and six-space-indented fields. Anything else throws instead of being
/// skipped, so a format change cannot quietly shrink the inventory.
List<Component> parsePubLock(
  String lockText, {
  String? sdkVersion,
  Set<String>? shippedNames,
}) {
  final lines = lockText.replaceAll('\r\n', '\n').split('\n');
  var inPackages = false;
  String? name;
  var fields = <String, String>{};
  var description = <String, String>{};
  var nested = false;
  final out = <Component>[];

  void flush() {
    if (name == null) return;
    final source = fields['source'] ?? 'hosted';
    final version = fields['version'] ?? '';
    // Without a closure to consult - `dart pub deps` refused, or a caller that
    // only wants the lockfile parsed - assume everything ships. Guessing
    // "excluded" would silently shrink what the audit covers.
    final scope = shippedNames == null || shippedNames.contains(name)
        ? 'required'
        : 'excluded';
    if (source == 'sdk') {
      // pub records 0.0.0 for SDK packages; the Flutter version is the useful one.
      out.add(
        Component(
          name: name!,
          version: sdkVersion ?? version,
          ecosystem: ecosystemFlutter,
          declaredLicense: 'BSD-3-Clause',
          scope: scope,
          note: 'shipped by the Flutter SDK',
        ),
      );
    } else {
      out.add(
        Component(
          name: description['name'] ?? name!,
          version: version,
          ecosystem: ecosystemPub,
          sha256: description['sha256'],
          scope: scope,
          note: scope == 'excluded'
              ? 'in the lockfile, reachable only from a dev dependency'
              : null,
        ),
      );
    }
    name = null;
    fields = <String, String>{};
    description = <String, String>{};
    nested = false;
  }

  for (final raw in lines) {
    final line = raw.trimRight();
    if (line.isEmpty || line.startsWith('#')) continue;
    if (!line.startsWith(' ')) {
      // A top-level key: `packages:` opens the block, `sdks:` closes it.
      flush();
      inPackages = line.startsWith('packages:');
      continue;
    }
    if (!inPackages) continue;
    final indent = line.length - line.trimLeft().length;
    final body = line.trim();
    if (indent == 2) {
      if (!body.endsWith(':')) {
        throw FormatException('unexpected package line: "$raw"');
      }
      flush();
      name = body.substring(0, body.length - 1);
      continue;
    }
    if (name == null) continue;
    if (indent == 4) {
      final colon = body.indexOf(':');
      if (colon < 0) throw FormatException('unexpected field line: "$raw"');
      final key = body.substring(0, colon);
      final value = body.substring(colon + 1).trim();
      if (key == 'description' && value.isEmpty) {
        nested = true;
        continue;
      }
      nested = false;
      fields[key] = _unquote(value);
      continue;
    }
    if (indent == 6 && nested) {
      final colon = body.indexOf(':');
      if (colon < 0) throw FormatException('unexpected description line: "$raw"');
      description[body.substring(0, colon)] = _unquote(
        body.substring(colon + 1).trim(),
      );
      continue;
    }
    throw FormatException('unexpected indentation in pubspec.lock: "$raw"');
  }
  flush();
  return out;
}

String _unquote(String value) {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.substring(1, value.length - 1);
  }
  return value;
}

/// Every crate `cargo metadata` reports, minus our own workspace members (they
/// are the product, not a third-party component).
///
/// [shippedCoordinates] decides the `scope`: what is reachable from a workspace
/// member through normal dependencies is in the binary; a crate that only a dev
/// or build edge pulls in is not, and is listed with scope `excluded`.
List<Component> parseCargoMetadata(
  String metadataJson, {
  Set<String> shippedCoordinates = const {},
}) {
  final root = jsonDecode(metadataJson) as Map<String, dynamic>;
  final members = (root['workspace_members'] as List).cast<String>().toSet();
  final out = <Component>[];
  for (final raw in root['packages'] as List) {
    final pkg = raw as Map<String, dynamic>;
    if (members.contains(pkg['id'])) continue;
    if (pkg['source'] == null) continue; // a path dependency: not third-party
    final coordinate = '${pkg['name']}@${pkg['version']}';
    final scope = shippedCoordinates.contains(coordinate)
        ? 'required'
        : 'excluded';
    out.add(
      Component(
        name: pkg['name'] as String,
        version: pkg['version'] as String,
        ecosystem: ecosystemCargo,
        declaredLicense: pkg['license'] as String?,
        sha256: pkg['checksum'] as String?,
        scope: scope,
        note: scope == 'excluded'
            ? 'in the lockfile, reachable only from a dev or build dependency'
            : null,
      ),
    );
  }
  return out;
}

/// The crates that end up in the shipped engine: everything reachable from a
/// workspace member through **normal** dependencies, as `name@version`. Dev
/// dependencies are test-only and build dependencies are compile-time only, so
/// neither is walked.
Set<String> cargoShippedCoordinates(String metadataJson) {
  final root = jsonDecode(metadataJson) as Map<String, dynamic>;
  final resolve = root['resolve'] as Map<String, dynamic>?;
  if (resolve == null) return const {};
  final nodes = <String, Map<String, dynamic>>{
    for (final raw in resolve['nodes'] as List)
      (raw as Map<String, dynamic>)['id'] as String: raw,
  };
  final byId = <String, Map<String, dynamic>>{
    for (final raw in root['packages'] as List)
      (raw as Map<String, dynamic>)['id'] as String: raw,
  };
  final seen = <String>{};
  final queue = [...(root['workspace_members'] as List).cast<String>()];
  while (queue.isNotEmpty) {
    final id = queue.removeLast();
    if (!seen.add(id)) continue;
    final node = nodes[id];
    if (node == null) continue;
    for (final raw in node['deps'] as List) {
      final dep = raw as Map<String, dynamic>;
      // `kind` is null for a normal dependency, "dev"/"build" otherwise.
      final kinds = {
        for (final k in dep['dep_kinds'] as List) (k as Map<String, dynamic>)['kind'],
      };
      if (!kinds.contains(null)) continue;
      queue.add(dep['pkg'] as String);
    }
  }
  final out = <String>{};
  for (final id in seen) {
    final pkg = byId[id];
    if (pkg == null || pkg['source'] == null) continue;
    out.add('${pkg['name']}@${pkg['version']}');
  }
  return out;
}

/// The SDK versions `dart pub deps --json` reports, keyed by lower-case SDK name
/// (`dart`, `flutter`).
Map<String, String> pubSdkVersions(String depsJson) {
  final root = jsonDecode(depsJson) as Map<String, dynamic>;
  final out = <String, String>{};
  for (final raw in root['sdks'] as List? ?? const []) {
    final sdk = raw as Map<String, dynamic>;
    final version = sdk['version'] as String?;
    if (version != null) {
      out[(sdk['name'] as String).toLowerCase()] = version;
    }
  }
  return out;
}

/// The Dart packages that end up in the shipped app, from `dart pub deps --json`:
/// everything reachable from the root's non-dev dependencies. The lockfile has no
/// graph, so pub has to answer this one.
Set<String> pubShippedNames(String depsJson) {
  final root = jsonDecode(depsJson) as Map<String, dynamic>;
  final packages = <String, Map<String, dynamic>>{
    for (final raw in root['packages'] as List)
      (raw as Map<String, dynamic>)['name'] as String: raw,
  };
  final rootPackage = packages[root['root']];
  final shipped = <String>{};
  final queue = <String>[
    ...(rootPackage?['directDependencies'] as List? ?? const [])
        .cast<String>(),
  ];
  while (queue.isNotEmpty) {
    final name = queue.removeLast();
    if (!shipped.add(name)) continue;
    final pkg = packages[name];
    if (pkg == null) continue;
    queue.addAll((pkg['dependencies'] as List? ?? const []).cast<String>());
  }
  return shipped;
}

/// The registry packages `Cargo.lock` pins, as `name@version`. License metadata
/// is not in that file, so this is only used to check that the committed SBOM
/// still describes the lockfile in front of us.
List<String> cargoLockCoordinates(String lockText) {
  final out = <String>[];
  String? name;
  String? version;
  var registry = false;
  void flush() {
    if (name != null && version != null && registry) {
      out.add('$name@$version');
    }
    name = null;
    version = null;
    registry = false;
  }

  for (final raw in lockText.replaceAll('\r\n', '\n').split('\n')) {
    final line = raw.trim();
    if (line == '[[package]]') {
      flush();
      continue;
    }
    if (line.startsWith('name = ')) {
      name = _unquote(line.substring('name = '.length).trim());
    } else if (line.startsWith('version = ')) {
      version = _unquote(line.substring('version = '.length).trim());
    } else if (line.startsWith('source = ')) {
      registry = line.contains('registry+');
    }
  }
  flush();
  return out;
}

// ---------------------------------------------------------------------------
// Filesystem facts
// ---------------------------------------------------------------------------

String joinPath(List<String> parts) => parts.join(Platform.pathSeparator);

String? readTextOrNull(String path) {
  final file = File(path);
  if (!file.existsSync()) return null;
  final String text;
  try {
    text = file.readAsStringSync();
  } on FormatException {
    // A license file that is not UTF-8 is still a license file.
    return latin1.decode(file.readAsBytesSync(), allowInvalid: true);
  }
  // Line endings are the platform's business, not the inventory's: this repo is
  // checked out with `core.autocrlf=true`, and a license text that arrived with
  // CRLF would otherwise land inside the generated notices and make them differ
  // from the committed copy on the next Unicode-aware machine.
  return text.replaceAll('\r\n', '\n');
}

String homeDirectory() =>
    Platform.environment['USERPROFILE'] ??
    Platform.environment['HOME'] ??
    Directory.current.path;

String defaultPubCache() {
  final explicit = Platform.environment['PUB_CACHE'];
  if (explicit != null && explicit.isNotEmpty) return explicit;
  final local = Platform.environment['LOCALAPPDATA'];
  if (Platform.isWindows && local != null && local.isNotEmpty) {
    return joinPath([local, 'Pub', 'Cache']);
  }
  return joinPath([homeDirectory(), '.pub-cache']);
}

/// The directories cargo extracts registry sources into: one per registry index.
List<String> cargoRegistrySourceRoots() {
  final home =
      Platform.environment['CARGO_HOME'] ?? joinPath([homeDirectory(), '.cargo']);
  final src = Directory(joinPath([home, 'registry', 'src']));
  if (!src.existsSync()) return const [];
  final roots = src
      .listSync()
      .whereType<Directory>()
      .map((d) => d.path)
      .toList();
  roots.sort();
  return roots;
}

/// The Flutter SDK root: `FLUTTER_ROOT` when this runs under the `flutter` tool,
/// otherwise the `flutter` package's location in `.dart_tool/package_config.json`
/// (which is how the project itself records where its SDK is), otherwise by
/// walking up from the Dart executable - which sits inside the SDK when Dart came
/// with Flutter, as it does in this repo.
String? flutterRoot({String? repoRoot}) {
  final fromEnv = Platform.environment['FLUTTER_ROOT'];
  if (fromEnv != null && fromEnv.isNotEmpty && _isFlutterRoot(fromEnv)) {
    return fromEnv;
  }
  if (repoRoot != null) {
    final fromPackages = _flutterRootFromPackageConfig(repoRoot);
    if (fromPackages != null) return fromPackages;
  }
  var dir = File(Platform.resolvedExecutable).parent;
  for (var i = 0; i < 8; i++) {
    if (_isFlutterRoot(dir.path)) return dir.path;
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
  return null;
}

bool _isFlutterRoot(String path) =>
    File(joinPath([path, 'LICENSE'])).existsSync() &&
    Directory(joinPath([path, 'bin'])).existsSync();

String? _flutterRootFromPackageConfig(String repoRoot) {
  final text = readTextOrNull(
    joinPath([repoRoot, '.dart_tool', 'package_config.json']),
  );
  if (text == null) return null;
  final Map<String, dynamic> json;
  try {
    json = jsonDecode(text) as Map<String, dynamic>;
  } on FormatException {
    return null;
  }
  final base = Uri.directory(joinPath([repoRoot, '.dart_tool']));
  for (final raw in json['packages'] as List? ?? const []) {
    final pkg = raw as Map<String, dynamic>;
    if (pkg['name'] != 'flutter') continue;
    final rawUri = pkg['rootUri'] as String;
    final uri = Uri.parse(rawUri.endsWith('/') ? rawUri : '$rawUri/');
    final directory = Directory.fromUri(uri.hasScheme ? uri : base.resolveUri(uri));
    // `<sdk>/packages/flutter`, so the SDK root is two levels up.
    final root = directory.parent.parent;
    return _isFlutterRoot(root.path) ? root.path : null;
  }
  return null;
}

/// The license-ish files a source directory carries, in a stable order.
List<String> licenseFilesIn(String directory) {
  final dir = Directory(directory);
  if (!dir.existsSync()) return const [];
  final out = <String>[];
  for (final entry in dir.listSync()) {
    if (entry is! File) continue;
    final base = entry.uri.pathSegments.last.toUpperCase();
    if (base.startsWith('LICENSE') ||
        base.startsWith('LICENCE') ||
        base.startsWith('COPYING') ||
        base.startsWith('NOTICE')) {
      out.add(entry.path);
    }
  }
  out.sort();
  return out;
}

// ---------------------------------------------------------------------------
// The inventory
// ---------------------------------------------------------------------------

/// The components no lockfile mentions. Each one is here because something ships
/// (or is required) that the two package managers do not know about.
List<Component> manualComponents({required String? flutterVersion}) {
  final out = <Component>[
    Component(
      name: 'Cairo',
      version: '3.130',
      ecosystem: ecosystemFont,
      declaredLicense: 'OFL-1.1',
      type: 'file',
      // The name table of assets/fonts/Cairo.ttf, not a guess.
      copyrightNotice:
          'Copyright 2009 The Cairo Project Authors '
          '(https://github.com/Gue3bara/Cairo)',
      note: 'assets/fonts/Cairo.ttf, read from the font\'s own name table',
    ),
    Component(
      name: 'JetBrains Mono',
      version: '2.211',
      ecosystem: ecosystemFont,
      declaredLicense: 'OFL-1.1',
      type: 'file',
      copyrightNotice:
          'Copyright 2020 The JetBrains Mono Project Authors '
          '(https://github.com/JetBrains/JetBrainsMono)',
      note:
          'assets/fonts/JetBrainsMono.ttf, read from the font\'s own name table',
    ),
    Component(
      name: 'Flutter engine',
      version: flutterVersion ?? 'unknown',
      ecosystem: ecosystemFlutter,
      declaredLicense: 'BSD-3-Clause',
      type: 'library',
      note: 'flutter_windows.dll, the engine the app links against',
    ),
    Component(
      name: 'Microsoft Visual C++ runtime',
      version: '14.x',
      ecosystem: ecosystemRuntime,
      declaredLicense: null,
      type: 'platform',
      scope: 'excluded',
      note:
          'not shipped: the app needs the VC++ redistributable to run, Windows '
          'supplies it, and it is not open source',
    ),
  ];
  return out
    ..sort((a, b) => a.coordinates.compareTo(b.coordinates));
}

/// The Flutter version the shipped engine belongs to. Modern SDKs have no
/// `version` file at the root; the framework version lives in the version cache.
String? flutterVersionOf(String? root) {
  if (root == null) return null;
  final plain = readTextOrNull(joinPath([root, 'version']))?.trim();
  if (plain != null && plain.isNotEmpty) return plain;
  final cached = readTextOrNull(
    joinPath([root, 'bin', 'cache', 'flutter.version.json']),
  );
  if (cached == null) return null;
  try {
    final json = jsonDecode(cached) as Map<String, dynamic>;
    final version = json['frameworkVersion'] as String?;
    return (version == null || version.isEmpty) ? null : version;
  } on FormatException {
    return null;
  }
}

/// Walks every component, works out the license we rely on and attaches the text
/// that license needs, taking each text from the component's own files.
void attachLicenses(
  List<Component> components, {
  required List<String> cargoRegistryRoots,
  required String pubCache,
  required String? flutterRootPath,
  required String oflTextPath,
  required List<String> warnings,
}) {
  for (final c in components) {
    String? declared = c.declaredLicense;
    if (declared == null && c.ecosystem == ecosystemRuntime) {
      // The VC++ runtime is not open source; an SPDX id would be a lie.
      c.assessment = LicenseAssessment('proprietary', const [], null,
          LicenseVerdict.unknown);
      continue;
    }
    String? bestFile;
    String? bestText;
    final unrecognised = <String>[];
    for (final file in _candidateLicenseFiles(
      c,
      cargoRegistryRoots: cargoRegistryRoots,
      pubCache: pubCache,
      flutterRootPath: flutterRootPath,
      oflTextPath: oflTextPath,
    )) {
      final text = readTextOrNull(file);
      if (text == null) continue;
      final detected = detectLicenseId(text);
      if (detected == null) {
        // Some upstreams ship a pointer file ("dual-licensed under the Unlicense
        // and MIT; see LICENSE-MIT"), so an unrecognised file is only worth
        // reporting when the component ends up with no text at all.
        unrecognised.add(file);
        continue;
      }
      declared ??= detected;
      if (bestFile == null) {
        bestFile = file;
        bestText = text;
      }
      final concluded = concludedId(declared);
      if (concluded != null && detected == concluded) {
        bestFile = file;
        bestText = text;
        break;
      }
    }
    if (declared == null) {
      warnings.add(
        '${c.coordinates}: no license file found'
        '${unrecognised.isEmpty ? '' : ' (unrecognised: ${unrecognised.join(', ')})'}',
      );
      continue;
    }
    final assessment = assess(declared);
    c.assessment = assessment;
    c.copyright = c.copyrightNotice ??
        (bestText == null ? null : copyrightLineOf(bestText));
    if (assessment.concluded != null && bestText != null) {
      c.licenseText = bestText;
    }
  }
}

List<String> _candidateLicenseFiles(
  Component c, {
  required List<String> cargoRegistryRoots,
  required String pubCache,
  required String? flutterRootPath,
  required String oflTextPath,
}) {
  switch (c.ecosystem) {
    case ecosystemCargo:
      for (final root in cargoRegistryRoots) {
        final dir = joinPath([root, '${c.name}-${c.version}']);
        final files = licenseFilesIn(dir);
        if (files.isNotEmpty) return files;
      }
      return const [];
    case ecosystemPub:
      final dir = joinPath([pubCache, 'hosted', 'pub.dev', '${c.name}-${c.version}']);
      return licenseFilesIn(dir);
    case ecosystemFlutter:
      if (c.name == 'Flutter engine' && flutterRootPath != null) {
        return [joinPath([flutterRootPath, 'LICENSE'])];
      }
      // The packages pub calls `sdk` are Flutter's own source: one BSD-3 text.
      return flutterRootPath == null
          ? const []
          : [joinPath([flutterRootPath, 'LICENSE'])];
    case ecosystemFont:
      return [oflTextPath];
    default:
      return const [];
  }
}

/// The full inventory: Rust crates, Dart packages, SDK packages, fonts and the
/// runtime prerequisites, license texts attached.
class Inventory {
  Inventory(this.components, this.warnings);

  final List<Component> components;
  final List<String> warnings;

  LicenseAudit get audit => LicenseAudit(components);

  int countOf(String ecosystem) =>
      components.where((c) => c.ecosystem == ecosystem).length;

  /// One text per license id we concluded, taken from the first component that
  /// supplied one. The citation names that component, so a reader can tell whose
  /// copy of the text this is.
  Map<String, LicenseText> get textsByLicense {
    final out = <String, LicenseText>{};
    for (final c in components) {
      final id = c.assessment?.concluded;
      final text = c.licenseText;
      if (id == null || text == null) continue;
      out.putIfAbsent(
        id,
        () => LicenseText(
          id: id,
          text: text,
          source: '${c.ecosystem}:${c.coordinates}',
          copyright: c.copyright,
        ),
      );
    }
    return {for (final k in (out.keys.toList()..sort())) k: out[k]!};
  }
}

class LicenseText {
  LicenseText({
    required this.id,
    required this.text,
    required this.source,
    this.copyright,
  });

  final String id;
  final String text;
  final String source;
  final String? copyright;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The CycloneDX 1.6 document, as sorted, timestamp-free JSON.
String renderCycloneDx({
  required String appName,
  required String appVersion,
  required String appLicense,
  required Inventory inventory,
}) {
  final components = [...inventory.components]
    ..sort((a, b) {
      final byEcosystem = a.ecosystem.compareTo(b.ecosystem);
      return byEcosystem != 0 ? byEcosystem : a.coordinates.compareTo(b.coordinates);
    });

  List<Map<String, dynamic>> licensesOf(Component c) {
    final assessment = c.assessment;
    if (assessment == null) return const [];
    if (c.ecosystem == ecosystemRuntime) {
      return [
        {
          'license': {
            'name': 'Proprietary (Microsoft Visual C++ redistributable)',
          },
        },
      ];
    }
    final ids = c.ecosystem == ecosystemCargo
        ? assessment.options
        : [assessment.concluded ?? assessment.options.first];
    return [
      for (final id in ids)
        {
          'license': {
            'id': id,
            'acknowledgement': c.ecosystem == ecosystemCargo
                ? 'declared'
                : 'concluded',
          },
        },
    ];
  }

  final bom = <String, dynamic>{
    'bomFormat': 'CycloneDX',
    'specVersion': '1.6',
    'serialNumber': _serialNumber(components, appVersion),
    'version': 1,
    'metadata': {
      'tools': {
        'components': [
          {
            'type': 'application',
            'name': 'tool/sbom.dart',
            'version': '1',
            'description':
                'MI CS third-party inventory generator (cargo metadata + '
                'pubspec.lock + the shipped fonts)',
          },
        ],
      },
      'component': {
        'type': 'application',
        'bom-ref': 'pkg:generic/mi-cs@$appVersion',
        'name': appName,
        'version': appVersion,
        'licenses': [
          {
            'license': {'id': appLicense},
          },
        ],
        'properties': [
          {'name': 'mics:sbom:componentCount', 'value': '${components.length}'},
          {
            'name': 'mics:sbom:reproducible',
            'value': 'no timestamp; serialNumber derived from the component set',
          },
        ],
      },
    },
    'components': [
      for (final c in components)
        {
          'type': c.type,
          // No `bom-ref`: CycloneDX falls back to the purl, and this document
          // carries no dependency graph for a ref to point at.
          'name': c.name,
          'version': c.version,
          'scope': c.scope,
          'purl': c.purl,
          if (c.sha256 != null)
            'hashes': [
              {'alg': 'SHA-256', 'content': c.sha256},
            ],
          if (licensesOf(c).isNotEmpty) 'licenses': licensesOf(c),
          if (c.copyright != null) 'copyright': c.copyright,
          if (c.note != null)
            'properties': [
              {'name': 'mics:sbom:note', 'value': c.note},
            ],
        },
    ],
  };
  return '${const JsonEncoder.withIndent('  ').convert(bom)}\n';
}

/// A serial number derived from the component set: the same inventory gives the
/// same BOM, so the committed file only changes when a dependency does. CycloneDX
/// recommends a unique serial per BOM; a reproducible one is worth more here,
/// and the SBOM's own `version` field can bump if a consumer needs that.
String _serialNumber(List<Component> components, String appVersion) {
  final seed = StringBuffer('MI CS $appVersion\n');
  final sorted = [...components]
    ..sort((a, b) => a.coordinates.compareTo(b.coordinates));
  for (final c in sorted) {
    seed.writeln('${c.ecosystem}|${c.name}|${c.version}|${c.declaredLicense}');
  }
  final digest = _sha256(seed.toString());
  final bytes = digest.sublist(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5: name-based, per RFC 4122
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
  String hex(int from, int to) =>
      bytes.sublist(from, to).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return 'urn:uuid:${hex(0, 4)}-${hex(4, 6)}-${hex(6, 8)}-${hex(8, 10)}-${hex(10, 16)}';
}

/// SHA-256 without a package dependency: Dart's crypto package is not a declared
/// dependency of this app, and pulling one in for a dev tool is not worth it.
List<int> _sha256(String input) {
  final bytes = utf8.encode(input);
  final h = List<int>.generate(8, (i) => _sha256Init[i]);
  final k = _sha256K;
  final padded = List<int>.from(bytes)..add(0x80);
  while (padded.length % 64 != 56) {
    padded.add(0);
  }
  final bitLength = bytes.length * 8;
  for (var i = 7; i >= 0; i--) {
    padded.add((bitLength >> (8 * i)) & 0xff);
  }
  final w = List<int>.filled(64, 0);
  for (var offset = 0; offset < padded.length; offset += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = (padded[offset + i * 4] << 24) |
          (padded[offset + i * 4 + 1] << 16) |
          (padded[offset + i * 4 + 2] << 8) |
          padded[offset + i * 4 + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ (~e & g);
      final temp1 = (hh + s1 + ch + k[i] + w[i]) & 0xffffffff;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xffffffff;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffff;
    }
    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }
  final out = <int>[];
  for (final value in h) {
    for (var i = 3; i >= 0; i--) {
      out.add((value >> (8 * i)) & 0xff);
    }
  }
  return out;
}

int _rotr(int value, int bits) =>
    ((value >> bits) | (value << (32 - bits))) & 0xffffffff;

const List<int> _sha256Init = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

const List<int> _sha256K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The human-readable notices, Markdown, sorted and timestamp-free.
String renderNotices({
  required String appName,
  required String appVersion,
  required String appLicense,
  required Inventory inventory,
}) {
  final audit = inventory.audit;
  final texts = inventory.textsByLicense;
  final byId = audit.byConcludedId;
  final out = StringBuffer();

  out.writeln('# Third-party notices for $appName $appVersion');
  out.writeln();
  out.writeln(
    'MI CS is licensed under $appLicense (see `LICENSE`). It ships the '
    'third-party components below, whose licenses are reproduced in full at the '
    'end of this file.',
  );
  out.writeln();
  out.writeln('Generated by `dart run tool/sbom.dart`; do not edit by hand.');
  out.writeln(
    'The same inventory in machine-readable form is `sbom.cdx.json` '
    '(CycloneDX 1.6).',
  );
  out.writeln();
  out.writeln('## Summary');
  out.writeln();
  out.writeln('| Ecosystem | Components | Shipped |');
  out.writeln('|---|---|---|');
  for (final ecosystem in const [
    ecosystemCargo,
    ecosystemPub,
    ecosystemFlutter,
    ecosystemFont,
    ecosystemRuntime,
  ]) {
    final count = inventory.countOf(ecosystem);
    if (count == 0) continue;
    final shipped = inventory.components
        .where((c) => c.ecosystem == ecosystem && c.scope == 'required')
        .length;
    out.writeln('| ${_ecosystemLabel(ecosystem)} | $count | $shipped |');
  }
  out.writeln(
    '| **total** | **${inventory.components.length}** | '
    '**${audit.shipped.length}** |',
  );
  out.writeln();
  out.writeln('| License we rely on | Components (incl. excluded) |');
  out.writeln('|---|---|');
  for (final entry in byId.entries) {
    out.writeln('| ${entry.key} | ${entry.value} |');
  }
  out.writeln();
  out.writeln('## Audit');
  out.writeln();
  out.writeln(
    'Audited: the ${audit.shipped.length} components that end up in the shipped '
    'artifact. The other ${audit.excluded.length} are in the lockfiles but reach '
    'only dev or build dependencies, so they are listed for completeness and not '
    'audited.',
  );
  out.writeln();
  out.writeln(
    '- Permissive: ${audit.permissive.length} of ${audit.shipped.length}',
  );
  out.writeln('- Copyleft: ${audit.copyleft.length}');
  for (final c in audit.copyleft) {
    out.writeln('  - ${c.coordinates}: ${c.declaredLicense}');
  }
  out.writeln('- Unclassified: ${audit.unknown.length}');
  for (final c in audit.unknown) {
    out.writeln('  - ${c.coordinates}: ${c.declaredLicense ?? 'no license file'}');
  }
  out.writeln('- License texts missing: ${audit.missingTexts.length}');
  for (final id in audit.missingTexts) {
    out.writeln('  - $id');
  }
  if (inventory.warnings.isNotEmpty) {
    out.writeln('- Warnings:');
    for (final w in inventory.warnings) {
      out.writeln('  - $w');
    }
  }
  out.writeln();
  out.writeln(
    'Where a crate offers a choice ("MIT OR Apache-2.0"), MI CS takes the '
    'permissive option named in the tables below; the full expression each '
    'component declares is in `sbom.cdx.json`.',
  );
  out.writeln();
  out.writeln('## Components');
  for (final entry in byId.entries) {
    final id = entry.key;
    final members = inventory.components
        .where((c) => c.assessment?.concluded == id)
        .toList()
      ..sort((a, b) => a.coordinates.compareTo(b.coordinates));
    out.writeln();
    out.writeln('### $id (${members.length})');
    out.writeln();
    out.writeln('| Component | Version | Ecosystem | Scope | Copyright notice |');
    out.writeln('|---|---|---|---|---|');
    for (final c in members) {
      final copyright = (c.copyright ?? '').replaceAll('|', r'\|');
      out.writeln(
        '| ${c.name} | ${c.version} | ${c.ecosystem} | ${c.scope} | $copyright |',
      );
    }
  }
  final unlicensed = inventory.components
      .where((c) => c.assessment?.concluded == null)
      .toList();
  if (unlicensed.isNotEmpty) {
    out.writeln();
    out.writeln('### No license concluded (${unlicensed.length})');
    out.writeln();
    for (final c in unlicensed) {
      out.writeln('- ${c.coordinates}: ${c.note ?? c.declaredLicense ?? 'unknown'}');
    }
  }
  out.writeln();
  out.writeln('## License texts');
  for (final entry in texts.entries) {
    out.writeln();
    out.writeln('### ${entry.key}');
    out.writeln();
    out.writeln('Reproduced from `${entry.value.source}`.');
    out.writeln();
    out.writeln('```');
    out.writeln(entry.value.text.trimRight());
    out.writeln('```');
  }
  return out.toString();
}

String _ecosystemLabel(String ecosystem) => switch (ecosystem) {
  ecosystemCargo => 'Rust crates',
  ecosystemPub => 'Dart packages',
  ecosystemFlutter => 'Flutter SDK',
  ecosystemFont => 'Fonts',
  ecosystemRuntime => 'Runtime prerequisites (not shipped)',
  _ => ecosystem,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Runs the tool and sets the process exit code from what it decided.
///
/// `main` returning a number does not set the exit code of `dart run` - the Dart
/// VM takes it from `dart:io`'s `exitCode` - so returning early from a helper and
/// assigning here is what makes `--check` usable as a release gate. Each outcome
/// also prints a `RESULT:` line, the convention the PowerShell probes in
/// `scripts\` follow, so a wrapper that swallows the code cannot hide a failure.
Future<void> main(List<String> args) async {
  exitCode = await _run(args);
}

Future<int> _run(List<String> args) async {
  final root = Directory.current;
  var outDir = root.path;
  var check = false;
  var version = _pubspecVersion(root.path) ?? '0.0.0';
  var verbose = false;

  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--check':
        check = true;
      case '--out':
        if (i + 1 >= args.length) return _usage('--out needs a directory');
        outDir = args[++i];
      case '--version':
        if (i + 1 >= args.length) return _usage('--version needs a version');
        version = args[++i];
      case '--verbose':
        verbose = true;
      default:
        return _usage('unknown argument: ${args[i]}');
    }
  }

  final engineDir = joinPath([root.path, 'engine']);
  final metadata = Process.runSync('cargo', [
    'metadata',
    '--locked',
    '--offline',
    '--format-version',
    '1',
  ], workingDirectory: engineDir, environment: {
    'CARGO_TARGET_DIR':
        Platform.environment['CARGO_TARGET_DIR'] ??
        joinPath([Directory.systemTemp.path, 'mics-target']),
  });
  if (metadata.exitCode != 0) {
    stderr.writeln('cargo metadata failed (${metadata.exitCode})');
    stderr.writeln(metadata.stderr);
    return 2;
  }

  final pubLock = readTextOrNull(joinPath([root.path, 'pubspec.lock']));
  if (pubLock == null) {
    stderr.writeln('pubspec.lock not found in ${root.path}');
    return 2;
  }
  final flutter = flutterRoot(repoRoot: root.path);
  final warnings = <String>[];

  // Who ships and who does not. cargo answers from its resolve graph; pub has to
  // be asked, because the lockfile records no edges. The same call reports the
  // Flutter version the SDK packages belong to.
  final cargoShipped = cargoShippedCoordinates(metadata.stdout as String);
  Set<String>? pubShipped;
  var flutterVersion = flutterVersionOf(flutter);
  final deps = Process.runSync('dart', [
    'pub',
    'deps',
    '--json',
  ], workingDirectory: root.path);
  if (deps.exitCode == 0) {
    pubShipped = pubShippedNames(deps.stdout as String);
    flutterVersion = pubSdkVersions(deps.stdout as String)['flutter'] ??
        flutterVersion;
  } else {
    warnings.add(
      'dart pub deps --json failed (${deps.exitCode}), so every Dart package is '
      'recorded as shipped',
    );
  }

  final components = <Component>[
    ...parseCargoMetadata(
      metadata.stdout as String,
      shippedCoordinates: cargoShipped,
    ),
    ...parsePubLock(
      pubLock,
      sdkVersion: flutterVersion,
      shippedNames: pubShipped,
    ),
    ...manualComponents(flutterVersion: flutterVersion),
  ];
  attachLicenses(
    components,
    cargoRegistryRoots: cargoRegistrySourceRoots(),
    pubCache: defaultPubCache(),
    flutterRootPath: flutter,
    oflTextPath: joinPath([root.path, 'assets', 'fonts', 'OFL-1.1.txt']),
    warnings: warnings,
  );

  final inventory = Inventory(components, warnings);
  final bom = renderCycloneDx(
    appName: 'MI CS',
    appVersion: version,
    appLicense: 'GPL-3.0-or-later',
    inventory: inventory,
  );
  final notices = renderNotices(
    appName: 'MI CS',
    appVersion: version,
    appLicense: 'GPL-3.0-or-later',
    inventory: inventory,
  );

  final bomPath = joinPath([outDir, 'sbom.cdx.json']);
  final noticesPath = joinPath([outDir, 'THIRD-PARTY-NOTICES']);

  if (check) {
    // Compared with line endings ignored: the committed file may be sitting in a
    // CRLF working copy (core.autocrlf), and that is not a content change.
    String? normalized(String? text) => text?.replaceAll('\r\n', '\n');
    final currentBom = normalized(readTextOrNull(bomPath));
    final currentNotices = normalized(readTextOrNull(noticesPath));
    if (currentBom == bom && currentNotices == notices) {
      print('sbom: up to date (${components.length} components)');
      print('RESULT: PASS - $bomPath and $noticesPath describe this tree');
      return 0;
    }
    stderr.writeln('sbom: $bomPath or $noticesPath is stale.');
    stderr.writeln('RESULT: FAIL - run: dart run tool/sbom.dart');
    return 1;
  }

  Directory(outDir).createSync(recursive: true);
  File(bomPath).writeAsStringSync(bom);
  File(noticesPath).writeAsStringSync(notices);

  final audit = inventory.audit;
  print('components: ${components.length}');
  for (final ecosystem in const [
    ecosystemCargo,
    ecosystemPub,
    ecosystemFlutter,
    ecosystemFont,
    ecosystemRuntime,
  ]) {
    final count = inventory.countOf(ecosystem);
    if (count > 0) {
      final shipped = components
          .where((c) => c.ecosystem == ecosystem && c.scope == 'required')
          .length;
      print('  ${_ecosystemLabel(ecosystem)}: $count ($shipped shipped)');
    }
  }
  print('licenses: ${audit.byConcludedId.entries.map((e) => '${e.key}=${e.value}').join(', ')}');
  print('copyleft: ${audit.copyleft.length}, unclassified: ${audit.unknown.length}');
  print('missing license texts: ${audit.missingTexts.length} ${audit.missingTexts}');
  print(
    'shipped components with no text of their own: '
    '${audit.componentsMissingText.length}',
  );
  if (verbose) {
    for (final c in audit.componentsMissingText) {
      print('  no text for ${c.coordinates} (${c.assessment?.expression})');
    }
    final excluded = inventory.components
        .where((c) => c.scope != 'required')
        .toList()
      ..sort((a, b) => a.coordinates.compareTo(b.coordinates));
    print('excluded (${excluded.length}): '
        '${excluded.map((c) => c.coordinates).join(', ')}');
    for (final w in warnings) {
      print('warning: $w');
    }
  } else if (warnings.isNotEmpty) {
    print('warnings: ${warnings.length} (--verbose to list)');
  }
  print('wrote $bomPath');
  print('wrote $noticesPath');
  if (audit.isClean) {
    print(
      'RESULT: PASS - ${components.length} components, '
      '${audit.byConcludedId.length} licenses, no copyleft, no gaps',
    );
    return 0;
  }
  stderr.writeln(
    'RESULT: FAIL - copyleft: ${audit.copyleft.length}, unclassified: '
    '${audit.unknown.length}, license texts missing: '
    '${audit.missingTexts.length}',
  );
  return 3;
}

/// Prints why the command line was refused, and the usage.
int _usage(String problem) {
  stderr.writeln(problem);
  stderr.writeln('RESULT: FAIL - $problem');
  stderr.writeln(
    'usage: dart run tool/sbom.dart [--check] [--out <dir>] '
    '[--version <x.y.z>] [--verbose]',
  );
  return 2;
}

String? _pubspecVersion(String root) {
  final text = readTextOrNull(joinPath([root, 'pubspec.yaml']));
  if (text == null) return null;
  final match = RegExp(r'^version:\s*([0-9]+\.[0-9]+\.[0-9]+)', multiLine: true)
      .firstMatch(text);
  if (match == null) return null;
  // The build number after `+` is not part of the release version.
  return match.group(1);
}

