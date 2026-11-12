// Two files declare this product's version, and nothing tied them together: the
// engine's `engine\Cargo.toml`, which the release lane reads (`make-release.ps1`
// names the ZIP and writes the package's `VERSION` line from it, `make-installer.ps1`
// names the installer and its Apps-&-features entry from it), and `pubspec.yaml`,
// which Flutter stamps into the app's own version resource - measured 2026-11-13,
// `mics_app.exe` carries `FileVersion 0.1.1+2` while the engine carries `0.1.1`.
// A bump that moved one file and not the other would ship
// `MICS-portable-0.1.2-x64.zip` holding an app that still calls itself 0.1.1, and
// every gate in the lane would stay green: no script read `pubspec.yaml` for a
// version, and `verify-release.ps1` checks the artifact's architecture and
// descriptions, not its numbers. This test is that missing tie.
//
// The rule is the *base* version, not the whole string: Flutter's build number
// (`+2`, the `N` Windows puts after the file version) has no counterpart in
// `Cargo.toml`, so only what the two files mean to say together is compared.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// The version `engine\Cargo.toml` declares - the one the release lane reads.
String engineVersion() {
  final match = RegExp(r'^version\s*=\s*"([^"]+)"', multiLine: true)
      .firstMatch(File('engine/Cargo.toml').readAsStringSync());
  if (match == null) {
    fail('engine/Cargo.toml declares no version');
  }
  return match.group(1)!;
}

/// `pubspec.yaml`'s version, split where Flutter splits it: `0.1.1+2` is base
/// `0.1.1` and build number `2`. Flutter stamps both into the app (`0.1.1+2`),
/// so the base is what must agree with the engine and the build number is what
/// this file may hold on its own.
({String base, String? build}) appVersion() {
  final match = RegExp(r'^version:\s*(\S+)', multiLine: true)
      .firstMatch(File('pubspec.yaml').readAsStringSync());
  if (match == null) {
    fail('pubspec.yaml declares no version');
  }
  final parts = match.group(1)!.split('+');
  return (base: parts.first, build: parts.length > 1 ? parts[1] : null);
}

void main() {
  test('the engine and the app declare the same version', () {
    final app = appVersion();
    expect(
      app.base,
      engineVersion(),
      reason: 'engine/Cargo.toml names the package and pubspec.yaml names the app, '
          'so a bump that moves one of them has to move the other',
    );
  });

  test('an app build number, when there is one, is a positive integer', () {
    final build = appVersion().build;
    if (build == null) {
      // Legal: Flutter defaults an absent build number, and this project's
      // package names and VERSION line never carry one.
      return;
    }
    final parsed = int.tryParse(build);
    expect(parsed, isNotNull, reason: 'pubspec.yaml build number is "$build"');
    expect(parsed, greaterThan(0));
  });
}
