// The three words `status.integrity` can carry are the UI's switch keys (ج2,
// D-025). A rename on either side fails nothing at run time: the About line
// would simply never appear, and the one screen that answers "is this copy the
// published one?" would answer nothing. So the words are read out of the
// engine's own source instead of being trusted in two places.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/package_integrity.dart';

void main() {
  test('every state the UI switches on is a word the engine writes', () {
    final source = File('engine/src/selfcheck.rs').readAsStringSync();
    for (final state in PackageIntegrity.values) {
      if (state == PackageIntegrity.unknown) continue;
      expect(source.contains('"${state.wire}"'), isTrue,
          reason: 'engine/src/selfcheck.rs no longer reports '
              '"${state.wire}", so the About line is dead copy');
    }
  });

  test('a word this build does not know is "not told", never a guess', () {
    // Reading an unknown word as `ok` would hide a real mismatch; reading it as
    // `unverified` would accuse a copy nothing is wrong with. Both are worse
    // than saying nothing.
    expect(PackageIntegrity.fromWire('ok'), PackageIntegrity.ok);
    expect(PackageIntegrity.fromWire('untrusted-certificate'),
        PackageIntegrity.untrustedCertificate);
    expect(PackageIntegrity.fromWire('unverified'),
        PackageIntegrity.unverified);
    expect(PackageIntegrity.fromWire('something-newer'),
        PackageIntegrity.unknown);
    expect(PackageIntegrity.fromWire(null), PackageIntegrity.unknown);
    expect(PackageIntegrity.fromWire(''), PackageIntegrity.unknown);
  });

  test('only a real mismatch wears the notice', () {
    expect(PackageIntegrity.unverified.warns, isTrue);
    expect(PackageIntegrity.ok.warns, isFalse);
    // The self-signed case is not a fault: this Windows has simply not been told
    // to trust the release certificate (D-002).
    expect(PackageIntegrity.untrustedCertificate.warns, isFalse);
    expect(PackageIntegrity.unknown.warns, isFalse);

    expect(PackageIntegrity.ok.known, isTrue);
    expect(PackageIntegrity.untrustedCertificate.known, isTrue);
    expect(PackageIntegrity.unverified.known, isTrue);
    expect(PackageIntegrity.unknown.known, isFalse);
  });
}
