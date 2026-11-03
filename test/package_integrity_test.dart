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

  test('the release gate pins the signer the engine pins', () {
    // The manifest's authenticity is the engine's own signature, and both halves
    // check whose it is: the engine at run time (`EXPECTED_SIGNER_CN`) and
    // `verify-manifest.ps1` before anything ships (`MicsSignerCn`). If those two
    // spellings drift, the gate could pass a package the app then refuses - so one
    // is read out of the other's source.
    final rust =
        File('engine/src/platform/windows/signature.rs').readAsStringSync();
    final pinned =
        RegExp(r'EXPECTED_SIGNER_CN: &str = "([^"]+)"').firstMatch(rust);
    expect(pinned, isNotNull,
        reason: 'signature.rs no longer names the signer it expects');
    final cn = pinned!.group(1)!;
    expect(File('scripts/manifest-resource.ps1').readAsStringSync(),
        contains('MicsSignerCn = "$cn"'),
        reason: 'scripts/manifest-resource.ps1 does not pin "$cn": the release '
            'gate and the engine disagree about who signs MI CS');
    expect(File('scripts/verify-manifest.ps1').readAsStringSync(),
        contains(r'$script:MicsSignerCn'),
        reason: 'verify-manifest.ps1 spelled the signer out instead of using the '
            'one constant, so the gate and the engine can drift apart');
  });
}
