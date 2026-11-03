// The package's own integrity, as the engine reports it (ج2, D-025).
//
// The engine reads the SHA-256 manifest injected into its own signed image,
// hashes the files beside it and classifies its own signature, and answers
// `status.integrity` with one of three words (`engine/src/selfcheck.rs`). The UI
// does not decide any of it: it only picks the surface for each word.
//
// `unknown` is the fourth answer and it is not a state of the package: it means
// the engine has not answered. Accusing a copy we could not ask about would be
// the same mistake `helperStatusProvider` avoids.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

/// What the engine said about this copy of MI CS.
enum PackageIntegrity {
  /// Signed by MI CS, trusted here, and every listed file hashes as published.
  ok('ok'),

  /// Signed by MI CS and intact, but this Windows does not trust the release
  /// certificate yet (the self-signed build, D-002). Nothing is wrong with it.
  untrustedCertificate('untrusted-certificate'),

  /// Not provable: no manifest, another signer, or a file that changed. This is
  /// the only state that wears the "unofficial build" notice.
  unverified('unverified'),

  /// The engine has not answered (yet, or at all).
  unknown('');

  const PackageIntegrity(this.wire);

  /// The word on the wire, so a test can pin the switch to the engine's strings.
  final String wire;

  static PackageIntegrity fromWire(String? wire) => PackageIntegrity.values
      .firstWhere((state) => state.wire == wire,
          orElse: () => PackageIntegrity.unknown);

  /// A real mismatch: the one state that earns the notice and the card.
  bool get warns => this == PackageIntegrity.unverified;

  /// Something the engine actually told us about this copy.
  bool get known => this != PackageIntegrity.unknown;
}

final packageIntegrityProvider =
    AsyncNotifierProvider<PackageIntegrityNotifier, PackageIntegrity>(
        PackageIntegrityNotifier.new);

class PackageIntegrityNotifier extends AsyncNotifier<PackageIntegrity> {
  @override
  Future<PackageIntegrity> build() async {
    try {
      final res = await ref.read(engineIpcProvider).request('status');
      return PackageIntegrity.fromWire((res as Map)['integrity'] as String?);
    } catch (_) {
      // The engine is unreachable: say nothing instead of claiming the files
      // changed. The verdict is cached engine-side, so the next read is cheap.
      return PackageIntegrity.unknown;
    }
  }
}