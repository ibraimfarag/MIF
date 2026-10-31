// The privileged helper (D-007), as the UI sees it.
//
// The engine owns the whole install: the UI only asks for the state, and for
// `helper.install` when the user presses the button. That single call is the one
// UAC prompt the product ever shows.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

/// Snapshot of `%PROGRAMDATA%\MICS`'s privileged helper service.
class HelperStatus {
  const HelperStatus({
    required this.service,
    required this.installed,
    required this.running,
    required this.state,
    required this.reachable,
    required this.elevated,
    required this.version,
    required this.pipe,
  });

  final String service;
  final bool installed;
  final bool running;

  /// `running` | `stopped` | `start_pending` | `not_installed` | `unknown`.
  final String state;

  /// The pipe answered: service + ACL + protocol all work.
  final bool reachable;

  /// The helper's own token is elevated (a non-elevated helper is a broken
  /// install, not a working one).
  final bool elevated;
  final String? version;
  final String pipe;

  /// Everything privileged works right now.
  bool get usable => reachable && elevated;

  factory HelperStatus.fromJson(Map<String, dynamic> j) => HelperStatus(
        service: j['service'] as String? ?? 'MICSHelper',
        installed: j['installed'] as bool? ?? false,
        running: j['running'] as bool? ?? false,
        state: j['state'] as String? ?? 'unknown',
        reachable: j['reachable'] as bool? ?? false,
        elevated: j['elevated'] as bool? ?? false,
        version: j['version'] as String?,
        pipe: j['pipe'] as String? ?? '',
      );

  static const empty = HelperStatus(
    service: 'MICSHelper',
    installed: false,
    running: false,
    state: 'unknown',
    reachable: false,
    elevated: false,
    version: null,
    pipe: '',
  );
}

final helperStatusProvider =
    AsyncNotifierProvider<HelperStatusNotifier, HelperStatus>(HelperStatusNotifier.new);

class HelperStatusNotifier extends AsyncNotifier<HelperStatus> {
  @override
  Future<HelperStatus> build() => refresh();

  Future<HelperStatus> refresh() async {
    try {
      final res = await ref.read(engineIpcProvider).request('helper.status');
      final status = HelperStatus.fromJson((res as Map).cast<String, dynamic>());
      if (ref.mounted) state = AsyncValue.data(status);
      return status;
    } catch (_) {
      // The engine is unreachable: say "unknown" instead of claiming the helper
      // is missing (which would push the user to reinstall for no reason).
      return state.value ?? HelperStatus.empty;
    }
  }

  /// Installs the helper: this is the one Windows prompt in the product. The
  /// engine launches the elevated step and waits for the pipe to answer.
  ///
  /// The call gets a longer deadline than the 120 s default on purpose: the
  /// engine allows the elevated child 180 s (the user has to read and answer one
  /// prompt), and a client that gave up first would report "timed out" while the
  /// install was still running.
  Future<HelperStatus> install() async {
    final res = await ref
        .read(engineIpcProvider)
        .request('helper.install', null, _privilegedTimeout);
    final status = HelperStatus.fromJson((res as Map).cast<String, dynamic>());
    if (ref.mounted) state = AsyncValue.data(status);
    return status;
  }

  /// Stops and deletes the service (needs one prompt as well).
  Future<HelperStatus> remove() async {
    final res = await ref
        .read(engineIpcProvider)
        .request('helper.uninstall', null, _privilegedTimeout);
    final status = HelperStatus.fromJson((res as Map).cast<String, dynamic>());
    if (ref.mounted) state = AsyncValue.data(status);
    return status;
  }

  /// Longer than the engine's own 180 s install deadline, deliberately.
  static const _privilegedTimeout = Duration(seconds: 240);
}
