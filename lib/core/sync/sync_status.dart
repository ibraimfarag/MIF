// Connectivity + intelligence freshness (P3).
//
// The engine is the only component that touches the network, so the UI asks it
// for a status snapshot instead of probing anything itself. The snapshot is
// polled once a minute and refreshed on demand (tap the chip / "Sync now").

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

class SyncStatus {
  const SyncStatus({
    required this.online,
    required this.iocHashes,
    required this.vtQueue,
    required this.ageSeconds,
    required this.intervalHours,
  });

  final bool online;
  final int iocHashes;
  final int vtQueue;

  /// Seconds since the last successful intel sync; `null` = never synced.
  final int? ageSeconds;
  final int intervalHours;

  bool get neverSynced => ageSeconds == null;

  /// Compact, language-neutral age ("12m", "3h", "2d"). The label around it is
  /// translated; the unit suffix stays short to fit the top bar.
  String get ageLabel {
    final age = ageSeconds;
    if (age == null) return '';
    if (age < 3600) return '${(age / 60).floor().clamp(1, 59)}m';
    if (age < 86400) return '${(age / 3600).floor()}h';
    return '${(age / 86400).floor()}d';
  }

  factory SyncStatus.fromJson(Map<String, dynamic> j) => SyncStatus(
        online: j['online'] as bool? ?? false,
        iocHashes: (j['ioc_hash_total'] as num?)?.toInt() ?? 0,
        vtQueue: (j['vt_queue_len'] as num?)?.toInt() ?? 0,
        ageSeconds: (j['age_seconds'] as num?)?.toInt(),
        intervalHours: (j['sync_interval_hours'] as num?)?.toInt() ?? 6,
      );

  static const empty = SyncStatus(
    online: false,
    iocHashes: 0,
    vtQueue: 0,
    ageSeconds: null,
    intervalHours: 6,
  );
}

final syncStatusProvider =
    AsyncNotifierProvider<SyncStatusNotifier, SyncStatus>(SyncStatusNotifier.new);

class SyncStatusNotifier extends AsyncNotifier<SyncStatus> {
  Timer? _timer;

  @override
  Future<SyncStatus> build() async {
    // Cheap, engine-side probe; a minute is plenty for an offline badge.
    _timer = Timer.periodic(const Duration(minutes: 1), (_) => refresh());
    ref.onDispose(() => _timer?.cancel());
    return _fetch();
  }

  Future<SyncStatus> _fetch() async {
    try {
      final res = await ref.read(engineIpcProvider).request('sync.status');
      return SyncStatus.fromJson((res as Map).cast<String, dynamic>());
    } catch (_) {
      // Engine unreachable: report offline rather than pretending to be fresh.
      return stateOrEmpty();
    }
  }

  SyncStatus stateOrEmpty() => state.value ?? SyncStatus.empty;

  /// Re-reads the snapshot (also used after `sync.now`).
  Future<void> refresh() async {
    final next = await _fetch();
    if (!ref.mounted) return;
    state = AsyncValue.data(next);
  }

  /// Asks the engine to sync now, then refreshes the badge.
  Future<Map<String, dynamic>> syncNow() async {
    final res = await ref.read(engineIpcProvider).request('sync.now');
    await refresh();
    return (res as Map).cast<String, dynamic>();
  }
}
