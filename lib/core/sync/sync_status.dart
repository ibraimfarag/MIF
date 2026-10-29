// Connectivity + intelligence freshness (P3).
//
// The engine is the only component that touches the network, so the UI asks it
// for a status snapshot instead of probing anything itself. The snapshot is
// polled once a minute and refreshed on demand (tap the chip / "Sync now").

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

/// One intel source, as the engine reports it (D-012). Every source keeps its
/// own freshness, error and next attempt, so one dead feed cannot hide behind a
/// single aggregate "last synced" number.
class SyncSource {
  const SyncSource({
    required this.source,
    required this.state,
    required this.network,
    required this.onDemand,
    required this.ageSeconds,
    required this.nextDueSeconds,
    required this.failures,
    required this.items,
    required this.lastError,
    required this.detail,
    required this.version,
  });

  final String source;

  /// ok | failed | not_configured | never
  final String state;
  final bool network;

  /// Recorded by the feature itself (NVD during a vulnerability scan) rather
  /// than by a scheduled feed.
  final bool onDemand;

  final int? ageSeconds;

  /// Seconds until the next scheduled attempt; `null` = on demand only.
  final int? nextDueSeconds;
  final int failures;
  final int items;
  final String? lastError;
  final String? detail;
  final String? version;

  bool get hasError => lastError != null && lastError!.isNotEmpty;

  /// Compact, language-neutral age ("12m", "3h", "2d").
  static String shortAge(int? seconds) {
    if (seconds == null) return '';
    if (seconds < 3600) return '${(seconds / 60).floor().clamp(1, 59)}m';
    if (seconds < 86400) return '${(seconds / 3600).floor()}h';
    return '${(seconds / 86400).floor()}d';
  }

  factory SyncSource.fromJson(Map<String, dynamic> j) => SyncSource(
        source: j['source'] as String? ?? '',
        state: j['state'] as String? ?? 'never',
        network: j['network'] as bool? ?? true,
        onDemand: j['on_demand'] as bool? ?? false,
        ageSeconds: (j['age_seconds'] as num?)?.toInt(),
        nextDueSeconds: (j['seconds_to_due'] as num?)?.toInt(),
        failures: (j['failures'] as num?)?.toInt() ?? 0,
        items: (j['items'] as num?)?.toInt() ?? 0,
        lastError: j['last_error'] as String?,
        detail: j['detail'] as String?,
        version: j['version'] as String?,
      );
}

class SyncStatus {
  const SyncStatus({
    required this.online,
    required this.iocHashes,
    required this.vtQueue,
    required this.ageSeconds,
    required this.intervalHours,
    this.iocDomains = 0,
    this.kevTotal = 0,
    this.cveCacheTotal = 0,
    this.geoipCountries = 0,
    this.sources = const <SyncSource>[],
  });

  final bool online;
  final int iocHashes;
  final int vtQueue;

  /// Seconds since the last successful intel sync; `null` = never synced.
  final int? ageSeconds;
  final int intervalHours;

  final int iocDomains;
  final int kevTotal;
  final int cveCacheTotal;
  final int geoipCountries;
  final List<SyncSource> sources;

  bool get neverSynced => ageSeconds == null;

  /// Compact, language-neutral age ("12m", "3h", "2d"). The label around it is
  /// translated; the unit suffix stays short to fit the top bar.
  String get ageLabel => SyncSource.shortAge(ageSeconds);

  factory SyncStatus.fromJson(Map<String, dynamic> j) => SyncStatus(
        online: j['online'] as bool? ?? false,
        iocHashes: (j['ioc_hash_total'] as num?)?.toInt() ?? 0,
        vtQueue: (j['vt_queue_len'] as num?)?.toInt() ?? 0,
        ageSeconds: (j['age_seconds'] as num?)?.toInt(),
        intervalHours: (j['sync_interval_hours'] as num?)?.toInt() ?? 6,
        iocDomains: (j['ioc_domain_total'] as num?)?.toInt() ?? 0,
        kevTotal: (j['kev_total'] as num?)?.toInt() ?? 0,
        cveCacheTotal: (j['cve_cache_total'] as num?)?.toInt() ?? 0,
        geoipCountries: (j['geoip_countries'] as num?)?.toInt() ?? 0,
        sources: (j['sources'] as List? ?? const [])
            .map((s) => SyncSource.fromJson((s as Map).cast<String, dynamic>()))
            .toList(),
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
