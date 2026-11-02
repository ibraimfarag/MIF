// The crash reports, as the UI sees them (ز2-ج).
//
// The engine writes one bundle per distinct failure under
// `<data dir>\crashes\` and owns that directory; the UI has exactly three doors
// to it - `crash.list`, `crash.get` and `crash.delete` - and this notifier is the
// only place that opens them. Nothing here reads a file, and nothing here sends
// anything anywhere.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/models/crash_models.dart';

final crashReportsProvider =
    AsyncNotifierProvider<CrashReportsNotifier, List<CrashSummary>>(
        CrashReportsNotifier.new);

class CrashReportsNotifier extends AsyncNotifier<List<CrashSummary>> {
  @override
  Future<List<CrashSummary>> build() => _load();

  /// How many reports the section asks for. The engine keeps every one on disk;
  /// this is the recent window the screen shows, newest first.
  static const _limit = 20;

  Future<List<CrashSummary>> _load() async {
    final res = await ref
        .read(engineIpcProvider)
        .request('crash.list', {'limit': _limit});
    return CrashSummary.listFrom(res);
  }

  /// The whole report, log tail included, for the row the user opened.
  Future<CrashReport> open(String bugId) async {
    final res = await ref
        .read(engineIpcProvider)
        .request('crash.get', {'bug_id': bugId});
    return CrashReport.fromJson((res as Map).cast<String, dynamic>());
  }

  /// Delete one report and re-read the list from the engine, so what stays on
  /// screen is what the engine still has rather than what the UI hoped it
  /// deleted. A failure propagates to the caller, which shows it.
  Future<List<CrashSummary>> delete(String bugId) async {
    await ref
        .read(engineIpcProvider)
        .request('crash.delete', {'bug_id': bugId});
    final list = await _load();
    if (ref.mounted) state = AsyncValue.data(list);
    return list;
  }
}
