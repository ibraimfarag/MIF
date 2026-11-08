import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

/// One handover of a path to the window that is already open (D-041).
///
/// A fresh object per handover, not a plain string: scanning the same file
/// twice from Explorer is two handovers, and a provider that held a string
/// would look unchanged the second time. The scanner screen reads it to show
/// which folder the scan came from.
class HandedScan {
  const HandedScan(this.path);

  final String path;
}

/// The handover the window has to act on, or null when there has been none.
final handedScanProvider =
    NotifierProvider<HandedScanNotifier, HandedScan?>(HandedScanNotifier.new);

class HandedScanNotifier extends Notifier<HandedScan?> {
  @override
  HandedScan? build() => null;

  /// Records a handover. A fresh object each time, so scanning the same file
  /// twice from Explorer is two handovers and not one value that looks
  /// unchanged.
  void handOver(String path) => state = HandedScan(path);
}

/// The handoff between two MI CS processes (D-041).
///
/// Windows starts a *new* process for the Explorer verb ("Scan with MI CS") and
/// for every later launch of the app, and a second process would start its own
/// window and its own engine. Instead, the newcomer asks the engine — the one
/// thing both processes are attached to — whether another client is already
/// there: [announce] returns true when one was, in which case the window that
/// is open has been handed the path (or just asked to come forward) and the
/// newcomer ends without owning or stopping anything.
///
/// The engine never talks to the window directly; the running process receives
/// an `event` notification it recognises as an activation, exactly like the
/// job and alert pushes it already listens to.
class AppHandoff {
  AppHandoff({required this.ipc, required this.onActivate});

  final EngineIpc ipc;

  /// Called on the window that was already open: raise it, and scan the path
  /// when this activation carried one.
  final void Function(String? path) onActivate;

  StreamSubscription<Map<String, dynamic>>? _sub;
  bool _handedOver = false;

  /// Starts listening for handovers aimed at this window. The window that
  /// answered "nobody else is here" is the one that keeps listening.
  void listen() {
    _sub ??= ipc.eventStream.listen(_onEvent);
  }

  /// Tells the engine this process has started, and whether another window took
  /// the handover. `path` is what `--scan` brought, if anything.
  ///
  /// True means this process has nothing to show and ends (the window that is
  /// open has the path); false means it *is* the window.
  ///
  /// A failed ask is false on purpose: an engine too old to know `app.activate`,
  /// or one that went away in the seconds it took to boot, must leave the user
  /// with a window, not with nothing. The cost of answering "I am the window"
  /// wrongly is a second window; the cost of the opposite is no window at all.
  Future<bool> announce({String? path}) async {
    dynamic res;
    try {
      res = await ipc.request('app.activate', {'path': ?path});
    } on EngineException {
      return false;
    }
    final delivered = res is Map && res['delivered'] == true;
    if (delivered) _handedOver = true;
    return delivered;
  }

  void _onEvent(Map<String, dynamic> event) {
    // This process is ending: the window that took the handover is the one that
    // acts, and it was handed the path by name.
    if (_handedOver) return;
    if (event['type'] != 'activate') return;
    final data = (event['data'] as Map?)?.cast<String, dynamic>();
    final path = data?['path'] as String?;
    onActivate((path == null || path.trim().isEmpty) ? null : path);
  }

  void dispose() {
    _sub?.cancel();
    _sub = null;
  }

  /// The path in `--scan "<path>"` / `--scan=<path>`, or null when this launch
  /// carries none. Pure, so the parsing is testable without a process.
  ///
  /// Explorer quotes the path, so a path with spaces arrives as one argument;
  /// `CommandLineToArgvW` has already done that splitting by the time Dart sees
  /// the list.
  static String? scanPathFrom(List<String> args) {
    for (var i = 0; i < args.length; i++) {
      final arg = args[i];
      if (arg == '--scan') {
        final value = i + 1 < args.length ? args[i + 1] : '';
        return value.trim().isEmpty ? null : value.trim();
      }
      if (arg.startsWith('--scan=')) {
        final value = arg.substring('--scan='.length).trim();
        return value.isEmpty ? null : value;
      }
    }
    return null;
  }
}
