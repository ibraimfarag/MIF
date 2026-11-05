// Notification sounds (D-004).
//
// The pack is generated in-house (`assets/sounds/*.wav`), so there is no
// third-party audio licence. Two playback paths exist on purpose:
//
//  * the **engine** plays the critical/high cue even when the UI is closed
//    (Rust `PlaySound` from embedded bytes, system volume);
//  * the **UI** plays every cue while it is open, honouring the Settings
//    volume slider, the sound toggle and do-not-disturb.
//
// This is the UI path.

import 'dart:async';

import 'package:audioplayers/audioplayers.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

class SoundCue {
  static const info = 'info';
  static const success = 'success';
  static const warning = 'warning';
  static const critical = 'critical';
  static const all = [info, success, warning, critical];
}

class SoundService {
  final AudioPlayer _player = AudioPlayer();
  bool _disposed = false;

  Future<void> play(String cue, {int volume = 70}) async {
    if (_disposed) return;
    if (!SoundCue.all.contains(cue)) return;
    try {
      await _player.stop();
      await _player.setVolume((volume.clamp(0, 100)) / 100);
      await _player.play(AssetSource('sounds/$cue.wav'));
    } catch (_) {
      // No audio device / decoder trouble must never break a screen.
    }
  }

  void dispose() {
    _disposed = true;
    _player.dispose();
  }
}

final soundServiceProvider = Provider<SoundService>((ref) {
  final service = SoundService();
  ref.onDispose(service.dispose);
  return service;
});

/// Maps engine events to cues. Started once when the app boots.
class SoundRouter {
  SoundRouter(this._ref);
  final Ref _ref;
  StreamSubscription<Map<String, dynamic>>? _sub;

  void start() {
    final ipc = _ref.read(engineIpcProvider);
    _sub = ipc.eventStream.listen(_onEvent);
  }

  void _onEvent(Map<String, dynamic> event) {
    final settings = _ref.read(settingsProvider).value;
    if (settings == null || !settings.soundEnabled || settings.dndMode) return;

    final type = event['type'];
    // Service mode wraps payloads as {type, data}; stdio mode sends the event
    // itself. Accept both so the router never depends on the transport.
    final data = (event['data'] as Map?)?.cast<String, dynamic>() ?? event;

    String? cue;
    switch (type) {
      case 'canary_triggered':
        cue = SoundCue.critical;
      case 'canary_read':
        // Nothing on disk changed, so this is not the critical cue.
        cue = SoundCue.warning;
      case 'process_suspicious':
        cue = (data['severity'] == 'critical')
            ? SoundCue.critical
            : SoundCue.warning;
      case 'job_finished':
        final findings = (data['findings'] as num?)?.toInt() ?? 0;
        cue = findings > 0 ? SoundCue.warning : SoundCue.success;
      case 'threat_detected':
        cue = SoundCue.critical;
    }
    if (cue != null) {
      _play(cue, settings.soundVolume);
    }
  }

  Future<void> _play(String cue, int volume) =>
      _ref.read(soundServiceProvider).play(cue, volume: volume);

  void dispose() {
    _sub?.cancel();
  }
}

final soundRouterProvider = Provider<SoundRouter>((ref) {
  final router = SoundRouter(ref);
  router.start();
  ref.onDispose(router.dispose);
  return router;
});
