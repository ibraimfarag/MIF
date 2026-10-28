import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/audio/sound_service.dart';

/// The sound pack is generated in-house (D-004). These checks keep it honest:
/// every cue the code can play must exist as a real, non-empty WAV.
void main() {
  test('every cue has a valid WAV file', () {
    for (final cue in SoundCue.all) {
      final file = File('assets/sounds/$cue.wav');
      expect(file.existsSync(), isTrue, reason: 'missing assets/sounds/$cue.wav');
      final bytes = file.readAsBytesSync();
      expect(bytes.length, greaterThan(1000), reason: '$cue.wav is too small');
      expect(String.fromCharCodes(bytes.sublist(0, 4)), 'RIFF');
      expect(String.fromCharCodes(bytes.sublist(8, 12)), 'WAVE');
    }
  });

  test('the pack has no unexpected extra files', () {
    final files = Directory('assets/sounds')
        .listSync()
        .whereType<File>()
        .map((f) => f.uri.pathSegments.last)
        .where((n) => n.endsWith('.wav'))
        .toSet();
    expect(files, SoundCue.all.map((c) => '$c.wav').toSet());
  });
}
