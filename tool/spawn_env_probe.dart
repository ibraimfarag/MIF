// ignore_for_file: avoid_print
//
// Diagnoses environment inheritance when the app spawns the engine.
//
//   dart run tool/spawn_env_probe.dart
//
// Prints what the parent has, then starts `mics-engine --service` exactly the
// way the app does and reports which data dir the child picked.
import 'dart:io';

Future<void> main() async {
  final exe = r'build\windows\x64\runner\Release\mics-engine.exe';
  print('parent PROGRAMDATA = ${Platform.environment['PROGRAMDATA']}');
  print('parent MICS_DATA_DIR = ${Platform.environment['MICS_DATA_DIR']}');
  final mode = Platform.environment['PROBE_MODE'] ?? 'null';
  final Map<String, String>? env = switch (mode) {
    'null' => null,
    'merged' => {...Platform.environment, 'MICS_SYNC_HOURS': '6'},
    _ => {'MICS_SYNC_HOURS': '6'},
  };
  print('spawn environment mode = $mode');
  final p = await Process.start(
    exe,
    const ['service'],
    environment: env,
    mode: ProcessStartMode.detached,
  );
  print('spawned pid=${p.pid}');
  await Future<void>.delayed(const Duration(seconds: 4));
  exit(0);
}
