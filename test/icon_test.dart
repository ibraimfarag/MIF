import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

/// Every Windows surface (Explorer, taskbar, Alt-Tab, the title bar, the tray)
/// renders the same art at a different size. An icon that only carries
/// 16/32/48/256 looks blurry at 20/24/40/64/96/128 — which is exactly what the
/// project shipped before — so this test pins the full size set.
const expectedSizes = {16, 20, 24, 32, 40, 48, 64, 96, 128, 256};

/// The icon files that must stay in sync:
///  * `windows/runner/resources/app_icon.ico` is embedded in `mics_app.exe`
///    (taskbar, Alt-Tab, Explorer, title bar);
///  * `assets/icons/mics.ico` is the tray icon;
///  * `assets/icons/desktop.ico` belongs to the desktop shortcut only — that is
///    how the desktop can show different art from the taskbar.
const taskIcons = <String>[
  'windows/runner/resources/app_icon.ico',
  'assets/icons/mics.ico',
];
const desktopIcon = 'assets/icons/desktop.ico';

void main() {
  for (final path in [...taskIcons, desktopIcon]) {
    test('$path carries every standard icon size', () {
      final file = File(path);
      expect(file.existsSync(), isTrue, reason: '$path is missing');
      final sizes = _icoSizes(file.readAsBytesSync());
      expect(sizes, equals(expectedSizes),
          reason: '$path is missing ${expectedSizes.difference(sizes)} '
              '(extra: ${sizes.difference(expectedSizes)})');
    });
  }

  test('the task icons are byte-identical (one art, no drift)', () {
    final a = File(taskIcons[0]).readAsBytesSync();
    final b = File(taskIcons[1]).readAsBytesSync();
    expect(_sameBytes(a, b), isTrue,
        reason: 'app_icon.ico and mics.ico must be the same task art');
  });

  test('the desktop art differs from the taskbar art', () {
    final task = File(taskIcons[0]).readAsBytesSync();
    final desktop = File(desktopIcon).readAsBytesSync();
    expect(_sameBytes(task, desktop), isFalse,
        reason: 'desktop.ico is a copy of the task icon — choosing the desktop '
            'art is the whole point of shipping it');
  });

  test('the source art (SVG) and its rasterised master exist', () {
    for (final path in [
      'assets/icons/task.svg',
      'assets/icons/Desktop.svg',
      'assets/icons/task.png',
      'assets/icons/Desktop.png',
    ]) {
      expect(File(path).existsSync(), isTrue, reason: '$path is missing');
    }
  });
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Reads the ICONDIR/ICONDIRENTRY table of an ICO file.
///
/// A width/height byte of 0 means 256 pixels (the format stores it in a byte).
Set<int> _icoSizes(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  expect(data.getUint16(0, Endian.little), 0, reason: 'not an .ico (reserved)');
  expect(data.getUint16(2, Endian.little), 1, reason: 'not an .ico (type)');
  final count = data.getUint16(4, Endian.little);
  expect(count, greaterThan(0), reason: 'icon contains no images');

  final sizes = <int>{};
  for (var i = 0; i < count; i++) {
    final entry = 6 + i * 16;
    final width = bytes[entry] == 0 ? 256 : bytes[entry];
    final height = bytes[entry + 1] == 0 ? 256 : bytes[entry + 1];
    expect(width, height, reason: 'icon frame $i is not square');
    sizes.add(width);
  }
  return sizes;
}