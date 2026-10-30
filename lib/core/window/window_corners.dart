// Rounded window corners for the frameless MI CS window.
//
// Two mechanisms, in order:
//  1. Windows 11: `DwmSetWindowAttribute(DWMWA_WINDOW_CORNER_PREFERENCE)` —
//     the compositor rounds the window, including the shadow and the border.
//  2. Windows 10 (or any build where (1) fails): `SetWindowRgn` with a
//     `CreateRoundRectRgn` region, which clips the window to the same shape.
//
// A region is never left installed while maximized (it would cut the corners
// of a full-screen window), and both mechanisms are re-applied when the window
// is restored. Failures are non-fatal: the window simply stays rectangular on
// an OS that supports neither call.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:mics_app/core/window/app_identity.dart';

class WindowCorners {
  /// Logical radius; scaled by the window DPI before use.
  static const int baseRadius = 14;

  static bool _dwmRounding = false;
  static bool _regionInstalled = false;

  /// Applies (or removes) rounded corners on the main window.
  ///
  /// [rounded] is false while maximized.
  static void apply({required bool rounded}) {
    if (!Platform.isWindows) return;
    try {
      final user32 = DynamicLibrary.open('user32.dll');
      final dwmapi = DynamicLibrary.open('dwmapi.dll');

      final findWindow = user32.lookupFunction<
          IntPtr Function(Pointer<Utf16>, Pointer<Utf16>),
          int Function(Pointer<Utf16>, Pointer<Utf16>)>('FindWindowW');
      final title = appDisplayName.toNativeUtf16();
      final hwnd = findWindow(Pointer.fromAddress(0), title);
      malloc.free(title);
      if (hwnd == 0) return;

      final dpr = _dpiScale(user32, hwnd);

      // 1) Windows 11 compositor rounding.
      final setAttr = dwmapi.lookupFunction<
          IntPtr Function(IntPtr, IntPtr, Pointer<Void>, IntPtr),
          int Function(int, int, Pointer<Void>, int)>('DwmSetWindowAttribute');
      final pref = malloc<Uint32>();
      pref.value = rounded ? 2 : 1; // DWMWCP_ROUND / DWMWCP_DONOTROUND
      final hr =
          setAttr(hwnd, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, pref.cast(), 4);
      malloc.free(pref);
      _dwmRounding = rounded && hr == 0;

      // 2) Region fallback (Windows 10, or DWM refused).
      if (!_dwmRounding) {
        _applyRegion(user32, hwnd, rounded ? (baseRadius * dpr).round() : 0);
      } else if (_regionInstalled) {
        // Drop a previously installed region so DWM rounding is the only clip.
        _applyRegion(user32, hwnd, 0);
      }
    } catch (_) {
      // Older Windows: square corners, no failure surfaced to the user.
    }
  }

  static void _applyRegion(DynamicLibrary user32, int hwnd, int radius) {
    final setWindowRgn = user32.lookupFunction<
        Int32 Function(IntPtr, IntPtr, Int32),
        int Function(int, int, int)>('SetWindowRgn');
    if (radius <= 0) {
      if (_regionInstalled) setWindowRgn(hwnd, 0, 1);
      _regionInstalled = false;
      return;
    }
    final getRect = user32.lookupFunction<
        Int32 Function(IntPtr, Pointer<Int32>),
        int Function(int, Pointer<Int32>)>('GetWindowRect');
    final rect = malloc<Int32>(4);
    if (getRect(hwnd, rect) == 0) {
      malloc.free(rect);
      return;
    }
    final w = rect[2] - rect[0];
    final h = rect[3] - rect[1];
    malloc.free(rect);

    final gdi32 = DynamicLibrary.open('gdi32.dll');
    final createRoundRectRgn = gdi32.lookupFunction<
        IntPtr Function(Int32, Int32, Int32, Int32, Int32, Int32),
        int Function(int, int, int, int, int, int)>('CreateRoundRectRgn');
    // +1 on width/height: a region excludes the right/bottom edge pixel.
    final rgn = createRoundRectRgn(0, 0, w + 1, h + 1, radius, radius);
    if (rgn == 0) return;
    // Windows owns the region after SetWindowRgn succeeds.
    _regionInstalled = setWindowRgn(hwnd, rgn, 1) != 0;
  }

  /// Device pixel ratio of the window (96 DPI = 1.0).
  static double _dpiScale(DynamicLibrary user32, int hwnd) {
    try {
      final getDpi = user32.lookupFunction<Uint32 Function(IntPtr),
          int Function(int)>('GetDpiForWindow');
      final dpi = getDpi(hwnd);
      if (dpi >= 72 && dpi <= 480) return dpi / 96.0;
    } catch (_) {}
    return 1.0;
  }
}
