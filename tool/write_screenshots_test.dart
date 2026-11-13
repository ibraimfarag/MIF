// Dev-only: renders the shipped UI in light mode and writes the README images.
//
//   flutter test --no-pub tool/write_screenshots_test.dart
//
// This file is deliberately **not** under `test/`: `flutter test` collects that
// directory, and a screenshot writer has no business running (or writing files)
// during the normal suite. Nothing here is shipped.
//
// The engine is canned (`_SampleEngine`), so what the images show is the real
// widget tree rendering one fixed, honest sample machine — an idle-audit score
// of 78 with two open findings. The images illustrate; the numbers in
// `docs/CONTRAST.md` and the `scripts\verify-*.ps1` probes are what prove.
//
// Method names and every field name below are the ones the screens parse
// (`lib/models/audit_models.dart`, `lib/core/sync/sync_status.dart`,
// `lib/core/i18n/app_i18n.dart`, `lib/core/ipc/helper_status.dart`). A wrong key
// renders an empty state, and the image then lies about what the product shows.
//
// The layout is Arabic RTL because that is the app's default language.

import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The window the shell is designed for (main.dart opens at 1440x860).
const Size _window = Size(1600, 1000);

/// The shell's navigation rail is 96 px wide and sits at the trailing edge.
const double _railWidth = 96;

const String _outDir = 'docs/images';

/// Light-palette page background and card surface (`lib/core/theme/app_theme.dart`).
const int _pageBackground = 0xF4F7FB;
const int _surface = 0xFFFFFF;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() async {
    // Without the real fonts every glyph is a box in a test render.
    await _loadFont('Cairo', 'assets/fonts/Cairo.ttf');
    await _loadFont('JetBrainsMono', 'assets/fonts/JetBrainsMono.ttf');
  });

  testWidgets('writes the light-mode README screenshots', (tester) async {
    // The widget-test framework exposes no public hook for seeding
    // SharedPreferences; `setMockInitialValues` is the documented, test-only
    // way to do it. This file is run by an explicit `flutter test <path>`, not
    // collected by the default suite, hence the narrow ignore.
    // ignore: invalid_use_of_visible_for_testing_member
    SharedPreferences.setMockInitialValues(<String, Object>{});
    Directory(_outDir).createSync(recursive: true);
    tester.view.physicalSize = _window;
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    _assertFontsLoaded();

    final boundaryKey = GlobalKey();
    await tester.pumpWidget(RepaintBoundary(
      key: boundaryKey,
      child: ProviderScope(
        overrides: [engineIpcProvider.overrideWithValue(_SampleEngine())],
        child: const MicsApp(),
      ),
    ));
    await tester.pumpAndSettle();

    // The dashboard runs the audit itself (post-frame), so it must be first:
    // the audit screen then shows the report instead of its empty state.
    //
    // Each screen is asserted before it is written: an image of an empty or
    // error state is worse than no image, because it looks like the product.
    _expectClean(tester);
    expect(find.text('78'), findsOneWidget,
        reason: 'the dashboard gauge should have settled on the score');
    expect(find.text('L1'), findsOneWidget);
    await _capture(tester, boundaryKey, 'light-dashboard.png');

    final rtl = _isRtl(tester);
    await _tapRail(tester, Icons.fact_check_outlined, rtl: rtl);
    _expectClean(tester);
    expect(find.textContaining('SMBv1 Protocol'), findsWidgets);
    expect(find.textContaining('3 local accounts'), findsWidgets);
    await _capture(tester, boundaryKey, 'light-audit.png');

    await _tapRail(tester, Icons.cloud_sync_outlined, rtl: rtl);
    _expectClean(tester);
    expect(find.textContaining('76737'), findsWidgets);
    expect(find.textContaining('1766'), findsWidgets);
    await _capture(tester, boundaryKey, 'light-intel.png');

    await _tapRail(tester, Icons.settings_outlined, rtl: rtl);
    _expectClean(tester);
    expect(find.byType(SegmentedButton<ThemeMode>), findsOneWidget);
    expect(find.byType(SwitchListTile), findsAtLeastNWidgets(4));
    await _capture(tester, boundaryKey, 'light-settings.png');

    // The receipt is only worth anything if the hash function is right.
    expect(_sha256Hex(utf8.encode('')),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(_sha256Hex(utf8.encode('abc')),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
}

/// Fails the run at the screen that caused it, instead of at the end with
/// "multiple exceptions were detected".
void _expectClean(WidgetTester tester) {
  expect(tester.takeException(), isNull);
}

Future<void> _loadFont(String family, String asset) async {
  final loader = FontLoader(family)..addFont(rootBundle.load(asset));
  await loader.load();
}

/// Proves the real fonts are in the render, not the test fallback.
///
/// Flutter's test font gives every glyph a width of exactly one em, so a
/// measured width of `characters * fontSize` is the Ahem signature. Real fonts
/// also measure differently from the default family — the second check.
void _assertFontsLoaded() {
  const size = 16.0;
  for (final (family, sample) in const <(String, String)>[
    ('Cairo', 'MI CS — الحماية الذكية 78'),
    ('JetBrainsMono', r'C:\Users\Public\Documents\passwords.txt'),
  ]) {
    final loaded = _measure(sample, family, size);
    final fallback = _measure(sample, null, size);
    stdout.writeln('font $family: ${sample.length} glyphs -> '
        '${loaded.toStringAsFixed(1)} px '
        '(default family ${fallback.toStringAsFixed(1)} px, '
        'Ahem signature ${(sample.length * size).toStringAsFixed(1)} px)');
    expect(loaded, isNot(equals(sample.length * size)),
        reason: '$family is not loaded: the width is the test-font signature');
    expect(loaded, isNot(equals(fallback)),
        reason: '$family renders exactly like the default family');
  }
}

double _measure(String text, String? family, double size) {
  final painter = TextPainter(
    text: TextSpan(
        text: text, style: TextStyle(fontFamily: family, fontSize: size)),
    textDirection: TextDirection.ltr,
  )..layout();
  return painter.width;
}

bool _isRtl(WidgetTester tester) =>
    Directionality.of(tester.element(find.byType(Scaffold).first)) ==
    TextDirection.rtl;

/// Taps the rail entry for [icon]. The same icon can also appear inside the
/// screen body, so the candidate that sits in the rail strip wins.
Future<void> _tapRail(WidgetTester tester, IconData icon,
    {required bool rtl}) async {
  final matches = find.byIcon(icon);
  final count = tester.widgetList(matches).length;
  for (var i = 0; i < count; i++) {
    final center = tester.getCenter(matches.at(i));
    final inRail =
        rtl ? center.dx > _window.width - _railWidth : center.dx < _railWidth;
    if (inRail) {
      await tester.tapAt(center);
      await tester.pumpAndSettle();
      return;
    }
  }
  fail('no navigation-rail entry for $icon (found $count matches)');
}

Future<void> _capture(
    WidgetTester tester, GlobalKey boundaryKey, String name) async {
  final boundary =
      tester.renderObject<RenderRepaintBoundary>(find.byKey(boundaryKey));
  late Uint8List png;
  var distinct = 0;
  var sampled = 0;
  var offBackground = 0;
  var luminance = 0.0;
  await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: 1.0);
    final data = await image.toByteData(format: ui.ImageByteFormat.png);
    png = data!.buffer.asUint8List();

    // A blank frame is the failure mode that still "writes an image", so
    // measure what is in it: distinct colours, how much of it is not the page
    // background, and the mean luminance (this is the light theme, so a dark
    // frame means the palette never switched).
    final rgba = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
    final bytes = rgba!.buffer.asUint8List();
    final seen = <int>{};
    var sum = 0.0;
    for (var i = 0; i + 3 < bytes.length; i += 4) {
      final r = bytes[i], g = bytes[i + 1], b = bytes[i + 2];
      final rgb = (r << 16) | (g << 8) | b;
      seen.add(rgb);
      if (rgb != _pageBackground && rgb != _surface) offBackground++;
      sum += (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0;
      sampled++;
    }
    distinct = seen.length;
    luminance = sum / sampled;
    image.dispose();
  });

  final file = File('$_outDir/$name')..writeAsBytesSync(png);
  final fraction = offBackground / sampled;
  // stdout, so the run leaves a text receipt for an image nobody can see.
  stdout.writeln('wrote ${file.path}  '
      '${_window.width.toInt()}x${_window.height.toInt()}  '
      '${png.lengthInBytes} bytes  sha256 ${_sha256Hex(png)}');
  stdout.writeln('  $distinct distinct colours  '
      '${(fraction * 100).toStringAsFixed(1)}% non-background  '
      'mean luminance ${luminance.toStringAsFixed(3)}');

  // Two independent "there is something on this frame" signals, either of
  // which is enough; the luminance floor is what catches a dark-mode capture.
  expect(distinct > 2000 || fraction > 0.02, isTrue,
      reason: '$name looks blank ($distinct colours, '
          '${(fraction * 100).toStringAsFixed(1)}% non-background)');
  expect(luminance, greaterThan(0.6),
      reason: '$name is dark: the light palette did not apply');
}

/// The engine, canned. State is `running`, so the UI renders its normal
/// screens rather than an offline banner; every response is the shape the
/// screens parse.
class _SampleEngine extends EngineIpc {
  @override
  Future<bool> ensureRunning() async => true;

  @override
  EngineState get state => EngineState.running;

  @override
  Stream<EngineState> get statusStream =>
      Stream<EngineState>.value(EngineState.running);

  @override
  String resolveEnginePath() => 'mics-engine.exe';

  @override
  void dispose() {}

  @override
  Future<dynamic> request(
    String method, [
    Map<String, dynamic>? params,
    Duration timeout = const Duration(seconds: 120),
  ]) async {
    switch (method) {
      case 'ping':
        return 'pong';
      case 'settings.get':
        return _settings;
      case 'settings.set':
        return <String, dynamic>{..._settings, ...?params};
      case 'sync.status':
        return _syncStatus;
      case 'helper.status':
        return _helperStatus;
      case 'guard.status':
        return _guardStatus;
      case 'ids.status':
        return _idsStatus;
      case 'incident.list':
        return _incidents;
      case 'audit.run':
        return _auditReport;
      case 'job.list':
        return _jobs;
      case 'update.check':
        return <String, dynamic>{'available': false, 'version': '0.1.0'};
      default:
        throw EngineException(
            'the screenshot harness has no canned answer for "$method"');
    }
  }
}

/// `settings.get` — the engine's own document key names, light + Arabic.
const Map<String, dynamic> _settings = <String, dynamic>{
  'lang': 'ar',
  'theme': 'light',
  'guard_autostart': true,
  'auto_resume_scans': true,
  'dnd': false,
  'sync_interval_hours': 6,
  'nvd_api_key': '',
  'ioc_feed_url': '',
  'ioc_feed_key': '',
  'update_manifest_url': '',
  'update_channel': 'stable',
  'sound_enabled': true,
  'sound_volume': 70,
  'toast_enabled': true,
  'scan_quarantine_default': true,
  'canary_paths': <String>[
    r'C:\Users\Public\Documents\passwords.txt',
    r'C:\Users\Public\Documents\payroll.xlsx',
  ],
};

/// `sync.status` — a machine that has synced, minus the hash feed.
const Map<String, dynamic> _syncStatus = <String, dynamic>{
  'online': true,
  'ioc_hash_total': 0,
  'age_seconds': 1500,
  'sync_interval_hours': 6,
  'ioc_domain_total': 76737,
  'kev_total': 1766,
  'cve_cache_total': 412,
  'geoip_countries': 3,
  'sources': <Map<String, dynamic>>[
    <String, dynamic>{
      'source': 'ioc_domains',
      'state': 'ok',
      'network': true,
      'on_demand': false,
      'age_seconds': 1500,
      'seconds_to_due': 20100,
      'failures': 0,
      'items': 76737,
      'last_error': null,
      'detail': 'StevenBlack unified hosts',
      'version': null,
    },
    <String, dynamic>{
      'source': 'kev',
      'state': 'ok',
      'network': true,
      'on_demand': false,
      'age_seconds': 1500,
      'seconds_to_due': 20100,
      'failures': 0,
      'items': 1766,
      'last_error': null,
      'detail': 'CISA Known Exploited Vulnerabilities',
      'version': null,
    },
    <String, dynamic>{
      'source': 'nvd',
      'state': 'ok',
      'network': true,
      'on_demand': true,
      'age_seconds': 5400,
      'seconds_to_due': null,
      'failures': 0,
      'items': 412,
      'last_error': null,
      'detail': 'installed software, on demand during a vulnerability scan',
      'version': null,
    },
    <String, dynamic>{
      'source': 'geoip_blocklists',
      'state': 'ok',
      'network': true,
      'on_demand': true,
      'age_seconds': null,
      'seconds_to_due': null,
      'failures': 0,
      'items': 3,
      'last_error': null,
      'detail': 'country CIDR lists read from disk',
      'version': null,
    },
    <String, dynamic>{
      'source': 'ioc_hashes',
      'state': 'not_configured',
      'network': true,
      'on_demand': false,
      'age_seconds': null,
      'seconds_to_due': null,
      'failures': 0,
      'items': 0,
      'last_error': null,
      'detail': 'no hash feed URL and Auth-Key set',
      'version': null,
    },
  ],
};

const Map<String, dynamic> _helperStatus = <String, dynamic>{
  'service': 'MICSHelper',
  'installed': true,
  'running': true,
  'state': 'running',
  'reachable': true,
  'elevated': true,
  'version': '0.1.0',
  'pipe': 'mics_helper',
};

const Map<String, dynamic> _guardStatus = <String, dynamic>{
  'running': true,
  'elevated': true,
  'rules': 6,
  'events': 12,
  'killed': 0,
  'targets': 0,
};

const Map<String, dynamic> _idsStatus = <String, dynamic>{
  'enabled': true,
  'blocked_domains': <String>[
    'ads.doubleclick.net',
    'telemetry.example.com',
    'tracker.example.org',
  ],
  'rules': 3,
};

const List<Map<String, dynamic>> _incidents = <Map<String, dynamic>>[
  <String, dynamic>{
    'id': 'inc-1',
    'title': 'Process started from a temporary folder',
    'severity': 'Medium',
    'status': 'open',
  },
  <String, dynamic>{
    'id': 'inc-2',
    'title': 'Canary file modified',
    'severity': 'High',
    'status': 'open',
  },
];

const List<Map<String, dynamic>> _jobs = <Map<String, dynamic>>[];

/// `audit.run` — section ids and wording follow
/// `engine/src/platform/windows/collectors.rs`; the machine is a normal Windows
/// box with SMBv1 still on and PUA blocking not set, which is what the two open
/// findings and the score of 78 describe.
final Map<String, dynamic> _auditReport = <String, dynamic>{
  'score': 78,
  'findings': <Map<String, dynamic>>[
    <String, dynamic>{
      'section': 'defender',
      'item': 'Real-time Protection',
      'status': 'Secure',
      'severity': 'Critical',
      'description': 'Real-time protection is enabled',
      'fix_available': false,
    },
    <String, dynamic>{
      'section': 'defender',
      'item': 'PUA Protection',
      'status': 'Warning',
      'severity': 'Medium',
      'description': 'Potentially unwanted app blocking is not set to Block',
      'fix_available': true,
    },
    <String, dynamic>{
      'section': 'firewall',
      'item': 'Domain Profile',
      'status': 'Secure',
      'severity': 'High',
      'description': 'The domain firewall profile is enabled',
      'fix_available': false,
    },
    <String, dynamic>{
      'section': 'rdp',
      'item': 'Remote Desktop',
      'status': 'Secure',
      'severity': 'High',
      'description': 'Remote Desktop is disabled',
      'fix_available': false,
    },
    <String, dynamic>{
      'section': 'smbv1',
      'item': 'SMBv1 Protocol',
      'status': 'Vulnerable',
      'severity': 'High',
      'description':
          'SMBv1 is enabled: the obsolete protocol ransomware spreads with',
      'fix_available': true,
    },
    <String, dynamic>{
      'section': 'uac',
      'item': 'UAC Level',
      'status': 'Secure',
      'severity': 'Medium',
      'description': 'User Account Control notifies on every change',
      'fix_available': false,
    },
    <String, dynamic>{
      'section': 'admins',
      'item': 'Administrator Accounts',
      'status': 'Warning',
      'severity': 'Medium',
      'description': '3 local accounts hold administrative rights',
      'fix_available': false,
    },
    <String, dynamic>{
      'section': 'hosts',
      'item': 'Managed Hosts Section',
      'status': 'Secure',
      'severity': 'Low',
      'description': 'The MI CS blocklist section is present',
      'fix_available': false,
    },
    <String, dynamic>{
      'section': 'remote_tools',
      'item': 'Remote-Access Tools',
      'status': 'Secure',
      'severity': 'Low',
      'description': 'No remote-access tool was found in the usual locations',
      'fix_available': false,
    },
  ],
  'startup_entries': <Map<String, dynamic>>[
    <String, dynamic>{
      'name': 'OneDrive',
      'command': r'C:\Users\<account>\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background',
      'location': r'HKCU\...\CurrentVersion\Run',
    },
    <String, dynamic>{
      'name': 'SecurityHealth',
      'command': r'%windir%\system32\SecurityHealthSystray.exe',
      'location': r'HKLM\...\CurrentVersion\Run',
    },
  ],
  'scheduled_tasks': <Map<String, dynamic>>[
    <String, dynamic>{
      'name': 'MicrosoftEdgeUpdateTaskMachineCore',
      'path': r'\Microsoft\EdgeUpdate\MicrosoftEdgeUpdateTaskMachineCore',
    },
    <String, dynamic>{
      'name': 'OneDriveStandaloneUpdater',
      'path': r'\OneDriveStandaloneUpdater',
    },
  ],
};

// ---------------- receipt hashing ----------------
//
// SHA-256 (FIPS 180-4), written out rather than pulled in: `crypto` is not a
// dependency of the app, and the images are the only thing this file produces
// a hash for. The test above checks it against two published vectors, so a
// receipt that prints can be trusted.

const List<int> _k256 = <int>[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

String _sha256Hex(List<int> input) {
  var h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a,
      h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;

  final message = <int>[...input, 0x80];
  while (message.length % 64 != 56) {
    message.add(0);
  }
  final bits = input.length * 8;
  for (var i = 7; i >= 0; i--) {
    message.add((bits >> (8 * i)) & 0xff);
  }

  final w = List<int>.filled(64, 0);
  for (var offset = 0; offset < message.length; offset += 64) {
    for (var i = 0; i < 16; i++) {
      final j = offset + i * 4;
      w[i] = (message[j] << 24) |
          (message[j + 1] << 16) |
          (message[j + 2] << 8) |
          message[j + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }

    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (var i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ (~e & g);
      final t1 = (h + s1 + ch + _k256[i] + w[i]) & 0xffffffff;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & 0xffffffff;
      h = g;
      g = f;
      f = e;
      e = (d + t1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xffffffff;
    }
    h0 = (h0 + a) & 0xffffffff;
    h1 = (h1 + b) & 0xffffffff;
    h2 = (h2 + c) & 0xffffffff;
    h3 = (h3 + d) & 0xffffffff;
    h4 = (h4 + e) & 0xffffffff;
    h5 = (h5 + f) & 0xffffffff;
    h6 = (h6 + g) & 0xffffffff;
    h7 = (h7 + h) & 0xffffffff;
  }

  final out = StringBuffer();
  for (final word in [h0, h1, h2, h3, h4, h5, h6, h7]) {
    out.write(word.toRadixString(16).padLeft(8, '0'));
  }
  return out.toString();
}

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xffffffff;
