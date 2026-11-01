// Mounting a screen the way the app mounts it, and then touching everything.
//
// A screen test that only checks the first frame proves the widget builds; it
// says nothing about the twelve buttons under it. [sweep] walks the rendered
// tree, taps every control it finds, and reports what it touched - so "every
// interactive control" becomes a list that can be compared with a ledger
// instead of a claim.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'fake_engine.dart';

/// The real language packs, read from disk. Loading them through the asset
/// bundle ties the first frame to when that future resolves, which makes
/// assertions flaky; the parity test guards the packs themselves.
class FixedI18n extends I18nLoader {
  @override
  Future<Map<String, Map<String, String>>> build() async {
    final tables = <String, Map<String, String>>{};
    for (final lang in bundledLangs.keys) {
      final table = <String, String>{};
      for (final file
          in Directory('assets/i18n/$lang').listSync().whereType<File>()) {
        final decoded =
            (jsonDecode(file.readAsStringSync()) as Map).cast<String, dynamic>();
        decoded.forEach((k, v) => table[k] = v.toString());
      }
      tables[lang] = table;
    }
    return tables;
  }
}

/// A viewport big enough for the longest screen, so a control is not "missing"
/// just because it is below the fold.
const _viewport = Size(1700, 2400);

/// Where the screen under test lives in the throw-away router.
const _screenPath = '/screen';

/// A mounted screen: its fake engine, and the router that lets a tap which
/// navigates (`context.go('/hardening')`) land somewhere instead of throwing.
class Mounted {
  Mounted(this.engine, this.router, this.container);

  final FakeEngine engine;
  final GoRouter router;
  final ProviderContainer container;

  /// Whether the router still shows the screen under test. A screen (or the
  /// shell) can navigate to a route this router does not have, which leaves
  /// the delegate with no match at all.
  bool get onScreen {
    try {
      return router.state.uri.path == _screenPath;
    } on StateError {
      return false;
    }
  }

  /// Returns to the screen under test after a tap navigated away.
  void back() {
    if (!onScreen) router.go(_screenPath);
  }
}

/// Mounts [screen] under the same providers the app uses, with a fake engine
/// and a router that contains the screen plus stubs for every other route.
///
/// The real shell (navigation rail, title bar) is deliberately not mounted:
/// this file is about the screen's own controls.
///
/// The language packs and the settings document are resolved *before* the
/// screen is mounted. In the app both are async, and a screen that builds
/// first - with empty tables - renders raw keys (`settings.dnd`) until
/// something rebuilds it. That startup ordering is worth its own test; here it
/// would only make every label depend on which future won, so the harness
/// starts from the steady state.
Future<Mounted> openScreen(
  WidgetTester tester,
  Widget screen, {
  FakeEngine? engine,
  List<String> otherRoutes = const [],
}) async {
  // ignore: invalid_use_of_visible_for_testing_member
  SharedPreferences.setMockInitialValues({});
  _mockWindowChannels();
  final fake = engine ?? FakeEngine();
  tester.view.physicalSize = _viewport;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);

  final router = GoRouter(
    initialLocation: _screenPath,
    routes: [
      GoRoute(path: _screenPath, builder: (_, _) => Scaffold(body: screen)),
      for (final path in otherRoutes)
        GoRoute(
          path: path,
          builder: (_, _) => Scaffold(body: Text('stub:$path')),
        ),
    ],
  );
  addTearDown(router.dispose);

  // The same scope in both frames, with the same number of overrides, so the
  // preload frame and the real frame share one container.
  final overrides = [
    engineIpcProvider.overrideWithValue(fake),
    i18nProvider.overrideWith(FixedI18n.new),
  ];
  await tester.pumpWidget(
      ProviderScope(overrides: overrides, child: const SizedBox.shrink()));
  final container = ProviderScope.containerOf(
      tester.element(find.byType(SizedBox).first));
  for (var i = 0; i < 50; i++) {
    final ready = container.read(i18nProvider).hasValue &&
        container.read(settingsProvider).hasValue;
    if (ready) break;
    await tester.pump(const Duration(milliseconds: 25));
  }

  await tester.pumpWidget(ProviderScope(
    overrides: overrides,
    child: MaterialApp.router(
      theme: AppTheme.darkTheme,
      routerConfig: router,
    ),
  ));
  await settle(tester);
  // One alert, so a screen that only renders pushed traffic has something to
  // render and its dismiss/mute controls exist to be tapped.
  fake.goLive();
  await settle(tester);
  return Mounted(fake, router, container);
}

/// The shell is a desktop window: its title bar drags the window, minimises it
/// and toggles the tray. Those calls are plugin channels that do not exist in a
/// widget test, and without an answer the corresponding buttons throw instead
/// of doing nothing — which would hide whether the button itself works.
void _mockWindowChannels() {
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  for (final name in const [
    'window_manager',
    'tray_manager',
    'screen_retriever',
  ]) {
    messenger.setMockMethodCallHandler(MethodChannel(name), (call) async {
    // A window is not maximised unless something said so: answering `null`
    // makes the green button's `await isMaximized() ? ... : ...` throw.
    switch (call.method) {
      case 'isMaximized':
      case 'isMinimized':
      case 'isVisible':
      case 'isFocused':
      case 'isFullScreen':
        return false;
    }
    return null;
  });
  }
}

/// Pumps a few frames without requiring the screen to become idle: a spinner
/// that never stops is a state to test, not a reason to hang.
///
/// The count matters for the ledger. A screen starts on its own defaults, then
/// `settings.get` answers with the saved language, and only then does text
/// replace the raw keys; a snapshot taken too early would record
/// `SwitchListTile(settings.dnd)` and then fail the next run, when the same
/// pump budget happens to land on the other side of that future.
Future<void> settle(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump(const Duration(milliseconds: 25));
  }
}

/// What a sweep saw.
class Sweep {
  Sweep();

  /// Stable description of every control found, in discovery order.
  final List<String> found = [];

  /// The subset that could be tapped without an exception.
  final List<String> tapped = [];

  /// Tap-time failures, in the order they happened.
  final List<String> errors = [];

  bool get clean => errors.isEmpty;
}

/// Finds every interactive control under the mounted tree and taps each one
/// once, re-reading the tree between taps.
///
/// Re-reading matters: a tap usually rebuilds the screen, and an element
/// collected before the rebuild is defunct. Labels (type plus the text a human
/// would name it by) are the stable handle, with an occurrence suffix so four
/// identical icons are four controls rather than one.
Future<Sweep> sweep(WidgetTester tester, Mounted mounted,
    {int limit = 300}) async {
  final result = Sweep();
  final tapped = <String>{};

  result.found.addAll(_labels(_collect(tester)));

  for (var step = 0; step < limit; step++) {
    if (!mounted.onScreen) {
      mounted.back();
      await settle(tester);
    }
    final targets = _collect(tester);
    final labels = _labels(targets);
    String? next;
    for (final label in labels) {
      if (!tapped.contains(label)) {
        next = label;
        break;
      }
    }
    if (next == null) break;
    final target = targets[labels.indexOf(next)];
    if (!result.found.contains(next)) result.found.add(next);
    tapped.add(next);

    try {
      await tester.tap(
        find.byElementPredicate((e) => identical(e, target.element)),
        warnIfMissed: false,
      );
      await settle(tester);
      result.tapped.add(next);
    } on Object catch (error) {
      result.errors.add('$next -> $error');
    }
    _dismissOverlays(tester);
    await settle(tester);
    await _keepEnglish(tester, mounted);
    // A thrown build error is reported through the tester, not by `tap`.
    final exception = tester.takeException();
    if (exception != null) result.errors.add('$next -> $exception');
  }
  return result;
}

/// A tap may switch language (the title bar, and the Settings screen's
/// language picker), which translates every label on the next frame. The
/// ledger is a list of controls, not of translations, so the sweep returns to
/// English between taps; the language switch itself has its own test.
Future<void> _keepEnglish(WidgetTester tester, Mounted mounted) async {
  final settings = mounted.container.read(settingsProvider).value;
  if (settings == null || settings.lang == AppLang.en) return;
  await mounted.container.read(settingsProvider.notifier).setLang(AppLang.en);
  await settle(tester);
}

void _dismissOverlays(WidgetTester tester) {
  final overlay = find.byType(AlertDialog).evaluate().isNotEmpty ||
      find.byType(Dialog).evaluate().isNotEmpty ||
      find.byType(BottomSheet).evaluate().isNotEmpty;
  if (!overlay) return;
  final navigator = tester.state<NavigatorState>(find.byType(Navigator).first);
  navigator.pop();
}

class _Target {
  _Target(this.element);

  final Element element;
}

/// Widget types that are a control on their own.
bool _isControl(Widget widget) =>
    widget is ButtonStyleButton ||
    widget is IconButton ||
    widget is Switch ||
    widget is Checkbox ||
    widget is Radio<dynamic> ||
    widget is DropdownButton<dynamic> ||
    widget is PopupMenuButton<dynamic> ||
    widget is SegmentedButton<dynamic> ||
    widget is Slider ||
    widget is TextField ||
    widget is Tab ||
    widget is InkWell ||
    widget is GestureDetector ||
    widget is ListTile ||
    widget is SwitchListTile ||
    widget is CheckboxListTile;

bool _isEnabled(Widget widget) {
  if (widget is ButtonStyleButton) return widget.onPressed != null;
  if (widget is IconButton) return widget.onPressed != null;
  if (widget is InkWell) return widget.onTap != null;
  if (widget is GestureDetector) {
    return widget.onTap != null || widget.onPanDown != null;
  }
  if (widget is ListTile) return widget.onTap != null;
  if (widget is Switch) return widget.onChanged != null;
  if (widget is Checkbox) return widget.onChanged != null;
  if (widget is Slider) return widget.onChanged != null;
  if (widget is PopupMenuButton<dynamic>) return widget.enabled;
  return true;
}

List<_Target> _collect(WidgetTester tester) {
  final targets = <_Target>[];
  void visit(Element element) {
    final widget = element.widget;
    if (_isControl(widget) && _isEnabled(widget)) {
      targets.add(_Target(element));
      // Do not descend into a control: the parts inside it are not separate
      // controls, and tapping both would double-fire.
      return;
    }
    element.visitChildren(visit);
  }

  for (final scaffold in find.byType(Scaffold).evaluate().take(1)) {
    scaffold.visitChildren(visit);
  }
  return targets;
}

/// Labels in tree order, with `#n` appended when the same description repeats.
List<String> _labels(List<_Target> targets) {
  final counts = <String, int>{};
  final labels = <String>[];
  for (final target in targets) {
    final base = _describe(target.element);
    final seen = counts[base] = (counts[base] ?? 0) + 1;
    labels.add(seen == 1 ? base : '$base#$seen');
  }
  return labels;
}

/// A name that survives a rebuild: the widget type plus the text (or tooltip,
/// or icon) that identifies it to a human reading the ledger. When the control
/// itself carries no text - a `GestureDetector` wrapping a row - the label
/// comes from the first tooltip or text inside it, so a navigation item reads
/// `GestureDetector(Dashboard)` rather than `GestureDetector#7`.
String _describe(Element element) {
  final widget = element.widget;
  final type = widget.runtimeType.toString();
  final parts = <String>[];
  if (widget is IconButton && widget.tooltip != null) parts.add(widget.tooltip!);
  if (widget is ButtonStyleButton) {
    parts.add(_textOf(widget.child) ?? '');
  }
  if (widget is SwitchListTile) parts.add(_textOf(widget.title) ?? '');
  if (widget is CheckboxListTile) parts.add(_textOf(widget.title) ?? '');
  if (widget is ListTile) parts.add(_textOf(widget.title) ?? '');
  if (widget is Tab) parts.add(_textOf(widget.child) ?? '');
  parts.add(_textOf(widget) ?? '');
  parts.removeWhere((p) => p.trim().isEmpty);
  if (parts.isEmpty) {
    final hint = _descendantHint(element);
    if (hint != null) parts.add(hint);
  }
  final unique = <String>[];
  for (final part in parts) {
    if (!unique.contains(part)) unique.add(part);
  }
  if (unique.isEmpty) {
    // A bare `GestureDetector` is not a name: the private widget around it is
    // (`_TrafficLight`), and it survives a rebuild.
    final owner = _ownerType(element);
    return owner == null ? type : '$owner/$type';
  }
  return '$type(${unique.join('|')})';
}

const _layoutTypes = {
  'Padding',
  'Center',
  'SizedBox',
  'Row',
  'Column',
  'Expanded',
  'Flexible',
  'Container',
  'DecoratedBox',
  'MouseRegion',
  'Semantics',
  'Focus',
  'Material',
  'InkWell',
  'InkResponse',
  'Stack',
  'Positioned',
  'ConstrainedBox',
  'Align',
  'Builder',
};

/// The nearest ancestor widget with a name of its own: an app widget is
/// private (`_TrafficLight`, `_PathRow`), which is exactly the name a reader
/// needs, so private ancestors win over framework ones.
String? _ownerType(Element element) {
  String? framework;
  String? found;
  element.visitAncestorElements((ancestor) {
    final type = ancestor.widget.runtimeType.toString();
    if (type.startsWith('_')) {
      found = type;
      return false;
    }
    if (framework == null && !_layoutTypes.contains(type)) framework = type;
    return true;
  });
  return found ?? framework;
}

/// The first tooltip, then the first text, inside [element]. Icons are
/// deliberately not a hint: a code point is not a name.
String? _descendantHint(Element element) {
  String? tooltip;
  String? text;
  var visited = 0;
  void visit(Element e) {
    if (visited++ > 60 || (tooltip != null && text != null)) return;
    final widget = e.widget;
    if (tooltip == null && widget is Tooltip && widget.message != null) {
      tooltip = widget.message!.trim();
    }
    if (text == null) {
      final candidate = _visibleText(widget);
      if (candidate != null && candidate.trim().isNotEmpty) {
        text = candidate.trim();
      }
    }
    e.visitChildren(visit);
  }

  element.visitChildren(visit);
  return tooltip ?? text;
}

String? _visibleText(Widget widget) {
  if (widget is Text) {
    final data = widget.data ?? widget.textSpan?.toPlainText();
    return _readable(data);
  }
  if (widget is RichText) return _readable(widget.text.toPlainText());
  return null;
}

/// Icon fonts draw their glyphs as private-use characters. A string made only
/// of those is an icon that happens to be a `Text`, not a name a human can
/// read in a ledger.
String? _readable(String? value) {
  if (value == null || value.trim().isEmpty) return null;
  final runes = value.trim().runes.toList();
  final isGlyph = runes.every((r) =>
      (r >= 0xE000 && r <= 0xF8FF) ||
      (r >= 0xF0000 && r <= 0x10FFFD) ||
      r == 0x200D ||
      r == 0xFE0F);
  return isGlyph ? null : value.trim();
}

String? _textOf(Widget? widget) {
  if (widget == null) return null;
  if (widget is Text) {
    final data = widget.data ?? widget.textSpan?.toPlainText();
    return data?.trim();
  }
  if (widget is RichText) return widget.text.toPlainText().trim();
  if (widget is Tooltip) return widget.message;
  if (widget is Icon) return widget.icon?.codePoint.toString();
  if (widget is TextField) {
    return widget.decoration?.hintText ?? widget.decoration?.labelText;
  }
  if (widget is ListTile) return _textOf(widget.title ?? const SizedBox());
  if (widget is SwitchListTile) return _textOf(widget.title);
  if (widget is CheckboxListTile) return _textOf(widget.title);
  return null;
}