import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';

/// The UI must read and write exactly the engine's document (D-008); a key
/// name mismatch would silently reset a setting to its default.
void main() {
  test('defaults match engine/src/settings.rs', () {
    const s = AppSettings();
    expect(s.lang, AppLang.ar);
    expect(s.storedLangTag, 'ar');
    expect(s.langPackMissing, isFalse);
    expect(s.themeMode, ThemeMode.dark);
    expect(s.guardAutostart, isTrue);
    expect(s.autoResumeScans, isTrue);
    expect(s.dndMode, isFalse);
    expect(s.syncIntervalHours, 6);
    expect(s.updateChannel, 'stable');
    expect(s.soundEnabled, isTrue);
    expect(s.soundVolume, 70);
    expect(s.toastEnabled, isTrue, reason: 'desktop cards are on by default (D-013)');
    expect(s.scanQuarantineDefault, isTrue);
    expect(s.canaryPaths, isEmpty);
  });

  test('engine JSON keys are the documented snake_case contract', () {
    const s = AppSettings(
      lang: AppLang.en,
      themeMode: ThemeMode.light,
      dndMode: true,
      syncIntervalHours: 24,
      canaryPaths: ['C:\\a', 'C:\\b'],
    );
    final json = s.toEngineJson();
    expect(json['lang'], 'en');
    expect(json['theme'], 'light');
    expect(json['dnd'], isTrue);
    expect(json['sync_interval_hours'], 24);
    expect(json['canary_paths'], hasLength(2));
    // Every documented key must be present in a full write.
    for (final key in const [
      'guard_autostart',
      'close_to_tray',
      'auto_resume_scans',
      'nvd_api_key',
      'ioc_feed_url',
      'ioc_feed_key',
      'lm_url',
      'lm_model',
      'update_manifest_url',
      'update_channel',
      'nl_bar_enabled',
      'sound_enabled',
      'sound_volume',
      'toast_enabled',
      'scan_quarantine_default',
    ]) {
      expect(json.containsKey(key), isTrue, reason: 'missing $key');
    }
  });

  test('roundtrip through the engine document preserves every field', () {
    const original = AppSettings(
      lang: AppLang.en,
      themeMode: ThemeMode.system,
      guardAutostart: false,
      autoResumeScans: false,
      dndMode: true,
      syncIntervalHours: 12,
      nvdApiKey: 'nvd',
      iocFeedUrl: 'https://example.com/hashes.csv',
      iocFeedKey: 'auth-key',
      lmUrl: 'http://localhost:1234',
      lmModel: 'qwen',
      updateManifestUrl: 'https://example.com/m.json',
      updateChannel: 'beta',
      nlBarEnabled: false,
      soundEnabled: false,
      soundVolume: 15,
      toastEnabled: false,
      scanQuarantineDefault: false,
      canaryPaths: [r'C:\one', r'D:\two'],
    );
    final back = AppSettings.fromEngineJson(original.toEngineJson());
    expect(back.lang, original.lang);
    expect(back.themeMode, original.themeMode);
    expect(back.guardAutostart, isFalse);
    expect(back.autoResumeScans, isFalse);
    expect(back.dndMode, isTrue);
    expect(back.syncIntervalHours, 12);
    expect(back.nvdApiKey, 'nvd');
    expect(back.iocFeedUrl, 'https://example.com/hashes.csv');
    expect(back.iocFeedKey, 'auth-key');
    expect(back.lmUrl, 'http://localhost:1234');
    expect(back.lmModel, 'qwen');
    expect(back.updateManifestUrl, 'https://example.com/m.json');
    expect(back.updateChannel, 'beta');
    expect(back.nlBarEnabled, isFalse);
    expect(back.soundEnabled, isFalse);
    expect(back.soundVolume, 15);
    expect(back.toastEnabled, isFalse);
    expect(back.scanQuarantineDefault, isFalse);
    expect(back.canaryPaths, hasLength(2));
  });

  test('closing the window quits unless the user asked for the background', () {
    // D-039: the engine's lifetime follows this switch, so its default is the
    // one the user chose — closing the window ends both.
    expect(const AppSettings().closeToTray, isFalse);
    expect(AppSettings.fromEngineJson(const {}).closeToTray, isFalse);
    final back = AppSettings.fromEngineJson(
        const AppSettings(closeToTray: true).toEngineJson());
    expect(back.closeToTray, isTrue);
  });

  test('unknown or missing keys fall back to defaults instead of throwing', () {
    final s = AppSettings.fromEngineJson({'lang': 'en', 'future_key': 42});
    expect(s.lang, AppLang.en);
    expect(s.themeMode, ThemeMode.dark);
    expect(s.syncIntervalHours, 6);
  });

  test('a partial patch merges without wiping other fields', () {
    const current = AppSettings(dndMode: true, syncIntervalHours: 24);
    final merged = AppSettings.fromEngineJson({
      ...current.toEngineJson(),
      'lang': 'en',
    });
    expect(merged.lang, AppLang.en);
    expect(merged.dndMode, isTrue);
    expect(merged.syncIntervalHours, 24);
  });

  // A tag this build cannot render is not nothing: it is a tag the engine really
  // stores (a hand-edited settings.json, or an RPC caller - the picker only
  // offers what ships), and the frame it produces has to be one language rather
  // than Arabic layout with English gaps and no explanation (D-049).
  test('a stored tag with no pack renders English and names the tag', () {
    final s = AppSettings.fromEngineJson({'lang': 'de'});
    expect(s.lang, AppLang.en,
        reason: 'the key-level fallback is English, so the frame must match it');
    expect(s.storedLangTag, 'de',
        reason: 'the stored tag is what the screen has to name');
    expect(s.langPackMissing, isTrue);
  });

  test('a bundled tag, its regional form and a short are not "missing"', () {
    for (final tag in const ['ar', 'en', 'en-GB', 'EN']) {
      final s = AppSettings.fromEngineJson({'lang': tag});
      expect(s.langPackMissing, isFalse, reason: '$tag has a pack');
    }
    expect(AppSettings.fromEngineJson({'lang': 'en-GB'}).lang, AppLang.en);
    expect(AppSettings.fromEngineJson({'lang': 'ar'}).lang, AppLang.ar);
    expect(AppSettings.fromEngineJson({'lang': 'en-GB'}).storedLangTag, 'en-GB',
        reason: 'the stored tag survives even when it resolves to a pack');
  });

  test('an absent tag is the engine default, not a missing pack', () {
    final s = AppSettings.fromEngineJson({'theme': 'light'});
    expect(s.lang, AppLang.ar);
    expect(s.langPackMissing, isFalse);
  });

  test('a write sends the stored tag back, so nothing overwrites it', () {
    final s = AppSettings.fromEngineJson({'lang': 'de', 'theme': 'light'});
    expect(s.toEngineJson()['lang'], 'de',
        reason: 'a save of some other setting must not silently drop the tag');
    // The picker is the one thing that replaces it, and only with a bundled code.
    final picked = AppSettings.fromEngineJson({
      ...s.toEngineJson(),
      'lang': 'ar',
    });
    expect(picked.lang, AppLang.ar);
    expect(picked.langPackMissing, isFalse);
  });
}
