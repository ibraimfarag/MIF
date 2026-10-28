import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';

/// The UI must read and write exactly the engine's document (D-008); a key
/// name mismatch would silently reset a setting to its default.
void main() {
  test('defaults match engine/src/settings.rs', () {
    const s = AppSettings();
    expect(s.lang, AppLang.ar);
    expect(s.themeMode, ThemeMode.dark);
    expect(s.guardAutostart, isTrue);
    expect(s.autoResumeScans, isTrue);
    expect(s.dndMode, isFalse);
    expect(s.syncIntervalHours, 6);
    expect(s.updateChannel, 'stable');
    expect(s.soundEnabled, isTrue);
    expect(s.soundVolume, 70);
    expect(s.scanQuarantineDefault, isTrue);
    expect(s.canaryPaths, isEmpty);
  });

  test('engine JSON keys are the documented snake_case contract', () {
    const s = AppSettings(
      lang: AppLang.en,
      themeMode: ThemeMode.light,
      dndMode: true,
      syncIntervalHours: 24,
      vtApiKey: 'abc',
      canaryPaths: ['C:\\a', 'C:\\b'],
    );
    final json = s.toEngineJson();
    expect(json['lang'], 'en');
    expect(json['theme'], 'light');
    expect(json['dnd'], isTrue);
    expect(json['sync_interval_hours'], 24);
    expect(json['vt_api_key'], 'abc');
    expect(json['canary_paths'], hasLength(2));
    // Every documented key must be present in a full write.
    for (final key in const [
      'guard_autostart',
      'auto_resume_scans',
      'nvd_api_key',
      'lm_url',
      'lm_model',
      'update_manifest_url',
      'update_channel',
      'nl_bar_enabled',
      'sound_enabled',
      'sound_volume',
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
      vtApiKey: 'vt',
      nvdApiKey: 'nvd',
      lmUrl: 'http://localhost:1234',
      lmModel: 'qwen',
      updateManifestUrl: 'https://example.com/m.json',
      updateChannel: 'beta',
      nlBarEnabled: false,
      soundEnabled: false,
      soundVolume: 15,
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
    expect(back.vtApiKey, 'vt');
    expect(back.nvdApiKey, 'nvd');
    expect(back.lmUrl, 'http://localhost:1234');
    expect(back.lmModel, 'qwen');
    expect(back.updateManifestUrl, 'https://example.com/m.json');
    expect(back.updateChannel, 'beta');
    expect(back.nlBarEnabled, isFalse);
    expect(back.soundEnabled, isFalse);
    expect(back.soundVolume, 15);
    expect(back.scanQuarantineDefault, isFalse);
    expect(back.canaryPaths, hasLength(2));
  });

  test('unknown or missing keys fall back to defaults instead of throwing', () {
    final s = AppSettings.fromEngineJson({'lang': 'en', 'future_key': 42});
    expect(s.lang, AppLang.en);
    expect(s.themeMode, ThemeMode.dark);
    expect(s.syncIntervalHours, 6);
  });

  test('a partial patch merges without wiping other fields', () {
    const current = AppSettings(dndMode: true, syncIntervalHours: 24, vtApiKey: 'k');
    final merged = AppSettings.fromEngineJson({
      ...current.toEngineJson(),
      'lang': 'en',
    });
    expect(merged.lang, AppLang.en);
    expect(merged.dndMode, isTrue);
    expect(merged.syncIntervalHours, 24);
    expect(merged.vtApiKey, 'k');
  });
}
