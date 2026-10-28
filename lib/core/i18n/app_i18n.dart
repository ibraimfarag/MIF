import 'dart:convert';
import 'dart:io' show stderr;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Language packs: JSON files under assets/i18n/<code>.json. Adding a language
/// = dropping a new file + one entry in [bundledLangs]. Missing keys fall
/// back to English; unknown keys surface the key itself (debug-friendly).
enum AppLang { ar, en }

const bundledLangs = {
  'ar': 'العربية',
  'en': 'English',
};

final i18nProvider =
    AsyncNotifierProvider<I18nLoader, Map<String, Map<String, String>>>(
        I18nLoader.new);

class I18nLoader extends AsyncNotifier<Map<String, Map<String, String>>> {
  @override
  Future<Map<String, Map<String, String>>> build() async {
    final tables = <String, Map<String, String>>{};
    for (final code in bundledLangs.keys) {
      try {
        final raw = await rootBundle.loadString('assets/i18n/$code.json');
        tables[code] = (jsonDecode(raw) as Map)
            .cast<String, dynamic>()
            .map((k, v) => MapEntry(k, v.toString()));
      } catch (e) {
        // A broken pack must never hang the app — degrade to keys/English.
        tables[code] = const {};
      }
    }
    return tables;
  }
}

String lookup(
    Map<String, Map<String, String>> tables, AppLang lang, String key) {
  final code = lang == AppLang.ar ? 'ar' : 'en';
  return tables[code]?[key] ?? tables['en']?[key] ?? key;
}

// ---------- settings: engine is the source of truth (D-008) ----------

/// Mirrors `engine/src/settings.rs`. The engine owns the document
/// (`%PROGRAMDATA%\MICS\settings.json`); this class is the UI's typed view of
/// exactly the same fields, so the two can never drift.
class AppSettings {
  final AppLang lang;
  final ThemeMode themeMode;
  final bool guardAutostart;
  final bool autoResumeScans;
  final bool dndMode;
  final int syncIntervalHours;
  final String vtApiKey;
  final String nvdApiKey;
  final String lmUrl;
  final String lmModel;
  final String updateManifestUrl;
  final String updateChannel;
  final bool nlBarEnabled;
  final bool soundEnabled;
  final int soundVolume;
  final bool scanQuarantineDefault;
  final List<String> canaryPaths;

  const AppSettings({
    this.lang = AppLang.ar,
    this.themeMode = ThemeMode.dark,
    this.guardAutostart = true,
    this.autoResumeScans = true,
    this.dndMode = false,
    this.syncIntervalHours = 6,
    this.vtApiKey = '',
    this.nvdApiKey = '',
    this.lmUrl = 'http://127.0.0.1:1234',
    this.lmModel = 'local-model',
    this.updateManifestUrl = '',
    this.updateChannel = 'stable',
    this.nlBarEnabled = true,
    this.soundEnabled = true,
    this.soundVolume = 70,
    this.scanQuarantineDefault = true,
    this.canaryPaths = const [],
  });

  static String themeToString(ThemeMode mode) => switch (mode) {
        ThemeMode.light => 'light',
        ThemeMode.system => 'system',
        _ => 'dark',
      };

  static ThemeMode themeFromString(String value) => switch (value) {
        'light' => ThemeMode.light,
        'system' => ThemeMode.system,
        _ => ThemeMode.dark,
      };

  factory AppSettings.fromEngineJson(Map<String, dynamic> j) => AppSettings(
        lang: (j['lang'] as String?) == 'en' ? AppLang.en : AppLang.ar,
        themeMode: themeFromString((j['theme'] as String?) ?? 'dark'),
        guardAutostart: j['guard_autostart'] as bool? ?? true,
        autoResumeScans: j['auto_resume_scans'] as bool? ?? true,
        dndMode: j['dnd'] as bool? ?? false,
        syncIntervalHours: (j['sync_interval_hours'] as num?)?.toInt() ?? 6,
        vtApiKey: j['vt_api_key'] as String? ?? '',
        nvdApiKey: j['nvd_api_key'] as String? ?? '',
        lmUrl: j['lm_url'] as String? ?? '',
        lmModel: j['lm_model'] as String? ?? '',
        updateManifestUrl: j['update_manifest_url'] as String? ?? '',
        updateChannel: j['update_channel'] as String? ?? 'stable',
        nlBarEnabled: j['nl_bar_enabled'] as bool? ?? true,
        soundEnabled: j['sound_enabled'] as bool? ?? true,
        soundVolume: (j['sound_volume'] as num?)?.toInt() ?? 70,
        scanQuarantineDefault: j['scan_quarantine_default'] as bool? ?? true,
        canaryPaths: (j['canary_paths'] as List? ?? const [])
            .map((e) => e.toString())
            .toList(),
      );

  /// Full document in the engine's own key names.
  Map<String, dynamic> toEngineJson() => {
        'lang': lang == AppLang.en ? 'en' : 'ar',
        'theme': themeToString(themeMode),
        'guard_autostart': guardAutostart,
        'auto_resume_scans': autoResumeScans,
        'dnd': dndMode,
        'sync_interval_hours': syncIntervalHours,
        'vt_api_key': vtApiKey,
        'nvd_api_key': nvdApiKey,
        'lm_url': lmUrl,
        'lm_model': lmModel,
        'update_manifest_url': updateManifestUrl,
        'update_channel': updateChannel,
        'nl_bar_enabled': nlBarEnabled,
        'sound_enabled': soundEnabled,
        'sound_volume': soundVolume,
        'scan_quarantine_default': scanQuarantineDefault,
        'canary_paths': canaryPaths,
      };

  /// Environment for the case where *this app* has to start the engine.
  Map<String, String> engineEnv() => {
        'MICS_SYNC_HOURS': syncIntervalHours.toString(),
        'MICS_DND': dndMode ? '1' : '0',
        if (vtApiKey.isNotEmpty) 'MICS_VT_API_KEY': vtApiKey,
        if (lmUrl.isNotEmpty) 'MICS_LM_URL': lmUrl,
        if (lmModel.isNotEmpty) 'MICS_LM_MODEL': lmModel,
        if (updateManifestUrl.isNotEmpty)
          'MICS_UPDATE_MANIFEST_URL': updateManifestUrl,
      };
}

final settingsProvider =
    AsyncNotifierProvider<SettingsNotifier, AppSettings>(SettingsNotifier.new);

class SettingsNotifier extends AsyncNotifier<AppSettings> {
  /// Local cache so the UI can start before the engine answers (and keeps the
  /// last known theme/language even if the engine is down).
  static const _cacheKey = 'settingsJson';
  static const _migratedKey = 'settingsMigratedV2';

  @override
  Future<AppSettings> build() async {
    final ipc = ref.read(engineIpcProvider);
    try {
      final res = await ipc.request('settings.get');
      var settings =
          AppSettings.fromEngineJson((res as Map).cast<String, dynamic>());
      settings = await _migrateLegacyPrefs(ipc, settings);
      await _writeCache(settings);
      return settings;
    } catch (_) {
      return await _readCache();
    }
  }

  /// One-time move of the old `shared_preferences` values into settings.json.
  Future<AppSettings> _migrateLegacyPrefs(
      EngineIpc ipc, AppSettings fromEngine) async {
    final prefs = await SharedPreferences.getInstance();
    if (prefs.getBool(_migratedKey) == true) return fromEngine;
    final hasLegacy = prefs.containsKey('guardAutostart') ||
        prefs.containsKey('dndMode') ||
        prefs.containsKey('syncIntervalHours') ||
        prefs.containsKey('vtApiKey') ||
        prefs.containsKey('lmUrl') ||
        prefs.containsKey('lmModel') ||
        prefs.containsKey('updateManifestUrl') ||
        prefs.containsKey('lang') ||
        prefs.containsKey('themeMode');
    if (!hasLegacy) {
      await prefs.setBool(_migratedKey, true);
      return fromEngine;
    }
    final legacy = AppSettings(
      lang: (prefs.getString('lang') ?? 'ar') == 'en' ? AppLang.en : AppLang.ar,
      themeMode: AppSettings.themeFromString(
          prefs.getString('themeMode') ?? 'dark'),
      guardAutostart: prefs.getBool('guardAutostart') ?? true,
      dndMode: prefs.getBool('dndMode') ?? false,
      syncIntervalHours: prefs.getInt('syncIntervalHours') ?? 6,
      vtApiKey: prefs.getString('vtApiKey') ?? '',
      lmUrl: prefs.getString('lmUrl') ?? '',
      lmModel: prefs.getString('lmModel') ?? '',
      updateManifestUrl: prefs.getString('updateManifestUrl') ?? '',
    );
    try {
      final res = await ipc.request('settings.set', legacy.toEngineJson());
      await prefs.setBool(_migratedKey, true);
      return AppSettings.fromEngineJson((res as Map).cast<String, dynamic>());
    } catch (_) {
      return fromEngine;
    }
  }

  /// Applies a partial update: engine persists + validates it, then the state
  /// and the local cache follow. Never rebuilds the object from scratch, which
  /// is what used to wipe every other field when changing language or theme.
  Future<void> patch(Map<String, dynamic> values) async {
    final current = state.value ?? const AppSettings();
    try {
      final res = await ref
          .read(engineIpcProvider)
          .request('settings.set', values);
      final next =
          AppSettings.fromEngineJson((res as Map).cast<String, dynamic>());
      state = AsyncValue.data(next);
      await _writeCache(next);
    } catch (e) {
      // Engine unavailable: apply locally so the UI stays responsive, and let
      // the next successful connect reconcile from the engine document.
      final optimistic = _mergeLocal(current, values);
      state = AsyncValue.data(optimistic);
      await _writeCache(optimistic);
      stderr.writeln('settings.set failed ($e) — applied locally');
    }
  }

  AppSettings _mergeLocal(AppSettings cur, Map<String, dynamic> values) {
    final merged = {...cur.toEngineJson(), ...values};
    return AppSettings.fromEngineJson(merged);
  }

  Future<void> setLang(AppLang lang) =>
      patch({'lang': lang == AppLang.en ? 'en' : 'ar'});

  Future<void> setThemeMode(ThemeMode mode) =>
      patch({'theme': AppSettings.themeToString(mode)});

  Future<void> setDnd(bool enabled) => patch({'dnd': enabled});

  Future<void> setSoundEnabled(bool enabled) =>
      patch({'sound_enabled': enabled});

  Future<void> setSoundVolume(int volume) =>
      patch({'sound_volume': volume.clamp(0, 100)});

  Future<void> setNlBarEnabled(bool enabled) =>
      patch({'nl_bar_enabled': enabled});

  Future<void> setAutoResumeScans(bool enabled) =>
      patch({'auto_resume_scans': enabled});

  Future<void> setGuardAutostart(bool enabled) =>
      patch({'guard_autostart': enabled});

  Future<void> setSyncHours(int hours) =>
      patch({'sync_interval_hours': hours.clamp(1, 168)});

  Future<void> setScanQuarantineDefault(bool enabled) =>
      patch({'scan_quarantine_default': enabled});

  Future<void> setCanaryPaths(List<String> paths) =>
      patch({'canary_paths': paths});

  Future<void> setVtKey(String key) => patch({'vt_api_key': key});

  Future<void> setNvdKey(String key) => patch({'nvd_api_key': key});

  Future<void> setLm(String url, String model) =>
      patch({'lm_url': url, 'lm_model': model});

  Future<void> setUpdates(String manifestUrl, String channel) => patch({
        'update_manifest_url': manifestUrl,
        'update_channel': channel,
      });

  Future<AppSettings> _readCache() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_cacheKey);
    if (raw != null) {
      try {
        final decoded = jsonDecode(raw) as Map<String, dynamic>;
        return AppSettings.fromEngineJson(decoded);
      } catch (_) {
        // fall through to defaults
      }
    }
    return const AppSettings();
  }

  Future<void> _writeCache(AppSettings settings) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_cacheKey, jsonEncode(settings.toEngineJson()));
  }
}

// ---------- convenience lookups ----------

extension TrX on BuildContext {
  String tr(String key) {
    final container = ProviderScope.containerOf(this);
    final lang =
        container.read(settingsProvider).value?.lang ?? AppLang.ar;
    final tables = container.read(i18nProvider).value ?? const {};
    return lookup(tables, lang, key);
  }

  AppLang get currentLang =>
      ProviderScope.containerOf(this).read(settingsProvider).value?.lang ??
      AppLang.ar;
}

final rtlProvider = Provider<bool>((ref) {
  return (ref.watch(settingsProvider).value?.lang ?? AppLang.ar) ==
      AppLang.ar;
});

/// Backwards-compat shim: old code watched this for the active language.
final localeProvider = Provider<AppLang>((ref) {
  return ref.watch(settingsProvider).value?.lang ?? AppLang.ar;
});
