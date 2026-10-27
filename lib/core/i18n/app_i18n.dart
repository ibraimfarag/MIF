import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
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

// ---------- persisted preferences (theme + language) ----------

class AppSettings {
  final AppLang lang;
  final ThemeMode themeMode;
  // --- advanced engine/integration settings (persisted) ---
  final bool guardAutostart; // start the real-time guard at launch
  final bool dndMode; // silence non-critical toasts
  final int syncIntervalHours; // intel refresh cadence when online
  final String vtApiKey;
  final String lmUrl;
  final String lmModel;
  final String updateManifestUrl;
  const AppSettings({
    this.lang = AppLang.ar,
    this.themeMode = ThemeMode.dark,
    this.guardAutostart = true,
    this.dndMode = false,
    this.syncIntervalHours = 6,
    this.vtApiKey = '',
    this.lmUrl = '',
    this.lmModel = '',
    this.updateManifestUrl = '',
  });

  /// Engine environment variables derived from these settings.
  Map<String, String> engineEnv() => {
        'MICS_SYNC_HOURS': syncIntervalHours.toString(),
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
  @override
  Future<AppSettings> build() async {
    final prefs = await SharedPreferences.getInstance();
    final lang = prefs.getString('lang') ?? 'ar';
    final theme = prefs.getString('themeMode') ?? 'dark';
    return AppSettings(
      lang: lang == 'en' ? AppLang.en : AppLang.ar,
      themeMode: switch (theme) {
        'light' => ThemeMode.light,
        'system' => ThemeMode.system,
        _ => ThemeMode.dark,
      },
      guardAutostart: prefs.getBool('guardAutostart') ?? true,
      dndMode: prefs.getBool('dndMode') ?? false,
      syncIntervalHours: prefs.getInt('syncIntervalHours') ?? 6,
      vtApiKey: prefs.getString('vtApiKey') ?? '',
      lmUrl: prefs.getString('lmUrl') ?? '',
      lmModel: prefs.getString('lmModel') ?? '',
      updateManifestUrl: prefs.getString('updateManifestUrl') ?? '',
    );
  }

  Future<void> setLang(AppLang lang) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('lang', lang == AppLang.ar ? 'ar' : 'en');
    state = AsyncValue.data(AppSettings(
        lang: lang, themeMode: state.value?.themeMode ?? ThemeMode.dark));
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('themeMode', switch (mode) {
      ThemeMode.light => 'light',
      ThemeMode.system => 'system',
      _ => 'dark',
    });
    state = AsyncValue.data(AppSettings(
        lang: state.value?.lang ?? AppLang.ar, themeMode: mode));
  }

  /// Generic persisted-field update used by the advanced settings screen.
  Future<void> _set(AppSettings Function(AppSettings cur) mutate) async {
    final cur = state.value ?? const AppSettings();
    final next = mutate(cur);
    state = AsyncValue.data(next);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('guardAutostart', next.guardAutostart);
    await prefs.setBool('dndMode', next.dndMode);
    await prefs.setInt('syncIntervalHours', next.syncIntervalHours);
    await prefs.setString('vtApiKey', next.vtApiKey);
    await prefs.setString('lmUrl', next.lmUrl);
    await prefs.setString('lmModel', next.lmModel);
    await prefs.setString('updateManifestUrl', next.updateManifestUrl);
  }

  Future<void> patchSettings(
      {bool? guardAutostart,
      bool? dndMode,
      int? syncIntervalHours,
      String? vtApiKey,
      String? lmUrl,
      String? lmModel,
      String? updateManifestUrl}) async {
    await _set((cur) => AppSettings(
          lang: cur.lang,
          themeMode: cur.themeMode,
          guardAutostart: guardAutostart ?? cur.guardAutostart,
          dndMode: dndMode ?? cur.dndMode,
          syncIntervalHours: syncIntervalHours ?? cur.syncIntervalHours,
          vtApiKey: vtApiKey ?? cur.vtApiKey,
          lmUrl: lmUrl ?? cur.lmUrl,
          lmModel: lmModel ?? cur.lmModel,
          updateManifestUrl: updateManifestUrl ?? cur.updateManifestUrl,
        ));
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
