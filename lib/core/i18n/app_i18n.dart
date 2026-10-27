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
      final raw = await rootBundle.loadString('assets/i18n/$code.json');
      tables[code] = (jsonDecode(raw) as Map)
          .cast<String, dynamic>()
          .map((k, v) => MapEntry(k, v.toString()));
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
  const AppSettings(
      {this.lang = AppLang.ar, this.themeMode = ThemeMode.dark});
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
