import 'package:flutter/material.dart';

/// Palette is mutable so toggling dark/light re-colors the whole tree on the
/// next MaterialApp rebuild. Never reference these inside `const` widgets.
class AppColors {
  static Color background = const Color(0xFF0A0E14);
  static Color surface = const Color(0xFF111826);
  static Color border = const Color(0xFF1E293B);
  static Color cyan = const Color(0xFF22D3EE);
  static Color green = const Color(0xFF34D399);
  static Color red = const Color(0xFFF43F5E);
  static Color orange = const Color(0xFFFB923C);
  static Color text = const Color(0xFFE2E8F0);
  static Color muted = const Color(0xFF64748B);

  static void applyDark() {
    background = const Color(0xFF0A0E14);
    surface = const Color(0xFF111826);
    border = const Color(0xFF1E293B);
    cyan = const Color(0xFF22D3EE);
    green = const Color(0xFF34D399);
    red = const Color(0xFFF43F5E);
    orange = const Color(0xFFFB923C);
    text = const Color(0xFFE2E8F0);
    muted = const Color(0xFF64748B);
  }

  static void applyLight() {
    background = const Color(0xFFF4F7FB);
    surface = const Color(0xFFFFFFFF);
    border = const Color(0xFFDDE4EE);
    cyan = const Color(0xFF0891B2);
    green = const Color(0xFF059669);
    red = const Color(0xFFE11D48);
    orange = const Color(0xFFEA580C);
    text = const Color(0xFF0F172A);
    muted = const Color(0xFF5B6B7F);
  }

  static Color scoreColor(int score) {
    if (score >= 80) return green;
    if (score >= 50) return orange;
    return red;
  }
}

class AppTheme {
  /// Applies the palette for a mode. Call BEFORE building MaterialApp —
  /// the theme getters below must NOT mutate statics (MaterialApp evaluates
  /// both darkTheme and theme getters, so last-write-wins would flip the
  /// palette back and produce half-dark half-light UI).
  static void applyPalette(ThemeMode mode) {
    final platformDark =
        WidgetsBinding.instance.platformDispatcher.platformBrightness ==
            Brightness.dark;
    final dark = mode == ThemeMode.dark ||
        (mode == ThemeMode.system && platformDark);
    if (dark) {
      AppColors.applyDark();
    } else {
      AppColors.applyLight();
    }
  }

  /// Whether the last-applied palette is dark (for widgets that need it).
  static bool get isDark => AppColors.background == const Color(0xFF0A0E14);

  static ThemeData get darkTheme => _theme(Brightness.dark);

  static ThemeData get lightTheme => _theme(Brightness.light);

  static ThemeData _theme(Brightness brightness) {
    final dark = brightness == Brightness.dark;
    final base = ThemeData(
      brightness: brightness,
      scaffoldBackgroundColor: AppColors.background,
      primaryColor: AppColors.cyan,
      colorScheme:
          (dark ? const ColorScheme.dark() : const ColorScheme.light())
              .copyWith(
        primary: AppColors.cyan,
        secondary: AppColors.green,
        surface: AppColors.surface,
        error: AppColors.red,
        onPrimary: dark ? const Color(0xFF0A0E14) : Colors.white,
        onSecondary: dark ? const Color(0xFF0A0E14) : Colors.white,
        onSurface: AppColors.text,
        onError: Colors.white,
        outline: AppColors.border,
      ),
      dividerColor: AppColors.border,
      fontFamily: 'Cairo',
    );
    return base.copyWith(
      cardTheme: CardThemeData(
        color: AppColors.surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: AppColors.border),
        ),
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: AppColors.background,
        elevation: 0,
        centerTitle: false,
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: AppColors.surface,
        indicatorColor: AppColors.cyan.withValues(alpha: 0.15),
        selectedIconTheme: IconThemeData(color: AppColors.cyan),
        unselectedIconTheme: IconThemeData(color: AppColors.muted),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.surface,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: AppColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: AppColors.border),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: AppColors.cyan,
          foregroundColor: AppColors.background,
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.cyan,
          side: BorderSide(color: AppColors.border),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      ),
      progressIndicatorTheme:
          ProgressIndicatorThemeData(color: AppColors.cyan),
      chipTheme: base.chipTheme.copyWith(
        backgroundColor: AppColors.surface,
        side: BorderSide(color: AppColors.border),
        labelStyle: TextStyle(fontSize: 12, color: AppColors.text),
      ),
    );
  }

  /// Mono font for hashes/numbers/CVSS.
  static TextStyle mono({double size = 12, Color? color}) => TextStyle(
      fontFamily: 'JetBrainsMono',
      fontSize: size,
      color: color ?? AppColors.text);
}
