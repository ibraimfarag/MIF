import 'package:flutter/material.dart';

class AppColors {
  static const Color background = Color(0xFF0A0E14);
  static const Color surface = Color(0xFF111826);
  static const Color border = Color(0xFF1E293B);
  static const Color cyan = Color(0xFF22D3EE);
  static const Color green = Color(0xFF34D399);
  static const Color red = Color(0xFFF43F5E);
  static const Color orange = Color(0xFFFB923C);
  static const Color text = Color(0xFFE2E8F0);
  static const Color muted = Color(0xFF64748B);

  static Color scoreColor(int score) {
    if (score >= 80) return green;
    if (score >= 50) return orange;
    return red;
  }
}

class AppTheme {
  static ThemeData get darkTheme {
    final base = ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: AppColors.background,
      primaryColor: AppColors.cyan,
      colorScheme: const ColorScheme.dark(
        primary: AppColors.cyan,
        secondary: AppColors.green,
        surface: AppColors.surface,
        error: AppColors.red,
        onPrimary: Color(0xFF0A0E14),
        onSecondary: Color(0xFF0A0E14),
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
          side: const BorderSide(color: AppColors.border),
        ),
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.background,
        elevation: 0,
        centerTitle: false,
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: AppColors.surface,
        indicatorColor: AppColors.cyan.withValues(alpha: 0.15),
        selectedIconTheme: const IconThemeData(color: AppColors.cyan),
        unselectedIconTheme: const IconThemeData(color: AppColors.muted),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.surface,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.border),
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
          side: const BorderSide(color: AppColors.border),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      ),
      progressIndicatorTheme:
          const ProgressIndicatorThemeData(color: AppColors.cyan),
      chipTheme: base.chipTheme.copyWith(
        backgroundColor: AppColors.surface,
        side: const BorderSide(color: AppColors.border),
        labelStyle: const TextStyle(fontSize: 12, color: AppColors.text),
      ),
    );
  }

  /// Mono font for hashes/numbers/CVSS.
  static TextStyle mono({double size = 12, Color? color}) => TextStyle(
      fontFamily: 'JetBrainsMono',
      fontSize: size,
      color: color ?? AppColors.text);
}
