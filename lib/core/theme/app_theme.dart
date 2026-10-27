import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppColors {
  static const Color background = Color(0xFF0A0E14);
  static const Color surface = Color(0xFF111826);
  static const Color border = Color(0xFF1E293B);
  static const Color cyan = Color(0xFF22D3EE);
  static const Color green = Color(0xFF34D399);
  static const Color red = Color(0xFFF43F5E);
  static const Color orange = Color(0xFFFB923C);
  static const Color text = Color(0xFFE2E8F0);
}

class AppTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: AppColors.background,
      primaryColor: AppColors.cyan,
      colorScheme: const ColorScheme.dark(
        primary: AppColors.cyan,
        secondary: AppColors.green,
        surface: AppColors.surface,
        error: AppColors.red,
        onPrimary: Colors.white,
        onSecondary: Colors.white,
        onSurface: AppColors.text,
        onError: Colors.white,
      ),
      textTheme: GoogleFonts.cairoTextTheme(ThemeData.dark().textTheme)
          .copyWith(
            displayLarge: GoogleFonts.cairo(
              color: AppColors.text,
              fontWeight: FontWeight.bold,
            ),
            bodyMedium: GoogleFonts.cairo(color: AppColors.text),
          ),
      cardTheme: CardTheme(
        color: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: AppColors.border),
        ),
      ),
    );
  }
}
