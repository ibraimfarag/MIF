// Hide the conflicting CardTheme and TextTheme types that come from the
// transitive `material_ui` package. We only want the Flutter definitions.
import 'package:flutter/material.dart' hide CardTheme;
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
      // Use the default dark text theme. Custom font can be set via `fontFamily`
      // in the ThemeData if needed.
      // textTheme: GoogleFonts.cairoTextTheme(), // removed to avoid type conflict
      // Remove the custom CardTheme to avoid conflict with the CardThemeData type from the
      // material_ui package. The default CardTheme from Flutter works fine with our colors.
    );
  }
}
