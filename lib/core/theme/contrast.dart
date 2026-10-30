import 'dart:math' as math;
import 'dart:ui';

/// WCAG 2.x contrast maths — the measurement behind
/// `test/light_contrast_audit_test.dart`.
///
/// "The colours look fine" is not evidence, and a screenshot cannot be checked
/// by a machine. These functions turn a pair of colours into the ratio WCAG 2.2
/// §1.4.3 talks about, so the audit prints numbers and a test can pin them.
///
/// Everything here expects **opaque** colours. A colour that carries alpha is
/// the caller's problem: blend it over its real background with [blendOver]
/// first, because a 15 %-tinted badge is not the plain colour it was mixed from.

/// Relative luminance of an opaque sRGB colour (the WCAG 2.2 definition).
///
/// [Color.r] / [Color.g] / [Color.b] are the sRGB channels as 0..1 doubles, and
/// the spec's linearisation takes 0..1 input too, so no 0..255 round trip is
/// involved anywhere in this file.
double relativeLuminance(Color color) {
  double channel(double value) => value <= 0.03928
      ? value / 12.92
      : math.pow((value + 0.055) / 1.055, 2.4).toDouble();
  return 0.2126 * channel(color.r) +
      0.7152 * channel(color.g) +
      0.0722 * channel(color.b);
}

/// The contrast ratio between two opaque colours: 1.0 (none) to 21.0 (black on
/// white). The WCAG bars are 4.5:1 for body text, 3:1 for large text (18.66 px
/// bold or 24 px) and 3:1 for UI boundaries and graphics.
double contrastRatio(Color a, Color b) {
  final la = relativeLuminance(a);
  final lb = relativeLuminance(b);
  final lighter = math.max(la, lb);
  final darker = math.min(la, lb);
  return (lighter + 0.05) / (darker + 0.05);
}

/// [foreground] painted at [alpha] over [background] — source-over per channel
/// in encoded sRGB, which is what the renderer composites for the flat
/// `withValues(alpha: ...)` fills this UI uses (`red.withValues(alpha: 0.08)`).
Color blendOver(Color foreground, double alpha, Color background) {
  final a = alpha.clamp(0.0, 1.0);
  return Color.from(
    alpha: 1.0,
    red: foreground.r * a + background.r * (1 - a),
    green: foreground.g * a + background.g * (1 - a),
    blue: foreground.b * a + background.b * (1 - a),
  );
}
