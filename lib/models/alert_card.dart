// One in-app alert card, as the engine's gate pushes it (D-024,
// `engine/src/notify/alert.rs`).
//
// The engine decides *whether* there is a card and writes its title and body,
// so the copy follows `settings.lang` in one place and a new event type cannot
// invent its own wording. This class only reads what arrived and answers the
// two questions the UI still has: what colour and icon it wears, and where a tap
// should go.

import 'package:flutter/material.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class AlertCard {
  const AlertCard({
    required this.kind,
    required this.severity,
    required this.title,
    required this.body,
    this.bugId,
    this.reportKind,
  });

  /// The producer class: `guard`, `canary`, `scan`, `quarantine`, `protection`,
  /// `crash` or `integrity`.
  final String kind;

  /// `critical`, `high`, `medium` or `low` — the engine's own severity.
  final String severity;
  final String title;
  final String body;

  /// Only a crash card has one: the report the engine filed (ز2-ج).
  final String? bugId;

  /// Only a crash card: the engine's report kind (`panic`, `unclean-exit`,
  /// `hang`), which picks the icon.
  final String? reportKind;

  factory AlertCard.fromJson(Map<String, dynamic> json) => AlertCard(
        kind: json['kind'] as String? ?? '',
        severity: json['severity'] as String? ?? '',
        title: json['title'] as String? ?? '',
        body: json['body'] as String? ?? '',
        bugId: json['bug_id'] as String?,
        reportKind: json['report_kind'] as String?,
      );

  /// The colour comes from the palette and never from a literal: the contrast
  /// audit measures the tokens on both surfaces, and a card is 10-12 px text
  /// (`test/dark_contrast_audit_test.dart`, `test/light_contrast_audit_test.dart`).
  Color get severityColor => switch (severity) {
        'critical' => AppColors.red,
        'high' => AppColors.orange,
        'medium' => AppColors.yellow,
        _ => AppColors.cyan,
      };

  IconData get icon => switch (kind) {
        'crash' => switch (reportKind) {
            'hang' => Icons.hourglass_bottom,
            'panic' => Icons.error_outline,
            'unclean-exit' => Icons.power_off,
            _ => Icons.bug_report_outlined,
          },
        'canary' => Icons.egg_outlined,
        'scan' => Icons.bug_report_outlined,
        'quarantine' => Icons.lock_outline,
        'protection' => Icons.shield_outlined,
        'integrity' => Icons.gpp_bad_outlined,
        // The filtering layer losing an object (D-044): the layer itself is what
        // was removed, so the card wears the firewall's own shield, not a bug.
        'firewall' => Icons.security,
        _ => Icons.notifications_none,
      };

  /// Where a tap goes: the one screen that explains this class of alert. A
  /// crash card opens Settings, where Diagnostics lists the report.
  String get route => switch (kind) {
        'canary' => '/canaries',
        'scan' => '/scanner',
        'quarantine' => '/scanner',
        'protection' => '/hardening',
        'crash' => '/settings',
        // The manifest verdict is explained in Settings → About (ج2, D-025).
        'integrity' => '/settings',
        // The connection list is where a block is written and where the engine's
        // filtering status is read, so that is where a removed layer is acted on.
        'firewall' => '/network',
        _ => '/guard',
      };
}
