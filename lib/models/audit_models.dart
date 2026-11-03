import 'package:flutter/material.dart';
import 'package:mics_app/core/theme/app_theme.dart';

/// Which audit section each hardening action changes, so a fix can re-read just
/// that section (`audit.run {sections:[id], merge:true}`) instead of the whole
/// sweep. Ids are the engine's (`engine/src/platform/traits.rs` AUDIT_SECTIONS);
/// action ids are `engine/src/hardening/mod.rs::list_actions`.
const Map<String, String> auditSectionForHardeningAction = {
  'pua_protection': 'defender',
  'defender_scan_quick': 'defender',
  'smbv1_off': 'smbv1',
  'rdp_off': 'rdp',
  'uac_on': 'uac',
};

/// Mirrors the engine's audit JSON (engine/src/platform/traits.rs).
class AuditFinding {
  /// The engine's section id (`rdp`, `remote_tools`, ...). The display `section`
  /// is not unique — `rdp` and `remote_tools` both read "Remote Access" — so the
  /// age of the check is resolved through this.
  final String sectionId;
  final String section;
  final String item;
  final String status; // Secure | Warning | Vulnerable | Unknown
  final String severity; // Low | Medium | High | Critical
  final String description;
  final bool fixAvailable;

  AuditFinding({
    required this.section,
    required this.item,
    required this.status,
    required this.severity,
    required this.description,
    required this.fixAvailable,
    this.sectionId = '',
  });

  factory AuditFinding.fromJson(Map<String, dynamic> j) => AuditFinding(
        sectionId: j['id'] as String? ?? '',
        section: j['section'] as String? ?? '',
        item: j['item'] as String? ?? '',
        status: j['status'] as String? ?? 'Unknown',
        severity: j['severity'] as String? ?? 'Low',
        description: j['description'] as String? ?? '',
        fixAvailable: j['fix_available'] as bool? ?? false,
      );

  /// Status and severity colours come from the palette, never from literals:
  /// a literal is the dark-mode value, and in light mode it was unreadable
  /// (1.78:1 for green, measured in `docs/CONTRAST.md`).
  Color get statusColor {
    switch (status) {
      case 'Secure':
        return AppColors.green;
      case 'Warning':
        return AppColors.orange;
      case 'Vulnerable':
        return AppColors.red;
      default:
        return AppColors.muted;
    }
  }

  Color get severityColor {
    switch (severity) {
      case 'Critical':
        return AppColors.red;
      case 'High':
        return AppColors.orange;
      case 'Medium':
        return AppColors.yellow;
      default:
        return AppColors.muted;
    }
  }
}

class StartupEntry {
  final String name;
  final String command;
  final String location;
  StartupEntry(
      {required this.name, required this.command, required this.location});

  factory StartupEntry.fromJson(Map<String, dynamic> j) => StartupEntry(
        name: j['name'] as String? ?? '',
        command: j['command'] as String? ?? '',
        location: j['location'] as String? ?? '',
      );
}

class ScheduledTaskEntry {
  final String name;
  final String path;
  ScheduledTaskEntry({required this.name, required this.path});

  factory ScheduledTaskEntry.fromJson(Map<String, dynamic> j) =>
      ScheduledTaskEntry(
        name: j['name'] as String? ?? '',
        path: j['path'] as String? ?? '',
      );
}

class AuditReport {
  final int score;
  final List<AuditFinding> findings;
  final List<StartupEntry> startupEntries;
  final List<ScheduledTaskEntry> scheduledTasks;

  /// True when this report was merged into an earlier full audit, so some
  /// sections were re-read just now and the rest were not (`refreshed`).
  final bool merged;

  /// The section ids the merge actually re-read.
  final List<String> refreshed;

  /// Unix seconds at which each section was collected, by section id.
  final Map<String, int> sectionTimes;

  AuditReport({
    required this.score,
    required this.findings,
    required this.startupEntries,
    required this.scheduledTasks,
    this.merged = false,
    this.refreshed = const [],
    this.sectionTimes = const {},
  });

  factory AuditReport.fromJson(dynamic json) {
    final j = json as Map<String, dynamic>;
    final times = (j['section_times'] as Map?) ?? const {};
    return AuditReport(
      score: (j['score'] as num? ?? 0).toInt(),
      findings: (j['findings'] as List? ?? [])
          .map((f) => AuditFinding.fromJson(f as Map<String, dynamic>))
          .toList(),
      startupEntries: (j['startup_entries'] as List? ?? [])
          .map((f) => StartupEntry.fromJson(f as Map<String, dynamic>))
          .toList(),
      scheduledTasks: (j['scheduled_tasks'] as List? ?? [])
          .map((f) => ScheduledTaskEntry.fromJson(f as Map<String, dynamic>))
          .toList(),
      merged: j['merged'] as bool? ?? false,
      refreshed: ((j['refreshed'] as List?) ?? const [])
          .map((s) => s.toString())
          .toList(),
      sectionTimes: {
        for (final entry in times.entries)
          entry.key.toString(): (entry.value as num).toInt(),
      },
    );
  }

  /// When [sectionId] was last read, or `null` when the engine did not say.
  DateTime? collectedAt(String sectionId) {
    final seconds = sectionTimes[sectionId];
    if (seconds == null) return null;
    return DateTime.fromMillisecondsSinceEpoch(seconds * 1000);
  }

  /// Whether this report's [sectionId] is current: a full audit re-read
  /// everything, a merge only the sections it was asked for.
  bool wasReRead(String sectionId) =>
      !merged || refreshed.contains(sectionId);

  int countByStatus(String status) =>
      findings.where((f) => f.status == status).length;

  /// The single highest-impact insecure finding for the smart panel.
  AuditFinding? get topAction {
    const order = {'Vulnerable': 0, 'Warning': 1};
    final insecure =
        findings.where((f) => order.containsKey(f.status)).toList()
          ..sort((a, b) {
            const sev = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3};
            final byStatus =
                (order[a.status] ?? 9).compareTo(order[b.status] ?? 9);
            if (byStatus != 0) return byStatus;
            return (sev[a.severity] ?? 9).compareTo(sev[b.severity] ?? 9);
          });
    return insecure.isEmpty ? null : insecure.first;
  }
}
