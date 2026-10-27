import 'package:flutter/material.dart';

/// Mirrors the engine's audit JSON (engine/src/platform/traits.rs).
class AuditFinding {
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
  });

  factory AuditFinding.fromJson(Map<String, dynamic> j) => AuditFinding(
        section: j['section'] as String? ?? '',
        item: j['item'] as String? ?? '',
        status: j['status'] as String? ?? 'Unknown',
        severity: j['severity'] as String? ?? 'Low',
        description: j['description'] as String? ?? '',
        fixAvailable: j['fix_available'] as bool? ?? false,
      );

  Color get statusColor {
    switch (status) {
      case 'Secure':
        return const Color(0xFF34D399);
      case 'Warning':
        return const Color(0xFFFB923C);
      case 'Vulnerable':
        return const Color(0xFFF43F5E);
      default:
        return const Color(0xFF64748B);
    }
  }

  Color get severityColor {
    switch (severity) {
      case 'Critical':
        return const Color(0xFFF43F5E);
      case 'High':
        return const Color(0xFFFB923C);
      case 'Medium':
        return const Color(0xFFEAB308);
      default:
        return const Color(0xFF64748B);
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

  AuditReport({
    required this.score,
    required this.findings,
    required this.startupEntries,
    required this.scheduledTasks,
  });

  factory AuditReport.fromJson(dynamic json) {
    final j = json as Map<String, dynamic>;
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
    );
  }

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
