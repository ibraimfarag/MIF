// The crash reports the engine wrote, as the UI reads them over the pipe.
//
// Two shapes, both defined by `engine/src/crash.rs`:
//  * `crash.list` answers one summary per report, newest first, with the message
//    clipped to 200 characters by the engine;
//  * `crash.get` answers the whole report: the session it happened in and the
//    tail of the engine log as well.
//
// The UI never opens the reports directory - the engine owns those files (rule 4
// of `AGENTS.md`), and these classes only translate what came back through the
// pipe.

/// One row of `crash.list`: enough to name the failure without carrying the log
/// tail of every report on screen.
class CrashSummary {
  const CrashSummary({
    required this.bugId,
    required this.kind,
    required this.created,
    required this.lastSeen,
    required this.occurrences,
    required this.message,
  });

  final String bugId;

  /// `panic`, `unclean-exit` or `hang` today.
  final String kind;
  final String created;
  final String lastSeen;
  final int occurrences;
  final String message;

  factory CrashSummary.fromJson(Map<String, dynamic> json) => CrashSummary(
        bugId: json['bug_id'] as String? ?? '',
        kind: json['kind'] as String? ?? '',
        created: json['created'] as String? ?? '',
        lastSeen: json['last_seen'] as String? ?? '',
        occurrences: (json['occurrences'] as num?)?.toInt() ?? 1,
        message: json['message'] as String? ?? '',
      );

  /// Reads the whole `crash.list` answer. A row that is not an object is
  /// skipped rather than thrown at the screen: the engine owns the file format,
  /// and a report it cannot parse must not blank the section.
  static List<CrashSummary> listFrom(dynamic raw) {
    if (raw is! List) return const [];
    return [
      for (final row in raw)
        if (row is Map)
          CrashSummary.fromJson(row.cast<String, dynamic>()),
    ];
  }
}

/// One full report (`crash.get`).
class CrashReport {
  const CrashReport({
    required this.bugId,
    required this.kind,
    required this.created,
    required this.lastSeen,
    required this.occurrences,
    required this.version,
    required this.message,
    this.location,
    this.sessionPid,
    this.sessionMode,
    this.sessionStarted,
    this.logTail = const [],
  });

  final String bugId;
  final String kind;
  final String created;
  final String lastSeen;
  final int occurrences;
  final String version;
  final String message;

  /// `file:line` where it happened, when the runtime knows (a hang has none).
  final String? location;

  /// The session marker as it was when the report was written.
  final int? sessionPid;
  final String? sessionMode;
  final String? sessionStarted;

  /// Tail of the engine log, oldest first, with secret-looking values removed.
  final List<String> logTail;

  factory CrashReport.fromJson(Map<String, dynamic> json) {
    final session = json['session'];
    final tail = json['log_tail'];
    return CrashReport(
      bugId: json['bug_id'] as String? ?? '',
      kind: json['kind'] as String? ?? '',
      created: json['created'] as String? ?? '',
      lastSeen: json['last_seen'] as String? ?? '',
      occurrences: (json['occurrences'] as num?)?.toInt() ?? 1,
      version: json['version'] as String? ?? '',
      message: json['message'] as String? ?? '',
      location: json['location'] as String?,
      sessionPid: session is Map ? (session['pid'] as num?)?.toInt() : null,
      sessionMode: session is Map ? session['mode'] as String? : null,
      sessionStarted: session is Map ? session['started'] as String? : null,
      logTail: tail is List ? [for (final line in tail) '$line'] : const [],
    );
  }

  /// The text the user copies.
  ///
  /// The bug id is the whole first line on purpose: a paste into a message, a
  /// ticket or a search box starts with the one thing the report is identified
  /// by. The field names mirror the `.txt` the engine writes next to the JSON
  /// (`crash.rs::render`), and they stay in English like it, because this text
  /// is read next to the engine's own bundle rather than as UI copy.
  String get pasteText {
    final out = StringBuffer()
      ..writeln(bugId)
      ..writeln('kind      : $kind');
    final repeat =
        occurrences > 1 ? ', last $lastSeen - $occurrences time(s)' : '';
    out
      ..writeln('when      : $created (first seen)$repeat')
      ..writeln('version   : $version');
    final where = location;
    if (where != null && where.isNotEmpty) out.writeln('where     : $where');
    if (sessionMode != null || sessionPid != null) {
      out.writeln('session   : ${sessionMode ?? 'unknown'} '
          'pid ${sessionPid ?? 0}, started ${sessionStarted ?? 'unknown'}');
    }
    out
      ..writeln()
      ..writeln('what happened:')
      ..writeln(message)
      ..writeln()
      ..writeln('last ${logTail.length} engine log lines (oldest first):');
    for (final line in logTail) {
      out.writeln(line);
    }
    return out.toString();
  }
}
