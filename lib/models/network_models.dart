/// The spec a one-click block sends, built by the engine (`NetworkBlock` in
/// `traits.rs`). The UI forwards it untouched: the field names are the ones
/// `fw.wfp.block` reads, and the engine already validated them, so nothing here
/// turns a display string back into a filter.
class NetworkBlock {
  final String app;
  final int port;
  final int protocol;
  final String note;

  const NetworkBlock({
    required this.app,
    required this.port,
    required this.protocol,
    required this.note,
  });

  factory NetworkBlock.fromJson(Map<String, dynamic> j) => NetworkBlock(
        app: j['app'] as String? ?? '',
        port: (j['port'] as num?)?.toInt() ?? 0,
        protocol: (j['protocol'] as num?)?.toInt() ?? 0,
        note: j['note'] as String? ?? '',
      );

  /// Exactly the params `fw.wfp.block` takes.
  Map<String, dynamic> toJson() => <String, dynamic>{
        'app': app,
        'port': port,
        'protocol': protocol,
        'note': note,
      };

  String get appName {
    final parts = app.split(RegExp(r'[\\/]'));
    return parts.isEmpty ? app : parts.last;
  }
}

/// Mirrors engine JSON for net.connections (traits.rs NetworkConnection).
class NetworkConnection {
  final String localAddress;
  final String remoteAddress;
  final String protocol;
  final String state;
  final int processId;
  final String processName;
  final String country;

  /// The owning process's image path, empty when the token could not query it.
  final String processPath;

  /// 6 (TCP) or 17 (UDP), so a row can be sent to the filtering engine without
  /// parsing [protocol] back.
  final int protocolNumber;

  /// The peer port, 0 when the row has no peer (UDP, or a TCP listener).
  final int remotePort;

  /// The block this row would become, or null when it cannot become one - the
  /// tile then says why instead of offering a button that fails.
  final NetworkBlock? block;

  NetworkConnection({
    required this.localAddress,
    required this.remoteAddress,
    required this.protocol,
    required this.state,
    required this.processId,
    required this.processName,
    this.country = '',
    this.processPath = '',
    this.protocolNumber = 0,
    this.remotePort = 0,
    this.block,
  });

  factory NetworkConnection.fromJson(Map<String, dynamic> j) =>
      NetworkConnection(
        localAddress: j['local_address'] as String? ?? '',
        remoteAddress: j['remote_address'] as String? ?? '',
        protocol: j['protocol'] as String? ?? '',
        state: j['state'] as String? ?? '',
        processId: (j['process_id'] as num?)?.toInt() ?? 0,
        processName: j['process_name'] as String? ?? '',
        country: j['country'] as String? ?? '',
        processPath: j['process_path'] as String? ?? '',
        protocolNumber: (j['protocol_number'] as num?)?.toInt() ?? 0,
        remotePort: (j['remote_port'] as num?)?.toInt() ?? 0,
        block: j['block'] == null
            ? null
            : NetworkBlock.fromJson(j['block'] as Map<String, dynamic>),
      );

  bool get isLoopback =>
      remoteAddress.startsWith('127.') || remoteAddress.startsWith('::1');

  /// Suspicious heuristics (v1): external established connections and
  /// listeners bound to all interfaces by non-system processes.
  bool get suspicious {
    if (state == 'ESTABLISHED' && !isPrivateOrLocal) return true;
    if (state == 'LISTENING' &&
        localAddress.startsWith('0.0.0.0') &&
        !_wellKnown.contains(processName.toLowerCase())) {
      return true;
    }
    return false;
  }

  bool get isPrivateOrLocal {
    final host = remoteAddress.split(':').first;
    if (host.startsWith('127.') ||
        host.startsWith('10.') ||
        host.startsWith('192.168.')) {
      return true;
    }
    if (host.startsWith('172.')) {
      final second = int.tryParse(host.split('.').elementAt(1)) ?? 0;
      if (second >= 16 && second <= 31) return true;
    }
    return remoteAddress == '*:*';
  }

  static const _wellKnown = {
    'system', 'svchost.exe', 'lsass.exe', 'services.exe', 'wininit.exe',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'explorer.exe', 'nginx.exe',
    'php.exe', 'httpd.exe', 'mysqld.exe', 'node.exe', 'docker.exe',
    'com.docker.backend.exe', 'code.exe', 'dart.exe', 'flutter.exe',
    'python.exe', 'java.exe', 'git.exe', 'steam.exe', 'discord.exe',
  };
}

/// Mirrors engine FirewallRule JSON.
class FirewallRule {
  final String name;
  final bool enabled;
  final String direction;
  final String action;
  final String remoteIp;
  FirewallRule({
    required this.name,
    required this.enabled,
    required this.direction,
    required this.action,
    required this.remoteIp,
  });

  factory FirewallRule.fromJson(Map<String, dynamic> j) => FirewallRule(
        name: j['name'] as String? ?? '',
        enabled: j['enabled'] as bool? ?? false,
        direction: j['direction'] as String? ?? '',
        action: j['action'] as String? ?? '',
        remoteIp: j['remote_ip'] as String? ?? '',
      );
}

/// Mirrors engine SoftwareVulns JSON.
class SoftwareVulns {
  final String software;
  final String version;
  final List<Vuln> vulnerabilities;
  final bool fromCache;
  SoftwareVulns({
    required this.software,
    required this.version,
    required this.vulnerabilities,
    required this.fromCache,
  });

  factory SoftwareVulns.fromJson(Map<String, dynamic> j) => SoftwareVulns(
        software: j['software'] as String? ?? '',
        version: j['version'] as String? ?? '',
        fromCache: j['from_cache'] as bool? ?? false,
        vulnerabilities: (j['vulnerabilities'] as List? ?? [])
            .map((v) => Vuln.fromJson(v as Map<String, dynamic>))
            .toList(),
      );
}

class Vuln {
  final String cveId;
  final double cvss;
  final String description;
  final String published;

  /// CISA lists this CVE as exploited in the wild, which outranks its score.
  final bool knownExploited;

  /// The catalog's remediation due date (only when [knownExploited]).
  final String? kevDue;

  Vuln({
    required this.cveId,
    required this.cvss,
    required this.description,
    required this.published,
    this.knownExploited = false,
    this.kevDue,
  });

  factory Vuln.fromJson(Map<String, dynamic> j) => Vuln(
        cveId: j['cve_id'] as String? ?? '',
        cvss: (j['cvss'] as num?)?.toDouble() ?? 0,
        description: j['description'] as String? ?? '',
        published: j['published'] as String? ?? '',
        knownExploited: j['known_exploited'] as bool? ?? false,
        kevDue: j['kev_due'] as String?,
      );
}
