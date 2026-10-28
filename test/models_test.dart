import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/models/audit_models.dart';
import 'package:mics_app/models/network_models.dart';

void main() {
  test('AuditReport parses engine JSON and ranks top action', () {
    final report = AuditReport.fromJson({
      'score': 62,
      'findings': [
        {
          'section': 'Legacy Protocols',
          'item': 'SMBv1',
          'status': 'Vulnerable',
          'severity': 'Critical',
          'description': 'SMBv1 enabled',
          'fix_available': true,
        },
        {
          'section': 'Firewall',
          'item': 'Private Profile',
          'status': 'Warning',
          'severity': 'Medium',
          'description': 'x',
          'fix_available': false,
        },
        {
          'section': 'UAC',
          'item': 'UAC',
          'status': 'Secure',
          'severity': 'High',
          'description': 'ok',
          'fix_available': false,
        },
      ],
      'startup_entries': [],
      'scheduled_tasks': [],
    });

    expect(report.score, 62);
    expect(report.countByStatus('Vulnerable'), 1);
    // Critical vulnerable beats warning in the smart panel.
    expect(report.topAction?.item, 'SMBv1');
    expect(report.topAction?.fixAvailable, true);
  });

  test('NetworkConnection suspicion heuristics', () {
    final external = NetworkConnection(
      localAddress: '192.168.1.4:51000',
      remoteAddress: '1.2.3.4:443',
      protocol: 'TCP',
      state: 'ESTABLISHED',
      processId: 100,
      processName: 'unknown_app.exe',
    );
    final loopback = NetworkConnection(
      localAddress: '127.0.0.1:8080',
      remoteAddress: '127.0.0.1:5000',
      protocol: 'TCP',
      state: 'ESTABLISHED',
      processId: 101,
      processName: 'dev_server.exe',
    );
    final listening = NetworkConnection(
      localAddress: '0.0.0.0:9999',
      remoteAddress: '0.0.0.0:0',
      protocol: 'TCP',
      state: 'LISTENING',
      processId: 102,
      processName: 'mystery.exe',
    );

    expect(external.suspicious, true);
    expect(loopback.suspicious, false);
    expect(listening.suspicious, true);
  });

  test('External IP is not flagged as private', () {
    final c = NetworkConnection(
      localAddress: '192.168.1.4:1',
      remoteAddress: '93.184.216.34:443',
      protocol: 'TCP',
      state: 'SYN_SENT',
      processId: 1,
      processName: 'a.exe',
    );
    expect(c.isPrivateOrLocal, false);
    expect(c.isLoopback, false);
  });
}
