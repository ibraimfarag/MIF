import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/models/network_models.dart';

void main() {
  // The engine marks exploit status itself (D-012); the UI only has to keep the
  // field, because "known to be exploited" outranks the CVSS number beside it.
  test('Vuln keeps the engine KEV annotation', () {
    final plain = Vuln.fromJson({
      'cve_id': 'CVE-2000-0001',
      'cvss': 8.8,
      'description': 'x',
      'published': '2000-01-01T00:00:00.000',
    });
    expect(plain.knownExploited, isFalse);
    expect(plain.kevDue, isNull);
  });

  test('Vuln carries known_exploited and kev_due when the catalog has them', () {
    final exploited = Vuln.fromJson({
      'cve_id': 'CVE-2025-0411',
      'cvss': 8.8,
      'description': 'Mark-of-the-Web bypass',
      'published': '2025-01-22T00:00:00.000',
      'known_exploited': true,
      'kev_due': '2025-02-27',
    });
    expect(exploited.knownExploited, isTrue);
    expect(exploited.kevDue, '2025-02-27');
  });

  test('a completed vulnerability job finding parses back into SoftwareVulns',
      () {
    final app = SoftwareVulns.fromJson({
      'software': '7-Zip 25.01 (x64)',
      'version': '25.01',
      'from_cache': true,
      'vulnerabilities': [
        {
          'cve_id': 'CVE-2025-0411',
          'cvss': 8.8,
          'description': 'Mark-of-the-Web bypass',
          'published': '2025-01-22T00:00:00.000',
          'known_exploited': true,
          'kev_due': '2025-02-27',
        }
      ],
    });
    expect(app.software, '7-Zip 25.01 (x64)');
    expect(app.fromCache, isTrue);
    expect(app.vulnerabilities, hasLength(1));
    expect(app.vulnerabilities.first.knownExploited, isTrue);
  });
}
