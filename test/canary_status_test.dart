import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/features/canaries/screens/canaries_screen.dart';

/// The read-coverage line is the one place the product says whether a decoy
/// *read* would be seen here. It is a measurement the engine sends, so the model
/// has to keep three answers apart: measured-and-yes, measured-and-no, and not
/// measured yet. Collapsing any two of them would make the UI claim coverage it
/// does not have.
void main() {
  test('an unread verdict stays unknown instead of becoming a no', () {
    final s = CanariesStatus.fromJson({
      'configured': 2,
      'deployed': 2,
      'read_settle_seconds': 90,
      'read_detection': null,
    });
    expect(s.readAvailable, isNull);
    expect(s.configured, 2);
    expect(s.deployed, 2);
    expect(s.readSettleSeconds, 90);
    expect(s.readProbedOn, isEmpty);
  });

  test('a volume that keeps no last-access time is reported as such', () {
    final s = CanariesStatus.fromJson({
      'configured': 1,
      'deployed': 1,
      'read_settle_seconds': 90,
      'read_detection': {
        'available': false,
        'probed_on': r'D:\decoys',
        'detail': 'this volume keeps no last-access time',
      },
    });
    expect(s.readAvailable, isFalse);
    expect(s.readProbedOn, r'D:\decoys');
  });

  test('a measured yes is a yes, and names the volume it was measured on', () {
    final s = CanariesStatus.fromJson({
      'configured': 3,
      'deployed': 3,
      'read_settle_seconds': 120,
      'read_detection': {
        'available': true,
        'probed_on': r'C:\Users\qa\Documents',
        'detail': 'measured',
      },
    });
    expect(s.readAvailable, isTrue);
    expect(s.readProbedOn, r'C:\Users\qa\Documents');
    expect(s.readSettleSeconds, 120);
  });

  test('a missing field is not an invented measurement', () {
    final s = CanariesStatus.fromJson(const {});
    expect(s.readAvailable, isNull);
    expect(s.configured, 0);
    expect(s.deployed, 0);
    expect(s.readSettleSeconds, 0);
  });
}
