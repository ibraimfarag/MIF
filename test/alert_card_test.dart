import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/models/alert_card.dart';

void main() {
  AlertCard card(String kind) => AlertCard.fromJson({
        'id': 'a1',
        'kind': kind,
        'severity': 'high',
        'title': 'title',
        'body': 'body',
        'at': 1700000000,
      });

  test('a tampered filtering layer wears its own icon, not the catch-all bell', () {
    // D-044: the card is about MI CS' own protection being dismantled, and the
    // one thing a user must not see is the same generic bell as every other
    // notification.
    expect(card('firewall').icon, Icons.security);
    expect(card('firewall').icon, isNot(Icons.notifications_none));
  });

  test('it opens the connection list, where a block is written and read', () {
    // The engine's side of the fix is a click on the firewall state, and that
    // lives on the network screen; /guard would show the incident but not the
    // action.
    expect(card('firewall').route, '/network');
    // An unknown kind still has to land somewhere.
    expect(card('something-new').route, '/guard');
  });
}