// The in-app alert cards the shell paints in the window's bottom corner
// (D-024).
//
// The engine's gate decides whether there is a card and writes its copy; this
// holds the few that are on screen and lets the user close them. It stays short
// on purpose: a card is a nudge, not a record — the Guard screen, the incident
// list and the crash reports on disk are the record, so a flood of low-severity
// events keeps the newest cards and drops the oldest.

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/models/alert_card.dart';

/// How many cards are on screen at once. A corner that grew forever would cover
/// the window it is there to help.
const alertCardLimit = 3;

final alertCardsProvider =
    NotifierProvider<AlertCardsNotifier, List<AlertCard>>(
        AlertCardsNotifier.new);

class AlertCardsNotifier extends Notifier<List<AlertCard>> {
  StreamSubscription<Map<String, dynamic>>? _sub;

  @override
  List<AlertCard> build() {
    _sub = ref.watch(engineIpcProvider).alertStream.listen((params) {
      final card = AlertCard.fromJson(params);
      // A card with nothing to say is a producer bug, not something to paint.
      if (card.title.isEmpty && card.body.isEmpty) return;
      // The engine files one report per distinct failure, so a failure that
      // happens again raises the same bug id. It is already on screen: a second
      // identical card would only push the others out of the corner.
      final bugId = card.bugId;
      if (bugId != null && state.any((open) => open.bugId == bugId)) return;
      // Newest first, so the newest card is the one nearest the corner.
      state = [card, ...state].take(alertCardLimit).toList();
    });
    ref.onDispose(() => _sub?.cancel());
    return const [];
  }

  /// The card the user closed. Compared by identity: two identical alerts are
  /// two cards, and closing one must not close the other.
  void dismiss(AlertCard card) {
    state = [
      for (final open in state)
        if (!identical(open, card)) open,
    ];
  }
}
