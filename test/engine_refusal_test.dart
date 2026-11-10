// The engine's refusal reaches the user only if both halves work: the sentence
// has to be captured from a stderr the detached start throws away, and it has to
// be shown where the state already is. The display half is proved in
// `test/ui_screens_test.dart`; this pins the capture half — which lines of a
// process's output survive, and how many of them.
//
// The register row this closes is "when the engine cannot start at all, the UI
// cannot say why"; that is only fixed if the tail of stderr becomes the message.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

void main() {
  test('the refusal keeps the end of what the process printed', () async {
    final kept = <String>[];
    await keepTail(
      Stream<List<int>>.value(
          utf8.encode('${List.generate(20, (i) => 'line $i').join('\n')}\n\n')),
      kept,
    ).asFuture<void>();

    expect(kept, hasLength(12), reason: 'the buffer is not bounded at 12 lines');
    expect(kept.first, 'line 8',
        reason: 'the oldest line kept is wrong, so the tail is not a tail');
    expect(kept.last, 'line 19', reason: 'the last line printed was dropped');
  });

  test('blank lines never reach the message', () async {
    final kept = <String>[];
    await keepTail(
      Stream<List<int>>.value(utf8.encode('why it refused\n \n\n\t\n')),
      kept,
    ).asFuture<void>();

    expect(kept, ['why it refused'],
        reason: 'padding would show as empty lines in the settings card');
  });

  test('a refusal that arrived in pieces is still one message', () async {
    // stderr arrives chunked and a chunk boundary can fall mid-line.
    final kept = <String>[];
    await keepTail(
      Stream<List<int>>.fromIterable([
        utf8.encode('MI CS was started from a Low-'),
        utf8.encode('integrity location: it cannot\nwrite its state database'),
      ]),
      kept,
    ).asFuture<void>();

    expect(kept.join(' '), contains('Low-integrity location'),
        reason: 'a line split across two chunks was lost or mangled');
    expect(kept.last, 'write its state database');
  });
}
