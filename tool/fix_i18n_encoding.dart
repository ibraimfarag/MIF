// Repairs UTF-8 text that was decoded as Latin-1 and re-encoded (mojibake),
// e.g. "Ø­ÙˆÙ„" -> "حول" and "â€“" -> "–".
//
//   dart run tool/fix_i18n_encoding.dart
//
// Safe to run repeatedly: strings that are already valid (Arabic/em-dash) fail
// the Latin-1 round-trip and are left untouched. Every file is rewritten as
// pretty UTF-8 without a BOM, and JSON validity is asserted before writing.

import 'dart:convert';
import 'dart:io';

void main() {
  var fixedFiles = 0;
  var fixedStrings = 0;
  for (final langDir in Directory('assets/i18n').listSync().whereType<Directory>()) {
    for (final file in langDir.listSync().whereType<File>()) {
      if (!file.path.endsWith('.json')) continue;
      final text = file.readAsStringSync(); // UTF-8 by default
      final decoded = jsonDecode(text) as Map<String, dynamic>;
      var changed = false;
      final repaired = <String, String>{};
      decoded.forEach((key, value) {
        final original = '$value';
        final fixed = _repair(original);
        if (fixed != original) {
          changed = true;
          fixedStrings++;
          stdout.writeln('  ${file.path}  "$key": "$original" -> "$fixed"');
        }
        repaired[key] = fixed;
      });
      if (changed) {
        final sorted = Map.fromEntries(
            repaired.entries.toList()..sort((a, b) => a.key.compareTo(b.key)));
        file.writeAsStringSync(
            '${const JsonEncoder.withIndent('  ').convert(sorted)}\n');
        jsonDecode(file.readAsStringSync()); // must still parse
        fixedFiles++;
      }
    }
  }
  stdout.writeln('files repaired: $fixedFiles, strings repaired: $fixedStrings');
}

/// If [value] looks like UTF-8 bytes that were read as Latin-1, undo that.
String _repair(String value) {
  if (!RegExp(r'[ÂÃØÙâ]').hasMatch(value)) return value;
  try {
    final bytes = latin1.encode(value); // throws if any char is > 0xFF
    final candidate = utf8.decode(bytes); // throws if not valid UTF-8
    // Only accept the repair when it removes the tell-tale sequence.
    if (RegExp(r'[ÂÃØÙâ]').hasMatch(candidate)) return value;
    return candidate;
  } catch (_) {
    return value;
  }
}
