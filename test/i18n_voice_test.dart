import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Guards the *voice* of a pack — the half of i18n that a key count cannot see.
///
/// The Arabic pack reads as فصحى, the register the tray slice settled on
/// (D-053), and two ways of losing it are mechanical enough to gate: a
/// colloquial word where فصحى has a counterpart, and a transliterated or
/// Latin-script term where Arabic has a settled one. A third rule is not about
/// voice but is just as invisible: a `{placeholder}` present in one language
/// and not the other, which the UI would print as a raw name inside a finished
/// sentence.
///
/// **Honest limits.** Rule 1 judges by a curated list, not a grammar: an
/// unlisted colloquialism passes, and `فيه` (فصحى "in it") is deliberately not
/// on the list because a blanket rule would fail on correct copy. Where only a
/// shadda separates the two — `نزّل` (حمّل) against فصحى `نزل` — the list stays
/// silent rather than guess. The Egyptian present tense (the بـ prefix:
/// `بيعمل`) is the same kind of gap: a pattern for it would fail on فصحى words
/// as ordinary as `بيع` and `بين`, so the listed verb forms stand in for it.
/// Rule 2 keeps a small allowlist of established technical borrowings, each
/// with its reason. Tone, sentence length and idiom are taste; they are not
/// gated here and are the reviewer's job.
void main() {
  Map<String, String> keysOf(String lang) {
    final table = <String, String>{};
    final dir = Directory('assets/i18n/$lang');
    for (final file in dir.listSync().whereType<File>()) {
      if (!file.path.endsWith('.json')) continue;
      final decoded =
          (jsonDecode(file.readAsStringSync()) as Map).cast<String, dynamic>();
      decoded.forEach((key, value) => table[key] = '$value');
    }
    return table;
  }

  final ar = keysOf('ar');
  final en = keysOf('en');

  /// The particles Arabic glues to the front of a word. A banned token is
  /// checked whole and with each of these stripped, so `واللي` is caught
  /// without listing every combination.
  const clitics = ['وال', 'فال', 'بال', 'كال', 'ال', 'و', 'ف', 'ب', 'ك', 'ل'];

  /// Colloquial token → the فصحى word that belongs there instead. Every entry
  /// names its replacement so a failure says what to write, not just what is
  /// wrong. Keys are written without diacritics, because the value under test
  /// is stripped of them before the lookup.
  const colloquial = <String, String>{
    'اللي': 'الذي / التي',
    'مش': 'ليس / لا',
    'مفيش': 'لا يوجد',
    'بتاع': 'الخاص بـ',
    'بتاعت': 'الخاصة بـ',
    'دايما': 'دائمًا',
    'عايز': 'تريد',
    'عايزة': 'تريد',
    'عايزين': 'تريد',
    'محتاج': 'يحتاج',
    'محتاجة': 'يحتاج',
    'سيب': 'اترك',
    'سيبه': 'اتركه',
    'سيبها': 'اتركها',
    'دوس': 'اضغط',
    'تدوس': 'تضغط',
    'دلوقتي': 'الآن',
    'لما': 'عندما',
    'عشان': 'لأن',
    'كده': 'هكذا',
    'كدا': 'هكذا',
    'زي': 'مثل',
    'برضه': 'أيضًا',
    'برضو': 'أيضًا',
    'كمان': 'أيضًا',
    'لسه': 'لا يزال',
    'حاجة': 'شيء',
    'حاجات': 'أشياء',
    'خلاص': 'تم',
    'شغال': 'يعمل / مفعّل',
    'شغالة': 'يعمل / مفعّلة',
    'بقي': 'أصبح',
    'بقت': 'أصبحت',
    'بقى': 'أصبح',
    'ينفع': 'يمكن',
    'مين': 'من',
    'ازاي': 'كيف',
    'ليه': 'لماذا',
    'شيل': 'أزل',
    'شيله': 'أزله',
    'خد': 'خذ',
    'وريني': 'أرني',
    'بالظبط': 'بالضبط',
    // The Egyptian passive: the verb فصحى spells with another pattern.
    'اتشال': 'أُزيل',
    'اتضاف': 'أُضيف',
    'اتنسخ': 'نُسخ',
    'اتمسح': 'حُذف',
    'اتقطع': 'انقطع',
    'اتقفل': 'أُغلق',
    'اتفتح': 'فُتح',
    'اتلقى': 'كُشف عنه',
    'هنج': 'تجمّد',
    // The Egyptian present tense, form by form (see the limits above).
    'بيعمل': 'يقوم بـ',
    'بيقفل': 'يُغلق',
    'بيكمل': 'يُكمل',
    'بيسيب': 'يترك',
    'بيسكت': 'يكتم',
    'بيتكتم': 'يُكتم',
    'بيشتغل': 'يعمل',
    'بتشتغل': 'تعمل',
    'بتظهر': 'تظهر',
    'بتبدا': 'تبدأ',
    'بتتبعت': 'تُرسل',
    'بتنزل': 'تُحمَّل',
    'بيتنزل': 'يُحمَّل',
    'بيقرا': 'يقرأ',
    'بيكتب': 'يكتب',
    'بيفضل': 'يبقى',
    'بيحصل': 'يحدث',
    'بيبدا': 'يبدأ',
    'بتقول': 'تقول',
    'بتقرا': 'تقرأ',
    'بيتولد': 'يُنشأ',
    'بيفشل': 'يفشل',
    'بيحجب': 'يحجب',
    'بيجيب': 'يجلب',
    'بيبلغ': 'يبلّغ',
    'بيخلي': 'يجعل',
    'بيحرك': 'يُحدِّث',
    'بتشوف': 'تُحتسَب',
    'بتتقاس': 'تُقاس',
    'بيترفع': 'يُرفع',
    'بيسجل': 'يسجّل',
  };

  /// The Egyptian `م…ش` negator, which wraps a فصحى verb: `بيقفلش` is
  /// `لا يُغلق`. No فصحى word of this shape appears in the packs; if one ever
  /// does, it belongs in [negationExceptions] with its reason rather than in a
  /// weakened rule.
  final negation = RegExp(r'^م[\u0621-\u064A]{2,}ش$');
  const negationExceptions = <String, String>{};

  /// A transliterated term → the Arabic that says the same thing. These are the
  /// words a reader of فصحى meets as foreign sounds inside an Arabic sentence.
  const transliterated = <String, String>{
    'التراي': 'منطقة الإشعارات',
    'سكان': 'فحص',
    'فولدر': 'مجلد',
    'فايروول': 'جدار الحماية',
    'ريجستري': 'سجل النظام',
    'دشبورد': 'لوحة المعلومات',
    'كارت': 'بطاقة',
    'باج': 'خلل',
    'فيد': 'مصدر',
    'الفيدات': 'المصادر',
    'دومين': 'نطاق',
    'دومينات': 'نطاقات',
    'هاش': 'تجزئة',
    'هاشات': 'تجزئات',
    'أوفلاين': 'بلا اتصال',
    'تليمتري': 'قياس عن بُعد',
    'الهارد': 'القرص',
    'سوكيت': 'مقبس',
    'تاب': 'تبويب',
  };

  /// Latin-script tokens that are allowed to stand in Arabic copy, each with
  /// the reason it is not translated. Anything else in Latin script fails.
  const latinAllowed = <String>{
    // The product, its platform, and the file manager it writes to.
    'MI', 'CS', 'MICS', 'Windows', 'Explorer', 'Microsoft', 'Defender',
    // Windows features, protocols and settings the copy names as Windows does,
    // because the user has to find the same words in the system UI.
    'UAC', 'RDP', 'SMBv1', 'LOLBin', 'DPAPI', 'NTLM', 'DLL', 'EXE',
    // The layers the app and its docs count in (THREAT-MODEL: L1–L5).
    'L1', 'L2', 'L3', 'L4', 'L5',
    // A Windows command quoted verbatim so the user can paste it. These are
    // one allowlisted set, and adding a word here is the price of not
    // translating a command.
    'fsutil', 'behavior', 'set', 'disablelastaccess',
    // Feeds and intel sources the user can configure (THREAT-MODEL §B6).
    'NVD', 'CISA', 'KEV', 'abuse.ch', 'GitHub', 'GeoIP', 'DNS',
    // The engine's own vocabulary for what it watches and what it scores.
    'IDS', 'IOC', 'CVSS', 'TCP', 'UDP', 'hosts', 'sha256',
    // Formats, algorithms and rule languages the engine reads or writes.
    'JSON', 'YARA', 'Sigma', 'Markdown', 'SHA-256', 'AES-256-GCM', 'AES', 'GCM',
    'TLS', 'cidr',
    'HTTP', 'HTTPS',
    // Levels the UI prints beside a finding (the engine's own words, which the
    // report and the toast share).
    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN', 'INFO',
    // Auth material a feed may ask for, and the header it travels in.
    'Auth-Key', 'API', 'URL', 'ID', 'UTC',
  };

  /// A file name, an environment variable, a CVE id, a dotted key name or a
  /// command-line flag is not copy: it is the name of a thing, spelled the one
  /// way it is spelled.
  final nameLike = RegExp(
      r'^[A-Za-z_][\w-]*(\.[\w-]+)+$'
      r'|^%[A-Za-z_]+%$'
      r'|^--[a-z-]+$'
      r'|^MICS[-_][A-Za-z0-9_-]+$'
      r'|^CVE-\d{4}-\d+$');

  /// The tokens a value is made of. Placeholders, environment variables, paths
  /// and URLs are removed first: they are values the engine fills in or things
  /// named by their own spelling, not the copy around them. What is left is
  /// stripped of diacritics and the tatweel, so `شغّال` and `شغال` are the same
  /// word and a key is written one way.
  List<String> wordsOf(String value) => value
      .replaceAll(RegExp(r'\{[^}]*\}'), ' ')
      .replaceAll(RegExp(r'<[^>]*>'), ' ')
      .replaceAll(RegExp(r'%[A-Za-z_]+%'), ' ')
      .replaceAll(RegExp(r'\S*/\S*'), ' ')
      .replaceAll(RegExp(r'\S*\\\S*'), ' ')
      .replaceAll(r'\n', ' ')
      .replaceAll(RegExp(r'[\u064B-\u0652\u0640]'), '')
      .split(RegExp(r'[^\u0621-\u064A\w.-]+'))
      .map((w) => w.replaceAll(RegExp(r'^[.-]+|[.-]+$'), ''))
      .where((w) => w.isNotEmpty)
      .toList();

  /// A word with the clitic that carries it stripped, so `وباللي` and `اللي`
  /// are judged the same.
  String bareOf(String word) {
    for (final clitic in clitics) {
      if (word.startsWith(clitic) && word.length > clitic.length) {
        return word.substring(clitic.length);
      }
    }
    return word;
  }

  void forEachValue(void Function(String key, List<String> words) body) {
    for (final entry in ar.entries) {
      body(entry.key, wordsOf(entry.value));
    }
  }

  test('the Arabic pack uses no listed colloquialism', () {
    final found = <String>[];
    forEachValue((key, words) {
      for (final word in words) {
        final bare = bareOf(word);
        final fix = colloquial[word] ?? colloquial[bare];
        if (fix != null) {
          found.add('$key: "$word" — use $fix');
        } else if (negation.hasMatch(bare) &&
            !negationExceptions.containsKey(bare)) {
          found.add('$key: "$word" — the Egyptian م…ش negation');
        }
      }
    });
    expect(found.length, 0,
        reason: 'colloquial Arabic in the pack:\n${found.join('\n')}');
  });

  test('the Arabic pack spells a transliterated term in Arabic', () {
    final found = <String>[];
    forEachValue((key, words) {
      for (final word in words) {
        final bare = bareOf(word);
        final fix = transliterated[word] ?? transliterated[bare];
        if (fix != null) {
          found.add('$key: "$word" — say $fix');
        }
      }
    });
    expect(found.length, 0,
        reason: 'transliterated Arabic in the pack:\n${found.join('\n')}');
  });

  test('the Arabic pack carries no Latin script but the names in the list', () {
    final found = <String>[];
    forEachValue((key, words) {
      for (final word in words) {
        if (!RegExp(r'^[A-Za-z]').hasMatch(word)) continue;
        if (latinAllowed.contains(word) || nameLike.hasMatch(word)) continue;
        found.add('$key: "$word"');
      }
    });
    expect(found.length, 0,
        reason: 'Latin script in the Arabic pack (add it to latinAllowed with '
            'its reason if it is a name):\n${found.join('\n')}');
  });

  test('every placeholder in English exists in Arabic with the same name', () {
    final placeholder = RegExp(r'\{([A-Za-z0-9_]+)\}');
    final found = <String>[];
    for (final key in en.keys) {
      final wanted =
          placeholder.allMatches(en[key]!).map((m) => m.group(1)).toSet();
      final have = placeholder
          .allMatches(ar[key] ?? '')
          .map((m) => m.group(1))
          .toSet();
      for (final name in wanted.difference(have)) {
        found.add('$key: "{$name}" is in English and missing in Arabic');
      }
      for (final name in have.difference(wanted)) {
        found.add('$key: "{$name}" is in Arabic and not in English');
      }
    }
    expect(found.length, 0,
        reason: 'placeholder drift between en and ar:\n${found.join('\n')}');
  });
}
