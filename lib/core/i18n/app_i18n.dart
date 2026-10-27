import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// AR/EN dictionary — every user-facing string goes through [tr].
/// Arabic is the default language (RTL).
enum AppLang { ar, en }

final localeProvider =
    NotifierProvider<LocaleNotifier, AppLang>(LocaleNotifier.new);

class LocaleNotifier extends Notifier<AppLang> {
  @override
  AppLang build() => AppLang.ar;
  void toggle() => state = state == AppLang.ar ? AppLang.en : AppLang.ar;
  void set(AppLang l) => state = l;
}

final rtlProvider = Provider<bool>((ref) {
  return ref.watch(localeProvider) == AppLang.ar;
});

String tr(BuildContext context, String key) {
  final lang = AppLang.ar; // fallback; widgets use the extension below
  return lookup(lang, key);
}

extension TrX on BuildContext {
  String tr(String key) {
    final container = ProviderScope.containerOf(this);
    final lang = container.read(localeProvider);
    return lookup(lang, key);
  }
}

String lookup(AppLang lang, String key) {
  final table = lang == AppLang.ar ? _ar : _en;
  return table[key] ?? _en[key] ?? key;
}

const Map<String, String> _en = {
  'app.name': 'MI CS Command Center',
  'app.tagline': 'Smart. Transparent. Open-source defense.',
  'nav.dashboard': 'Dashboard',
  'nav.audit': 'System Audit',
  'nav.scanner': 'Malware Scanner',
  'nav.network': 'Network & Firewall',
  'nav.ids': 'IDS (L2)',
  'nav.vulns': 'Vulnerabilities',
  'nav.guard': 'Process Guard',
  'nav.canaries': 'Canaries',
  'nav.hardening': 'Hardening Center',
  'nav.incidents': 'Incidents',
  'nav.reports': 'Reports',
  'nav.settings': 'Settings',
  'state.engine': 'Engine',
  'engine.running': 'Protected',
  'engine.reconnecting': 'Reconnecting…',
  'engine.missing': 'Engine not found',
  'engine.stopped': 'Stopped',
  'score.title': 'Security Score',
  'score.whatNow': 'What should I do now?',
  'score.doFirst': 'Fix the highest-impact finding first:',
  'common.refresh': 'Refresh',
  'common.fix': 'Fix',
  'common.critical': 'Critical',
  'common.high': 'High',
  'common.medium': 'Medium',
  'common.low': 'Low',
  'common.secure': 'Secure',
  'common.warning': 'Warning',
  'common.vulnerable': 'Vulnerable',
  'common.unknown': 'Unknown',
  'status.secure': 'Secure',
  'audit.title': 'System Audit',
  'audit.subtitle': 'Real checks from your machine — Defender, firewall, RDP, SMBv1, UAC, admins, startup and more',
  'audit.findings': 'findings',
  'audit.startup': 'Startup entries',
  'audit.tasks': 'Non-Microsoft scheduled tasks',
  'audit.empty.title': 'No audit has run yet',
  'audit.empty.action': 'Run first audit',
  'audit.loading': 'Collecting live data from the engine…',
  'audit.error': 'Audit failed',
  'dashboard.liveFeed': 'Layer Health (L1–L5)',
  'dashboard.summary': 'Findings Summary',
  'soon.title': 'Module coming in a later phase',
  'soon.body':
      'This module ships in an upcoming phase of the build plan. The engine-side work for it is scheduled — the screen will light up with live data once wired.',
  'settings.title': 'Settings',
  'settings.language': 'Language',
  'settings.enginePath': 'Engine executable',
  'lang.ar': 'العربية',
  'lang.en': 'English',
};

const Map<String, String> _ar = {
  'app.name': 'مركز MI CS للدفاع السيبراني',
  'app.tagline': 'حماية ذكية، شفافة، ومفتوحة المصدر',
  'nav.dashboard': 'الرئيسية',
  'nav.audit': 'فحص النظام',
  'nav.scanner': 'فاحص الملفات',
  'nav.network': 'الشبكة والجدار',
  'nav.ids': 'كاشف التسلل L2',
  'nav.vulns': 'الثغرات',
  'nav.guard': 'حارس العمليات',
  'nav.canaries': 'الفخاخ',
  'nav.hardening': 'مركز التقوية',
  'nav.incidents': 'الحوادث',
  'nav.reports': 'التقارير',
  'nav.settings': 'الإعدادات',
  'state.engine': 'المحرك',
  'engine.running': 'محمي',
  'engine.reconnecting': 'إعادة الاتصال…',
  'engine.missing': 'المحرك غير موجود',
  'engine.stopped': 'متوقف',
  'score.title': 'درجة الحماية',
  'score.whatNow': 'ماذا أفعل الآن؟',
  'score.doFirst': 'ابدأ بأخطر ملاحظة:',
  'common.refresh': 'تحديث',
  'common.fix': 'إصلاح',
  'common.critical': 'حرج',
  'common.high': 'مرتفع',
  'common.medium': 'متوسط',
  'common.low': 'منخفض',
  'common.secure': 'آمن',
  'common.warning': 'تحذير',
  'common.vulnerable': 'معرض للخطر',
  'common.unknown': 'غير معروف',
  'status.secure': 'آمن',
  'audit.title': 'فحص النظام',
  'audit.subtitle':
      'نتائج حقيقية من جهازك — ديفندر، الجدار الناري، RDP، SMBv1، UAC، المدراء، بدء التشغيل والمزيد',
  'audit.findings': 'ملاحظة',
  'audit.startup': 'عناصر بدء التشغيل',
  'audit.tasks': 'مهام مجدولة (غير Microsoft)',
  'audit.empty.title': 'لم يتم تشغيل فحص بعد',
  'audit.empty.action': 'ابدأ الفحص الأول',
  'audit.loading': 'جارٍ جمع البيانات الحية من المحرك…',
  'audit.error': 'فشل الفحص',
  'dashboard.liveFeed': 'صحة الطبقات (L1–L5)',
  'dashboard.summary': 'ملخص الملاحظات',
  'soon.title': 'الوحدة تظهر في مرحلة لاحقة',
  'soon.body':
      'هذه الوحدة ضمن المراحل القادمة من خطة البناء. سيتم ربطها بالمحرك وتظهر بالبيانات الحية فور اكتمال مرحلتها.',
  'settings.title': 'الإعدادات',
  'settings.language': 'اللغة',
  'settings.enginePath': 'مسار المحرك',
  'lang.ar': 'العربية',
  'lang.en': 'English',
};
