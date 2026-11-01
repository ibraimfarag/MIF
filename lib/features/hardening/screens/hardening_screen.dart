import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/providers/providers.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class HardeningAction {
  final String id;
  final String name;
  final String nameAr;
  final String explanation;
  final bool applied;
  HardeningAction({
    required this.id,
    required this.name,
    required this.nameAr,
    required this.explanation,
    required this.applied,
  });
  factory HardeningAction.fromJson(Map<String, dynamic> j) => HardeningAction(
        id: j['id'] as String? ?? '',
        name: j['name'] as String? ?? '',
        nameAr: j['name_ar'] as String? ?? '',
        explanation: j['explanation'] as String? ?? '',
        applied: j['applied'] as bool? ?? false,
      );
}

final hardeningProvider =
    NotifierProvider<HardeningNotifier, List<HardeningAction>>(
        HardeningNotifier.new);

class HardeningNotifier extends Notifier<List<HardeningAction>> {
  @override
  List<HardeningAction> build() => const [];

  Future<void> refresh() async {
    try {
      final res = await ref.read(engineIpcProvider).request('hardening.list');
      state = (res as List)
          .map((a) => HardeningAction.fromJson(a as Map<String, dynamic>))
          .toList();
    } catch (_) {}
  }

  Future<String?> apply(String id) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('hardening.apply', {'action': id});
      await refresh();
      return null;
    } catch (e) {
      return e.toString();
    }
  }

  Future<String?> rollback(String id) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('hardening.rollback', {'action': id});
      await refresh();
      return null;
    } catch (e) {
      return e.toString();
    }
  }
}

class HardeningScreen extends ConsumerStatefulWidget {
  const HardeningScreen({super.key});

  @override
  ConsumerState<HardeningScreen> createState() => _HardeningScreenState();
}

class _HardeningScreenState extends ConsumerState<HardeningScreen> {
  String? _busy;
  String? _message;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(hardeningProvider.notifier).refresh();
    });
  }

  @override
  Widget build(BuildContext context) {
    final actions = ref.watch(hardeningProvider);
    // Not a direction check: the engine ships two names per action (`name` and
    // `nameAr`), so a screen that shows the human-readable one has to pick a
    // language rather than ask "is this RTL". `AppLang` compares by code, so
    // this keeps working when the language list grows.
    final preferArabicNames = ref.watch(localeProvider) == AppLang.ar;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(context.tr('nav.hardening'),
            style: TextStyle(
                color: AppColors.text,
                fontSize: 16,
                fontWeight: FontWeight.w800)),
        const SizedBox(height: 6),
        Text(
          context.tr('hardening.intro'),
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 12),
        if (_message != null)
          Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.cyan.withValues(alpha: 0.4)),
            ),
            child: Text(_message!,
                style: TextStyle(color: AppColors.text, fontSize: 12)),
          ),
        for (final a in actions)
          Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                  color: a.applied
                      ? AppColors.green.withValues(alpha: 0.4)
                      : AppColors.border),
            ),
            child: Row(children: [
              Icon(
                a.applied ? Icons.verified : Icons.recommend,
                color: a.applied ? AppColors.green : AppColors.orange,
                size: 20,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(preferArabicNames ? a.nameAr : a.name,
                        style: TextStyle(
                            color: AppColors.text,
                            fontWeight: FontWeight.w700,
                            fontSize: 13.5)),
                    const SizedBox(height: 2),
                    Text(a.explanation,
                        style: TextStyle(
                            color: AppColors.muted, fontSize: 11.5)),
                  ],
                ),
              ),
              if (_busy == a.id)
                const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
              else ...[
                if (!a.applied)
                  FilledButton(
                    onPressed: () async {
                      setState(() => _busy = a.id);
                      final before =
                          ref.read(auditProvider).report?.score;
                      final err = await ref
                          .read(hardeningProvider.notifier)
                          .apply(a.id);
                      // Re-read the section this action changes — merged into the
                      // full report — so the score delta flashes immediately
                      // without re-running every collector.
                      await ref
                          .read(auditProvider.notifier)
                          .refreshAfterFix(a.id);
                      final after = ref.read(auditProvider).report?.score;
                      final delta = (after != null && before != null)
                          ? after - before
                          : null;
                      setState(() {
                        _busy = null;
                        _message = err ??
                            '✓ ${preferArabicNames ? a.nameAr : a.name} — applied'
                                '${delta != null && delta != 0 ? "  (score ${delta > 0 ? "+" : ""}$delta)" : ""}';
                      });
                    },
                    style: FilledButton.styleFrom(
                        backgroundColor: AppColors.green,
                        foregroundColor: AppColors.background),
                    child: Text(context.tr('common.fix')),
                  ),
                if (a.applied)
                  OutlinedButton(
                    onPressed: () async {
                      setState(() => _busy = a.id);
                      final err = await ref
                          .read(hardeningProvider.notifier)
                          .rollback(a.id);
                      // The rollback moves the same section back: re-read it so
                      // the audit agrees with the hardening card.
                      await ref
                          .read(auditProvider.notifier)
                          .refreshAfterFix(a.id);
                      setState(() {
                        _busy = null;
                        _message = err ??
                            '↩ ${preferArabicNames ? a.nameAr : a.name} — rolled back';
                      });
                    },
                    child: Text(context.tr('hardening.rollback')),
                  ),
              ],
            ]),
          ),
      ],
    );
  }
}
