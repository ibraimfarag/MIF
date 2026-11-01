import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class IdsState {
  final List<String> blockedDomains;
  final bool hostsManaged;
  final bool loading;
  final String? error;
  const IdsState(
      {this.blockedDomains = const [],
      this.hostsManaged = false,
      this.loading = false,
      this.error});
}

final idsProvider = NotifierProvider<IdsNotifier, IdsState>(IdsNotifier.new);

class IdsNotifier extends Notifier<IdsState> {
  @override
  IdsState build() => const IdsState();

  Future<void> refresh() async {
    try {
      final res = await ref.read(engineIpcProvider).request('ids.status');
      state = IdsState(
        blockedDomains: (res['blocked_domains'] as List? ?? [])
            .map((d) => d.toString())
            .toList(),
        hostsManaged: res['hosts_managed'] as bool? ?? false,
      );
    } catch (e) {
      state = IdsState(error: e.toString());
    }
  }

  Future<void> addDomain(String domain) async {
    state = IdsState(
        blockedDomains: state.blockedDomains,
        hostsManaged: state.hostsManaged,
        loading: true);
    try {
      await ref
          .read(engineIpcProvider)
          .request('ids.block.add', {'domains': [domain]});
      await refresh();
    } catch (e) {
      state = IdsState(
          blockedDomains: state.blockedDomains, error: e.toString());
    }
  }

  Future<void> removeDomain(String domain) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('ids.block.remove', {'domain': domain});
      await refresh();
    } catch (e) {
      state = IdsState(
          blockedDomains: state.blockedDomains, error: e.toString());
    }
  }
}

class IdsScreen extends ConsumerStatefulWidget {
  const IdsScreen({super.key});

  @override
  ConsumerState<IdsScreen> createState() => _IdsScreenState();
}

class _IdsScreenState extends ConsumerState<IdsScreen> {
  final _domainController = TextEditingController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(idsProvider.notifier).refresh();
    });
  }

  @override
  void dispose() {
    _domainController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final st = ref.watch(idsProvider);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(children: [
          Icon(Icons.radar, color: AppColors.cyan),
          const SizedBox(width: 8),
          Text(context.tr('nav.ids'),
              style: TextStyle(
                  color: AppColors.text,
                  fontSize: 16,
                  fontWeight: FontWeight.w800)),
          const Spacer(),
          if (st.loading)
            const SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2)),
          OutlinedButton.icon(
            onPressed: () => ref.read(idsProvider.notifier).refresh(),
            icon: const Icon(Icons.refresh, size: 16),
            label: Text(context.tr('common.refresh')),
          ),
        ]),
        const SizedBox(height: 6),
        Text(
          context.tr('ids.intro'),
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 12),
        if (st.error != null)
          Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.red.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.red.withValues(alpha: 0.4)),
            ),
            child: Text(st.error!,
                style: TextStyle(color: AppColors.orange, fontSize: 12)),
          ),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Row(children: [
              Expanded(
                child: TextField(
                  controller: _domainController,
                  style: AppTheme.mono(size: 12),
                  decoration: InputDecoration(
                    labelText: context.tr('ids.domainLabel'),
                    hintText: context.tr('ids.domainHint'),
                  ),
                  onSubmitted: (d) {
                    if (d.trim().isNotEmpty) {
                      ref.read(idsProvider.notifier).addDomain(d.trim());
                      _domainController.clear();
                    }
                  },
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                onPressed: () {
                  final d = _domainController.text.trim();
                  if (d.isNotEmpty) {
                    ref.read(idsProvider.notifier).addDomain(d);
                    _domainController.clear();
                  }
                },
                icon: const Icon(Icons.block, size: 16),
                label: Text(context.tr('ids.block')),
              ),
            ]),
          ),
        ),
        const SizedBox(height: 12),
        Row(children: [
          Text(
              context
                  .tr('ids.blockedDomains')
                  .replaceAll('{count}', '${st.blockedDomains.length}'),
              style: TextStyle(
                  color: AppColors.text, fontWeight: FontWeight.w700)),
          const Spacer(),
          if (st.hostsManaged)
            Chip(
              label: Text(context.tr('ids.hostsManaged'),
                  style: TextStyle(fontSize: 10)),
              side: BorderSide(color: AppColors.green.withValues(alpha: 0.5)),
              labelStyle: TextStyle(color: AppColors.green),
            ),
        ]),
        const SizedBox(height: 8),
        if (st.blockedDomains.isEmpty)
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              context.tr('ids.empty'),
              style: TextStyle(color: AppColors.muted, fontSize: 12.5),
            ),
          ),
        for (final d in st.blockedDomains)
          Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border),
            ),
            child: Row(children: [
              Icon(Icons.block, size: 14, color: AppColors.red),
              const SizedBox(width: 10),
              Expanded(
                child: Text(d,
                    style: AppTheme.mono(size: 11.5, color: AppColors.text)),
              ),
              IconButton(
                tooltip: context.tr('common.remove'),
                icon: Icon(Icons.delete_outline,
                    size: 16, color: AppColors.muted),
                onPressed: () =>
                    ref.read(idsProvider.notifier).removeDomain(d),
              ),
            ]),
          ),
      ],
    );
  }
}
