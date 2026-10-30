// Intelligence & sync (D-012): what the engine actually has, per source.
//
// The screen is deliberately a report, not a control panel: freshness, what a
// source produced, when it is due next, and the last error when it is failing.
// A single aggregate "last synced" number is exactly the thing that used to hide
// a feed that had been dead for weeks.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/sync/sync_status.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class IntelScreen extends ConsumerStatefulWidget {
  const IntelScreen({super.key});

  @override
  ConsumerState<IntelScreen> createState() => _IntelScreenState();
}

class _IntelScreenState extends ConsumerState<IntelScreen> {
  bool _syncing = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // The provider polls once a minute; opening the screen should not show a
      // snapshot that is up to 60 s stale.
      ref.read(syncStatusProvider.notifier).refresh();
    });
  }

  Future<void> _syncNow() async {
    setState(() => _syncing = true);
    final messenger = ScaffoldMessenger.of(context);
    final done = context.tr('intel.done');
    final failed = context.tr('intel.syncFailed');
    try {
      await ref.read(syncStatusProvider.notifier).syncNow();
      _snack(messenger, done);
    } catch (e) {
      _snack(messenger, failed.replaceAll('{error}', '$e'), error: true);
    } finally {
      if (mounted) setState(() => _syncing = false);
    }
  }

  void _snack(ScaffoldMessengerState messenger, String text,
      {bool error = false}) {
    // Only the failure case recolours the bar; a success message keeps the
    // theme's own colours. Overriding the background alone is what made this
    // message invisible in light mode (white text on the white surface it used
    // to set) — see `docs/CONTRAST.md`.
    messenger.showSnackBar(SnackBar(
      content: Text(text),
      backgroundColor: error ? AppColors.red : null,
    ));
  }

  @override
  Widget build(BuildContext context) {
    final async = ref.watch(syncStatusProvider);
    final st = async.value ?? SyncStatus.empty;
    final totals = context.tr('intel.age').replaceAll('{age}', st.ageLabel);

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(children: [
            Text(context.tr('intel.title'),
                style: TextStyle(
                    color: AppColors.text,
                    fontSize: 16,
                    fontWeight: FontWeight.w800)),
            const SizedBox(width: 10),
            _OnlineChip(online: st.online),
            const Spacer(),
            if (_syncing)
              const Padding(
                padding: EdgeInsetsDirectional.only(end: 10),
                child: SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2)),
              ),
            FilledButton.icon(
              onPressed: _syncing ? null : _syncNow,
              icon: const Icon(Icons.sync, size: 18),
              label: Text(context.tr('intel.syncNow')),
            ),
          ]),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Align(
            alignment: AlignmentDirectional.centerStart,
            child: Text(
              st.neverSynced ? context.tr('sync.never') : totals,
              style: AppTheme.mono(size: 11, color: AppColors.muted),
            ),
          ),
        ),
        if (!st.online)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Align(
              alignment: AlignmentDirectional.centerStart,
              child: Text(context.tr('intel.offline'),
                  style: TextStyle(color: AppColors.orange, fontSize: 12)),
            ),
          ),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _TotalsCard(st: st),
              const SizedBox(height: 14),
              for (final source in st.sources) _SourceCard(source: source),
              const SizedBox(height: 6),
              Text(
                context.tr('intel.hint'),
                style: TextStyle(color: AppColors.muted, fontSize: 11),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _OnlineChip extends StatelessWidget {
  const _OnlineChip({required this.online});
  final bool online;

  @override
  Widget build(BuildContext context) {
    final color = online ? AppColors.green : AppColors.orange;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Text(
        online ? context.tr('sync.online') : context.tr('sync.offline'),
        style: AppTheme.mono(size: 10, color: color),
      ),
    );
  }
}

/// What the counters add up to across sources — the answer to "what do I
/// actually have on this machine?".
class _TotalsCard extends StatelessWidget {
  const _TotalsCard({required this.st});
  final SyncStatus st;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(context.tr('intel.totals'),
              style: TextStyle(
                  color: AppColors.text,
                  fontSize: 13,
                  fontWeight: FontWeight.w700)),
          const SizedBox(height: 10),
          Wrap(spacing: 22, runSpacing: 10, children: [
            _Stat(
                value: '${st.iocDomains}',
                label: context.tr('intel.source.ioc_domains')),
            _Stat(
                value: '${st.kevTotal}',
                label: context.tr('intel.source.kev')),
            _Stat(
                value: '${st.cveCacheTotal}',
                label: context.tr('intel.source.nvd')),
            _Stat(
                value: '${st.iocHashes}',
                label: context.tr('intel.source.ioc_hashes')),
            _Stat(
                value: '${st.geoipCountries}',
                label: context.tr('intel.source.geoip_blocklists')),
          ]),
          const SizedBox(height: 10),
          Text(
            context
                .tr('sync.every')
                .replaceAll('{hours}', '${st.intervalHours}'),
            style: AppTheme.mono(size: 10, color: AppColors.muted),
          ),
        ],
      ),
    );
  }
}

class _Stat extends StatelessWidget {
  const _Stat({required this.value, required this.label});
  final String value;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(value, style: AppTheme.mono(size: 18, color: AppColors.cyan)),
        Text(label,
            style: TextStyle(color: AppColors.muted, fontSize: 10.5)),
      ],
    );
  }
}

class _SourceCard extends StatelessWidget {
  const _SourceCard({required this.source});
  final SyncSource source;

  @override
  Widget build(BuildContext context) {
    final color = _stateColor(source.state);
    final items = _itemsLine(context, source);
    final next = source.onDemand
        ? context.tr('intel.onDemand')
        : source.nextDueSeconds == null
            ? context.tr('intel.onDemand')
            : context
                .tr('intel.nextDue')
                .replaceAll('{age}', SyncSource.shortAge(source.nextDueSeconds));
    final last = source.ageSeconds == null
        ? context.tr('intel.state.never')
        : context
            .tr('sync.intel')
            .replaceAll('{age}', SyncSource.shortAge(source.ageSeconds));

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            Container(
                width: 4,
                height: 26,
                decoration: BoxDecoration(
                    color: color, borderRadius: BorderRadius.circular(2))),
            const SizedBox(width: 10),
            Expanded(
              child: Text(_sourceLabel(context, source.source),
                  style: TextStyle(
                      color: AppColors.text,
                      fontSize: 13.5,
                      fontWeight: FontWeight.w700)),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(999),
                border: Border.all(color: color.withValues(alpha: 0.6)),
              ),
              child: Text(_stateLabel(context, source.state),
                  style: AppTheme.mono(size: 10, color: color)),
            ),
          ]),
          const SizedBox(height: 8),
          Text(items,
              style: AppTheme.mono(size: 11, color: AppColors.text)),
          if (source.detail != null && source.detail!.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(source.detail!,
                style: TextStyle(color: AppColors.muted, fontSize: 11)),
          ],
          const SizedBox(height: 6),
          Text('$last · $next',
              style: AppTheme.mono(size: 10, color: AppColors.muted)),
          if (source.hasError) ...[
            const SizedBox(height: 6),
            Text(
              context
                  .tr('intel.error')
                  .replaceAll('{error}', source.lastError!),
              style: AppTheme.mono(size: 10.5, color: AppColors.red),
            ),
          ],
        ],
      ),
    );
  }

  static Color _stateColor(String state) => switch (state) {
        'ok' => AppColors.green,
        'failed' => AppColors.red,
        'not_configured' => AppColors.orange,
        _ => AppColors.muted,
      };

  static String _sourceLabel(BuildContext context, String id) => switch (id) {
        'ioc_hashes' => context.tr('intel.source.ioc_hashes'),
        'ioc_domains' => context.tr('intel.source.ioc_domains'),
        'kev' => context.tr('intel.source.kev'),
        'geoip_blocklists' => context.tr('intel.source.geoip_blocklists'),
        'nvd' => context.tr('intel.source.nvd'),
        _ => id,
      };

  static String _stateLabel(BuildContext context, String state) =>
      switch (state) {
        'ok' => context.tr('intel.state.ok'),
        'failed' => context.tr('intel.state.failed'),
        'not_configured' => context.tr('intel.state.notConfigured'),
        _ => context.tr('intel.state.never'),
      };

  /// The unit matters: 76k domains, 1.7k CVEs and 3 country lists are all
  /// "items", but reading them as the same kind of number would be a lie.
  static String _itemsLine(BuildContext context, SyncSource source) {
    final count = '${source.items}';
    return switch (source.source) {
      'ioc_domains' =>
        context.tr('intel.countDomains').replaceAll('{count}', count),
      'ioc_hashes' =>
        context.tr('intel.countHashes').replaceAll('{count}', count),
      'kev' => context.tr('intel.countCves').replaceAll('{count}', count),
      'nvd' => context.tr('intel.countCves').replaceAll('{count}', count),
      'geoip_blocklists' =>
        context.tr('intel.countRanges').replaceAll('{count}', count),
      _ => count,
    };
  }
}