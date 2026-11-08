import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/models/network_models.dart';

// ---------- providers ----------

final connectionsProvider =
    NotifierProvider<ConnectionsNotifier, AsyncValue<List<NetworkConnection>>>(
        ConnectionsNotifier.new);

class ConnectionsNotifier
    extends Notifier<AsyncValue<List<NetworkConnection>>> {
  @override
  AsyncValue<List<NetworkConnection>> build() =>
      const AsyncValue.data(<NetworkConnection>[]);

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    try {
      final res = await ref.read(engineIpcProvider).request('net.connections');
      final list = (res as List)
          .map((c) => NetworkConnection.fromJson(c as Map<String, dynamic>))
          .toList();
      state = AsyncValue.data(list);
    } catch (e, st) {
      state = AsyncValue.error(e, st);
    }
  }

  /// Sends the spec the engine built for one row (D-043). Returns null when the
  /// machine accepted it, or the engine's own sentence when it refused it -
  /// "needs an administrator" included, because that is a real answer and not a
  /// failure of the click.
  Future<String?> block(NetworkBlock block) async {
    try {
      await ref.read(engineIpcProvider).request('fw.wfp.block', block.toJson());
      return null;
    } catch (e) {
      return e.toString();
    }
  }
}

final firewallProvider =
    NotifierProvider<FirewallNotifier, FirewallState>(FirewallNotifier.new);

class FirewallState {
  final bool defaultDeny;
  final List<FirewallRule> rules;
  final bool loading;
  final String? error;
  const FirewallState(
      {this.defaultDeny = false,
      this.rules = const [],
      this.loading = false,
      this.error});
}

class FirewallNotifier extends Notifier<FirewallState> {
  @override
  FirewallState build() => const FirewallState();

  Future<void> refresh() async {
    state = FirewallState(
        defaultDeny: state.defaultDeny, rules: state.rules, loading: true);
    try {
      final ipc = ref.read(engineIpcProvider);
      final denyRes = await ipc.request('fw.default_deny.status');
      final rulesRes = await ipc.request('fw.rules.list');
      state = FirewallState(
        defaultDeny:
            (denyRes as Map)['default_deny_outbound'] as bool? ?? false,
        rules: (rulesRes as List)
            .map((r) => FirewallRule.fromJson(r as Map<String, dynamic>))
            .toList(),
      );
    } catch (e) {
      state = FirewallState(error: e.toString());
    }
  }

  Future<void> toggleDefaultDeny(bool enable) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request(enable ? 'fw.default_deny.enable' : 'fw.default_deny.disable');
      await refresh();
    } catch (e) {
      state = FirewallState(
          defaultDeny: state.defaultDeny,
          rules: state.rules,
          error: e.toString());
    }
  }

  Future<void> blockCountry(String cc) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('fw.country.block', {'country': cc});
      await refresh();
    } catch (e) {
      state = FirewallState(
          defaultDeny: state.defaultDeny,
          rules: state.rules,
          error: e.toString());
    }
  }

  Future<void> removeRule(String name) async {
    try {
      await ref
          .read(engineIpcProvider)
          .request('fw.rules.remove', {'name': name});
      await refresh();
    } catch (e) {
      state = FirewallState(
          defaultDeny: state.defaultDeny,
          rules: state.rules,
          error: e.toString());
    }
  }
}

// ---------- screen ----------

class NetworkMonitorScreen extends ConsumerStatefulWidget {
  const NetworkMonitorScreen({super.key});

  @override
  ConsumerState<NetworkMonitorScreen> createState() =>
      _NetworkMonitorScreenState();
}

class _NetworkMonitorScreenState extends ConsumerState<NetworkMonitorScreen> {
  Timer? _timer;
  int _tab = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(connectionsProvider.notifier).refresh();
      ref.read(firewallProvider.notifier).refresh();
    });
    _timer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (_tab == 0) ref.read(connectionsProvider.notifier).refresh();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: SegmentedButton<int>(
            segments: [
              ButtonSegment(
                  value: 0,
                  label: Text(context.tr('nav.network')),
                  icon: const Icon(Icons.lan)),
              ButtonSegment(
                  value: 1,
                  label: Text(context.tr('network.firewall')),
                  icon: const Icon(Icons.security)),
            ],
            selected: {_tab},
            onSelectionChanged: (s) => setState(() => _tab = s.first),
          ),
        ),
        Expanded(child: _tab == 0 ? const _ConnectionsView() : const _FirewallView()),
      ],
    );
  }
}

class _ConnectionsView extends ConsumerStatefulWidget {
  const _ConnectionsView();

  @override
  ConsumerState<_ConnectionsView> createState() => _ConnectionsViewState();
}

class _ConnectionsViewState extends ConsumerState<_ConnectionsView> {
  @override
  void initState() {
    super.initState();
    // A snapshot is fetched when the screen opens, so the list is never the
    // empty state of a live machine. It is a microtask because the provider is
    // read after the first frame, not while it is being built.
    Future.microtask(() => ref.read(connectionsProvider.notifier).refresh());
  }

  /// Confirms, then sends the engine's own block spec for this row, then says
  /// what happened. The confirmation is not decoration: the filter persists after
  /// MI CS closes, so one click must be one deliberate act with its scope on
  /// screen.
  Future<void> _block(NetworkConnection conn) async {
    final block = conn.block;
    if (block == null) return;
    final messenger = ScaffoldMessenger.of(context);
    final yes = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(ctx.tr('network.blockTitle')),
        content: Text(ctx
            .tr('network.blockBody')
            .replaceAll('{app}', conn.processName)
            .replaceAll('{port}', '${block.port}')),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: Text(ctx.tr('common.cancel')),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(ctx.tr('network.block')),
          ),
        ],
      ),
    );
    if (yes != true) return;
    final err = await ref.read(connectionsProvider.notifier).block(block);
    if (!mounted) return;
    messenger.showSnackBar(SnackBar(
      content: Text(err == null
          ? context
              .tr('network.blocked')
              .replaceAll('{app}', conn.processName)
              .replaceAll('{port}', '${block.port}')
          : context.tr('network.blockFailed').replaceAll('{reason}', err)),
    ));
    if (err == null) {
      await ref.read(connectionsProvider.notifier).refresh();
    }
  }

  @override
  Widget build(BuildContext context) {
    final async = ref.watch(connectionsProvider);
    return async.when(
      data: (conns) {
        final suspicious = conns.where((c) => c.suspicious).toList();
        return ListView(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          children: [
            Row(children: [
              Text(
                  context
                      .tr('network.connections')
                      .replaceAll('{count}', '${conns.length}'),
                  style: AppTheme.mono(size: 12, color: AppColors.muted)),
              const SizedBox(width: 12),
              if (suspicious.isNotEmpty)
                Chip(
                  label: Text(
                      context
                          .tr('network.suspicious')
                          .replaceAll('{count}', '${suspicious.length}'),
                      style: TextStyle(
                          color: AppColors.orange, fontSize: 11)),
                  side: BorderSide(
                      color: AppColors.orange.withValues(alpha: 0.5)),
                ),
              const Spacer(),
              OutlinedButton.icon(
                onPressed: () =>
                    ref.read(connectionsProvider.notifier).refresh(),
                icon: const Icon(Icons.refresh, size: 16),
                label: Text(context.tr('common.refresh')),
              ),
            ]),
            const SizedBox(height: 8),
            if (suspicious.isNotEmpty) ...[
              for (final c in suspicious.take(20))
                _ConnTile(
                    conn: c,
                    highlight: true,
                    onBlock: () => _block(c)),
              const SizedBox(height: 8),
            ],
            for (final c in conns.where((c) => !c.suspicious).take(300))
              _ConnTile(
                  conn: c,
                  highlight: false,
                  onBlock: () => _block(c)),
          ],
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, _) =>
          Center(child: Text('$e', style: TextStyle(color: AppColors.red))),
    );
  }
}

class _ConnTile extends StatelessWidget {
  const _ConnTile(
      {required this.conn, required this.highlight, required this.onBlock});
  final NetworkConnection conn;
  final bool highlight;
  final VoidCallback onBlock;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color:
            highlight ? AppColors.orange.withValues(alpha: 0.06) : AppColors.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
            color: highlight
                ? AppColors.orange.withValues(alpha: 0.4)
                : AppColors.border),
      ),
      child: Row(children: [
        SizedBox(
          width: 44,
          child: Text(conn.protocol,
              style: AppTheme.mono(size: 11, color: AppColors.cyan)),
        ),
        Expanded(
          flex: 3,
          child: Text(conn.localAddress,
              style: AppTheme.mono(size: 11, color: AppColors.text)),
        ),
        Expanded(
          flex: 3,
          child: Text(conn.remoteAddress,
              style: AppTheme.mono(
                  size: 11,
                  color: highlight ? AppColors.orange : AppColors.muted)),
        ),
        SizedBox(
          width: 96,
          child: Text(conn.state,
              style: TextStyle(color: AppColors.muted, fontSize: 11)),
        ),
        Expanded(
          flex: 2,
          child: Text('${conn.processName} (${conn.processId})',
              style: TextStyle(color: AppColors.text, fontSize: 11),
              overflow: TextOverflow.ellipsis),
        ),
        // One click to a persistent filter - only for rows that can become one
        // (the engine derives the spec, and answers null when it cannot). A row
        // that cannot shows the reason instead of a button that fails.
        if (conn.block != null)
          IconButton(
            icon: const Icon(Icons.block, size: 16),
            color: AppColors.orange,
            tooltip: context.tr('network.block'),
            onPressed: onBlock,
          )
        else
          Tooltip(
            message: context.tr('network.noBlock'),
            child: Icon(Icons.block, size: 16, color: AppColors.border),
          ),
      ]),
    );
  }
}

class _FirewallView extends ConsumerWidget {
  const _FirewallView();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fw = ref.watch(firewallProvider);
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      children: [
        if (fw.error != null)
          Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.red.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.red.withValues(alpha: 0.4)),
            ),
            child: Text(fw.error!,
                style: TextStyle(color: AppColors.orange, fontSize: 12)),
          ),
        Card(
          child: SwitchListTile(
            title: Text(context.tr('network.defaultDeny'),
                style: TextStyle(
                    color: AppColors.text, fontWeight: FontWeight.w700)),
            subtitle: Text(
              fw.defaultDeny
                  ? context.tr('network.defaultDenyOn')
                  : context.tr('network.defaultDenyOff'),
              style: TextStyle(color: AppColors.muted, fontSize: 12),
            ),
            value: fw.defaultDeny,
            onChanged: fw.loading
                ? null
                : (v) =>
                    ref.read(firewallProvider.notifier).toggleDefaultDeny(v),
          ),
        ),
        const SizedBox(height: 8),
        Card(
          child: ListTile(
            leading: Icon(Icons.public_off, color: AppColors.cyan),
            title: Text(context.tr('network.blockCountry'),
                style: TextStyle(color: AppColors.text, fontSize: 13)),
            subtitle: Text(
                context.tr('network.blockCountryHint'),
                style: TextStyle(color: AppColors.muted, fontSize: 11)),
            trailing: SizedBox(
              width: 90,
              child: TextField(
                decoration: InputDecoration(
                    hintText: context.tr('network.countryHint')),
                style: AppTheme.mono(size: 12),
                onSubmitted: (cc) => ref
                    .read(firewallProvider.notifier)
                    .blockCountry(cc.trim()),
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Row(children: [
          Text(
              context
                  .tr('network.rules')
                  .replaceAll('{count}', '${fw.rules.length}'),
              style: TextStyle(
                  color: AppColors.text, fontWeight: FontWeight.w700)),
          const Spacer(),
          OutlinedButton.icon(
            onPressed: () => ref.read(firewallProvider.notifier).refresh(),
            icon: const Icon(Icons.refresh, size: 16),
            label: Text(context.tr('common.refresh')),
          ),
        ]),
        const SizedBox(height: 8),
        if (fw.rules.isEmpty)
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              context.tr('network.noRules'),
              style: TextStyle(color: AppColors.muted, fontSize: 12),
            ),
          ),
        for (final r in fw.rules)
          Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border),
            ),
            child: Row(children: [
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(4),
                  color: r.action == 'Block'
                      ? AppColors.red.withValues(alpha: 0.15)
                      : AppColors.green.withValues(alpha: 0.15),
                ),
                child: Text(r.action,
                    style: TextStyle(
                        fontSize: 10,
                        color: r.action == 'Block'
                            ? AppColors.red
                            : AppColors.green)),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(r.name,
                          style:
                              AppTheme.mono(size: 11, color: AppColors.text)),
                      Text(
                          '${r.direction}  ·  ${r.remoteIp.isEmpty ? "any" : r.remoteIp}',
                          style: AppTheme.mono(
                              size: 10, color: AppColors.muted)),
                    ]),
              ),
              IconButton(
                tooltip: context.tr('common.remove'),
                icon: Icon(Icons.delete_outline,
                    size: 18, color: AppColors.muted),
                onPressed: () =>
                    ref.read(firewallProvider.notifier).removeRule(r.name),
              ),
            ]),
          ),
      ],
    );
  }
}
