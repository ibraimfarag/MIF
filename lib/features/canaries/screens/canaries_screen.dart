import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';
import 'package:mics_app/core/theme/app_theme.dart';

class CanaryFile {
  final String path;
  final bool deployed;
  CanaryFile({required this.path, required this.deployed});
}

final canariesProvider =
    NotifierProvider<CanariesNotifier, List<CanaryFile>>(CanariesNotifier.new);

class CanariesNotifier extends Notifier<List<CanaryFile>> {
  @override
  List<CanaryFile> build() => const [];

  Future<void> refresh() async {
    try {
      final res = await ref.read(engineIpcProvider).request('canary.list');
      state = (res as List)
          .map((e) => CanaryFile(
              path: e[0] as String, deployed: e[1] as bool))
          .toList();
    } catch (_) {}
    await ref.read(canariesStatusProvider.notifier).refresh();
  }

  Future<void> deploy() async {
    await ref.read(engineIpcProvider).request('canary.deploy');
    await refresh();
  }

  Future<void> addPath(String path) async {
    final paths = state.map((c) => c.path).toList()..add(path);
    await ref
        .read(engineIpcProvider)
        .request('canary.configure', {'paths': paths});
    await refresh();
  }

  Future<void> removePath(String path) async {
    final paths = state.map((c) => c.path).where((p) => p != path).toList();
    await ref
        .read(engineIpcProvider)
        .request('canary.configure', {'paths': paths});
    await refresh();
  }
}

/// What the decoys actually cover on this machine. It is a measurement, not a
/// promise: a volume that keeps no last-access time cannot show a decoy read at
/// all, and [readAvailable] is `null` until the engine has measured it.
class CanariesStatus {
  final int configured;
  final int deployed;
  final int readSettleSeconds;
  final bool? readAvailable;
  final String readProbedOn;

  const CanariesStatus({
    required this.configured,
    required this.deployed,
    required this.readSettleSeconds,
    required this.readAvailable,
    required this.readProbedOn,
  });

  factory CanariesStatus.fromJson(Map<String, dynamic> j) {
    final detection = (j['read_detection'] as Map?)?.cast<String, dynamic>();
    return CanariesStatus(
      configured: (j['configured'] as num?)?.toInt() ?? 0,
      deployed: (j['deployed'] as num?)?.toInt() ?? 0,
      readSettleSeconds: (j['read_settle_seconds'] as num?)?.toInt() ?? 0,
      readAvailable: detection?['available'] as bool?,
      readProbedOn: (detection?['probed_on'] as String?) ?? '',
    );
  }
}

final canariesStatusProvider =
    NotifierProvider<CanariesStatusNotifier, CanariesStatus?>(
        CanariesStatusNotifier.new);

class CanariesStatusNotifier extends Notifier<CanariesStatus?> {
  @override
  CanariesStatus? build() => null;

  Future<void> refresh() async {
    try {
      final res = await ref.read(engineIpcProvider).request('canary.status');
      state = CanariesStatus.fromJson((res as Map).cast<String, dynamic>());
    } catch (_) {}
  }
}

/// The honest coverage line: whether a read-only open of a decoy would be seen
/// here, and the one window in which a read is settled instead of reported.
class _ReadCoverage extends StatelessWidget {
  final CanariesStatus? status;
  const _ReadCoverage({required this.status});

  @override
  Widget build(BuildContext context) {
    final s = status;
    if (s == null) {
      return Text(
        context.tr('canaries.readDetection.unknown'),
        style: TextStyle(color: AppColors.muted, fontSize: 11),
      );
    }
    final IconData icon;
    final Color color;
    final String key;
    if (s.readAvailable == true) {
      icon = Icons.verified_user_outlined;
      color = AppColors.green;
      key = 'canaries.readDetection.on';
    } else if (s.readAvailable == false) {
      icon = Icons.warning_amber_outlined;
      color = AppColors.yellow;
      key = 'canaries.readDetection.off';
    } else {
      icon = Icons.help_outline;
      color = AppColors.muted;
      key = 'canaries.readDetection.unknown';
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: color, size: 16),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                context.tr(key),
                style: TextStyle(color: AppColors.text, fontSize: 11),
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        Text(
          context
              .tr('canaries.readDetection.settle')
              .replaceAll('{seconds}', '${s.readSettleSeconds}'),
          style: TextStyle(color: AppColors.muted, fontSize: 11),
        ),
        if (s.readProbedOn.isNotEmpty) ...[
          const SizedBox(height: 4),
          Text(s.readProbedOn, style: AppTheme.mono(size: 10)),
        ],
      ],
    );
  }
}

class CanariesScreen extends ConsumerStatefulWidget {
  const CanariesScreen({super.key});

  @override
  ConsumerState<CanariesScreen> createState() => _CanariesScreenState();
}

class _CanariesScreenState extends ConsumerState<CanariesScreen> {
  final _pathController = TextEditingController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(canariesProvider.notifier).refresh();
    });
  }

  @override
  void dispose() {
    _pathController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final files = ref.watch(canariesProvider);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(children: [
          Icon(Icons.egg, color: AppColors.cyan),
          const SizedBox(width: 8),
          Text(context.tr('nav.canaries'),
              style: TextStyle(
                  color: AppColors.text,
                  fontSize: 16,
                  fontWeight: FontWeight.w800)),
          const Spacer(),
          FilledButton.icon(
            onPressed: () => ref.read(canariesProvider.notifier).deploy(),
            icon: const Icon(Icons.download),
            label: Text(context.tr('canaries.deploy')),
          ),
        ]),
        const SizedBox(height: 6),
        Text(
          context.tr('canaries.intro'),
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 10),
        _ReadCoverage(status: ref.watch(canariesStatusProvider)),
        const SizedBox(height: 16),
        Row(children: [
          Expanded(
            child: TextField(
              controller: _pathController,
              style: AppTheme.mono(size: 11),
              decoration: InputDecoration(
                labelText: context.tr('canaries.addPath'),
                hintText: r'C:\Users\...\Documents\secret.txt.canary',
              ),
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
            tooltip: context.tr('common.add'),
            onPressed: () {
              final p = _pathController.text.trim();
              if (p.isNotEmpty) {
                ref.read(canariesProvider.notifier).addPath(p);
                _pathController.clear();
              }
            },
            icon: Icon(Icons.add, color: AppColors.cyan),
          ),
        ]),
        const SizedBox(height: 12),
        for (final f in files)
          Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                  color: f.deployed
                      ? AppColors.green.withValues(alpha: 0.4)
                      : AppColors.border),
            ),
            child: Row(children: [
              Icon(
                f.deployed ? Icons.check_circle : Icons.help_outline,
                size: 15,
                color: f.deployed ? AppColors.green : AppColors.muted,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(f.path,
                    style: AppTheme.mono(size: 11, color: AppColors.text),
                    overflow: TextOverflow.ellipsis),
              ),
              IconButton(
                tooltip: context.tr('common.remove'),
                icon: Icon(Icons.delete_outline,
                    size: 16, color: AppColors.muted),
                onPressed: () =>
                    ref.read(canariesProvider.notifier).removePath(f.path),
              ),
            ]),
          ),
      ],
    );
  }
}
