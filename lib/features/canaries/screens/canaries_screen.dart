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
            label: const Text('Deploy decoys'),
          ),
        ]),
        const SizedBox(height: 6),
        Text(
          'Decoy files nobody should ever touch. Any access is a CRITICAL canary event — the classic sign of ransomware or a snooper. Decoys arm when the Guard runs.',
          style: TextStyle(color: AppColors.muted, fontSize: 12),
        ),
        const SizedBox(height: 16),
        Row(children: [
          Expanded(
            child: TextField(
              controller: _pathController,
              style: AppTheme.mono(size: 11),
              decoration: const InputDecoration(
                labelText: 'Add decoy path',
                hintText: r'C:\Users\...\Documents\secret.txt.canary',
              ),
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
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
