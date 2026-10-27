import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

class AuditScreen extends ConsumerStatefulWidget {
  const AuditScreen({super.key});

  @override
  ConsumerState<AuditScreen> createState() => _AuditScreenState();
}

class _AuditScreenState extends ConsumerState<AuditScreen> {
  bool _isLoading = false;
  List<dynamic> _findings = [];

  Future<void> _runAudit() async {
    setState(() => _isLoading = true);
    try {
      final ipcClient = ref.read(ipcClientProvider);
      await ipcClient.connect();

      final response = await ipcClient.send(
        IpcRequest(method: 'audit.run', id: 1),
      );

      if (response.result != null) {
        setState(() {
          _findings = (response.result as List).cast<dynamic>();
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Audit failed: $e'),
          backgroundColor: AppColors.red,
        ),
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('System Audit'),
        backgroundColor: AppColors.surface,
        actions: [
          IconButton(
            icon: const Icon(Icons.play_arrow, color: AppColors.cyan),
            onPressed: _isLoading ? null : _runAudit,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(color: AppColors.cyan),
            )
          : _findings.isEmpty
          ? const Center(child: Text('No audit data. Press play to start.'))
          : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _findings.length,
              itemBuilder: (context, index) {
                final item = _findings[index];
                return _buildFindingCard(item);
              },
            ),
    );
  }

  Widget _buildFindingCard(dynamic item) {
    final status = item['status'] ?? 'Unknown';
    final color = status == 'Secure'
        ? AppColors.green
        : (status == 'Warning' ? AppColors.orange : AppColors.red);

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        leading: Icon(Icons.circle, color: color, size: 12),
        title: Text(
          item['item'] ?? 'Unknown',
          style: const TextStyle(color: AppColors.text),
        ),
        subtitle: Text(
          item['description'] ?? '',
          style: const TextStyle(color: AppColors.text),
        ),
        trailing: Text(
          item['section'] ?? '',
          style: const TextStyle(color: AppColors.cyan, fontSize: 12),
        ),
      ),
    );
  }
}
