import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

class VulnScannerScreen extends ConsumerStatefulWidget {
  const VulnScannerScreen({super.key});

  @override
  ConsumerState<VulnScannerScreen> createState() => _VulnScannerScreenState();
}

class _VulnScannerScreenState extends ConsumerState<VulnScannerScreen> {
  bool _isLoading = false;
  List<dynamic> _results = [];

  Future<void> _startScan() async {
    setState(() => _isLoading = true);
    try {
      final ipcClient = ref.read(ipcClientProvider);
      await ipcClient.connect();
      final response = await ipcClient.send(
        IpcRequest(method: 'vuln.scan', id: 1),
      );
      if (response.result != null) {
        setState(() {
          _results = (response.result as List).cast<dynamic>();
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Scan failed: $e')));
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Vulnerability Scanner'),
        backgroundColor: AppColors.surface,
        actions: [
          IconButton(
            icon: const Icon(Icons.search, color: AppColors.cyan),
            onPressed: _isLoading ? null : _startScan,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(color: AppColors.cyan),
            )
          : _results.isEmpty
          ? const Center(
              child: Text('No scan data. Start scan to check for CVEs.'),
            )
          : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _results.length,
              itemBuilder: (context, index) {
                final item = _results[index];
                return _buildSoftwareCard(item);
              },
            ),
    );
  }

  Widget _buildSoftwareCard(dynamic item) {
    final vulnerabilities = item['vulnerabilities'] as List;
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: ExpansionTile(
        leading: const Icon(Icons.apps, color: AppColors.cyan),
        title: Text(
          '${item['software']} (${item['version']})',
          style: const TextStyle(color: AppColors.text),
        ),
        subtitle: Text(
          '${vulnerabilities.length} Vulnerabilities found',
          style: const TextStyle(color: AppColors.red),
        ),
        children: vulnerabilities
            .map(
              (v) => ListTile(
                leading: const Icon(
                  Icons.warning,
                  color: AppColors.orange,
                  size: 20,
                ),
                title: Text(
                  '${v['cve_id']} - CVSS: ${v['cvss']}',
                  style: const TextStyle(color: AppColors.text),
                ),
                subtitle: Text(
                  v['description'],
                  style: const TextStyle(color: AppColors.text, fontSize: 12),
                ),
              ),
            )
            .toList(),
      ),
    );
  }
}
