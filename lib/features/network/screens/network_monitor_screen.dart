import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

class NetworkMonitorScreen extends ConsumerStatefulWidget {
  const NetworkMonitorScreen({super.key});

  @override
  ConsumerState<NetworkMonitorScreen> createState() =>
      _NetworkMonitorScreenState();
}

class _NetworkMonitorScreenState extends ConsumerState<NetworkMonitorScreen> {
  List<dynamic> _connections = [];
  bool _isLoading = false;

  Future<void> _fetchConnections() async {
    setState(() => _isLoading = true);
    try {
      final ipcClient = ref.read(ipcClientProvider);
      await ipcClient.connect();
      final response = await ipcClient.send(
        IpcRequest(method: 'net.connections', id: 1),
      );
      if (response.result != null) {
        setState(() {
          _connections = (response.result as List).cast<dynamic>();
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Error: $e')));
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  void initState() {
    super.initState();
    _fetchConnections();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Network Monitor'),
        backgroundColor: AppColors.surface,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: AppColors.cyan),
            onPressed: _fetchConnections,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(color: AppColors.cyan),
            )
          : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _connections.length,
              itemBuilder: (context, index) {
                final conn = _connections[index];
                return Card(
                  margin: const EdgeInsets.only(bottom: 10),
                  child: ListTile(
                    leading: const Icon(Icons.language, color: AppColors.cyan),
                    title: Text(
                      '${conn['local_address']} \u2192 ${conn['remote_address']}',
                      style: const TextStyle(color: AppColors.text),
                    ),
                    subtitle: Text(
                      'Process: ${conn['process_name']} (PID: ${conn['process_id']})',
                      style: const TextStyle(color: AppColors.text),
                    ),
                    trailing: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: AppColors.border,
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        conn['state'],
                        style: const TextStyle(
                          color: AppColors.green,
                          fontSize: 10,
                        ),
                      ),
                    ),
                  ),
                );
              },
            ),
    );
  }
}
