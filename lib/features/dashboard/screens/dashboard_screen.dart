import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/ipc/ipc_client.dart';

class DashboardScreen extends ConsumerWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('MI CS Dashboard'),
        backgroundColor: AppColors.surface,
        actions: [
          IconButton(
            icon: const Icon(Icons.sync, color: AppColors.cyan),
            onPressed: () {
              // Trigger sync logic
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildScoreCard(context),
            const SizedBox(height: 24),
            Text(
              'Security Overview',
              style: Theme.of(context).textTheme.displayLarge
                  ?.copyWith(fontSize: 20),
            ),
            const SizedBox(height: 16),
            GridView.count(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              crossAxisCount: 2,
              crossAxisSpacing: 16,
              mainAxisSpacing: 16,
              children: [
                _buildHealthCard('Network', Icons.language, AppColors.cyan),
                _buildHealthCard('Files', Icons.security, AppColors.green),
                _buildHealthCard('Processes', Icons.memory, AppColors.orange),
                _buildHealthCard('Vulns', Icons.bug_report, AppColors.red),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildScoreCard(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppColors.border),
        gradient: LinearGradient(
          colors: [AppColors.surface, AppColors.background],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Column(
        children: [
          const Text(
            'Security Score',
            style: TextStyle(color: AppColors.text, fontSize: 16),
          ),
          const SizedBox(height: 10),
          Text(
            '85',
            style: Theme.of(context).textTheme.displayLarge?.copyWith(
              fontSize: 64,
              color: AppColors.cyan,
              fontWeight: FontWeight.bold,
            ),
          ),
          const Text(
            'Strong Protection',
            style: TextStyle(color: AppColors.green),
          ),
        ],
      ),
    );
  }

  Widget _buildHealthCard(String title, IconData icon, Color color) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, color: color, size: 32),
          const SizedBox(height: 8),
          Text(
            title,
            style: const TextStyle(
              color: AppColors.text,
              fontWeight: FontWeight.bold,
            ),
          ),
        ],
      ),
    );
  }
}
