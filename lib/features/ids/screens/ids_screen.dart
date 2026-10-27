import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mics_app/core/i18n/app_i18n.dart';
import 'package:mics_app/core/theme/app_theme.dart';

/// Phase-3 skeleton: designed empty state wired into the shell. The module
/// comes alive when its engine phase lands (see MI-CS-Agent-Prompt.md section 12).
class IdsScreen extends ConsumerWidget {
  const IdsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: AppColors.border),
                color: AppColors.surface,
              ),
              child: Icon(Icons.radar_outlined, color: AppColors.cyan, size: 32),
            ),
            const SizedBox(height: 16),
            Text(context.tr('nav.ids'),
                style: const TextStyle(
                    color: AppColors.text,
                    fontSize: 17,
                    fontWeight: FontWeight.w700)),
            const SizedBox(height: 8),
            ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Text(context.tr('soon.body'),
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: AppColors.muted, fontSize: 13)),
            ),
          ],
        ),
      ),
    );
  }
}
