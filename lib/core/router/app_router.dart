import 'package:go_router/go_router.dart';
import 'package:mics_app/features/audit/screens/audit_screen.dart';
import 'package:mics_app/features/canaries/screens/canaries_screen.dart';
import 'package:mics_app/features/dashboard/screens/dashboard_screen.dart';
import 'package:mics_app/features/guard/screens/guard_screen.dart';
import 'package:mics_app/features/hardening/screens/hardening_screen.dart';
import 'package:mics_app/features/ids/screens/ids_screen.dart';
import 'package:mics_app/features/incidents/screens/incidents_screen.dart';
import 'package:mics_app/features/intel/screens/intel_screen.dart';
import 'package:mics_app/features/network/screens/network_monitor_screen.dart';
import 'package:mics_app/features/reports/screens/reports_screen.dart';
import 'package:mics_app/features/scanner/screens/scanner_screen.dart';
import 'package:mics_app/features/settings/screens/settings_screen.dart';
import 'package:mics_app/features/shell/app_shell.dart';
import 'package:mics_app/features/vulns/screens/vuln_scanner_screen.dart';

final appRouter = GoRouter(
  initialLocation: '/dashboard',
  routes: [
    ShellRoute(
      builder: (context, state, child) => AppShell(child: child),
      routes: [
        GoRoute(path: '/dashboard', builder: (_, _) => const DashboardScreen()),
        GoRoute(path: '/audit', builder: (_, _) => const AuditScreen()),
        GoRoute(path: '/scanner', builder: (_, _) => const ScannerScreen()),
        GoRoute(
            path: '/network', builder: (_, _) => const NetworkMonitorScreen()),
        GoRoute(path: '/ids', builder: (_, _) => const IdsScreen()),
        GoRoute(
            path: '/vulns', builder: (_, _) => const VulnScannerScreen()),
        GoRoute(path: '/guard', builder: (_, _) => const GuardScreen()),
        GoRoute(path: '/canaries', builder: (_, _) => const CanariesScreen()),
        GoRoute(
            path: '/hardening', builder: (_, _) => const HardeningScreen()),
        GoRoute(
            path: '/incidents', builder: (_, _) => const IncidentsScreen()),
        GoRoute(path: '/reports', builder: (_, _) => const ReportsScreen()),
        GoRoute(path: '/intel', builder: (_, _) => const IntelScreen()),
        GoRoute(path: '/settings', builder: (_, _) => const SettingsScreen()),
      ],
    ),
  ],
);
