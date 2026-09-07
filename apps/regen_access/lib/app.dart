import 'package:flutter/material.dart';

import 'dart:async';

import 'api/access_client.dart';
import 'api/windows_shell.dart';
import 'model/tray_state.dart';
import 'model/status.dart';
import 'pages/home.dart';
import 'pages/details.dart';
import 'theme.dart';

class MyApp extends StatelessWidget {
  const MyApp({
    super.key,
    this.client = const UnavailableAccessClient(),
    this.now,
    this.fontFamily,
    this.shell,
  });
  final AccessClient client;
  final DateTime Function()? now;
  final String? fontFamily;
  final WindowsShell? shell;
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'RegenBio 海外访问',
    debugShowCheckedModeBanner: false,
    theme: accessTheme(fontFamily),
    home: _Desktop(client: client, now: now ?? DateTime.now, shell: shell),
  );
}

class _Desktop extends StatefulWidget {
  const _Desktop({required this.client, required this.now, this.shell});
  final AccessClient client;
  final DateTime Function() now;
  final WindowsShell? shell;
  @override
  State<_Desktop> createState() => _DesktopState();
}

class _DesktopState extends State<_Desktop> {
  Status? status;
  bool unavailable = false, busy = false, polling = false, details = false;
  bool uncertain = false;
  late final Timer timer;
  Timer? requestDeadline;
  static const statusBudget = Duration(seconds: 8);
  // Service lifecycle deadlines are 120s/90s; allow transport completion grace.
  static const connectBudget = Duration(seconds: 130);
  static const disconnectBudget = Duration(seconds: 100);
  static const probeBudget = Duration(seconds: 10);
  @override
  void initState() {
    super.initState();
    widget.shell?.attach(
      (intent) async {
        final current = TrayState.fromStatus(
          status,
          busy: busy,
          polling: polling,
          uncertain: uncertain,
        );
        if (current.enabled && current.action == intent) {
          await act(intent: intent);
        }
      },
      navigate: (value) {
        if (mounted) {
          setState(() {
            details = value && status != null && !unavailable;
          });
        }
      },
    );
    refresh();
    timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
  }

  @override
  void setState(VoidCallback fn) {
    super.setState(fn);
    widget.shell?.update(
      TrayState.fromStatus(
        unavailable ? null : status,
        busy: busy,
        polling: polling,
        uncertain: uncertain,
      ),
    );
  }

  Future<void> refresh() async {
    if (!mounted || polling || busy) return;
    setState(() {
      polling = true;
    });
    try {
      final value = await observe(
        widget.client.status(),
        statusBudget,
        discardLate: true,
      );
      // Calls are serialized: no persistent generation cache survives service restart.
      if (mounted) {
        setState(() {
          status = value;
          unavailable = false;
        });
      }
    } catch (_) {
      markUnavailable();
    } finally {
      if (mounted) {
        setState(() {
          polling = false;
        });
      }
    }
  }

  void markUnavailable() {
    if (!mounted) return;
    setState(() {
      status = null;
      unavailable = true;
    });
  }

  /// A deadline invalidates display data, but never abandons request ownership.
  /// Transport loss is classified separately from completion. A late status
  /// sample cannot restore a stale claim or unlock an uncertain lifecycle.
  Future<T> observe<T>(
    Future<T> request,
    Duration budget, {
    bool discardLate = false,
  }) async {
    var overdue = false;
    final deadline = Timer(budget, () {
      overdue = true;
      markUnavailable();
    });
    requestDeadline = deadline;
    try {
      final value = await request;
      if (discardLate && overdue) {
        throw TimeoutException('Status sample expired');
      }
      return value;
    } finally {
      deadline.cancel();
      if (identical(requestDeadline, deadline)) requestDeadline = null;
    }
  }

  Future<void> act({bool probe = false, String? intent}) async {
    if (!mounted ||
        busy ||
        polling ||
        uncertain ||
        status?.transitioning == true) {
      return;
    }
    final previous = status;
    final action = TrayState.fromStatus(previous).action;
    if (intent != null && intent != action) return;
    final restore = action == 'disconnect' || action == 'restore';
    if (!probe && previous?.configurationUnavailable == true) {
      return;
    }
    if (probe && previous?.connected != true) return;
    setState(() {
      busy = true;
      if (!probe) {
        status = Status(state: restore ? 'restoring' : 'connecting');
      }
    });
    try {
      if (probe) {
        // The following status carries authoritative quality/history/counters.
        await observe(widget.client.probe(), probeBudget);
      } else if (restore) {
        await observe(widget.client.disconnect(), disconnectBudget);
      } else {
        await observe(widget.client.connect(), connectBudget);
      }
      if (!mounted) return;
      final value = await observe(
        widget.client.status(),
        statusBudget,
        discardLate: true,
      );
      if (mounted) {
        setState(() {
          status = value;
          unavailable = false;
        });
      }
    } on OperationUncertainException {
      uncertain = true;
      markUnavailable();
    } catch (_) {
      markUnavailable();
    } finally {
      if (mounted) {
        setState(() {
          busy = false;
        });
      }
    }
  }

  @override
  void dispose() {
    widget.shell?.dispose();
    timer.cancel();
    requestDeadline?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: Center(
      child: SizedBox(
        width: 460,
        height: 540,
        child: RepaintBoundary(
          key: const Key('desktop-shell'),
          child: ColoredBox(
            color: Colors.white,
            child: details && !unavailable && status != null
                ? DetailsPage(
                    status: status!,
                    now: widget.now(),
                    busy: busy || uncertain,
                    polling: polling,
                    onBack: () => setState(() {
                      details = false;
                    }),
                    onProbe: () => act(probe: true),
                  )
                : HomePage(
                    status: status,
                    now: widget.now(),
                    unavailable: unavailable,
                    busy: busy || uncertain,
                    polling: polling,
                    onAction: () => unavailable ? refresh() : act(),
                    onDetails: () => setState(() {
                      details = true;
                    }),
                  ),
          ),
        ),
      ),
    ),
  );
}
