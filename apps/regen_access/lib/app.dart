import 'package:flutter/material.dart';

import 'dart:async';

import 'api/access_client.dart';
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
  });
  final AccessClient client;
  final DateTime Function()? now;
  final String? fontFamily;
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'RegenBio 海外访问',
    debugShowCheckedModeBanner: false,
    theme: accessTheme(fontFamily),
    home: _Desktop(client: client, now: now ?? DateTime.now),
  );
}

class _Desktop extends StatefulWidget {
  const _Desktop({required this.client, required this.now});
  final AccessClient client;
  final DateTime Function() now;
  @override
  State<_Desktop> createState() => _DesktopState();
}

class _DesktopState extends State<_Desktop> {
  Status? status;
  bool unavailable = false, busy = false, polling = false, details = false;
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
    refresh();
    timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
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
  /// Task 7 transport cancellation must complete the original Future before a
  /// later request may start. A late status sample cannot restore a stale claim.
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

  Future<void> act({bool probe = false}) async {
    if (!mounted || busy || polling) return;
    final previous = status;
    if (!probe && previous?.configurationUnavailable == true) {
      return;
    }
    if (probe && previous?.connected != true) return;
    setState(() {
      busy = true;
      if (!probe) {
        status = Status(
          state: previous?.connected == true || previous?.needsRestore == true
              ? 'restoring'
              : 'connecting',
        );
      }
    });
    try {
      if (probe) {
        // The following status carries authoritative quality/history/counters.
        await observe(widget.client.probe(), probeBudget);
      } else if (previous?.connected == true ||
          previous?.needsRestore == true) {
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
                    busy: busy,
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
                    busy: busy,
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
