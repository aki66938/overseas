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
  static const timeout = Duration(seconds: 8);
  @override
  void initState() {
    super.initState();
    refresh();
    timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
  }

  Future<void> refresh() async {
    if (polling || busy) return;
    polling = true;
    try {
      final value = await widget.client.status().timeout(timeout);
      // Calls are serialized: no persistent generation cache survives service restart.
      if (mounted) {
        setState(() {
          status = value;
          unavailable = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          status = null;
          unavailable = true;
        });
      }
    } finally {
      polling = false;
    }
  }

  Future<void> act({bool probe = false}) async {
    if (busy || polling) return;
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
        await widget.client.probe().timeout(timeout);
      } else if (previous?.connected == true ||
          previous?.needsRestore == true) {
        await widget.client.disconnect().timeout(timeout);
      } else {
        await widget.client.connect().timeout(timeout);
      }
      final value = await widget.client.status().timeout(timeout);
      if (mounted) {
        setState(() {
          status = value;
          unavailable = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          status = null;
          unavailable = true;
        });
      }
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
