import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:regen_access/app.dart';
import 'package:regen_access/api/access_client.dart';
import 'package:regen_access/api/windows_shell.dart';

import 'dart:async';

import 'pages_test.dart' show FakeClient, snapshot;

import 'package:regen_access/model/status.dart';
import 'package:regen_access/model/tray_state.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('tray and page share ownership and uncertainty disables both', (
    tester,
  ) async {
    const channel = MethodChannel('regen_access/shell');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    final updates = <Map>[];
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'update') updates.add(call.arguments as Map);
      return null;
    });
    addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
    final client = FakeClient(snapshot('idle'))..connecting = Completer<void>();
    await tester.pumpWidget(MyApp(client: client, shell: WindowsShell()));
    await tester.pump();
    Future<void> trayAction() async {
      unawaited(
        messenger.handlePlatformMessage(
          channel.name,
          const StandardMethodCodec().encodeMethodCall(
            const MethodCall('action', 'connect'),
          ),
          (_) {},
        ),
      );
      await tester.pump();
    }

    await trayAction();
    await trayAction();
    expect(client.connects, 1);
    expect(updates.last['enabled'], false);
    client.connecting!.completeError(const OperationUncertainException());
    await tester.pump();
    await tester.pump(const Duration(seconds: 4));
    expect(client.statusCalls, greaterThan(1));
    expect(updates.last['enabled'], false);
    expect(
      tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
      isNull,
    );
    await trayAction();
    expect(client.connects, 1);
    await tester.pumpWidget(const SizedBox());
  });
  for (final initial in ['connected', 'idle']) {
    testWidgets(
      'stale $initial menu intent never inverts after status changes',
      (tester) async {
        const channel = MethodChannel('regen_access/shell');
        final messenger =
            TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
        messenger.setMockMethodCallHandler(channel, (_) async => null);
        addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
        final client = FakeClient(snapshot(initial));
        await tester.pumpWidget(MyApp(client: client, shell: WindowsShell()));
        await tester.pump();
        // This is the explicit command the menu displayed when it opened.
        final displayedAction = initial == 'connected'
            ? 'disconnect'
            : 'connect';
        client.value = snapshot(initial == 'connected' ? 'idle' : 'connected');
        await tester.pump(const Duration(seconds: 3));
        await tester.pump();
        unawaited(
          messenger.handlePlatformMessage(
            channel.name,
            const StandardMethodCodec().encodeMethodCall(
              MethodCall('action', displayedAction),
            ),
            (_) {},
          ),
        );
        await tester.pump();
        expect(
          client.connects,
          0,
          reason: 'a stale menu command must be rejected',
        );
        expect(
          client.disconnects,
          0,
          reason: 'a stale menu command must be rejected',
        );
        final currentAction = initial == 'connected' ? 'connect' : 'disconnect';
        unawaited(
          messenger.handlePlatformMessage(
            channel.name,
            const StandardMethodCodec().encodeMethodCall(
              MethodCall('action', currentAction),
            ),
            (_) {},
          ),
        );
        await tester.pump();
        expect(client.connects, initial == 'connected' ? 1 : 0);
        expect(client.disconnects, initial == 'idle' ? 1 : 0);
        await tester.pumpWidget(const SizedBox());
      },
    );
  }
  test('tray derives the same actions for every service state', () {
    for (final state in [
      'idle',
      'preparing',
      'connecting',
      'connected',
      'restoring',
      'needs_action',
    ]) {
      final status = Status(state: state);
      final tray = TrayState.fromStatus(status);
      expect(tray.enabled, !status.transitioning);
      expect(
        tray.action,
        state == 'connected'
            ? 'disconnect'
            : state == 'needs_action'
            ? 'restore'
            : 'connect',
      );
      expect(
        tray.label,
        state == 'needs_action'
            ? '仅恢复网络'
            : state == 'connected'
            ? '关闭海外访问'
            : state == 'idle'
            ? '开启海外访问'
            : state == 'restoring'
            ? '正在恢复网络'
            : '正在连接',
      );
    }
  });
  test('faults distinguish retry, restoration and configuration', () {
    expect(
      TrayState.fromStatus(
        const Status(state: 'idle', errorCode: 'core_start_failed'),
      ).label,
      '重试',
    );
    expect(
      TrayState.fromStatus(const Status(state: 'needs_action')).label,
      '仅恢复网络',
    );
    expect(
      TrayState.fromStatus(
        const Status(state: 'idle', errorCode: 'invalid_policy'),
      ).enabled,
      isFalse,
    );
  });
  test('tray summary exposes only current connected latency', () {
    expect(
      TrayState.fromStatus(snapshot('connected')).toMap()['summary'],
      '已连接 · 92 ms',
    );
    expect(
      TrayState.fromStatus(snapshot('idle', history: true)).toMap()['summary'],
      '未连接',
    );
  });
  test(
    'busy, polling, unknown and uncertain cannot issue lifecycle commands',
    () {
      const idle = Status(state: 'idle');
      expect(TrayState.fromStatus(idle, busy: true).enabled, isFalse);
      expect(TrayState.fromStatus(idle, polling: true).enabled, isFalse);
      expect(TrayState.fromStatus(null).enabled, isFalse);
      expect(TrayState.fromStatus(idle, uncertain: true).enabled, isFalse);
    },
  );
}
