import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'pages_test.dart' show FakeClient, mount, snapshot;

void main() {
  for (final connect in [true, false]) {
    testWidgets(
      '${connect ? 'connect' : 'disconnect'} may complete after 8 seconds without overlapping work',
      (tester) async {
        final operation = Completer<void>();
        final client = FakeClient(snapshot(connect ? 'idle' : 'connected'));
        if (connect) {
          client.connecting = operation;
        } else {
          client.disconnecting = operation;
        }
        await mount(tester, client);
        await tester.tap(find.text(connect ? '开启海外访问' : '关闭海外访问'));
        await tester.pump();
        await tester.pump(const Duration(seconds: 12));
        expect(find.text('服务暂不可用'), findsNothing);
        expect(
          tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
          isNull,
        );
        expect(client.statusCalls, 1);
        operation.complete();
        await tester.pump();
        await tester.pump();
        expect(find.text(connect ? '正在连接' : '未连接'), findsOneWidget);
        expect(client.statusCalls, 2);
        expect(client.connects + client.disconnects, 1);
      },
    );
  }
  for (final connect in [true, false]) {
    testWidgets(
      '${connect ? 'connect' : 'disconnect'} overdue operation stays owned until late completion',
      (tester) async {
        final operation = Completer<void>();
        final client = FakeClient(snapshot(connect ? 'idle' : 'connected'));
        if (connect) {
          client.connecting = operation;
        } else {
          client.disconnecting = operation;
        }
        await mount(tester, client);
        await tester.tap(find.text(connect ? '开启海外访问' : '关闭海外访问'));
        await tester.pump();
        await tester.pump(Duration(seconds: connect ? 131 : 101));
        await tester.pump();
        expect(find.text('服务暂不可用'), findsOneWidget);
        expect(
          tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
          isNull,
        );
        await tester.tap(find.byType(FilledButton));
        await tester.pump(const Duration(seconds: 9));
        expect(client.statusCalls, 1);
        expect(client.connects + client.disconnects, 1);
        operation.complete();
        await tester.pump();
        await tester.pump();
        expect(client.statusCalls, 2);
        expect(find.text('服务暂不可用'), findsNothing);
        expect(client.connects + client.disconnects, 1);
      },
    );
  }
  testWidgets(
    'overdue probe retains ownership and rereads status only after completion',
    (tester) async {
      final client = FakeClient(snapshot('connected'))..probing = Completer();
      await mount(tester, client);
      await tester.tap(find.text('线路详情'));
      await tester.pump();
      await tester.tap(find.text('立即测速'));
      await tester.pump();
      await tester.pump(const Duration(seconds: 11));
      await tester.pump();
      expect(find.text('服务暂不可用'), findsOneWidget);
      expect(
        tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNull,
      );
      expect(client.statusCalls, 1);
      client.probing!.complete(client.value.results);
      await tester.pump();
      await tester.pump();
      expect(client.probes, 1);
      expect(client.statusCalls, 2);
      expect(find.text('立即测速'), findsOneWidget);
    },
  );
  for (final state in ['connected', 'needs_action', 'probe']) {
    testWidgets(
      '$state action is honestly disabled during delayed poll then available',
      (tester) async {
        final client = FakeClient(
          snapshot(state == 'probe' ? 'connected' : state),
        );
        await mount(tester, client);
        if (state == 'probe') {
          await tester.tap(find.text('线路详情'));
          await tester.pump();
        }
        client.pending = Completer();
        await tester.pump(const Duration(seconds: 3));
        await tester.pump();
        expect(find.text('正在读取状态'), findsOneWidget);
        if (state == 'connected') {
          expect(find.text('已连接'), findsOneWidget);
          expect(find.text('08:42'), findsOneWidget);
        }
        final button = state == 'probe'
            ? find.byType(OutlinedButton)
            : find.byType(FilledButton);
        expect(tester.widget<ButtonStyleButton>(button).onPressed, isNull);
        await tester.tap(button);
        await tester.pump();
        expect(client.disconnects + client.probes, 0);
        client.pending!.complete(client.value);
        client.pending = null;
        await tester.pump();
        await tester.pump();
        expect(tester.widget<ButtonStyleButton>(button).onPressed, isNotNull);
        await tester.tap(button);
        await tester.pump();
        await tester.pump();
        expect(client.disconnects + client.probes, 1);
        expect(client.connects, 0);
      },
    );
  }
  testWidgets(
    'overdue status read holds ownership and discards its late stale result',
    (tester) async {
      final client = FakeClient(snapshot('connected'));
      await mount(tester, client);
      client.pending = Completer();
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 9));
      await tester.pump();
      expect(find.text('服务暂不可用'), findsOneWidget);
      expect(
        tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNull,
      );
      await tester.pump(const Duration(seconds: 12));
      expect(client.statusCalls, 2);
      client.pending!.complete(snapshot('connected'));
      client.pending = null;
      await tester.pump();
      await tester.pump();
      expect(find.text('已连接'), findsNothing);
      expect(
        tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNotNull,
      );
    },
  );
  for (final operation in ['connect', 'disconnect', 'probe', 'poll']) {
    testWidgets('dispose during $operation neither follows up nor revives UI', (
      tester,
    ) async {
      final client = FakeClient(
        snapshot(operation == 'connect' ? 'idle' : 'connected'),
      );
      await mount(tester, client);
      final completion = Completer<void>();
      switch (operation) {
        case 'connect':
          client.connecting = completion;
          await tester.tap(find.text('开启海外访问'));
        case 'disconnect':
          client.disconnecting = completion;
          await tester.tap(find.text('关闭海外访问'));
        case 'probe':
          client.probing = Completer();
          await tester.tap(find.text('线路详情'));
          await tester.pump();
          await tester.tap(find.text('立即测速'));
        case 'poll':
          client.pending = Completer();
          await tester.pump(const Duration(seconds: 3));
      }
      await tester.pump();
      final readsBeforeDispose = client.statusCalls;
      await tester.pumpWidget(const SizedBox());
      if (operation == 'probe') {
        client.probing!.complete(client.value.results);
      } else if (operation == 'poll') {
        client.pending!.complete(client.value);
      } else {
        completion.complete();
      }
      await tester.pump();
      await tester.pump(const Duration(seconds: 140));
      expect(client.statusCalls, readsBeforeDispose);
      expect(tester.takeException(), isNull);
    });
  }
}
