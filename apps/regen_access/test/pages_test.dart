import 'package:flutter_test/flutter_test.dart';

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:regen_access/api/access_client.dart';
import 'package:regen_access/model/status.dart';
import 'package:regen_access/main.dart';

// All numbers here are synthetic fixtures, never production defaults.
final clock = DateTime.utc(2026, 9, 7, 12, 8, 42);
ProbeResult result(String id, {int ms = 92, int? failures = 0}) => ProbeResult(
  id: id,
  latencyMs: ms,
  reachable: failures == 0,
  checkedAt: clock.subtract(const Duration(seconds: 12)),
  consecutiveFailures: failures,
);
Status snapshot(
  String state, {
  String quality = 'good',
  bool history = false,
  int generation = 8,
  List<ProbeResult>? results,
}) => Status(
  state: state,
  quality: quality,
  connectedAt: DateTime.utc(2026, 9, 7, 12),
  generation: generation,
  probeGeneration: generation,
  probeHistorical: history,
  results: results ?? targetNames.keys.map((id) => result(id)).toList(),
);

class FakeClient implements AccessClient {
  FakeClient(this.value);
  Status value;
  bool fail = false;
  int connects = 0, disconnects = 0, probes = 0;
  Completer<Status>? pending;
  Completer<List<ProbeResult>>? probing;
  Completer<void>? connecting;
  @override
  Future<Status> status() async {
    if (fail) throw StateError('secret internal path');
    return pending == null ? value : pending!.future;
  }

  @override
  Future<void> connect() async {
    connects++;
    if (connecting != null) await connecting!.future;
    value = snapshot('connecting');
  }

  @override
  Future<void> disconnect() async {
    disconnects++;
    value = snapshot('idle', history: true);
  }

  @override
  Future<List<ProbeResult>> probe() async {
    probes++;
    return probing == null ? value.results : probing!.future;
  }
}

Future<void> mount(
  WidgetTester tester,
  FakeClient client, {
  Size size = const Size(460, 540),
  double scale = 1,
}) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = size;
  tester.platformDispatcher.textScaleFactorTestValue = scale;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
  await tester.pumpWidget(MyApp(client: client, now: () => clock));
  await tester.pump();
}

void main() {
  for (final error in [
    'invalid_policy',
    'invalid_binary',
    'credential_unavailable',
    'credential_expired',
    'prepared_state_unavailable',
    'config_render_failed',
  ]) {
    testWidgets('configuration $error offers IT rather than reconnect', (
      tester,
    ) async {
      final client = FakeClient(Status(state: 'idle', errorCode: error));
      await mount(tester, client);
      expect(find.text('配置不可用'), findsOneWidget);
      expect(find.text('联系 IT'), findsOneWidget);
      expect(find.byType(FilledButton), findsNothing);
      expect(client.connects, 0);
      expect(client.disconnects, 0);
    });
  }
  testWidgets('failed restoration only offers network restore', (tester) async {
    final client = FakeClient(
      const Status(
        state: 'needs_action',
        errorCode: 'automatic_restore_failed',
      ),
    );
    await mount(tester, client);
    expect(find.text('网络未恢复'), findsOneWidget);
    expect(find.text('开启海外访问'), findsNothing);
    await tester.tap(find.text('仅恢复网络'));
    await tester.pump();
    await tester.pump();
    expect(client.disconnects, 1);
    expect(client.connects, 0);
  });
  testWidgets('restored transaction failure retries connection', (
    tester,
  ) async {
    final client = FakeClient(
      const Status(state: 'idle', errorCode: 'core_start_failed'),
    );
    await mount(tester, client);
    expect(find.text('连接失败'), findsOneWidget);
    await tester.tap(find.text('重试'));
    await tester.pump();
    await tester.pump();
    expect(client.connects, 1);
    expect(client.disconnects, 0);
  });
  testWidgets('primary action has readable white text on deep green', (
    tester,
  ) async {
    await mount(tester, FakeClient(snapshot('connected')));
    await tester.pump(const Duration(milliseconds: 300));
    final paragraph = tester.renderObject<RenderParagraph>(find.text('关闭海外访问'));
    expect(paragraph.text.style?.color, Colors.white);
  });
  testWidgets('a missing native service never claims a connection', (
    tester,
  ) async {
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();
    expect(find.text('服务暂不可用'), findsOneWidget);
    expect(find.text('已连接'), findsNothing);
  });
  for (final entry in <String, String>{
    'idle': '未连接',
    'preparing': '正在准备',
    'connecting': '正在连接',
    'connected': '已连接',
    'restoring': '正在断开',
    'needs_action': '网络未恢复',
  }.entries) {
    testWidgets('renders ${entry.key} with unchanged shell', (tester) async {
      await mount(tester, FakeClient(snapshot(entry.key)));
      expect(find.text(entry.value), findsOneWidget);
      expect(
        tester.getSize(find.byKey(const Key('desktop-shell'))),
        const Size(460, 540),
      );
    });
  }
  testWidgets('degraded quality keeps connected tunnel and disconnect action', (
    tester,
  ) async {
    final client = FakeClient(snapshot('connected', quality: 'failed'));
    await mount(tester, client);
    expect(find.text('已连接'), findsOneWidget);
    expect(find.text('部分目标暂不可达'), findsOneWidget);
    await tester.tap(find.text('关闭海外访问'));
    await tester.pump();
    await tester.pump();
    expect(find.text('未连接'), findsOneWidget);
    expect(client.disconnects, 1);
  });
  testWidgets('connect starts only once and hides stale results', (
    tester,
  ) async {
    final client = FakeClient(snapshot('idle', history: true));
    await mount(tester, client);
    await tester.tap(find.text('开启海外访问'));
    await tester.pump();
    await tester.pump();
    expect(client.connects, 1);
    expect(find.text('正在连接'), findsOneWidget);
    await tester.tap(find.text('线路详情'));
    await tester.pump();
    expect(find.text('92 ms'), findsNothing);
  });
  testWidgets(
    'details has fixed targets, timestamp, manual loading, same shell',
    (tester) async {
      final client = FakeClient(snapshot('connected'));
      await mount(tester, client);
      expect(find.text('已连接 08:42'), findsOneWidget);
      await tester.tap(find.text('线路详情'));
      await tester.pump();
      for (final name in targetNames.values) {
        expect(find.text(name), findsOneWidget);
      }
      expect(find.textContaining('12 秒前更新'), findsOneWidget);
      expect(find.text('92 ms'), findsNWidgets(5));
      expect(find.text('正常'), findsNWidgets(5));
      expect(
        tester.getSize(find.byKey(const Key('desktop-shell'))),
        const Size(460, 540),
      );
      client.probing = Completer<List<ProbeResult>>();
      await tester.tap(find.text('立即测速'));
      await tester.pump();
      expect(find.text('正在测速'), findsOneWidget);
      expect(client.probes, 1);
      client.probing!.complete(client.value.results);
      await tester.pump();
      await tester.pump();
      await tester.tap(find.text('返回'));
      await tester.pump();
      expect(find.text('已连接'), findsOneWidget);
    },
  );
  testWidgets('history is marked and cannot trigger probes', (tester) async {
    final client = FakeClient(snapshot('idle', history: true));
    await mount(tester, client);
    await tester.tap(find.text('线路详情'));
    await tester.pump();
    expect(find.textContaining('历史结果'), findsOneWidget);
    expect(
      tester.widget<OutlinedButton>(find.byType(OutlinedButton)).onPressed,
      isNull,
    );
    expect(client.probes, 0);
  });
  testWidgets(
    'poll failure clears connected claim and retry recovers restarted generation',
    (tester) async {
      final client = FakeClient(snapshot('connected'));
      await mount(tester, client);
      client.fail = true;
      await tester.pump(const Duration(seconds: 3));
      await tester.pump();
      expect(find.text('服务暂不可用'), findsOneWidget);
      expect(find.text('已连接'), findsNothing);
      expect(find.textContaining('secret'), findsNothing);
      client.fail = false;
      client.value = snapshot('idle', generation: 0);
      await tester.tap(find.text('重试'));
      await tester.pump();
      await tester.pump();
      expect(find.text('未连接'), findsOneWidget);
    },
  );
  testWidgets(
    'pending status shows loading and disposal ignores its completion',
    (tester) async {
      final client = FakeClient(snapshot('idle'))
        ..pending = Completer<Status>();
      await mount(tester, client);
      expect(find.text('正在读取状态'), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
      client.pending!.complete(snapshot('connected'));
      await tester.pump();
      expect(tester.takeException(), isNull);
    },
  );
  testWidgets('stalled poll has a bounded lifetime', (tester) async {
    final client = FakeClient(snapshot('connected'));
    await mount(tester, client);
    client.pending = Completer<Status>();
    await tester.pump(const Duration(seconds: 3));
    await tester.pump(const Duration(seconds: 9));
    await tester.pump();
    expect(find.text('服务暂不可用'), findsOneWidget);
    client.pending!.complete(snapshot('connected'));
    await tester.pump();
  });
  testWidgets('connection request hides history before service responds', (
    tester,
  ) async {
    final client = FakeClient(snapshot('idle', history: true))
      ..connecting = Completer<void>();
    await mount(tester, client);
    await tester.tap(find.text('开启海外访问'));
    await tester.pump();
    expect(find.text('正在连接'), findsOneWidget);
    await tester.tap(find.text('线路详情'));
    await tester.pump();
    expect(find.text('92 ms'), findsNothing);
    client.connecting!.complete();
    await tester.pump();
    await tester.pump();
  });
  testWidgets('repeated status polls never turn one failure into abnormal', (
    tester,
  ) async {
    final client = FakeClient(
      snapshot('connected', results: [result('google', failures: 1)]),
    );
    await mount(tester, client);
    await tester.tap(find.text('线路详情'));
    await tester.pump();
    for (var i = 0; i < 4; i++) {
      await tester.pump(const Duration(seconds: 3));
      await tester.pump();
    }
    expect(find.text('待确认'), findsOneWidget);
    expect(find.text('异常'), findsNothing);
  });
  testWidgets('probe failure clears stale status without exposing raw errors', (
    tester,
  ) async {
    final client = FakeClient(snapshot('connected'))
      ..probing = Completer<List<ProbeResult>>();
    await mount(tester, client);
    await tester.tap(find.text('线路详情'));
    await tester.pump();
    await tester.tap(find.text('立即测速'));
    await tester.pump();
    client.probing!.completeError(StateError('raw error code'));
    await tester.pump();
    expect(find.text('服务暂不可用'), findsOneWidget);
    expect(find.textContaining('raw error'), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });
  testWidgets('two hundred percent DPI retains logical shell size', (
    tester,
  ) async {
    await mount(tester, FakeClient(snapshot('connected')));
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = const Size(920, 1080);
    await tester.pump();
    expect(
      tester.getSize(find.byKey(const Key('desktop-shell'))),
      const Size(460, 540),
    );
    expect(tester.takeException(), isNull);
  });
  testWidgets('narrow viewport and doubled text scroll on both pages', (
    tester,
  ) async {
    await mount(
      tester,
      FakeClient(snapshot('connected')),
      size: const Size(280, 320),
      scale: 2,
    );
    expect(tester.takeException(), isNull);
    await tester.ensureVisible(find.text('线路详情'));
    await tester.tap(find.text('线路详情'));
    await tester.pump();
    expect(tester.takeException(), isNull);
    await tester.ensureVisible(find.text('立即测速'));
    expect(tester.takeException(), isNull);
  });
}
