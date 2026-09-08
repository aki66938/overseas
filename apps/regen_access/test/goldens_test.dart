import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:regen_access/app.dart';
import 'package:regen_access/model/status.dart';

import 'pages_test.dart' show FakeClient, clock, snapshot, result;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    final text = FontLoader('GoldenNoto')
      ..addFont(
        Future.value(
          ByteData.sublistView(
            await File('test/fonts/NotoSansSC.ttf').readAsBytes(),
          ),
        ),
      );
    final icons = FontLoader('MaterialIcons')
      ..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'));
    await text.load();
    await icons.load();
  });
  for (final state in [
    'idle',
    'connecting',
    'connected',
    'degraded',
    'needs_action',
    'unavailable',
    'configuration',
    'retry',
  ]) {
    testWidgets('golden home $state', (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(480, 224);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final client = FakeClient(
        state == 'configuration'
            ? const Status(state: 'idle', errorCode: 'invalid_policy')
            : state == 'retry'
            ? const Status(state: 'idle', errorCode: 'core_start_failed')
            : snapshot(
                state == 'degraded' ? 'connected' : state,
                quality: state == 'degraded' ? 'slow' : 'good',
              ),
      )..fail = state == 'unavailable';
      await tester.pumpWidget(
        MyApp(client: client, now: () => clock, fontFamily: 'GoldenNoto'),
      );
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 300));
      await expectLater(
        find.byKey(const Key('desktop-shell')),
        matchesGoldenFile('goldens/home_$state.png'),
      );
      await tester.pumpWidget(const SizedBox());
    });
  }
  for (final history in [false, true]) {
    testWidgets('golden details history=$history', (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(480, 224);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final client = FakeClient(
        snapshot(
          history ? 'idle' : 'connected',
          history: history,
          quality: 'slow',
          results: [
            result('google', ms: 38),
            result('pinterest', ms: 1050),
            result('gemini', failures: 1),
            result('chatgpt', failures: 3),
            result('claude', failures: null),
          ],
        ),
      );
      await tester.pumpWidget(
        MyApp(client: client, now: () => clock, fontFamily: 'GoldenNoto'),
      );
      await tester.pump();
      await tester.tap(find.text('线路详情'));
      await tester.pump(const Duration(milliseconds: 300));
      await expectLater(
        find.byKey(const Key('desktop-shell')),
        matchesGoldenFile(
          'goldens/details_${history ? 'history' : 'mixed'}.png',
        ),
      );
      await tester.pumpWidget(const SizedBox());
    });
  }
}
