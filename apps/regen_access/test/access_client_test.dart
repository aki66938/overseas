import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:regen_access/api/access_client.dart';

String response(String id, {String state = 'idle'}) =>
    '${jsonEncode({
      'version': 1,
      'id': id,
      'status': {'state': state, 'quality': 'unknown', 'generation': 1},
    })}\n';
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('regen_access/access');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));
  test(
    'uses fixed channel actions and unique APIv1 request identities',
    () async {
      final ids = <String>{};
      messenger.setMockMethodCallHandler(channel, (call) async {
        expect(call.method, 'request');
        final args = call.arguments as Map;
        expect(args.keys.toSet(), {'id', 'action'});
        expect(ids.add(args['id'] as String), isTrue);
        return response(args['id'] as String);
      });
      final client = WindowsAccessClient();
      expect((await client.status()).state, 'idle');
      await client.connect();
      await client.disconnect();
      expect(ids.length, 3);
    },
  );
  for (final invalid in [
    'id',
    'version',
    'state',
    'code',
    'probe',
    'newline',
    'large',
    'extra',
  ]) {
    test('rejects malformed $invalid response', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        var frame = response((call.arguments as Map)['id']);
        final value = jsonDecode(frame) as Map<String, dynamic>;
        switch (invalid) {
          case 'id':
            value['id'] = 'another-request';
          case 'version':
            value['version'] = 2;
          case 'state':
            value['status']['state'] = 'raw_internal_state';
          case 'code':
            value['status']['error_code'] = 'raw-secret';
          case 'probe':
            value['probe_results'] = [
              {
                'id': 'google',
                'latency_ms': 0,
                'reachable': true,
                'checked_at': '2026-09-07T00:00:00Z',
                'http_status': 900,
              },
            ];
          case 'newline':
            return frame.trim();
          case 'large':
            return '${' ' * 65536}$frame';
          case 'extra':
            return '$frame{}\n';
        }
        return '${jsonEncode(value)}\n';
      });
      await expectLater(
        WindowsAccessClient().status(),
        throwsA(isA<FormatException>()),
      );
    });
  }
  test(
    'rejects overlapping lifecycle while original response is pending',
    () async {
      final pending = Completer<String>();
      messenger.setMockMethodCallHandler(channel, (_) => pending.future);
      final client = WindowsAccessClient();
      final first = client.connect();
      await expectLater(client.disconnect(), throwsA(isA<StateError>()));
      pending.completeError(PlatformException(code: 'pre_dispatch'));
      await expectLater(first, throwsA(isA<PlatformException>()));
    },
  );
  test(
    'post-dispatch transport loss stays uncertain after fresh terminal status',
    () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        final args = call.arguments as Map;
        if (args['action'] != 'status') {
          throw PlatformException(code: 'transport_lost');
        }
        return response(args['id']);
      });
      final client = WindowsAccessClient();
      await expectLater(
        client.connect(),
        throwsA(isA<OperationUncertainException>()),
      );
      await client.status();
      await expectLater(
        client.disconnect(),
        throwsA(isA<OperationUncertainException>()),
      );
    },
  );
  test('definite pre-dispatch failure permits a subsequent request', () async {
    var calls = 0;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (++calls == 1) throw PlatformException(code: 'pre_dispatch');
      return response((call.arguments as Map)['id']);
    });
    final client = WindowsAccessClient();
    await expectLater(client.connect(), throwsA(isA<PlatformException>()));
    await client.connect();
    expect(calls, 2);
  });
  for (final timestamp in [
    '2026-99-07T00:00:00Z',
    '2026-09-07',
    '0001-01-01T00:00:00Z',
  ]) {
    test('rejects invalid probe timestamp $timestamp', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        final value = jsonDecode(
          response((call.arguments as Map)['id'], state: 'connected'),
        ) as Map;
        value['probe_generation'] = 1;
        value['probe_results'] = [
          {
            'id': 'google',
            'latency_ms': 1,
            'reachable': true,
            'checked_at': timestamp,
          },
        ];
        return '${jsonEncode(value)}\n';
      });
      await expectLater(
        WindowsAccessClient().status(),
        throwsA(isA<FormatException>()),
      );
    });
  }
}
