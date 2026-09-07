import 'package:flutter_test/flutter_test.dart';
import 'package:regen_access/model/status.dart';

import 'pages_test.dart' show result;

void main() {
  test('authoritative counters and production slow threshold', () {
    expect(result('google', ms: 92).health, '正常');
    expect(result('google', ms: 999).health, '正常');
    expect(result('google', ms: 1000).health, '较慢');
    expect(result('google', failures: null).health, '未知');
    expect(result('google', failures: 1).health, '待确认');
    expect(result('google', failures: 2).health, '待确认');
    expect(result('google', failures: 3).health, '异常');
  });
  test('decodes APIv1 response and preserves history and missing counters', () {
    final status = Status.fromResponse({
      'version': 1,
      'id': 'test',
      'status': {'state': 'idle', 'quality': 'unknown', 'generation': 4},
      'probe_generation': 3,
      'probe_historical': true,
      'probe_results': [
        {
          'id': 'google',
          'latency_ms': 42,
          'reachable': true,
          'http_status': 200,
          'checked_at': '2026-09-07T12:00:00Z',
        },
      ],
    });
    expect(status.generation, 4);
    expect(status.probeHistorical, isTrue);
    expect(status.probeGeneration, 3);
    expect(status.results.single.consecutiveFailures, isNull);
  });
  test('unknown wire states never become connected', () {
    expect(
      () => Status.fromResponse({
        'version': 1,
        'status': {'state': 'unexpected', 'quality': 'good', 'generation': 0},
      }),
      throwsFormatException,
    );
    expect(
      () => Status.fromResponse({
        'version': 2,
        'status': {'state': 'connected', 'quality': 'good', 'generation': 0},
      }),
      throwsFormatException,
    );
  });
}
