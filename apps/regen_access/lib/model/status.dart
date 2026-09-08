const targetNames = <String, String>{
  'google': 'Google',
  'pinterest': 'Pinterest',
  'gemini': 'Gemini',
  'chatgpt': 'ChatGPT',
  'claude': 'Claude',
  'tiktok': 'TikTok',
  'amazon': '亚马逊',
  'facebook': 'Facebook',
};

class ProbeResult {
  const ProbeResult({
    required this.id,
    required this.latencyMs,
    required this.reachable,
    required this.checkedAt,
    this.consecutiveFailures,
  });
  final String id;
  final int latencyMs;
  final bool reachable;
  final DateTime checkedAt;
  final int? consecutiveFailures;
  String get health {
    if (consecutiveFailures == null) return '未知';
    if (consecutiveFailures! >= 3) return '异常';
    if (consecutiveFailures! > 0 || !reachable) return '待确认';
    return latencyMs >= 1000 ? '较慢' : '正常';
  }
}

class Status {
  const Status({
    required this.state,
    this.errorCode = '',
    this.quality = 'unknown',
    this.connectedAt,
    this.generation = 0,
    this.probeGeneration = 0,
    this.probeHistorical = false,
    this.results = const [],
  });
  final String state;
  final String errorCode;
  final String quality;
  final DateTime? connectedAt;
  final int generation;
  final int probeGeneration;
  final bool probeHistorical;
  final List<ProbeResult> results;
  bool get connected => state == 'connected';
  bool get needsRestore =>
      state == 'needs_action' ||
      const ['restore_failed', 'automatic_restore_failed'].contains(errorCode);
  bool get configurationUnavailable =>
      !connected &&
      !needsRestore &&
      const [
        'invalid_policy',
        'invalid_binary',
        'credential_unavailable',
        'credential_expired',
        'prepared_state_unavailable',
        'config_render_failed',
      ].contains(errorCode);
  bool get transactionFailed =>
      state == 'idle' &&
      errorCode.isNotEmpty &&
      errorCode != 'canceled' &&
      !configurationUnavailable &&
      !needsRestore;
  String? get errorTitle => needsRestore
      ? '网络未恢复'
      : configurationUnavailable
      ? '配置不可用'
      : transactionFailed
      ? '连接失败'
      : null;
  String? get errorAction => needsRestore
      ? '仅恢复网络'
      : configurationUnavailable
      ? '联系 IT'
      : transactionFailed
      ? '重试'
      : null;
  bool get transitioning =>
      const ['preparing', 'connecting', 'restoring'].contains(state);
  List<ProbeResult> get visibleResults => transitioning ? const [] : results;
  String get qualityLabel => switch (quality) {
    'good' => '良好',
    'slow' => '较慢',
    'failed' => '异常',
    _ => '待测速',
  };
  factory Status.fromResponse(Map<String, dynamic> json) {
    final raw = json['status'];
    if (json['version'] != 1 ||
        raw is! Map<String, dynamic> ||
        !const [
          'idle',
          'preparing',
          'connecting',
          'connected',
          'restoring',
          'needs_action',
        ].contains(raw['state']) ||
        !const ['unknown', 'good', 'slow', 'failed'].contains(raw['quality']) ||
        !_statusErrors.contains(raw['error_code'] ?? '')) {
      throw const FormatException('Invalid APIv1 status');
    }
    final results = <ProbeResult>[];
    final seen = <String>{};
    for (final value in (json['probe_results'] as List? ?? const [])) {
      final r = value as Map<String, dynamic>;
      final id = r['id'] as String;
      final ms = r['latency_ms'] as int;
      final failures = r['consecutive_failures'] as int?;
      final http = r['http_status'] ?? 0;
      if (!targetNames.containsKey(id) ||
          !seen.add(id) ||
          ms < 0 ||
          ms > 5000 ||
          (failures != null && (failures < 0 || failures > 3)) ||
          http is! int ||
          http < 0 ||
          http > 599 ||
          !const [
            '',
            'timeout',
            'canceled',
            'tls_error',
            'network_error',
            'http_server_error',
            'invalid_target',
          ].contains(r['error_code'] ?? '')) {
        throw const FormatException('Invalid probe result');
      }
      results.add(
        ProbeResult(
          id: id,
          latencyMs: ms,
          reachable: r['reachable'] as bool,
          checkedAt: _timestamp(r['checked_at'] as String),
          consecutiveFailures: failures,
        ),
      );
    }
    final generation = raw['generation'] as int;
    final probeGeneration = json['probe_generation'] as int? ?? 0;
    final historical = json['probe_historical'] as bool? ?? false;
    if (generation < 0 ||
        probeGeneration < 0 ||
        (results.isEmpty && (probeGeneration != 0 || historical)) ||
        (results.isNotEmpty &&
            (probeGeneration > generation ||
                (raw['state'] == 'connected'
                    ? historical || probeGeneration != generation
                    : !historical)))) {
      throw const FormatException('Invalid probe generation');
    }
    return Status(
      state: raw['state'] as String,
      errorCode: raw['error_code'] as String? ?? '',
      quality: raw['quality'] as String,
      connectedAt: raw['connected_at'] == null || raw['connected_at'] == ''
          ? null
          : _timestamp(raw['connected_at'] as String),
      generation: generation,
      probeGeneration: probeGeneration,
      probeHistorical: historical,
      results: List.unmodifiable(results),
    );
  }
}

DateTime _timestamp(String value) {
  final match = RegExp(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$',
  ).firstMatch(value);
  if (match == null) throw const FormatException('Invalid API timestamp');
  final parts = [for (var i = 1; i <= 6; i++) int.parse(match.group(i)!)];
  final date = DateTime.utc(parts[0], parts[1], parts[2]);
  final zone = match.group(7)!;
  if (date.year != parts[0] ||
      date.month != parts[1] ||
      date.day != parts[2] ||
      parts[3] > 23 ||
      parts[4] > 59 ||
      parts[5] > 59 ||
      (zone != 'Z' &&
          (int.parse(zone.substring(1, 3)) > 23 ||
              int.parse(zone.substring(4)) > 59))) {
    throw const FormatException('Invalid API timestamp');
  }
  final parsed = DateTime.parse(value);
  if (parsed == DateTime.utc(1)) {
    throw const FormatException('Empty API timestamp');
  }
  return parsed;
}

const _statusErrors = {
  '',
  'invalid_action',
  'invalid_request',
  'invalid_policy',
  'invalid_binary',
  'credential_unavailable',
  'credential_expired',
  'prepared_state_unavailable',
  'vpn_conflict',
  'network_changed',
  'network_capture_failed',
  'firewall_enable_failed',
  'firewall_verify_failed',
  'public_tcp_block_failed',
  'config_render_failed',
  'core_start_failed',
  'core_not_ready',
  'tun_not_found',
  'tun_identity_mismatch',
  'route_activation_failed',
  'readiness_lost',
  'restore_failed',
  'automatic_restore_failed',
  'canceled',
  'account_unauthorized',
};
