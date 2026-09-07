import 'status.dart';

/// The tray projects the page's state; it never owns a second lifecycle.
class TrayState {
  const TrayState(this.label, this.enabled, this.summary, this.details);
  final String label;
  final bool enabled;
  final String summary;
  final bool details;

  factory TrayState.fromStatus(
    Status? status, {
    bool busy = false,
    bool polling = false,
    bool uncertain = false,
  }) {
    final label = uncertain
        ? '操作结果待确认'
        : status == null
        ? '服务暂不可用'
        : status.errorAction ??
              (status.connected
                  ? '关闭海外访问'
                  : status.state == 'restoring'
                  ? '正在恢复网络'
                  : status.transitioning
                  ? '正在连接'
                  : '开启海外访问');
    var summary = uncertain
        ? '操作结果待确认'
        : status == null
        ? '服务暂不可用'
        : status.errorTitle ??
              (status.connected
                  ? '已连接'
                  : status.transitioning
                  ? label
                  : '未连接');
    if (!uncertain &&
        status?.connected == true &&
        !status!.probeHistorical &&
        status.probeGeneration == status.generation) {
      final current = status.results.where((r) => r.reachable).toList();
      if (current.isNotEmpty) {
        final average =
            (current.fold<int>(0, (sum, r) => sum + r.latencyMs) /
                    current.length)
                .round();
        summary += ' · $average ms';
      }
    }
    return TrayState(
      label,
      status != null &&
          !busy &&
          !polling &&
          !uncertain &&
          !status.transitioning &&
          !status.configurationUnavailable,
      summary,
      status != null,
    );
  }
  Map<String, Object> toMap() => {
    'label': label,
    'enabled': enabled,
    'summary': summary,
    'details': details,
  };
}
