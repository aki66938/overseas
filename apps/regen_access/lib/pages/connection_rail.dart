import 'package:flutter/material.dart';

import '../model/status.dart';
import '../theme.dart';

class ConnectionRail extends StatelessWidget {
  const ConnectionRail({
    super.key,
    required this.status,
    required this.now,
    required this.unavailable,
    required this.details,
    required this.onNavigate,
  });

  final Status? status;
  final DateTime now;
  final bool unavailable, details;
  final VoidCallback? onNavigate;

  String get _title {
    final value = status;
    if (unavailable) return '服务暂不可用';
    if (value == null) return '正在读取状态';
    if (value.errorTitle != null) return value.errorTitle!;
    return switch (value.state) {
      'idle' => '未连接',
      'preparing' => '正在准备',
      'connecting' => '正在连接',
      'connected' => '已连接',
      'restoring' => '正在断开',
      _ => '需要处理',
    };
  }

  String get _duration {
    final connectedAt = status?.connectedAt;
    if (connectedAt == null || status?.connected != true) return '—';
    final seconds = now.difference(connectedAt).inSeconds.clamp(0, 999999999);
    return '${(seconds ~/ 60).toString().padLeft(2, '0')}:${(seconds % 60).toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) => ColoredBox(
    key: const Key('connection-rail'),
    color: railBackground,
    child: SizedBox(
      width: 138,
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 14),
        child: ConstrainedBox(
          constraints: const BoxConstraints(minHeight: 194),
          child: IntrinsicHeight(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('当前连接', style: railLabelStyle),
                const SizedBox(height: 7),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      margin: const EdgeInsets.only(top: 10, right: 7),
                      decoration: BoxDecoration(
                        color: status?.connected == true ? railDot : warning,
                        shape: BoxShape.circle,
                      ),
                    ),
                    Expanded(
                      child: Text(
                        _title,
                        style: TextStyle(
                          color: railText,
                          fontSize: _title.length > 5 ? 15 : 20,
                          height: 1.3,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
                const Spacer(),
                const Text('连接时长', style: railLabelStyle),
                const SizedBox(height: 5),
                Text(
                  _duration,
                  style: const TextStyle(
                    color: railText,
                    fontSize: 19,
                    letterSpacing: .4,
                  ),
                ),
                const Spacer(),
                Container(
                  padding: const EdgeInsets.only(top: 8),
                  decoration: const BoxDecoration(
                    border: Border(top: BorderSide(color: railDivider)),
                  ),
                  child: TextButton(
                    onPressed: onNavigate,
                    style: TextButton.styleFrom(
                      foregroundColor: railText,
                      padding: EdgeInsets.zero,
                      minimumSize: const Size(106, 28),
                      alignment: Alignment.centerLeft,
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: Text(
                            details ? '返回主页' : '线路详情',
                            style: const TextStyle(
                              fontSize: 11,
                              color: railText,
                            ),
                          ),
                        ),
                        const Icon(
                          Icons.chevron_right,
                          size: 14,
                          color: railText,
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}
