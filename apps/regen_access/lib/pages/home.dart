import 'package:flutter/material.dart';

import '../model/status.dart';
import '../theme.dart';

class HomePage extends StatelessWidget {
  const HomePage({
    super.key,
    required this.status,
    required this.now,
    required this.unavailable,
    required this.busy,
    required this.onAction,
    required this.onDetails,
  });
  final Status? status;
  final DateTime now;
  final bool unavailable, busy;
  final VoidCallback onAction, onDetails;

  @override
  Widget build(BuildContext context) {
    final s = status;
    final connected = s?.connected == true;
    final loading = !unavailable && s == null;
    final transitional = s?.transitioning == true;
    final title = unavailable
        ? '服务暂不可用'
        : loading
        ? '正在读取状态'
        : s?.errorTitle ??
              switch (s!.state) {
                'idle' => '未连接',
                'preparing' => '正在准备',
                'connecting' => '正在连接',
                'connected' => '已连接',
                'restoring' => '正在断开',
                _ => '需要处理',
              };
    final subtitle = unavailable
        ? '请稍后重试'
        : connected
        ? switch (s!.quality) {
            'good' => '海外线路正常',
            'slow' => '部分目标响应较慢',
            'failed' => '部分目标暂不可达',
            _ => '线路质量待确认',
          }
        : s?.errorTitle != null
        ? ''
        : transitional || loading
        ? '请稍候'
        : '按需开启海外访问';
    final label = unavailable
        ? '重试'
        : busy
        ? '正在处理'
        : connected
        ? '关闭海外访问'
        : s?.errorAction != null
        ? s!.errorAction!
        : transitional
        ? '请稍候'
        : '开启海外访问';
    final seconds = s?.connectedAt == null
        ? null
        : now.difference(s!.connectedAt!).inSeconds.clamp(0, 999999999);
    final duration = seconds == null
        ? '时长待确认'
        : '${(seconds ~/ 60).toString().padLeft(2, '0')}:${(seconds % 60).toString().padLeft(2, '0')}';
    final healthy = connected && s!.quality == 'good';
    return LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: constraints.maxHeight),
          child: IntrinsicHeight(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(32, 54, 32, 22),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Center(
                    child: Container(
                      width: 88,
                      height: 88,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: healthy
                            ? successBackground
                            : const Color(0xfff1f5f3),
                      ),
                      child: loading || transitional || busy
                          ? const Padding(
                              padding: EdgeInsets.all(29),
                              child: CircularProgressIndicator(
                                strokeWidth: 2.5,
                              ),
                            )
                          : Icon(
                              healthy
                                  ? Icons.check_rounded
                                  : connected ||
                                        unavailable ||
                                        s?.state == 'needs_action'
                                  ? Icons.priority_high_rounded
                                  : Icons.power_settings_new_rounded,
                              color: healthy
                                  ? success
                                  : connected ||
                                        unavailable ||
                                        s?.state == 'needs_action'
                                  ? warning
                                  : primary,
                              size: 38,
                            ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  Text(
                    title,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      fontSize: 26,
                      fontWeight: FontWeight.w600,
                      color: primary,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    subtitle,
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: muted),
                  ),
                  const SizedBox(height: 34),
                  if (s?.configurationUnavailable == true)
                    const Text(
                      '联系 IT',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: secondary),
                    )
                  else
                    FilledButton(
                      onPressed: loading || transitional || busy
                          ? null
                          : onAction,
                      child: Text(label),
                    ),
                  const SizedBox(height: 28),
                  const Spacer(),
                  if (!unavailable && !loading && s?.errorTitle == null) ...[
                    const Divider(color: border, height: 1),
                    const SizedBox(height: 12),
                    Wrap(
                      alignment: WrapAlignment.spaceBetween,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      spacing: 12,
                      children: [
                        if (connected)
                          Text(
                            '已连接 $duration',
                            style: const TextStyle(fontSize: 13, color: muted),
                          )
                        else
                          const SizedBox(),
                        TextButton(
                          onPressed: onDetails,
                          child: const Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text('线路详情'),
                              Icon(Icons.chevron_right, size: 18),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
