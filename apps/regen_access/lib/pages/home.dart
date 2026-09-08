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
    required this.polling,
    required this.onAction,
    required this.onDetails,
  });
  final Status? status;
  final DateTime now;
  final bool unavailable, busy, polling;
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
        ? ''
        : s?.errorTitle != null
        ? ''
        : transitional || loading
        ? '请稍候'
        : '按需开启海外访问';
    final label = loading
        ? '请稍候'
        : polling
        ? '正在读取状态'
        : unavailable
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
    final hasError = unavailable || s?.errorTitle != null;
    return LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: constraints.maxHeight),
          child: IntrinsicHeight(
            child: ColoredBox(
              color: canvas,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(24, 22, 24, 20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Text(
                      'REGENBIO  ·  海外访问',
                      style: TextStyle(
                        color: muted,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        letterSpacing: .8,
                      ),
                    ),
                    const SizedBox(height: 18),
                    Container(
                      padding: const EdgeInsets.fromLTRB(24, 28, 24, 24),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(18),
                        border: Border.all(color: border),
                        boxShadow: const [
                          BoxShadow(
                            color: cardShadow,
                            blurRadius: 18,
                            offset: Offset(0, 5),
                          ),
                        ],
                      ),
                      child: Column(
                        children: [
                          Container(
                            width: 112,
                            height: 112,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: connected ? successBackground : canvas,
                              border: Border.all(
                                color: connected ? primary : border,
                                width: connected ? 4 : 2,
                              ),
                            ),
                            child: loading || transitional || busy
                                ? const Padding(
                                    padding: EdgeInsets.all(29),
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2.5,
                                    ),
                                  )
                                : Icon(
                                    connected
                                        ? Icons.check_rounded
                                        : hasError || s?.state == 'needs_action'
                                        ? Icons.priority_high_rounded
                                        : Icons.power_settings_new_rounded,
                                    color: connected
                                        ? primary
                                        : hasError || s?.state == 'needs_action'
                                        ? warning
                                        : primary,
                                    size: 42,
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
                          if (subtitle.isNotEmpty) ...[
                            const SizedBox(height: 8),
                            Text(
                              subtitle,
                              textAlign: TextAlign.center,
                              style: const TextStyle(color: muted),
                            ),
                          ],
                          if (connected) ...[
                            const SizedBox(height: 8),
                            Text(
                              '已连接 $duration',
                              style: const TextStyle(
                                fontSize: 13,
                                color: muted,
                              ),
                            ),
                          ],
                          const SizedBox(height: 24),
                          if (s?.configurationUnavailable == true)
                            const Text(
                              '联系 IT',
                              textAlign: TextAlign.center,
                              style: TextStyle(color: secondary),
                            )
                          else
                            FilledButton(
                              onPressed:
                                  loading || transitional || busy || polling
                                  ? null
                                  : onAction,
                              child: Text(label),
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                    if (!unavailable && !loading && s?.errorTitle == null) ...[
                      Container(
                        decoration: BoxDecoration(
                          color: Colors.white,
                          borderRadius: BorderRadius.circular(14),
                          border: Border.all(color: border),
                        ),
                        child: TextButton(
                          onPressed: onDetails,
                          child: const Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text('线路详情'),
                              Icon(Icons.chevron_right, size: 18),
                            ],
                          ),
                        ),
                      ),
                    ],
                    const Spacer(),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
