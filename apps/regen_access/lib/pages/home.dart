import 'package:flutter/material.dart';

import '../model/status.dart';
import '../theme.dart';

class HomePage extends StatelessWidget {
  const HomePage({
    super.key,
    required this.status,
    required this.unavailable,
    required this.busy,
    required this.polling,
    required this.onAction,
  });

  final Status? status;
  final bool unavailable, busy, polling;
  final VoidCallback onAction;

  @override
  Widget build(BuildContext context) {
    final value = status;
    final loading = !unavailable && value == null;
    final transitional = value?.transitioning == true;
    final label = loading
        ? '请稍候'
        : polling
        ? '正在读取状态'
        : unavailable
        ? '重试'
        : busy
        ? '正在处理'
        : value?.connected == true
        ? '关闭海外访问'
        : value?.errorAction ?? (transitional ? '请稍候' : '开启海外访问');

    return ColoredBox(
      color: Colors.white,
      child: LayoutBuilder(
        builder: (context, constraints) => SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: constraints.maxHeight - 40),
            child: IntrinsicHeight(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Column(
                    key: const Key('home-content-group'),
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const Text(
                        '海外访问',
                        style: TextStyle(
                          color: primary,
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 22),
                      if (value?.configurationUnavailable == true)
                        const Center(
                          child: Text(
                            '联系 IT',
                            style: TextStyle(color: secondary),
                          ),
                        )
                      else
                        FilledButton(
                          onPressed: loading || transitional || busy || polling
                              ? null
                              : onAction,
                          child: Text(label),
                        ),
                      if (unavailable) ...[
                        const SizedBox(height: 8),
                        const Text(
                          '请稍后重试',
                          textAlign: TextAlign.center,
                          style: TextStyle(fontSize: 10, color: muted),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
