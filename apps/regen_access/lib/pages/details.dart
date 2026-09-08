import 'package:flutter/material.dart';

import '../model/status.dart';
import '../theme.dart';

class DetailsPage extends StatelessWidget {
  const DetailsPage({
    super.key,
    required this.status,
    required this.now,
    required this.busy,
    required this.polling,
    required this.onBack,
    required this.onProbe,
  });
  final Status status;
  final DateTime now;
  final bool busy, polling;
  final VoidCallback onBack, onProbe;
  @override
  Widget build(BuildContext context) {
    final results = {for (final r in status.visibleResults) r.id: r};
    final dates = results.values.map((r) => r.checkedAt).toList()..sort();
    final seconds = dates.isEmpty
        ? null
        : now.difference(dates.last).inSeconds.clamp(0, 999999999);
    final updated = seconds == null
        ? '尚未测速'
        : seconds < 60
        ? '$seconds 秒前更新'
        : '${dates.last.toLocal().hour.toString().padLeft(2, '0')}:${dates.last.toLocal().minute.toString().padLeft(2, '0')} 更新';
    final history =
        status.probeHistorical || (!status.connected && results.isNotEmpty);
    final compactLayout =
        MediaQuery.sizeOf(context).width < 320 ||
        MediaQuery.textScalerOf(context).scale(1) > 1.5;
    final back = TextButton(
      onPressed: onBack,
      child: const Row(
        mainAxisSize: MainAxisSize.min,
        children: [Icon(Icons.chevron_left, size: 18), Text('返回')],
      ),
    );
    const heading = Text(
      '线路详情',
      style: TextStyle(fontSize: 21, fontWeight: FontWeight.w600),
    );
    final connection = Text(
      status.connected ? '已连接' : '历史记录',
      style: TextStyle(fontSize: 12, color: status.connected ? success : muted),
    );
    return LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: constraints.maxHeight),
          child: IntrinsicHeight(
            child: ColoredBox(
              color: canvas,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(20, 14, 20, 18),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (compactLayout)
                      Wrap(
                        crossAxisAlignment: WrapCrossAlignment.center,
                        spacing: 8,
                        runSpacing: 4,
                        children: [back, heading, connection],
                      )
                    else
                      Row(
                        children: [
                          back,
                          const SizedBox(width: 2),
                          heading,
                          const Spacer(),
                          connection,
                        ],
                      ),
                    const SizedBox(height: 10),
                    Text(
                      history ? '历史结果 · $updated' : updated,
                      style: const TextStyle(fontSize: 13, color: muted),
                    ),
                    const SizedBox(height: 12),
                    Container(
                      decoration: BoxDecoration(
                        color: Colors.white,
                        border: Border.all(color: border),
                        borderRadius: BorderRadius.circular(16),
                        boxShadow: const [
                          BoxShadow(
                            color: cardShadow,
                            blurRadius: 14,
                            offset: Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Column(
                        children: [
                          for (var i = 0; i < targetNames.entries.length; i++)
                            _TargetRow(
                              entry: targetNames.entries.elementAt(i),
                              result:
                                  results[targetNames.entries.elementAt(i).key],
                              historical: history,
                              showDivider: i != targetNames.entries.length - 1,
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                    const Spacer(),
                    OutlinedButton(
                      onPressed: status.connected && !busy && !polling
                          ? onProbe
                          : null,
                      child: Text(
                        polling
                            ? '正在读取状态'
                            : busy
                            ? '正在测速'
                            : '立即测速',
                      ),
                    ),
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

class _TargetRow extends StatelessWidget {
  const _TargetRow({
    required this.entry,
    required this.result,
    required this.historical,
    required this.showDivider,
  });

  final MapEntry<String, String> entry;
  final ProbeResult? result;
  final bool historical, showDivider;

  @override
  Widget build(BuildContext context) {
    final health = result?.health ?? '待测速';
    final healthColor = historical
        ? muted
        : health == '正常'
        ? success
        : health == '异常' || health == '较慢'
        ? warning
        : muted;
    return Container(
      constraints: const BoxConstraints(minHeight: 41),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        border: showDivider
            ? const Border(bottom: BorderSide(color: border))
            : null,
      ),
      child: Builder(
        builder: (context) {
          final name = Text(
            entry.value,
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
          );
          final latency = Text(
            result?.reachable == true ? '${result!.latencyMs} ms' : '—',
            textAlign: TextAlign.right,
            style: const TextStyle(fontSize: 13, color: primary),
          );
          final state = Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(
                  color: healthColor,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 6),
              Text(health, style: TextStyle(fontSize: 12, color: healthColor)),
            ],
          );
          if (MediaQuery.sizeOf(context).width < 320 ||
              MediaQuery.textScalerOf(context).scale(1) > 1.5) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Expanded(child: name),
                    latency,
                  ],
                ),
                const SizedBox(height: 4),
                Align(alignment: Alignment.centerRight, child: state),
              ],
            );
          }
          return Row(
            children: [
              Expanded(child: name),
              SizedBox(width: 76, child: latency),
              const SizedBox(width: 14),
              SizedBox(width: 70, child: state),
            ],
          );
        },
      ),
    );
  }
}
