import 'package:flutter/material.dart';

import '../model/status.dart';
import '../theme.dart';

class DetailsPage extends StatelessWidget {
  const DetailsPage({
    super.key,
    required this.status,
    required this.now,
    required this.busy,
    required this.onBack,
    required this.onProbe,
  });
  final Status status;
  final DateTime now;
  final bool busy;
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
    Widget cell(String text, {Color color = primary, bool bold = false}) =>
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 12),
          child: Text(
            text,
            style: TextStyle(
              fontSize: 13,
              color: color,
              fontWeight: bold ? FontWeight.w600 : FontWeight.normal,
            ),
          ),
        );
    return LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: constraints.maxHeight),
          child: IntrinsicHeight(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(24, 18, 24, 22),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Wrap(
                    crossAxisAlignment: WrapCrossAlignment.center,
                    spacing: 10,
                    runSpacing: 4,
                    children: [
                      TextButton(
                        onPressed: onBack,
                        child: const Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.chevron_left, size: 18),
                            Text('返回'),
                          ],
                        ),
                      ),
                      const Text(
                        '线路详情',
                        style: TextStyle(
                          fontSize: 21,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        status.connected ? '● ${status.qualityLabel}' : '● 未连接',
                        style: TextStyle(
                          fontSize: 13,
                          color: status.connected && status.quality == 'good'
                              ? success
                              : muted,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text(
                    history ? '历史结果 · $updated' : updated,
                    style: const TextStyle(fontSize: 13, color: muted),
                  ),
                  const SizedBox(height: 16),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(10),
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        border: Border.all(color: border),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Table(
                        columnWidths: const {
                          0: FlexColumnWidth(1.35),
                          1: FlexColumnWidth(1),
                          2: FlexColumnWidth(.85),
                        },
                        defaultVerticalAlignment:
                            TableCellVerticalAlignment.middle,
                        border: const TableBorder(
                          horizontalInside: BorderSide(color: border),
                        ),
                        children: [
                          TableRow(
                            decoration: const BoxDecoration(
                              color: Color(0xfff7faf8),
                            ),
                            children: [
                              cell('目标', color: muted),
                              cell('延迟', color: muted),
                              cell('状态', color: muted),
                            ],
                          ),
                          for (final entry in targetNames.entries)
                            TableRow(
                              children: [
                                cell(entry.value, bold: true),
                                cell(
                                  results[entry.key]?.reachable == true
                                      ? '${results[entry.key]!.latencyMs} ms'
                                      : '—',
                                ),
                                cell(
                                  results[entry.key]?.health ?? '待测速',
                                  color: history
                                      ? muted
                                      : results[entry.key]?.health == '正常'
                                      ? success
                                      : results[entry.key]?.health == '异常' ||
                                            results[entry.key]?.health == '较慢'
                                      ? warning
                                      : muted,
                                ),
                              ],
                            ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  const Spacer(),
                  OutlinedButton(
                    onPressed: status.connected && !busy ? onProbe : null,
                    child: Text(busy ? '正在测速' : '立即测速'),
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
