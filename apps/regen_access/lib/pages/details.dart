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
    required this.onProbe,
  });
  final Status status;
  final DateTime now;
  final bool busy, polling;
  final VoidCallback onProbe;

  @override
  Widget build(BuildContext context) {
    final results = {
      for (final result in status.visibleResults) result.id: result,
    };
    final dates = results.values.map((result) => result.checkedAt).toList()
      ..sort();
    final seconds = dates.isEmpty
        ? null
        : now.difference(dates.last).inSeconds.clamp(0, 999999999);
    final updated = seconds == null
        ? '尚未测速'
        : seconds < 60
        ? '$seconds 秒前更新'
        : '${dates.last.toLocal().hour.toString().padLeft(2, '0')}:${dates.last.toLocal().minute.toString().padLeft(2, '0')} 更新';
    final historical =
        status.probeHistorical || (!status.connected && results.isNotEmpty);
    final entries = targetNames.entries.toList();
    final compact = MediaQuery.textScalerOf(context).scale(1) > 1.5;

    return ColoredBox(
      color: Colors.white,
      child: LayoutBuilder(
        builder: (context, constraints) => SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(12, 7, 12, 9),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: constraints.maxHeight - 16),
            child: IntrinsicHeight(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      const Text(
                        '线路详情',
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const Spacer(),
                      Flexible(
                        child: Text(
                          historical ? '历史结果 · $updated' : updated,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontSize: 9, color: muted),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 3),
                  if (compact)
                    for (var index = 0; index < entries.length; index++)
                      _TargetCell(
                        entry: entries[index],
                        result: results[entries[index].key],
                        historical: historical,
                        compact: true,
                      )
                  else
                    for (var row = 0; row < 4; row++)
                      Row(
                        key: Key('site-grid-row-$row'),
                        children: [
                          Expanded(
                            child: _TargetCell(
                              entry: entries[row * 2],
                              result: results[entries[row * 2].key],
                              historical: historical,
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: _TargetCell(
                              entry: entries[row * 2 + 1],
                              result: results[entries[row * 2 + 1].key],
                              historical: historical,
                            ),
                          ),
                        ],
                      ),
                  const Spacer(),
                  Wrap(
                    alignment: WrapAlignment.spaceBetween,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    spacing: 8,
                    runSpacing: 4,
                    children: [
                      const Text(
                        'HTTPS 首响应',
                        style: TextStyle(fontSize: 9, color: muted),
                      ),
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
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _TargetCell extends StatelessWidget {
  const _TargetCell({
    required this.entry,
    required this.result,
    required this.historical,
    this.compact = false,
  });
  final MapEntry<String, String> entry;
  final ProbeResult? result;
  final bool historical;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final health = result?.health ?? '待测速';
    final color = historical
        ? muted
        : health == '正常'
        ? success
        : health == '异常' || health == '较慢'
        ? warning
        : muted;
    return Container(
      constraints: BoxConstraints(minHeight: compact ? 52 : 33),
      decoration: const BoxDecoration(
        border: Border(bottom: BorderSide(color: border)),
      ),
      child: compact
          ? Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                nameAndHealth(entry.value, health, color),
                Align(alignment: Alignment.centerRight, child: latency()),
              ],
            )
          : Row(
              children: [
                Expanded(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        entry.value,
                        style: const TextStyle(
                          fontSize: 11,
                          height: 1,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                      Row(
                        children: [
                          Container(
                            width: 4,
                            height: 4,
                            decoration: BoxDecoration(
                              color: color,
                              shape: BoxShape.circle,
                            ),
                          ),
                          const SizedBox(width: 4),
                          Flexible(
                            child: Text(
                              health,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 9,
                                height: 1,
                                color: color,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                latency(),
              ],
            ),
    );
  }

  Widget nameAndHealth(String name, String health, Color color) => Column(
    mainAxisAlignment: MainAxisAlignment.center,
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        name,
        style: const TextStyle(
          fontSize: 11,
          height: 1,
          fontWeight: FontWeight.w500,
        ),
      ),
      Row(
        children: [
          Container(
            width: 4,
            height: 4,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 4),
          Flexible(
            child: Text(
              health,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontSize: 9, height: 1, color: color),
            ),
          ),
        ],
      ),
    ],
  );

  Widget latency() => Text(
    result?.reachable == true ? '${result!.latencyMs} ms' : '—',
    style: const TextStyle(fontSize: 12, color: primary),
  );
}
