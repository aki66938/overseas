package main

import (
	"fmt"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

func formatTraceTimeline(events []traceevent.Event, gap, warning bool, location *time.Location) string {
	if location == nil {
		location = time.Local
	}
	var lines []string
	if gap {
		lines = append(lines, "[WARN] ! 部分早期日志已被内存缓冲覆盖，磁盘仍保留")
	}
	if warning {
		lines = append(lines, "[WARN] ! 日志通道暂不可用，正在重试")
	}
	seen := make(map[uint64]bool, len(events))
	var generation uint64
	haveGeneration := false
	for _, event := range events {
		if seen[event.Sequence] {
			continue
		}
		seen[event.Sequence] = true
		if !haveGeneration || event.Generation != generation {
			generation = event.Generation
			haveGeneration = true
			lines = append(lines, fmt.Sprintf("===== Generation %d =====", generation))
		}
		level := map[string]string{traceevent.LevelInfo: "INFO", traceevent.LevelWarning: "WARN", traceevent.LevelError: "ERROR"}[event.Level]
		symbol := map[string]string{traceevent.EventStarted: "→", traceevent.EventSucceeded: "✓", traceevent.EventFailed: "✕", traceevent.EventState: "!"}[event.Event]
		elapsed := ""
		if event.ElapsedMS != nil {
			elapsed = fmt.Sprintf(" (%d ms)", *event.ElapsedMS)
		}
		lines = append(lines, fmt.Sprintf("%s [%s] %s [%s] %s/%s%s %s",
			event.TimestampUTC.In(location).Format("15:04:05.000"), level, symbol,
			event.Component, event.Stage, event.Event, elapsed, event.Message))
		if event.Detail != "" {
			lines = append(lines, "    "+event.Detail)
		}
		if event.Residue != nil {
			lines = append(lines, fmt.Sprintf(
				"    residue: managed_rules=%d product_routes=%d product_tuns=%d core_processes=%d snapshot=%t snapshot_phase=%s",
				event.Residue.ManagedRules, event.Residue.ProductRoutes, event.Residue.ProductTUNs,
				event.Residue.CoreProcesses, event.Residue.Snapshot, event.Residue.SnapshotPhase))
		}
	}
	return strings.Join(lines, "\r\n")
}

func latestGeneration(events []traceevent.Event) uint64 {
	var generation uint64
	for _, event := range events {
		if event.Generation > generation {
			generation = event.Generation
		}
	}
	return generation
}

func generationSummary(events []traceevent.Event) string {
	if len(events) == 0 {
		return "Generation: —"
	}
	return fmt.Sprintf("Generation: %d", latestGeneration(events))
}

func stageSummary(events []traceevent.Event) string {
	if len(events) == 0 {
		return "当前阶段：等待操作"
	}
	event := events[len(events)-1]
	return fmt.Sprintf("当前阶段：%s / %s", event.Stage, event.Event)
}

func protectionSummary(events []traceevent.Event, status clientapi.Status) string {
	for index := len(events) - 1; index >= 0; index-- {
		residue := events[index].Residue
		if residue == nil {
			continue
		}
		if residue.IsZero() {
			return "防泄漏状态：无连接残留"
		}
		return fmt.Sprintf("防泄漏状态：%d 条规则；%d 路由；%d TUN；%d 核心进程；快照=%t（%s）",
			residue.ManagedRules, residue.ProductRoutes, residue.ProductTUNs, residue.CoreProcesses, residue.Snapshot, residue.SnapshotPhase)
	}
	if status.State == accessmodel.StateFailed {
		return "防泄漏状态：等待残留检查"
	}
	return "防泄漏状态：尚无残留摘要"
}
