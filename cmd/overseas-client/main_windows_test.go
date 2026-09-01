//go:build windows

package main

import "testing"

func TestBuildWindowHasDefaultExpandedDebugControls(t *testing.T) {
	controls, err := buildWindow()
	if err != nil {
		t.Fatal(err)
	}
	defer controls.window.Dispose()
	if windowWidth != 820 || windowHeight != 620 {
		t.Fatalf("window size constants = %dx%d", windowWidth, windowHeight)
	}
	if !controls.logEdit.ReadOnly() {
		t.Fatal("log control is editable")
	}
	if controls.primaryButton.Text() != "开启海外访问" || controls.restoreButton.Text() != "仅恢复网络" || controls.copyButton.Text() != "复制全部日志" {
		t.Fatalf("button labels = %q %q %q", controls.primaryButton.Text(), controls.restoreButton.Text(), controls.copyButton.Text())
	}
	if controls.generationLabel == nil || controls.stageLabel == nil || controls.protectionLabel == nil || controls.logEdit == nil {
		t.Fatal("debug summary or log control is missing")
	}
	if min := controls.window.MinSize(); min.Width != windowWidth || min.Height != windowHeight {
		t.Fatalf("minimum window size = %#v", min)
	}
}

func TestLogScrollStatePausesAndResumesFollowing(t *testing.T) {
	state := newLogScrollState()
	if !state.following() {
		t.Fatal("new log view does not follow")
	}
	state.observe(false)
	if state.following() {
		t.Fatal("scroll-up did not pause following")
	}
	state.observe(false)
	if state.following() {
		t.Fatal("new text resumed following while user remained above bottom")
	}
	state.observe(true)
	if !state.following() {
		t.Fatal("returning to bottom did not resume following")
	}
}
