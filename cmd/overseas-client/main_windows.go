//go:build windows

package main

import (
	"context"
	"os"

	"corp.example/overseas-access-gateway/internal/clientapi"
	"github.com/lxn/walk"
	"github.com/lxn/win"
)

const (
	windowTitle  = "RegenBio 海外访问"
	windowWidth  = 820
	windowHeight = 620
)

type walkClipboard struct{}

func (walkClipboard) SetText(value string) error { return walk.Clipboard().SetText(value) }

type windowControls struct {
	window          *walk.MainWindow
	statusLabel     *walk.TextLabel
	detailLabel     *walk.TextLabel
	generationLabel *walk.TextLabel
	stageLabel      *walk.TextLabel
	protectionLabel *walk.TextLabel
	logEdit         *walk.TextEdit
	primaryButton   *walk.PushButton
	restoreButton   *walk.PushButton
	copyButton      *walk.PushButton
}

func main() {
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString("overseas-client failed to start\n")
		os.Exit(1)
	}
}

func run() error {
	client := clientapi.New()
	vm := NewViewModel(client, walkClipboard{})
	controls, err := buildWindow()
	if err != nil {
		return err
	}
	logUpdater := newLogTextUpdater()
	applyState := func(state ViewState) {
		_ = controls.statusLabel.SetText(state.StatusText)
		_ = controls.detailLabel.SetText(state.DetailText)
		_ = controls.generationLabel.SetText(state.GenerationText)
		_ = controls.stageLabel.SetText(state.StageText)
		_ = controls.protectionLabel.SetText(state.ProtectionText)
		logUpdater.Apply(controls.logEdit, state.LogText)
		_ = controls.primaryButton.SetText(state.PrimaryButtonText)
		controls.primaryButton.SetEnabled(state.PrimaryEnabled)
		controls.restoreButton.SetEnabled(state.RestoreEnabled)
		controls.copyButton.SetEnabled(state.CopyEnabled)
	}
	vm.SetOnChange(func(state ViewState) {
		controls.window.Synchronize(func() { applyState(state) })
	})
	controls.primaryButton.Clicked().Attach(func() {
		go func() { _ = vm.Toggle(context.Background()) }()
	})
	controls.restoreButton.Clicked().Attach(func() {
		go func() { _ = vm.Restore(context.Background()) }()
	})
	controls.copyButton.Clicked().Attach(func() {
		go func() {
			if err := vm.CopyLogs(); err != nil {
				controls.window.Synchronize(func() {
					walk.MsgBox(controls.window, windowTitle, "日志复制失败", walk.MsgBoxIconError)
				})
			}
		}()
	})
	controls.window.Closing().Attach(func(_ *bool, _ walk.CloseReason) {
		vm.SetOnChange(nil)
		vm.Close()
	})
	if err := vm.Refresh(context.Background()); err != nil {
		return err
	}
	_ = vm.RefreshTrace(context.Background())
	vm.Start()
	defer vm.Close()
	controls.window.Show()
	controls.window.Run()
	return nil
}

func buildWindow() (*windowControls, error) {
	window, err := walk.NewMainWindow()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*windowControls, error) {
		window.Dispose()
		return nil, err
	}
	window.SetTitle(windowTitle)
	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{HNear: 16, VNear: 16, HFar: 16, VFar: 16})
	layout.SetSpacing(8)
	if err := window.SetLayout(layout); err != nil {
		return fail(err)
	}
	if err := window.SetMinMaxSize(walk.Size{Width: windowWidth, Height: windowHeight}, walk.Size{}); err != nil {
		return fail(err)
	}
	if err := window.SetSize(walk.Size{Width: windowWidth, Height: windowHeight}); err != nil {
		return fail(err)
	}

	titleLabel, err := newTextLabel(window, windowTitle)
	if err != nil {
		return fail(err)
	}
	titleFont, err := walk.NewFont("Segoe UI", 11, walk.FontBold)
	if err != nil {
		return fail(err)
	}
	titleLabel.SetFont(titleFont)
	window.Disposing().Attach(func() { titleFont.Dispose() })

	statusLabel, err := newTextLabel(window, "未连接")
	if err != nil {
		return fail(err)
	}
	detailLabel, err := newTextLabel(window, "")
	if err != nil {
		return fail(err)
	}
	generationLabel, err := newTextLabel(window, "Generation: —")
	if err != nil {
		return fail(err)
	}
	stageLabel, err := newTextLabel(window, "当前阶段：等待操作")
	if err != nil {
		return fail(err)
	}
	protectionLabel, err := newTextLabel(window, "防泄漏状态：尚无残留摘要")
	if err != nil {
		return fail(err)
	}

	logEdit, err := walk.NewTextEditWithStyle(window, win.WS_VSCROLL|win.WS_HSCROLL|win.ES_AUTOVSCROLL|win.ES_AUTOHSCROLL)
	if err != nil {
		return fail(err)
	}
	if err := logEdit.SetReadOnly(true); err != nil {
		return fail(err)
	}
	logEdit.SetMaxLength(4 * 1024 * 1024)
	logFont, err := walk.NewFont("Consolas", 9, 0)
	if err != nil {
		return fail(err)
	}
	logEdit.SetFont(logFont)
	window.Disposing().Attach(func() { logFont.Dispose() })
	if err := layout.SetStretchFactor(logEdit, 10); err != nil {
		return fail(err)
	}

	buttonRow, err := walk.NewComposite(window)
	if err != nil {
		return fail(err)
	}
	buttonLayout := walk.NewHBoxLayout()
	buttonLayout.SetMargins(walk.Margins{})
	buttonLayout.SetSpacing(8)
	if err := buttonRow.SetLayout(buttonLayout); err != nil {
		return fail(err)
	}
	primaryButton, err := newButton(buttonRow, "开启海外访问")
	if err != nil {
		return fail(err)
	}
	restoreButton, err := newButton(buttonRow, "仅恢复网络")
	if err != nil {
		return fail(err)
	}
	copyButton, err := newButton(buttonRow, "复制全部日志")
	if err != nil {
		return fail(err)
	}
	restoreButton.SetEnabled(false)
	copyButton.SetEnabled(false)
	for _, button := range []*walk.PushButton{primaryButton, restoreButton, copyButton} {
		if err := buttonLayout.SetStretchFactor(button, 1); err != nil {
			return fail(err)
		}
	}

	return &windowControls{
		window: window, statusLabel: statusLabel, detailLabel: detailLabel,
		generationLabel: generationLabel, stageLabel: stageLabel, protectionLabel: protectionLabel,
		logEdit: logEdit, primaryButton: primaryButton, restoreButton: restoreButton, copyButton: copyButton,
	}, nil
}

func newTextLabel(parent walk.Container, text string) (*walk.TextLabel, error) {
	label, err := walk.NewTextLabel(parent)
	if err != nil {
		return nil, err
	}
	if err := label.SetText(text); err != nil {
		return nil, err
	}
	return label, nil
}

func newButton(parent walk.Container, text string) (*walk.PushButton, error) {
	button, err := walk.NewPushButton(parent)
	if err != nil {
		return nil, err
	}
	if err := button.SetText(text); err != nil {
		return nil, err
	}
	return button, nil
}
