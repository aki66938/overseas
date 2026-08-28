//go:build windows

package main

import (
	"context"
	"os"

	"corp.example/overseas-access-gateway/internal/clientapi"
	"github.com/lxn/walk"
)

const (
	windowTitle  = "RegenBio 海外访问"
	windowWidth  = 360
	windowHeight = 180
)

type walkClipboard struct{}

func (walkClipboard) SetText(value string) error {
	return walk.Clipboard().SetText(value)
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
	window, statusLabel, detailLabel, actionButton, diagnosticsButton, err := buildWindow()
	if err != nil {
		return err
	}
	applyState := func(state ViewState) {
		_ = statusLabel.SetText(state.StatusText)
		_ = detailLabel.SetText(state.DetailText)
		_ = actionButton.SetText(state.ButtonText)
		actionButton.SetEnabled(state.ButtonEnabled)
	}
	vm.SetOnChange(func(state ViewState) {
		window.Synchronize(func() {
			applyState(state)
		})
	})
	actionButton.Clicked().Attach(func() {
		go func() {
			_ = vm.Toggle(context.Background())
		}()
	})
	diagnosticsButton.Clicked().Attach(func() {
		go func() {
			if err := vm.CopyDiagnostics(context.Background()); err != nil {
				window.Synchronize(func() {
					walk.MsgBox(window, windowTitle, "诊断信息复制失败", walk.MsgBoxIconError)
				})
			}
		}()
	})
	window.Closing().Attach(func(_ *bool, _ walk.CloseReason) {
		vm.Close()
	})
	if err := vm.Refresh(context.Background()); err != nil {
		return err
	}
	vm.Start()
	defer vm.Close()
	window.SetMinMaxSize(walk.Size{Width: windowWidth, Height: windowHeight}, walk.Size{Width: windowWidth, Height: windowHeight})
	window.SetSize(walk.Size{Width: windowWidth, Height: windowHeight})
	window.Show()
	window.Run()
	return nil
}

func buildWindow() (*walk.MainWindow, *walk.TextLabel, *walk.TextLabel, *walk.PushButton, *walk.PushButton, error) {
	window, err := walk.NewMainWindow()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	window.SetTitle(windowTitle)
	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{HNear: 16, VNear: 16, HFar: 16, VFar: 16})
	layout.SetSpacing(10)
	if err := window.SetLayout(layout); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	titleLabel, err := walk.NewTextLabel(window)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_ = titleLabel.SetText(windowTitle)

	statusLabel, err := walk.NewTextLabel(window)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_ = statusLabel.SetText("未连接")

	detailLabel, err := walk.NewTextLabel(window)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_ = detailLabel.SetText("")

	actionButton, err := walk.NewPushButton(window)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_ = actionButton.SetText("开启海外访问")

	diagnosticsButton, err := walk.NewPushButton(window)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_ = diagnosticsButton.SetText("复制诊断信息")
	diagnosticsButton.SetEnabled(true)
	return window, statusLabel, detailLabel, actionButton, diagnosticsButton, nil
}
