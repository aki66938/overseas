//go:build windows

package main

import (
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

type logScrollState struct {
	follow bool
}

func newLogScrollState() logScrollState { return logScrollState{follow: true} }

func (s *logScrollState) observe(atBottom bool) { s.follow = atBottom }

func (s logScrollState) following() bool { return s.follow }

type logTextUpdater struct {
	scroll logScrollState
}

func newLogTextUpdater() *logTextUpdater {
	return &logTextUpdater{scroll: newLogScrollState()}
}

func (u *logTextUpdater) Apply(edit *walk.TextEdit, text string) {
	if edit == nil || edit.Text() == text {
		return
	}
	u.scroll.observe(textEditAtBottom(edit))
	selectionStart, selectionEnd := edit.TextSelection()
	firstVisible := int32(edit.SendMessage(win.EM_GETFIRSTVISIBLELINE, 0, 0))
	_ = edit.SetText(text)
	length := edit.TextLength()
	if u.scroll.following() {
		edit.SetTextSelection(length, length)
		edit.ScrollToCaret()
		return
	}
	selectionStart = clamp(selectionStart, 0, length)
	selectionEnd = clamp(selectionEnd, selectionStart, length)
	edit.SetTextSelection(selectionStart, selectionEnd)
	currentFirst := int32(edit.SendMessage(win.EM_GETFIRSTVISIBLELINE, 0, 0))
	delta := firstVisible - currentFirst
	if delta != 0 {
		edit.SendMessage(win.EM_LINESCROLL, 0, uintptr(delta))
	}
}

func textEditAtBottom(edit *walk.TextEdit) bool {
	info := win.SCROLLINFO{CbSize: uint32(unsafe.Sizeof(win.SCROLLINFO{})), FMask: win.SIF_PAGE | win.SIF_POS | win.SIF_RANGE}
	if !win.GetScrollInfo(edit.Handle(), win.SB_VERT, &info) {
		return true
	}
	if info.NMax <= info.NMin || info.NPage == 0 {
		return true
	}
	return info.NPos+int32(info.NPage) >= info.NMax
}

func clamp(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
