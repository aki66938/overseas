#include "tray_controller.h"
#include <utility>
#include <vector>

namespace {
constexpr wchar_t kRunKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunName[] = L"RegenBioOverseasAccess";
HICON MakeIcon() {
  // App-owned simple R mark, drawn locally. No downloaded/generated scaffold.
  BITMAPINFO info{};
  info.bmiHeader = {sizeof(BITMAPINFOHEADER), 32, -32, 1, 32, BI_RGB, 0, 0, 0, 0, 0};
  void* bits = nullptr;
  HDC dc = CreateCompatibleDC(nullptr);
  HBITMAP color = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
  if (!dc || !color) { if (dc) DeleteDC(dc); return nullptr; }
  auto previous = SelectObject(dc, color);
  RECT box{0, 0, 32, 32};
  HBRUSH brush = CreateSolidBrush(RGB(0, 125, 117));
  FillRect(dc, &box, brush);
  DeleteObject(brush);
  SetBkMode(dc, TRANSPARENT);
  SetTextColor(dc, RGB(255, 255, 255));
  HFONT font = CreateFont(-25, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, L"Segoe UI");
  auto old_font = SelectObject(dc, font);
  DrawText(dc, L"R", 1, &box, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  SelectObject(dc, old_font);
  DeleteObject(font);
  for (size_t i = 0; i < 32 * 32; ++i) static_cast<DWORD*>(bits)[i] |= 0xff000000;
  SelectObject(dc, previous);
  DeleteDC(dc);
  const BYTE mask_bits[128] = {};
  HBITMAP mask = CreateBitmap(32, 32, 1, 1, mask_bits);
  ICONINFO icon_info{TRUE, 0, 0, mask, color};
  HICON icon = CreateIconIndirect(&icon_info);
  DeleteObject(mask);
  DeleteObject(color);
  return icon;
}
std::wstring Executable() {
  std::vector<wchar_t> path(32768);
  const auto length = GetModuleFileName(nullptr, path.data(), static_cast<DWORD>(path.size()));
  return length && length < path.size() ? std::wstring(path.data(), length) : L"";
}
}

std::wstring StartupCommand(const std::wstring& executable) {
  return executable.empty() ? L"" : L"\"" + executable + L"\" --startup";
}
TrayController::TrayController(HWND window, std::function<void()> action,
    std::function<void(bool)> navigate)
    : window_(window), icon_(MakeIcon()),
      taskbar_created_(RegisterWindowMessage(L"TaskbarCreated")),
      activate_(RegisterWindowMessage(kRegenActivateMessage)),
      action_(std::move(action)), navigate_(std::move(navigate)) {
  data_.cbSize = sizeof(data_);
  data_.hWnd = window_;
  data_.uID = 1;
  data_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  data_.uCallbackMessage = kCallback;
  data_.hIcon = icon_;
  wcscpy_s(data_.szTip, L"RegenBio 海外访问");
  SendMessage(window_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(icon_));
  SendMessage(window_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon_));
  Add();
}
TrayController::~TrayController() {
  Shell_NotifyIcon(NIM_DELETE, &data_);
  SendMessage(window_, WM_SETICON, ICON_BIG, 0);
  SendMessage(window_, WM_SETICON, ICON_SMALL, 0);
  if (icon_) DestroyIcon(icon_);
}
bool TrayController::Add() {
  added_ = Shell_NotifyIcon(NIM_ADD, &data_) != FALSE;
  if (added_) {
    data_.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIcon(NIM_SETVERSION, &data_);
  }
  return added_;
}
void TrayController::Update(const std::wstring& label, bool enabled,
    const std::wstring& summary, bool details) {
  label_ = label;
  summary_ = summary;
  enabled_ = enabled;
  details_ = details;
}
void TrayController::Focus() {
  ShowWindow(window_, IsIconic(window_) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(window_);
}
bool TrayController::HandleMessage(UINT message, WPARAM, LPARAM lparam, LRESULT* result) {
  *result = 0;
  if (message == activate_) { Focus(); return true; }
  if (message == taskbar_created_) { added_ = false; Add(); return true; }
  if (message == WM_CLOSE) {
    // Keep a visible escape hatch if Explorer is unavailable or add failed.
    if (!added_ && !Add()) return true;
    ShowWindow(window_, SW_HIDE);
    if (!hinted_) {
      hinted_ = true;
      data_.uFlags |= NIF_INFO;
      wcscpy_s(data_.szInfoTitle, L"RegenBio 海外访问");
      wcscpy_s(data_.szInfo, L"应用已收起到托盘，当前连接保持不变。");
      data_.dwInfoFlags = NIIF_INFO;
      Shell_NotifyIcon(NIM_MODIFY, &data_);
      data_.uFlags &= ~NIF_INFO;
    }
    return true;
  }
  if (message == kCallback) {
    const auto event = LOWORD(lparam);
    if (event == NIN_SELECT || event == NIN_KEYSELECT) Focus();
    if (event == WM_CONTEXTMENU) Menu();
    return true;
  }
  return false;
}
bool TrayController::StartupEnabled() const {
  wchar_t value[32768]{};
  DWORD bytes = sizeof(value);
  return RegGetValue(HKEY_CURRENT_USER, kRunKey, kRunName, RRF_RT_REG_SZ, nullptr,
      value, &bytes) == ERROR_SUCCESS && StartupCommand(Executable()) == value;
}
bool TrayController::SetStartup(bool enabled) {
  HKEY key = nullptr;
  if (RegCreateKeyEx(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0, KEY_SET_VALUE,
      nullptr, &key, nullptr) != ERROR_SUCCESS) return false;
  const auto command = StartupCommand(Executable());
  LSTATUS status = ERROR_INVALID_DATA;
  if (enabled && !command.empty()) status = RegSetValueEx(key, kRunName, 0, REG_SZ,
      reinterpret_cast<const BYTE*>(command.c_str()), static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
  else if (!enabled) status = RegDeleteValue(key, kRunName);
  RegCloseKey(key);
  return status == ERROR_SUCCESS || (!enabled && status == ERROR_FILE_NOT_FOUND);
}
void TrayController::Menu() {
  HMENU menu = CreatePopupMenu();
  if (!menu) return;
  AppendMenu(menu, MF_STRING | MF_GRAYED, 0, summary_.c_str());
  AppendMenu(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenu(menu, MF_STRING, 1, L"打开主窗口");
  AppendMenu(menu, MF_STRING | (details_ ? 0 : MF_GRAYED), 2, L"查看线路详情");
  AppendMenu(menu, MF_STRING | (enabled_ ? 0 : MF_GRAYED), 3, label_.c_str());
  AppendMenu(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenu(menu, MF_STRING | (StartupEnabled() ? MF_CHECKED : 0), 4, L"开机时启动");
  AppendMenu(menu, MF_STRING, 5, L"退出应用");
  POINT cursor{};
  GetCursorPos(&cursor);
  SetForegroundWindow(window_);
  const UINT selected = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
      cursor.x, cursor.y, 0, window_, nullptr);
  DestroyMenu(menu);
  PostMessage(window_, WM_NULL, 0, 0);
  if (selected == 1 || (selected == 2 && details_)) {
    if (navigate_) navigate_(selected == 2);
    Focus();
  } else if (selected == 3 && enabled_) {
    enabled_ = false;
    action_();
  } else if (selected == 4) {
    if (!SetStartup(!StartupEnabled())) MessageBox(window_, L"无法保存开机启动设置。", L"RegenBio 海外访问", MB_OK | MB_ICONINFORMATION);
  } else if (selected == 5) {
    // Destroy only this GUI. Neither service control nor disconnect is invoked.
    PostMessage(window_, kExit, 0, 0);
  }
}
