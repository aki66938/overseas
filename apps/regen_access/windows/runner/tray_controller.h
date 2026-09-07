#ifndef REGEN_TRAY_CONTROLLER_H_
#define REGEN_TRAY_CONTROLLER_H_
#include <windows.h>
#include <shellapi.h>
#include <functional>
#include <string>

inline constexpr wchar_t kRegenWindowClass[] = L"RegenBioOverseasAccessFlutterWindow";
inline constexpr wchar_t kRegenActivateMessage[] = L"RegenBioOverseasAccess.Activate";
std::wstring StartupCommand(const std::wstring& executable);

class TrayController {
 public:
  static constexpr UINT kCallback = WM_APP + 32;
  static constexpr UINT kExit = WM_APP + 33;
  TrayController(HWND window, std::function<void()> action,
                 std::function<void(bool)> navigate = {});
  ~TrayController();
  void Update(const std::wstring& label, bool enabled,
              const std::wstring& summary, bool details);
  void Focus();
  bool HandleMessage(UINT message, WPARAM wparam, LPARAM lparam, LRESULT* result);
 private:
  bool Add();
  void Menu();
  bool StartupEnabled() const;
  bool SetStartup(bool enabled);
  HWND window_;
  HICON icon_;
  NOTIFYICONDATA data_{};
  UINT taskbar_created_, activate_;
  bool added_ = false, hinted_ = false, enabled_ = false, details_ = false;
  std::wstring label_ = L"服务暂不可用", summary_ = L"正在读取状态";
  std::function<void()> action_;
  std::function<void(bool)> navigate_;
};
#endif
