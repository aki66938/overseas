#include "flutter_window.h"

#include <optional>

#include "flutter/generated_plugin_registrant.h"

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  RegisterPlugins(flutter_controller_->engine());
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  auto messenger = flutter_controller_->engine()->messenger();
  caption_ = std::make_unique<NativeCaption>(GetHandle());
  access_bridge_ = std::make_unique<AccessBridge>(GetHandle(), messenger);
  shell_ = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      messenger, "regen_access/shell", &flutter::StandardMethodCodec::GetInstance());
  tray_ = std::make_unique<TrayController>(GetHandle(), [this](const std::string& intent) {
    shell_->InvokeMethod("action", std::make_unique<flutter::EncodableValue>(intent));
  }, [this](bool details) {
    shell_->InvokeMethod(details ? "details" : "home", nullptr);
  });
  shell_->SetMethodCallHandler([this](const auto& call, auto result) {
    if (call.method_name() != "update") { result->NotImplemented(); return; }
    const auto* args = call.arguments() ? std::get_if<flutter::EncodableMap>(call.arguments()) : nullptr;
    if (!args || args->size() != 5) { result->Error("invalid_state"); return; }
    const auto label = args->find(flutter::EncodableValue("label"));
    const auto summary = args->find(flutter::EncodableValue("summary"));
    const auto enabled = args->find(flutter::EncodableValue("enabled"));
    const auto details = args->find(flutter::EncodableValue("details"));
    const auto action = args->find(flutter::EncodableValue("action"));
    if (label == args->end() || summary == args->end() || enabled == args->end() || details == args->end() || action == args->end()) {
      result->Error("invalid_state"); return;
    }
    const auto* text = std::get_if<std::string>(&label->second);
    const auto* status = std::get_if<std::string>(&summary->second);
    const auto* action_enabled = std::get_if<bool>(&enabled->second);
    const auto* details_enabled = std::get_if<bool>(&details->second);
    const auto* intent = std::get_if<std::string>(&action->second);
    if (!text || !status || !action_enabled || !details_enabled || !intent ||
        (*intent != "" && *intent != "connect" && *intent != "disconnect" && *intent != "restore") ||
        text->size() > 128 || status->size() > 256) {
      result->Error("invalid_state"); return;
    }
    const auto wide = [](const std::string& value) {
      const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
      std::wstring output(size, L'\0');
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), size);
      return output;
    };
    tray_->Update(wide(*text), *action_enabled, wide(*status), *details_enabled, *intent);
    result->Success();
  });

  flutter_controller_->engine()->SetNextFrameCallback([&]() {
    this->Show();
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::OnDestroy() {
  // Stop worker and destroy method results while the engine still exists.
  access_bridge_.reset();
  tray_.reset();
  caption_.reset();
  if (shell_) shell_->SetMethodCallHandler(nullptr);
  shell_.reset();
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  if (message == AccessBridge::kComplete && access_bridge_) {
    access_bridge_->Complete();
    return 0;
  }
  if (message == TrayController::kExit) { DestroyWindow(hwnd); return 0; }
  LRESULT handled = 0;
  if (tray_ && tray_->HandleMessage(message, wparam, lparam, &handled)) return handled;
  if (caption_ && caption_->HandleMessage(message, wparam, lparam, &handled)) return handled;
  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_FONTCHANGE:
      if (flutter_controller_) flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}
