#include "../access_bridge.h"
#include "../tray_controller.h"
#include "../native_caption.h"
#include <iostream>
#include <thread>
#include <stdexcept>
#include <chrono>

int checks = 0;
void Check(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(what);
  ++checks;
}

int main() {
  try {
    const std::wstring name = L"\\\\.\\pipe\\RegenAccessIsolatedTest-" + std::to_wstring(GetCurrentProcessId());
    HANDLE stop = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    auto exchange = [&](std::string reply, DWORD timeout = 1000, bool stall = false, bool cancel = false) {
      HANDLE pipe = CreateNamedPipe(name.c_str(), PIPE_ACCESS_DUPLEX,
          PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, nullptr);
      Check(pipe != INVALID_HANDLE_VALUE, "create isolated pipe");
      bool request_valid = false;
      std::thread server([&] {
        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
          char input[512]; DWORD size = 0;
          ReadFile(pipe, input, sizeof(input), &size, nullptr);
          request_valid = std::string(input, size) == "{\"version\":1,\"id\":\"" + std::string(32, 'a') + "\",\"action\":\"status\"}\n";
          if (cancel) SetEvent(stop);
          if (stall) std::this_thread::sleep_for(std::chrono::milliseconds(150));
          else {
            // Deliberately fragment every response to test byte-mode framing.
            DWORD written = 0;
            WriteFile(pipe, reply.data(), 1, &written, nullptr);
            WriteFile(pipe, reply.data() + 1, static_cast<DWORD>(reply.size() - 1), &written, nullptr);
          }
        }
        CloseHandle(pipe);
      });
      auto result = ExchangePipeForTest(name, "status", std::string(32, 'a'), stop, timeout);
      server.join();
      Check(request_valid, "fixed native APIv1 request frame");
      ResetEvent(stop);
      return result;
    };
    auto good = exchange("{\"version\":1}\n");
    Check(good.error.empty() && good.frame == "{\"version\":1}\n", "fragmented frame");
    Check(exchange(std::string(65536, 'a') + "\n").error == "transport_lost", "bounded frame");
    Check(exchange("{}", 1000).error == "transport_lost", "missing newline");
    Check(exchange("{}\n", 25, true).error == "transport_lost", "post-dispatch timeout is uncertain");
    Check(exchange("{}\n", 1000, true, true).error == "transport_lost", "shutdown cancels pending read and joins safely");
    Check(ExchangePipeForTest(name, "status", std::string(32, 'a'), stop, 25).error == "pre_dispatch", "missing pipe is definite");
    Check(ExchangePipeForTest(name, "diagnostics", std::string(32, 'a'), stop, 25).error == "pre_dispatch", "unsupported action rejected");
    Check(ExchangePipeForTest(name, "status", "bad\"id", stop, 25).error == "pre_dispatch", "identity injection rejected");
    SetEvent(stop);
    Check(ExchangePipeForTest(name, "status", std::string(32, 'a'), stop, 25).error == "pre_dispatch", "stop before dispatch");
    CloseHandle(stop);

    HWND window = CreateWindowEx(0, L"STATIC", L"Regen shell isolated test", WS_OVERLAPPEDWINDOW,
        0, 0, 460, 540, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    Check(window != nullptr, "owned test window");
    {
      NativeCaption caption(window);
      TITLEBARINFOEX info{};
      info.cbSize = sizeof(info);
      LRESULT hit = 0;
      Check(caption.HandleMessage(WM_GETTITLEBARINFOEX, 0, reinterpret_cast<LPARAM>(&info), &hit), "caption exposes native accessibility geometry");
      Check((info.rgstate[3] & STATE_SYSTEM_INVISIBLE) != 0 && IsRectEmpty(&info.rgrect[3]), "maximize slot absent, not disabled");
      for (int index : {2, 5}) {
        const auto& rect = info.rgrect[index];
        Check(!IsRectEmpty(&rect) && info.rgstate[index] == 0, "minimize and close are visible and enabled");
        const LPARAM point = MAKELPARAM((rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2);
        Check(caption.HandleMessage(WM_NCHITTEST, 0, point, &hit) && hit == (index == 2 ? HTMINBUTTON : HTCLOSE), "native caption button hit regions");
      }
      Check(caption.HandleMessage(WM_SYSCOMMAND, SC_MAXIMIZE, 0, &hit), "maximize system command ignored");
    }
    int actions = 0;
    {
      TrayController tray(window, [&] { ++actions; });
      LRESULT value = 0;
      ShowWindow(window, SW_SHOWNOACTIVATE);
      Check(tray.HandleMessage(WM_CLOSE, 0, 0, &value) && !IsWindowVisible(window), "close hides");
      tray.Focus();
      Check(IsWindowVisible(window), "focus restores hidden window");
      ShowWindow(window, SW_MINIMIZE);
      Check(IsIconic(window) && IsWindowVisible(window), "minimize remains taskbar window");
      tray.Focus();
      Check(!IsIconic(window), "focus restores minimized window");
      Check(actions == 0, "hide and focus never disconnect");
      Check(tray.HandleMessage(RegisterWindowMessage(L"TaskbarCreated"), 0, 0, &value), "Explorer restart notification handled without restarting Explorer");
    }
    DestroyWindow(window);
    Check(StartupCommand(L"C:\\Program Files\\Regen\\regen_access.exe") ==
        L"\"C:\\Program Files\\Regen\\regen_access.exe\" --startup", "quoted UI-only startup command");
    std::cout << checks << " native assertions passed; isolated pipes and owned window only\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
