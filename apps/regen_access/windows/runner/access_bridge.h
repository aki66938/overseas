#ifndef REGEN_ACCESS_BRIDGE_H_
#define REGEN_ACCESS_BRIDGE_H_
#include <windows.h>
#include <string>

struct PipeReply { std::string frame; std::string error; };
// No endpoint can be supplied by Flutter or command-line arguments.
PipeReply RequestAccessPipe(const std::string& action, const std::string& id, HANDLE stop);
#ifdef REGEN_NATIVE_TEST
PipeReply ExchangePipeForTest(const std::wstring& endpoint, const std::string& action,
    const std::string& id, HANDLE stop, DWORD timeout);
#else
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

class AccessBridge {
 public:
  static constexpr UINT kComplete = WM_APP + 31;
  AccessBridge(HWND window, flutter::BinaryMessenger* messenger);
  ~AccessBridge();
  void Complete();
 private:
  using Result = flutter::MethodResult<flutter::EncodableValue>;
  struct Work {
    std::string action, id;
    std::unique_ptr<Result> result;
    PipeReply reply;
  };
  void Run();
  HWND window_;
  HANDLE stop_;
  bool stopping_ = false;
  size_t outstanding_ = 0;
  std::mutex mutex_;
  std::condition_variable ready_;
  std::deque<Work> pending_, completed_;
  std::thread worker_;
  flutter::MethodChannel<flutter::EncodableValue> channel_;
};
#endif
#endif
