#include "access_bridge.h"
#include <algorithm>
#include <array>
#include <utility>

namespace {
constexpr wchar_t kPipe[] = L"\\\\.\\pipe\\RegenBioOverseasAccess";
constexpr size_t kMaxFrame = 64 * 1024;
class Handle {
 public:
  explicit Handle(HANDLE value) : value_(value) {}
  ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
  HANDLE get() const { return value_; }
 private:
  HANDLE value_;
};

bool Valid(const std::string& action, const std::string& id) {
  return (action == "status" || action == "probe" || action == "connect" || action == "disconnect") &&
      id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
      });
}
DWORD Remaining(ULONGLONG deadline) {
  const auto now = GetTickCount64();
  return now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
}

// Overlapped storage remains alive until Windows confirms I/O completion,
// including cancellation. This cancels I/O only, never the service operation.
bool Transfer(HANDLE pipe, HANDLE stop, ULONGLONG deadline, bool writing,
              char* bytes, DWORD length, DWORD* transferred) {
  Handle event(CreateEvent(nullptr, TRUE, FALSE, nullptr));
  if (!event.get() || WaitForSingleObject(stop, 0) == WAIT_OBJECT_0 || !Remaining(deadline)) return false;
  OVERLAPPED overlapped{};
  overlapped.hEvent = event.get();
  BOOL ok = writing ? WriteFile(pipe, bytes, length, transferred, &overlapped)
                    : ReadFile(pipe, bytes, length, transferred, &overlapped);
  if (ok) return true;
  if (GetLastError() != ERROR_IO_PENDING) return false;
  HANDLE events[] = {event.get(), stop};
  const auto wait = WaitForMultipleObjects(2, events, FALSE, Remaining(deadline));
  if (wait != WAIT_OBJECT_0) {
    CancelIoEx(pipe, &overlapped);
    GetOverlappedResult(pipe, &overlapped, transferred, TRUE);
    return false;
  }
  return GetOverlappedResult(pipe, &overlapped, transferred, FALSE) != FALSE;
}

PipeReply Exchange(const std::wstring& endpoint, const std::string& action,
                   const std::string& id, HANDLE stop, DWORD timeout) {
  if (!Valid(action, id) || !stop || WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) return {{}, "pre_dispatch"};
  const auto deadline = GetTickCount64() + timeout;
  HANDLE raw = INVALID_HANDLE_VALUE;
  do {
    raw = CreateFile(endpoint.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (raw != INVALID_HANDLE_VALUE) break;
    if (GetLastError() != ERROR_PIPE_BUSY) return {{}, "pre_dispatch"};
    if (WaitForSingleObject(stop, std::min<DWORD>(25, Remaining(deadline))) != WAIT_TIMEOUT) return {{}, "pre_dispatch"};
  } while (Remaining(deadline));
  if (raw == INVALID_HANDLE_VALUE) return {{}, "pre_dispatch"};
  Handle pipe(raw);
  std::string request = "{\"version\":1,\"id\":\"" + id + "\",\"action\":\"" + action + "\"}\n";
  DWORD count = 0;
  // Once write is attempted, any loss is conservative uncertainty. Never
  // report a transport timeout as confirmed cancellation of a mutation.
  if (!Transfer(pipe.get(), stop, deadline, true, request.data(), static_cast<DWORD>(request.size()), &count) || count != request.size()) {
    return {{}, "transport_lost"};
  }
  std::string frame;
  std::array<char, 4096> bytes{};
  while (frame.size() < kMaxFrame) {
    if (!Transfer(pipe.get(), stop, deadline, false, bytes.data(),
        static_cast<DWORD>(std::min(bytes.size(), kMaxFrame - frame.size())), &count) || !count) return {{}, "transport_lost"};
    frame.append(bytes.data(), count);
    const auto newline = frame.find('\n');
    if (newline != std::string::npos) {
      if (newline != frame.size() - 1) return {{}, "transport_lost"};
      return {std::move(frame), {}};
    }
  }
  return {{}, "transport_lost"};
}
}  // namespace

PipeReply RequestAccessPipe(const std::string& action, const std::string& id, HANDLE stop) {
  const DWORD timeout = action == "connect" ? 130000 : action == "disconnect" ? 100000 : action == "probe" ? 10000 : 8000;
  return Exchange(kPipe, action, id, stop, timeout);
}
#ifdef REGEN_NATIVE_TEST
PipeReply ExchangePipeForTest(const std::wstring& endpoint, const std::string& action,
    const std::string& id, HANDLE stop, DWORD timeout) {
  return Exchange(endpoint, action, id, stop, timeout);
}
#else
AccessBridge::AccessBridge(HWND window, flutter::BinaryMessenger* messenger)
    : window_(window), stop_(CreateEvent(nullptr, TRUE, FALSE, nullptr)),
      channel_(messenger, "regen_access/access", &flutter::StandardMethodCodec::GetInstance()) {
  channel_.SetMethodCallHandler([this](const auto& call, auto result) {
    if (call.method_name() != "request") { result->NotImplemented(); return; }
    const auto* args = call.arguments() ? std::get_if<flutter::EncodableMap>(call.arguments()) : nullptr;
    if (!args || args->size() != 2) { result->Error("pre_dispatch"); return; }
    const auto action = args->find(flutter::EncodableValue("action"));
    const auto id = args->find(flutter::EncodableValue("id"));
    if (action == args->end() || id == args->end()) { result->Error("pre_dispatch"); return; }
    const auto* action_text = std::get_if<std::string>(&action->second);
    const auto* id_text = std::get_if<std::string>(&id->second);
    if (!action_text || !id_text || !Valid(*action_text, *id_text) || !stop_) { result->Error("pre_dispatch"); return; }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_ || outstanding_ >= 3) { result->Error("busy"); return; }
      ++outstanding_;
      pending_.push_back({*action_text, *id_text, std::move(result), {}});
    }
    ready_.notify_one();
  });
  worker_ = std::thread([this] { Run(); });
}

AccessBridge::~AccessBridge() {
  channel_.SetMethodCallHandler(nullptr);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
  }
  SetEvent(stop_);
  ready_.notify_one();
  worker_.join();
  // Posted notifications contain no object pointers. Drain before engine dies.
  MSG message;
  while (PeekMessage(&message, window_, kComplete, kComplete, PM_REMOVE)) {}
  completed_.clear();
  pending_.clear();
  if (stop_) CloseHandle(stop_);
}
void AccessBridge::Run() {
  while (true) {
    Work work;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      ready_.wait(lock, [this] { return stopping_ || !pending_.empty(); });
      if (stopping_) return;
      work = std::move(pending_.front());
      pending_.pop_front();
    }
    work.reply = RequestAccessPipe(work.action, work.id, stop_);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      completed_.push_back(std::move(work));
      if (stopping_) return;
      PostMessage(window_, kComplete, 0, 0);
    }
  }
}
void AccessBridge::Complete() {
  std::deque<Work> completed;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    completed.swap(completed_);
    outstanding_ -= completed.size();
  }
  for (auto& work : completed) {
    if (work.reply.error.empty()) work.result->Success(flutter::EncodableValue(work.reply.frame));
    else work.result->Error(work.reply.error);
  }
}
#endif
