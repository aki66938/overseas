#ifndef REGEN_NATIVE_CAPTION_H_
#define REGEN_NATIVE_CAPTION_H_
#include <windows.h>

// Keep the Windows nonclient geometry and system commands, but omit the
// disabled maximize slot that Windows otherwise draws next to minimize.
class NativeCaption {
 public:
  explicit NativeCaption(HWND window);
  bool HandleMessage(UINT message, WPARAM wparam, LPARAM lparam, LRESULT* result);
 private:
  TITLEBARINFOEX Geometry() const;
  LRESULT Hit(POINT screen) const;
  void Paint();
  HWND window_;
  int hover_ = 0, pressed_ = 0;
  bool active_ = true;
};
#endif
