#include "native_caption.h"
#include <dwmapi.h>
#include <windowsx.h>
#include <algorithm>

NativeCaption::NativeCaption(HWND window) : window_(window) {
  const DWMNCRENDERINGPOLICY policy = DWMNCRP_DISABLED;
  DwmSetWindowAttribute(window_, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));
  HMENU system = GetSystemMenu(window_, FALSE);
  DeleteMenu(system, SC_MAXIMIZE, MF_BYCOMMAND);
  DeleteMenu(system, SC_SIZE, MF_BYCOMMAND);
}
TITLEBARINFOEX NativeCaption::Geometry() const {
  TITLEBARINFOEX info{};
  info.cbSize = sizeof(info);
  RECT window{};
  GetWindowRect(window_, &window);
  POINT client{};
  ClientToScreen(window_, &client);
  const int dpi = static_cast<int>(GetDpiForWindow(window_));
  const int border = std::max(1, static_cast<int>(client.x - window.left));
  info.rcTitleBar = {window.left + border, window.top + border,
      window.right - border, client.y};
  const int button = MulDiv(46, dpi, 96);
  info.rgrect[5] = {info.rcTitleBar.right - button, info.rcTitleBar.top,
      info.rcTitleBar.right, info.rcTitleBar.bottom};
  info.rgrect[2] = info.rgrect[5];
  OffsetRect(&info.rgrect[2], -button, 0);
  info.rgstate[1] = STATE_SYSTEM_INVISIBLE;
  info.rgstate[3] = STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_UNAVAILABLE;
  info.rgstate[4] = STATE_SYSTEM_INVISIBLE;
  return info;
}
LRESULT NativeCaption::Hit(POINT screen) const {
  const auto geometry = Geometry();
  if (PtInRect(&geometry.rgrect[5], screen)) return HTCLOSE;
  if (PtInRect(&geometry.rgrect[2], screen)) return HTMINBUTTON;
  if (PtInRect(&geometry.rcTitleBar, screen)) return HTCAPTION;
  return HTNOWHERE;
}
void NativeCaption::Paint() {
  if (IsIconic(window_)) return;
  HDC dc = GetWindowDC(window_);
  if (!dc) return;
  const auto geometry = Geometry();
  RECT screen{};
  GetWindowRect(window_, &screen);
  RECT client{};
  GetClientRect(window_, &client);
  MapWindowPoints(window_, nullptr, reinterpret_cast<POINT*>(&client), 2);
  OffsetRect(&client, -screen.left, -screen.top);
  ExcludeClipRect(dc, client.left, client.top, client.right, client.bottom);
  RECT outer{0, 0, screen.right - screen.left, screen.bottom - screen.top};
  FillRect(dc, &outer, GetSysColorBrush(COLOR_WINDOW));
  FrameRect(dc, &outer, GetSysColorBrush(COLOR_3DSHADOW));
  RECT title = geometry.rcTitleBar;
  OffsetRect(&title, -screen.left, -screen.top);
  const UINT dpi = GetDpiForWindow(window_);
  const auto scale = [dpi](int value) { return MulDiv(value, static_cast<int>(dpi), 96); };
  HICON icon = reinterpret_cast<HICON>(SendMessage(window_, WM_GETICON, ICON_SMALL, 0));
  if (icon) DrawIconEx(dc, title.left + scale(7), title.top + (title.bottom - title.top - scale(16)) / 2,
      icon, scale(16), scale(16), 0, nullptr, DI_NORMAL);
  NONCLIENTMETRICS metrics{};
  metrics.cbSize = sizeof(metrics);
  SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, dpi);
  HFONT font = CreateFontIndirect(&metrics.lfCaptionFont);
  auto old_font = SelectObject(dc, font);
  SetTextColor(dc, GetSysColor(active_ ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT));
  SetBkMode(dc, TRANSPARENT);
  wchar_t text[128]{};
  GetWindowText(window_, text, 128);
  RECT text_rect = title;
  text_rect.left += scale(30);
  text_rect.right = geometry.rgrect[2].left - screen.left - scale(4);
  DrawText(dc, text, -1, &text_rect, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
  SelectObject(dc, old_font);
  DeleteObject(font);
  for (int index : {2, 5}) {
    RECT button = geometry.rgrect[index];
    OffsetRect(&button, -screen.left, -screen.top);
    const int hit = index == 5 ? HTCLOSE : HTMINBUTTON;
    const bool highlight = hover_ == hit;
    if (highlight) {
      HBRUSH background = CreateSolidBrush(index == 5 ? RGB(196, 43, 28) : RGB(230, 230, 230));
      FillRect(dc, &button, background);
      DeleteObject(background);
    }
    HPEN pen = CreatePen(PS_SOLID, std::max(1, scale(1)),
        highlight && index == 5 ? RGB(255, 255, 255) : GetSysColor(COLOR_WINDOWTEXT));
    auto old_pen = SelectObject(dc, pen);
    const int x = (button.left + button.right) / 2;
    const int y = (button.top + button.bottom) / 2;
    const int radius = scale(5);
    if (index == 5) {
      MoveToEx(dc, x - radius, y - radius, nullptr);
      LineTo(dc, x + radius, y + radius);
      MoveToEx(dc, x + radius, y - radius, nullptr);
      LineTo(dc, x - radius, y + radius);
    } else {
      MoveToEx(dc, x - radius, y, nullptr);
      LineTo(dc, x + radius, y);
    }
    SelectObject(dc, old_pen);
    DeleteObject(pen);
  }
  ReleaseDC(window_, dc);
}
bool NativeCaption::HandleMessage(UINT message, WPARAM wparam, LPARAM lparam, LRESULT* result) {
  *result = 0;
  switch (message) {
    case WM_GETTITLEBARINFOEX: {
      auto* info = reinterpret_cast<TITLEBARINFOEX*>(lparam);
      if (info && info->cbSize == sizeof(TITLEBARINFOEX)) *info = Geometry();
      return true;
    }
    case WM_NCPAINT: Paint(); return true;
    case WM_NCACTIVATE:
      active_ = wparam != 0;
      Paint();
      *result = TRUE;
      return true;
    case WM_NCHITTEST:
      *result = Hit({GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)});
      return *result != HTNOWHERE;
    case WM_NCLBUTTONDBLCLK:
      if (wparam == HTCAPTION || wparam == HTMINBUTTON || wparam == HTCLOSE) return true;
      break;
    case WM_SYSCOMMAND:
      if ((wparam & 0xfff0) == SC_MAXIMIZE || (wparam & 0xfff0) == SC_SIZE) return true;
      break;
    case WM_NCMOUSEMOVE: {
      hover_ = static_cast<int>(wparam);
      TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE | TME_NONCLIENT, window_, 0};
      TrackMouseEvent(&track);
      Paint();
      return true;
    }
    case WM_NCMOUSELEAVE: hover_ = 0; Paint(); return true;
    case WM_NCLBUTTONDOWN:
      if (wparam == HTMINBUTTON || wparam == HTCLOSE) {
        pressed_ = static_cast<int>(wparam);
        hover_ = pressed_;
        SetCapture(window_);
        Paint();
        return true;
      }
      break;
    case WM_MOUSEMOVE:
      if (pressed_) {
        POINT point{};
        GetCursorPos(&point);
        hover_ = static_cast<int>(Hit(point));
        Paint();
        return true;
      }
      break;
    case WM_LBUTTONUP:
      if (pressed_) {
        POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
        ClientToScreen(window_, &point);
        const auto hit = Hit(point);
        const bool invoke = hit == pressed_;
        pressed_ = 0;
        ReleaseCapture();
        Paint();
        if (invoke) PostMessage(window_, WM_SYSCOMMAND, hit == HTCLOSE ? SC_CLOSE : SC_MINIMIZE, 0);
        return true;
      }
      break;
    case WM_CAPTURECHANGED: pressed_ = 0; hover_ = 0; Paint(); break;
    case WM_SETTEXT:
    case WM_SETICON:
      *result = DefWindowProc(window_, message, wparam, lparam);
      Paint();
      return true;
  }
  return false;
}
