#include "platform/frame_window.h"

#include <windowsx.h>

#include <algorithm>
#include <cstring>

namespace hicar {
namespace platform {
namespace {

constexpr const wchar_t* kWindowClass = L"HiCarProjectionWindow";

ATOM register_class(HINSTANCE instance) {
  static ATOM atom = 0;
  if (atom != 0) return atom;
  WNDCLASSEXW cls{};
  cls.cbSize = sizeof(cls);
  cls.style = CS_HREDRAW | CS_VREDRAW;
  cls.lpfnWndProc = FrameWindow::window_proc;
  cls.hInstance = instance;
  cls.hCursor = LoadCursor(nullptr, IDC_ARROW);
  cls.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
  cls.lpszClassName = kWindowClass;
  atom = RegisterClassExW(&cls);
  return atom;
}

int android_key(WPARAM key) {
  switch (key) {
    case VK_BACK:
    case VK_ESCAPE:
      return 4;
    case VK_HOME:
      return 3;
    case VK_UP:
      return 19;
    case VK_DOWN:
      return 20;
    case VK_LEFT:
      return 21;
    case VK_RIGHT:
      return 22;
    case VK_RETURN:
      return 23;
    case VK_VOLUME_UP:
      return 24;
    case VK_VOLUME_DOWN:
      return 25;
    case VK_MEDIA_PLAY_PAUSE:
      return 85;
    case VK_MEDIA_STOP:
      return 86;
    case VK_MEDIA_NEXT_TRACK:
      return 87;
    case VK_MEDIA_PREV_TRACK:
      return 88;
    default:
      return -1;
  }
}

}  // namespace

FrameWindow::FrameWindow() = default;

FrameWindow::~FrameWindow() { close(); }

bool FrameWindow::create(int width, int height, const std::string& title, std::string* error) {
  close();
  HINSTANCE instance = GetModuleHandleW(nullptr);
  if (register_class(instance) == 0) {
    if (error != nullptr) *error = "注册投屏窗口类失败";
    return false;
  }
  RECT rect{0, 0, width, height};
  AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW, FALSE);
  hwnd_ = CreateWindowExW(0, kWindowClass, std::wstring(title.begin(), title.end()).c_str(),
                          WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                          rect.right - rect.left, rect.bottom - rect.top, nullptr, nullptr, instance,
                          this);
  if (hwnd_ == nullptr) {
    if (error != nullptr) *error = "创建投屏窗口失败";
    return false;
  }
  SetWindowLongPtrW(hwnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
  ShowWindow(hwnd_, SW_SHOW);
  UpdateWindow(hwnd_);
  return true;
}

void FrameWindow::close() {
  if (hwnd_ != nullptr) {
    SetWindowLongPtrW(hwnd_, GWLP_USERDATA, 0);
    DestroyWindow(hwnd_);
    hwnd_ = nullptr;
  }
  frame_.clear();
}

void FrameWindow::set_sinks(TouchSink touch, KeySink key, CloseSink close) {
  touch_sink_ = std::move(touch);
  key_sink_ = std::move(key);
  close_sink_ = std::move(close);
}

void FrameWindow::set_frame(const uint8_t* bgra, int width, int height) {
  if (bgra == nullptr || width <= 0 || height <= 0) return;
  const size_t size = static_cast<size_t>(width) * height * 4;
  frame_.resize(size);
  std::memcpy(frame_.data(), bgra, size);
  video_width_ = width;
  video_height_ = height;
  if (hwnd_ != nullptr) InvalidateRect(hwnd_, nullptr, FALSE);
}

bool FrameWindow::map_point(int client_x, int client_y, int* x, int* y) const {
  if (video_width_ <= 0 || video_height_ <= 0) return false;
  RECT client{};
  GetClientRect(hwnd_, &client);
  const int cw = client.right - client.left;
  const int ch = client.bottom - client.top;
  if (cw <= 0 || ch <= 0) return false;
  const double scale = std::min(static_cast<double>(cw) / video_width_,
                                static_cast<double>(ch) / video_height_);
  const int draw_w = static_cast<int>(video_width_ * scale);
  const int draw_h = static_cast<int>(video_height_ * scale);
  const int off_x = (cw - draw_w) / 2;
  const int off_y = (ch - draw_h) / 2;
  if (client_x < off_x || client_y < off_y || client_x >= off_x + draw_w || client_y >= off_y + draw_h) {
    return false;
  }
  *x = static_cast<int>((client_x - off_x) * video_width_ / draw_w);
  *y = static_cast<int>((client_y - off_y) * video_height_ / draw_h);
  *x = std::clamp(*x, 0, video_width_ - 1);
  *y = std::clamp(*y, 0, video_height_ - 1);
  return true;
}

void FrameWindow::paint() {
  if (hwnd_ == nullptr) return;
  PAINTSTRUCT ps{};
  HDC dc = BeginPaint(hwnd_, &ps);
  RECT client{};
  GetClientRect(hwnd_, &client);
  FillRect(dc, &client, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
  if (!frame_.empty() && video_width_ > 0 && video_height_ > 0) {
    const int cw = client.right;
    const int ch = client.bottom;
    const double scale = std::min(static_cast<double>(cw) / video_width_,
                                  static_cast<double>(ch) / video_height_);
    const int draw_w = static_cast<int>(video_width_ * scale);
    const int draw_h = static_cast<int>(video_height_ * scale);
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = video_width_;
    info.bmiHeader.biHeight = -video_height_;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(dc, HALFTONE);
    SetBrushOrgEx(dc, 0, 0, nullptr);
    StretchDIBits(dc, (cw - draw_w) / 2, (ch - draw_h) / 2, draw_w, draw_h, 0, 0, video_width_,
                  video_height_, frame_.data(), &info, DIB_RGB_COLORS, SRCCOPY);
  }
  EndPaint(hwnd_, &ps);
}

LRESULT CALLBACK FrameWindow::window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
  FrameWindow* self = reinterpret_cast<FrameWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (self != nullptr) return self->handle_message(message, wparam, lparam);
  return DefWindowProcW(hwnd, message, wparam, lparam);
}

LRESULT FrameWindow::handle_message(UINT message, WPARAM wparam, LPARAM lparam) {
  switch (message) {
    case WM_PAINT:
      paint();
      return 0;
    case WM_LBUTTONDOWN: {
      int x = 0;
      int y = 0;
      if (map_point(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam), &x, &y)) {
        mouse_down_ = true;
        last_x_ = x;
        last_y_ = y;
        SetCapture(hwnd_);
        if (touch_sink_) touch_sink_(0, 0, x, y);
      }
      return 0;
    }
    case WM_MOUSEMOVE:
      if (mouse_down_) {
        int x = 0;
        int y = 0;
        if (map_point(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam), &x, &y) &&
            (x != last_x_ || y != last_y_)) {
          last_x_ = x;
          last_y_ = y;
          if (touch_sink_) touch_sink_(2, 0, x, y);
        }
      }
      return 0;
    case WM_LBUTTONUP:
      if (mouse_down_) {
        int x = last_x_;
        int y = last_y_;
        map_point(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam), &x, &y);
        mouse_down_ = false;
        ReleaseCapture();
        if (touch_sink_) touch_sink_(1, 0, x, y);
      }
      return 0;
    case WM_KEYDOWN:
    case WM_KEYUP: {
      const int code = android_key(wparam);
      if (code >= 0 && key_sink_) {
        if (message == WM_KEYUP || (lparam & (1LL << 30)) == 0) {
          key_sink_(message == WM_KEYDOWN, code);
        }
      }
      return 0;
    }
    case WM_APPCOMMAND: {
      const int command = GET_APPCOMMAND_LPARAM(lparam);
      int code = -1;
      if (command == APPCOMMAND_MEDIA_PLAY_PAUSE) code = 85;
      else if (command == APPCOMMAND_MEDIA_STOP) code = 86;
      else if (command == APPCOMMAND_MEDIA_NEXTTRACK) code = 87;
      else if (command == APPCOMMAND_MEDIA_PREVIOUSTRACK) code = 88;
      else if (command == APPCOMMAND_VOLUME_UP) code = 24;
      else if (command == APPCOMMAND_VOLUME_DOWN) code = 25;
      if (code >= 0 && key_sink_) {
        key_sink_(true, code);
        key_sink_(false, code);
      }
      return 0;
    }
    case WM_CLOSE:
      if (close_sink_) close_sink_();
      return 0;
    case WM_DESTROY:
      hwnd_ = nullptr;
      return 0;
    default:
      return DefWindowProcW(hwnd_, message, wparam, lparam);
  }
}

void FrameWindow::pump() {
  if (hwnd_ == nullptr) return;
  MSG msg{};
  while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
}

}  // namespace platform
}  // namespace hicar
