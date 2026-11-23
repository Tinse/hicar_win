#include "platform/frame_window.h"

#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <string>

namespace hicar {
namespace platform {
namespace {

constexpr const wchar_t* kWindowClass = L"HiCarProjectionWindow";

std::wstring utf8_to_wide(const std::string& text) {
  if (text.empty()) return {};
  const int chars = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring out(static_cast<size_t>(chars), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), chars);
  return out;
}

ATOM register_class(HINSTANCE instance) {  static ATOM atom = 0;
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
  hwnd_ = CreateWindowExW(0, kWindowClass, utf8_to_wide(title).c_str(),
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
  release_backbuffer();
  if (hwnd_ != nullptr) {
    SetWindowLongPtrW(hwnd_, GWLP_USERDATA, 0);
    DestroyWindow(hwnd_);
    hwnd_ = nullptr;
  }
  {
    std::lock_guard<std::mutex> lock(frame_mutex_);
    frame_.clear();
  }
  video_width_ = 0;
  video_height_ = 0;
}

void FrameWindow::release_backbuffer() {
  if (back_dc_ != nullptr) {
    if (old_back_bitmap_ != nullptr) SelectObject(back_dc_, old_back_bitmap_);
    DeleteDC(back_dc_);
    back_dc_ = nullptr;
    old_back_bitmap_ = nullptr;
  }
  if (back_bitmap_ != nullptr) {
    DeleteObject(back_bitmap_);
    back_bitmap_ = nullptr;
  }
  back_width_ = 0;
  back_height_ = 0;
}

bool FrameWindow::ensure_backbuffer(HDC dc, int width, int height) {
  if (dc == nullptr || width <= 0 || height <= 0) return false;
  if (back_dc_ != nullptr && back_width_ == width && back_height_ == height) return true;
  release_backbuffer();
  back_dc_ = CreateCompatibleDC(dc);
  if (back_dc_ == nullptr) return false;
  back_bitmap_ = CreateCompatibleBitmap(dc, width, height);
  if (back_bitmap_ == nullptr) {
    DeleteDC(back_dc_);
    back_dc_ = nullptr;
    return false;
  }
  old_back_bitmap_ = static_cast<HBITMAP>(SelectObject(back_dc_, back_bitmap_));
  back_width_ = width;
  back_height_ = height;
  SetStretchBltMode(back_dc_, HALFTONE);
  SetBrushOrgEx(back_dc_, 0, 0, nullptr);
  return true;
}

void FrameWindow::set_sinks(TouchSink touch, KeySink key, CloseSink close) {
  touch_sink_ = std::move(touch);
  key_sink_ = std::move(key);
  close_sink_ = std::move(close);
}

void FrameWindow::set_frame(const uint8_t* bgra, int width, int height) {
  if (bgra == nullptr || width <= 0 || height <= 0) return;
  const size_t size = static_cast<size_t>(width) * height * 4;
  {
    std::lock_guard<std::mutex> lock(frame_mutex_);
    frame_.resize(size);
    std::memcpy(frame_.data(), bgra, size);
    video_width_ = width;
    video_height_ = height;
  }
  if (hwnd_ != nullptr) InvalidateRect(hwnd_, nullptr, FALSE);
}

bool FrameWindow::map_point(int client_x, int client_y, int* x, int* y) const {
  std::lock_guard<std::mutex> lock(frame_mutex_);
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
  const int cw = client.right - client.left;
  const int ch = client.bottom - client.top;
  if (cw <= 0 || ch <= 0) {
    EndPaint(hwnd_, &ps);
    return;
  }

  // 先画到后台缓冲，再一次性 BitBlt 到窗口。不要在窗口 DC 上先 FillRect：
  // 30fps 下那会把黑色背景直接暴露给 DWM，形成可见黑闪。
  if (!ensure_backbuffer(dc, cw, ch)) {
    EndPaint(hwnd_, &ps);
    return;
  }
  FillRect(back_dc_, &client, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));

  std::lock_guard<std::mutex> lock(frame_mutex_);
  if (!frame_.empty() && video_width_ > 0 && video_height_ > 0) {
    const double scale = std::min(static_cast<double>(cw) / video_width_,
                                  static_cast<double>(ch) / video_height_);
    const int draw_w = static_cast<int>(video_width_ * scale);
    const int draw_h = static_cast<int>(video_height_ * scale);
    const int dst_x = (cw - draw_w) / 2;
    const int dst_y = (ch - draw_h) / 2;
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = video_width_;
    info.bmiHeader.biHeight = -video_height_;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    if (draw_w == video_width_ && draw_h == video_height_) {
      // 等尺寸时不做拉伸，比 StretchDIBits 快一个数量级。
      SetDIBitsToDevice(back_dc_, dst_x, dst_y, static_cast<DWORD>(video_width_),
                        static_cast<DWORD>(video_height_), 0, 0, 0,
                        static_cast<DWORD>(video_height_), frame_.data(), &info,
                        DIB_RGB_COLORS);
    } else {
      StretchDIBits(back_dc_, dst_x, dst_y, draw_w, draw_h, 0, 0, video_width_, video_height_,
                    frame_.data(), &info, DIB_RGB_COLORS, SRCCOPY);
    }
  }
  BitBlt(dc, 0, 0, cw, ch, back_dc_, 0, 0, SRCCOPY);
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
    case WM_ERASEBKGND:
      // 背景完全由后台缓冲覆盖；擦背景会造成黑闪。
      return 1;
    case WM_SIZE:
      release_backbuffer();
      InvalidateRect(hwnd_, nullptr, FALSE);
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
      release_backbuffer();
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
