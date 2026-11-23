#include "platform/app_window.h"

#include <windowsx.h>

#include <algorithm>
#include <cwchar>

namespace hicar {
namespace platform {
namespace {

constexpr const wchar_t* kClassName = L"HiCarAppWindow";
constexpr int kWidth = 920;
constexpr int kHeight = 640;

std::wstring wide(const std::string& text) {
  if (text.empty()) return {};
  const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring result(static_cast<size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length);
  return result;
}

void fill_round_rect(HDC dc, const RECT& rect, COLORREF color) {
  HBRUSH brush = CreateSolidBrush(color);
  FillRect(dc, &rect, brush);
  DeleteObject(brush);
}

void draw_text(HDC dc, const RECT& rect, const std::wstring& text, COLORREF color, int size,
               bool center = false, bool bold = false) {
  HFONT font = CreateFontW(size, 0, 0, 0, bold ? FW_SEMIBOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
  HGDIOBJ old = SelectObject(dc, font);
  SetTextColor(dc, color);
  SetBkMode(dc, TRANSPARENT);
  RECT copy = rect;
  DrawTextW(dc, text.c_str(), -1, &copy,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | (center ? DT_CENTER : DT_LEFT));
  SelectObject(dc, old);
  DeleteObject(font);
}

}  // namespace

AppWindow::AppWindow() = default;

AppWindow::~AppWindow() { close(); }

bool AppWindow::create(std::string* error) {
  if (window_ != nullptr) return true;
  static bool registered = false;
  HINSTANCE instance = GetModuleHandleW(nullptr);
  if (!registered) {
    WNDCLASSEXW cls{};
    cls.cbSize = sizeof(cls);
    cls.style = CS_HREDRAW | CS_VREDRAW;
    cls.lpfnWndProc = &AppWindow::window_proc;
    cls.hInstance = instance;
    cls.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));  // IDC_ARROW
    cls.hbrBackground = CreateSolidBrush(RGB(16, 20, 28));
    cls.lpszClassName = kClassName;
    if (RegisterClassExW(&cls) == 0) {
      if (error != nullptr) *error = "注册应用窗口类失败";
      return false;
    }
    registered = true;
  }
  RECT rect{0, 0, kWidth, kHeight};
  AdjustWindowRectEx(&rect, WS_OVERLAPPEDWINDOW, FALSE, 0);
  window_ = CreateWindowExW(0, kClassName, L"HiCar 应用中心 - 华为视频 / 华为音乐",
                            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                            CW_USEDEFAULT, CW_USEDEFAULT, rect.right - rect.left,
                            rect.bottom - rect.top, nullptr, nullptr, instance, this);
  if (window_ == nullptr) {
    if (error != nullptr) *error = "创建应用窗口失败";
    return false;
  }
  closed_ = false;
  ShowWindow(window_, SW_SHOW);
  UpdateWindow(window_);
  return true;
}

void AppWindow::close() {
  if (window_ != nullptr) {
    DestroyWindow(window_);
    window_ = nullptr;
  }
  closed_ = true;
}

void AppWindow::pump() {
  if (window_ == nullptr) return;
  MSG message{};
  while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
}

void AppWindow::set_apps(std::vector<CarApp> apps) {
  apps_ = std::move(apps);
  if (window_ != nullptr) InvalidateRect(window_, nullptr, TRUE);
}

void AppWindow::set_status(const std::string& status) {
  status_ = status;
  if (window_ != nullptr) InvalidateRect(window_, nullptr, TRUE);
}

void AppWindow::set_start_sink(std::function<void(const std::string&)> sink) {
  start_sink_ = std::move(sink);
}

void AppWindow::start(const std::string& package_name) {
  if (start_sink_) start_sink_(package_name);
}

void AppWindow::layout() {
  hits_.clear();
  RECT client{};
  GetClientRect(window_, &client);
  int y = 108;
  int x = 24;
  int column = 0;
  const int card_width = 280;
  const int card_height = 64;
  for (const auto& app : apps_) {
    if (column >= 3) {
      column = 0;
      x = 24;
      y += card_height + 12;
    }
    if (y + card_height > client.bottom - 120) break;
    HitBox box;
    box.rect = {x, y, x + card_width, y + card_height};
    box.package_name = app.package_name;
    hits_.push_back(box);
    x += card_width + 12;
    ++column;
  }
  // 固定入口始终存在，即使手机没把这两个包列进融合桌面。
  const int fixed_y = client.bottom - 96;
  const int fixed_width = 200;
  HitBox video;
  video.rect = {24, fixed_y, 24 + fixed_width, fixed_y + 56};
  video.package_name = "com.huawei.himovie";
  hits_.push_back(video);
  HitBox music;
  music.rect = {24 + fixed_width + 16, fixed_y, 24 + fixed_width * 2 + 16, fixed_y + 56};
  music.package_name = "com.android.mediacenter";
  hits_.push_back(music);
  HitBox market;
  market.rect = {24 + fixed_width * 2 + 32, fixed_y, 24 + fixed_width * 3 + 32, fixed_y + 56};
  market.package_name = "com.huawei.appmarket";
  hits_.push_back(market);
  HitBox refresh;
  refresh.rect = {24 + fixed_width * 3 + 48, fixed_y, 24 + fixed_width * 3 + 48 + 160, fixed_y + 56};
  refresh.package_name = "__refresh__";
  hits_.push_back(refresh);
}

void AppWindow::paint() {
  PAINTSTRUCT paint_struct{};
  HDC dc = BeginPaint(window_, &paint_struct);
  RECT client{};
  GetClientRect(window_, &client);

  HDC memory = CreateCompatibleDC(dc);
  HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
  HGDIOBJ old_bitmap = SelectObject(memory, bitmap);
  fill_round_rect(memory, client, RGB(16, 20, 28));

  RECT title{24, 16, client.right - 24, 56};
  draw_text(memory, title, L"HiCar 应用中心", RGB(245, 248, 255), 30, false, true);
  RECT subtitle{24, 58, client.right - 24, 88};
  draw_text(memory, subtitle,
            L"点击应用 → 手机启动 → HiCar 自动投屏；未安装华为视频/音乐时先点“应用市场”",
            RGB(140, 156, 180), 16);
  RECT line{24, 96, client.right - 24, 98};
  fill_round_rect(memory, line, RGB(42, 52, 68));

  layout();
  for (size_t i = 0; i < apps_.size() && i + 4 < hits_.size(); ++i) {
    const RECT& box = hits_[i].rect;
    fill_round_rect(memory, box, RGB(28, 35, 47));
    RECT icon{box.left + 12, box.top + 12, box.left + 52, box.top + 52};
    fill_round_rect(memory, icon, RGB(0, 122, 255));
    std::wstring initial = wide(apps_[i].name.empty() ? apps_[i].package_name : apps_[i].name).substr(0, 1);
    draw_text(memory, icon, initial, RGB(255, 255, 255), 20, true, true);
    RECT text{box.left + 64, box.top + 6, box.right - 12, box.top + 52};
    std::wstring name = wide(apps_[i].name.empty() ? apps_[i].package_name : apps_[i].name);
    draw_text(memory, text, name, RGB(235, 242, 250), 17, false, true);
    RECT package{box.left + 64, box.top + 34, box.right - 12, box.top + 58};
    draw_text(memory, package, wide(apps_[i].package_name), RGB(120, 138, 160), 12);
  }

  RECT video{hits_[hits_.size() - 4].rect};
  fill_round_rect(memory, video, RGB(0, 106, 220));
  draw_text(memory, video, L"华为视频", RGB(255, 255, 255), 19, true, true);

  RECT music{hits_[hits_.size() - 3].rect};
  fill_round_rect(memory, music, RGB(0, 150, 136));
  draw_text(memory, music, L"华为音乐", RGB(255, 255, 255), 19, true, true);

  RECT market{hits_[hits_.size() - 2].rect};
  fill_round_rect(memory, market, RGB(212, 116, 0));
  draw_text(memory, market, L"应用市场", RGB(255, 255, 255), 17, true, true);

  RECT refresh{hits_[hits_.size() - 1].rect};
  fill_round_rect(memory, refresh, RGB(46, 56, 72));
  draw_text(memory, refresh, L"刷新应用列表", RGB(220, 228, 240), 15, true, true);

  RECT status{24, client.bottom - 34, client.right - 24, client.bottom - 6};
  draw_text(memory, status, wide(status_), RGB(130, 150, 175), 14);

  BitBlt(dc, 0, 0, client.right, client.bottom, memory, 0, 0, SRCCOPY);
  SelectObject(memory, old_bitmap);
  DeleteObject(bitmap);
  DeleteDC(memory);
  EndPaint(window_, &paint_struct);
}

LRESULT CALLBACK AppWindow::window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
  if (message == WM_NCCREATE) {
    auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    return TRUE;
  }
  auto* self = reinterpret_cast<AppWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (self == nullptr) return DefWindowProcW(hwnd, message, wparam, lparam);
  self->window_ = hwnd;
  return self->handle(message, wparam, lparam);
}

LRESULT AppWindow::handle(UINT message, WPARAM wparam, LPARAM lparam) {
  switch (message) {
    case WM_PAINT:
      paint();
      return 0;
    case WM_ERASEBKGND:
      return 1;
    case WM_LBUTTONUP: {
      const int x = GET_X_LPARAM(lparam);
      const int y = GET_Y_LPARAM(lparam);
      for (const auto& box : hits_) {
        if (x >= box.rect.left && x <= box.rect.right && y >= box.rect.top && y <= box.rect.bottom) {
          if (box.package_name == "__refresh__") {
            if (start_sink_) start_sink_("__refresh__");
          } else {
            start(box.package_name);
          }
          return 0;
        }
      }
      return 0;
    }
    case WM_CLOSE:
      DestroyWindow(window_);
      window_ = nullptr;
      closed_ = true;
      return 0;
    case WM_DESTROY:
      window_ = nullptr;
      closed_ = true;
      return 0;
    default:
      return DefWindowProcW(window_, message, wparam, lparam);
  }
}

}  // namespace platform
}  // namespace hicar
