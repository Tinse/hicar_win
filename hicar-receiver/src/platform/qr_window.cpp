#include "platform/qr_window.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "qrcodegen.hpp"

namespace hicar {
namespace platform {

namespace {

struct QrBitmap {
  int size = 0;
  std::vector<uint8_t> modules;  // 每行 size 字节，1 表示黑块

  bool black(int x, int y) const {
    if (x < 0 || y < 0 || x >= size || y >= size) return false;
    return modules[static_cast<size_t>(y) * static_cast<size_t>(size) + static_cast<size_t>(x)] != 0;
  }
};

QrBitmap make_qr_bitmap(const std::string& content) {
  const auto qr = qrcodegen::QrCode::encodeText(content.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
  QrBitmap out;
  out.size = qr.getSize();
  out.modules.resize(static_cast<size_t>(out.size) * static_cast<size_t>(out.size));
  for (int y = 0; y < out.size; ++y) {
    for (int x = 0; x < out.size; ++x) {
      out.modules[static_cast<size_t>(y) * static_cast<size_t>(out.size) + static_cast<size_t>(x)] =
          qr.getModule(x, y) ? 1 : 0;
    }
  }
  return out;
}

std::wstring widen(const std::string& text) {
  if (text.empty()) return {};
  const int chars = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring out(static_cast<size_t>(chars), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), chars);
  return out;
}

std::string utf8_path(const std::filesystem::path& path) {
  const auto text = path.u8string();
  return std::string(text.begin(), text.end());
}

// 生成一份可直接双击查看/扫描的 24 位 BMP，避免只有控制台文字。
bool write_qr_bmp(const QrBitmap& qr, const std::filesystem::path& path, int scale, std::string* error) {
  constexpr int kBorder = 4;
  const int dim = (qr.size + kBorder * 2) * scale;
  const int row_bytes = ((dim * 24 + 31) / 32) * 4;
  const DWORD image_size = static_cast<DWORD>(row_bytes) * static_cast<DWORD>(dim);

  BITMAPFILEHEADER file_header{};
  file_header.bfType = 0x4D42;  // 'BM'
  file_header.bfOffBits = sizeof(file_header) + sizeof(BITMAPINFOHEADER);
  file_header.bfSize = file_header.bfOffBits + image_size;

  BITMAPINFOHEADER info{};
  info.biSize = sizeof(info);
  info.biWidth = dim;
  info.biHeight = dim;
  info.biPlanes = 1;
  info.biBitCount = 24;
  info.biCompression = BI_RGB;
  info.biSizeImage = image_size;

  std::ofstream stream(path, std::ios::binary);
  if (!stream) {
    if (error != nullptr) *error = "无法创建二维码图片：" + utf8_path(path);
    return false;
  }
  stream.write(reinterpret_cast<const char*>(&file_header), sizeof(file_header));
  stream.write(reinterpret_cast<const char*>(&info), sizeof(info));

  std::vector<uint8_t> row(static_cast<size_t>(row_bytes), 0xFF);
  for (int py = dim - 1; py >= 0; --py) {
    const int my = py / scale - kBorder;
    for (int px = 0; px < dim; ++px) {
      const int mx = px / scale - kBorder;
      const bool black = qr.black(mx, my);
      const uint8_t value = black ? 0 : 255;
      row[static_cast<size_t>(px) * 3 + 0] = value;  // B
      row[static_cast<size_t>(px) * 3 + 1] = value;  // G
      row[static_cast<size_t>(px) * 3 + 2] = value;  // R
    }
    stream.write(reinterpret_cast<const char*>(row.data()), row_bytes);
  }
  if (!stream) {
    if (error != nullptr) *error = "写入二维码图片失败：" + utf8_path(path);
    return false;
  }
  return true;
}

struct WindowState {
  QrBitmap qr;
  std::string pin;
};

constexpr wchar_t kWindowClass[] = L"HiCarPairingQrWindow";

LRESULT CALLBACK qr_window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
  if (message == WM_NCCREATE) {
    const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
  }

  auto* state = reinterpret_cast<WindowState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  switch (message) {
    case WM_ERASEBKGND:
      return 1;
    case WM_PAINT: {
      PAINTSTRUCT paint{};
      HDC dc = BeginPaint(hwnd, &paint);
      RECT client{};
      GetClientRect(hwnd, &client);
      HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
      FillRect(dc, &client, white);
      DeleteObject(white);
      if (state == nullptr || state->qr.size <= 0) {
        EndPaint(hwnd, &paint);
        return 0;
      }

      constexpr int kBorder = 4;
      const int available_w = std::max(1, static_cast<int>(client.right) - 40);
      const int available_h = std::max(1, static_cast<int>(client.bottom) - 220);
      const int scale = std::max(2, std::min(available_w / (state->qr.size + kBorder * 2),
                                             available_h / (state->qr.size + kBorder * 2)));
      const int qr_pixels = (state->qr.size + kBorder * 2) * scale;
      const int left = (static_cast<int>(client.right) - qr_pixels) / 2;
      const int top = 42;

      HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
      for (int y = 0; y < state->qr.size; ++y) {
        for (int x = 0; x < state->qr.size; ++x) {
          if (!state->qr.black(x, y)) continue;
          RECT block{left + (x + kBorder) * scale, top + (y + kBorder) * scale,
                     left + (x + kBorder + 1) * scale, top + (y + kBorder + 1) * scale};
          FillRect(dc, &block, black);
        }
      }
      DeleteObject(black);

      SetBkMode(dc, TRANSPARENT);
      SetTextColor(dc, RGB(20, 20, 20));
      HFONT title_font = CreateFontW(-24, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                     OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                     DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
      HFONT pin_font = CreateFontW(-44, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
      HFONT hint_font = CreateFontW(-20, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                    DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");

      RECT title{0, 8, client.right, 36};
      HFONT old_font = static_cast<HFONT>(SelectObject(dc, title_font));
      DrawTextW(dc, L"HiCar 无线连接", -1, &title, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

      SelectObject(dc, pin_font);
      RECT pin_rect{0, top + qr_pixels + 12, client.right, top + qr_pixels + 70};
      const std::wstring pin_text = L"连接码  " + widen(state->pin);
      DrawTextW(dc, pin_text.c_str(), -1, &pin_rect, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

      SelectObject(dc, hint_font);
      SetTextColor(dc, RGB(90, 90, 90));
      RECT hint{0, top + qr_pixels + 76, client.right, top + qr_pixels + 110};
      DrawTextW(dc, L"手机打开 HiCar，扫描二维码连接", -1, &hint,
                DT_CENTER | DT_SINGLELINE | DT_VCENTER);

      SelectObject(dc, old_font);
      DeleteObject(title_font);
      DeleteObject(pin_font);
      DeleteObject(hint_font);
      EndPaint(hwnd, &paint);
      return 0;
    }
    case WM_CLOSE:
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    case WM_NCDESTROY:
      delete state;
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
      break;
    default:
      break;
  }
  return DefWindowProcW(hwnd, message, wparam, lparam);
}

}  // namespace

struct QrWindow::Impl {
  std::thread thread;
  std::atomic<HWND> hwnd{nullptr};
  HANDLE ready = nullptr;
  QrBitmap qr;
  std::string pin;
  std::string error;
  bool ok = false;
  bool shutting_down = false;

  void run() {
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = qr_window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));  // IDC_ARROW
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    window_class.lpszClassName = kWindowClass;
    if (RegisterClassExW(&window_class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
      error = "注册二维码窗口类失败，错误码 " + std::to_string(GetLastError());
      SetEvent(ready);
      return;
    }

    auto* state = new WindowState{qr, pin};
    HWND window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_TOPMOST, kWindowClass, L"HiCar 配对",
                                  WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT,
                                  CW_USEDEFAULT, 620, 780, nullptr, nullptr, instance, state);
    if (window == nullptr) {
      delete state;
      error = "创建二维码窗口失败，错误码 " + std::to_string(GetLastError());
      SetEvent(ready);
      return;
    }
    hwnd.store(window);
    ok = true;
    SetEvent(ready);

    ShowWindow(window, SW_SHOWNORMAL);
    SetWindowPos(window, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(window);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
    hwnd.store(nullptr);
  }
};

QrWindow::QrWindow() : impl_(std::make_unique<Impl>()) {}

QrWindow::~QrWindow() { close(); }

bool QrWindow::show(const std::string& content, const std::string& pin, std::string* image_path,
                    std::string* error) {
  close();
  if (impl_ == nullptr) impl_ = std::make_unique<Impl>();
  if (error != nullptr) error->clear();
  if (image_path != nullptr) image_path->clear();

  try {
    impl_->qr = make_qr_bitmap(content);
  } catch (const std::exception& exception) {
    if (error != nullptr) *error = std::string("生成二维码失败：") + exception.what();
    return false;
  }
  impl_->pin = pin;

  std::filesystem::path bmp_path;
  try {
    bmp_path = std::filesystem::current_path() / "pairing_qr.bmp";
    std::string write_error;
    if (write_qr_bmp(impl_->qr, bmp_path, 8, &write_error)) {
      if (image_path != nullptr) *image_path = utf8_path(bmp_path);
    } else {
      std::fprintf(stderr, "[配对] 二维码图片保存失败：%s\n", write_error.c_str());
    }
  } catch (const std::exception& exception) {
    std::fprintf(stderr, "[配对] 二维码图片路径计算失败：%s\n", exception.what());
  }

  impl_->ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (impl_->ready == nullptr) {
    if (error != nullptr) *error = "创建二维码窗口事件失败，错误码 " + std::to_string(GetLastError());
    return false;
  }
  impl_->ok = false;
  impl_->error.clear();
  impl_->thread = std::thread([this] { impl_->run(); });

  const DWORD wait = WaitForSingleObject(impl_->ready, 5000);
  CloseHandle(impl_->ready);
  impl_->ready = nullptr;
  if (wait != WAIT_OBJECT_0 || !impl_->ok) {
    if (impl_->thread.joinable()) impl_->thread.join();
    if (error != nullptr) {
      *error = impl_->error.empty() ? "二维码窗口启动超时" : impl_->error;
    }
    return false;
  }
  return true;
}

void QrWindow::close() {
  if (impl_ == nullptr) return;
  if (impl_->thread.joinable()) {
    HWND window = impl_->hwnd.load();
    if (window != nullptr) PostMessageW(window, WM_CLOSE, 0, 0);
    impl_->thread.join();
  }
  if (impl_->ready != nullptr) {
    CloseHandle(impl_->ready);
    impl_->ready = nullptr;
  }
  impl_->hwnd.store(nullptr);
  impl_->ok = false;
}

bool QrWindow::visible() const {
  if (impl_ == nullptr) return false;
  const HWND window = impl_->hwnd.load();
  return window != nullptr && IsWindowVisible(window) != FALSE;
}

}  // namespace platform
}  // namespace hicar
