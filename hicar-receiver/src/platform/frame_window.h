#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace hicar {
namespace platform {

// Win32 投屏窗口：GDI 绘制 BGRA 帧；鼠标转触摸，键盘转安卓键码。
class FrameWindow {
 public:
  // action：0 按下、1 抬起、2 移动（坐标系为视频像素）。
  using TouchSink = std::function<void(int action, int id, int x, int y)>;
  using KeySink = std::function<void(bool down, int key_code)>;
  using CloseSink = std::function<void()>;

  FrameWindow();
  ~FrameWindow();

  bool create(int width, int height, const std::string& title, std::string* error);
  void close();
  void pump();
  void set_frame(const uint8_t* bgra, int width, int height);
  void set_sinks(TouchSink touch, KeySink key, CloseSink close);

  bool valid() const { return hwnd_ != nullptr; }
  int video_width() const { return video_width_; }
  int video_height() const { return video_height_; }

  static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

 private:
  LRESULT handle_message(UINT message, WPARAM wparam, LPARAM lparam);
  bool map_point(int client_x, int client_y, int* x, int* y) const;
  void paint();
  bool ensure_backbuffer(HDC dc, int width, int height);
  void release_backbuffer();

  HWND hwnd_ = nullptr;
  HDC back_dc_ = nullptr;
  HBITMAP back_bitmap_ = nullptr;
  HBITMAP old_back_bitmap_ = nullptr;
  int back_width_ = 0;
  int back_height_ = 0;
  mutable std::mutex frame_mutex_;

  std::vector<uint8_t> frame_;
  int video_width_ = 0;
  int video_height_ = 0;
  bool mouse_down_ = false;
  int last_x_ = 0;
  int last_y_ = 0;
  TouchSink touch_sink_;
  KeySink key_sink_;
  CloseSink close_sink_;
};

}  // namespace platform
}  // namespace hicar
