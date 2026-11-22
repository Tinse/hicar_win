#pragma once

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

namespace hicar {
namespace platform {

struct CarApp {
  std::string package_name;
  std::string name;
  std::string icon;  // 原样保留；当前只画首字
};

// HiCar 应用中心：列出手机返回的应用，并内置华为视频 / 华为音乐的启动入口。
class AppWindow {
 public:
  AppWindow();
  ~AppWindow();

  bool create(std::string* error);
  void close();
  void pump();
  void set_apps(std::vector<CarApp> apps);
  void set_status(const std::string& status);
  void set_start_sink(std::function<void(const std::string&)> sink);

  bool valid() const { return window_ != nullptr; }
  bool closed() const { return closed_; }

 private:
  struct HitBox {
    RECT rect{};
    std::string package_name;
  };

  static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
  LRESULT handle(UINT message, WPARAM wparam, LPARAM lparam);
  void paint();
  void layout();
  void start(const std::string& package_name);

  HWND window_ = nullptr;
  std::vector<CarApp> apps_;
  std::vector<HitBox> hits_;
  std::string status_;
  bool closed_ = false;
  std::function<void(const std::string&)> start_sink_;
};

}  // namespace platform
}  // namespace hicar
