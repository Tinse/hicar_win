#pragma once

#include <memory>
#include <string>

namespace hicar {
namespace platform {

// 配对二维码窗口：启动无线接收端时弹出，显示二维码、连接码和操作提示。
// 窗口在独立线程里跑消息循环，不阻塞接收端主循环。
class QrWindow {
 public:
  QrWindow();
  ~QrWindow();
  QrWindow(const QrWindow&) = delete;
  QrWindow& operator=(const QrWindow&) = delete;

  // content 是 hicar:// 扫码内容；pin 是 6 位连接码。
  // 成功时返回 true，并把生成的 pairing_qr.bmp 绝对路径写入 image_path（可为 nullptr）。
  bool show(const std::string& content, const std::string& pin, std::string* image_path,
            std::string* error);
  void close();
  bool visible() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace platform
}  // namespace hicar
