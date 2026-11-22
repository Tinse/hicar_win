#include <windows.h>

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <string>
#include <thread>
#include <vector>

#include "app/bt_probe.h"
#include "app/phone_sim.h"
#include "app/receiver.h"
#include "common/hex.h"
#include "identity/default_identity.h"
#include "identity/device_id.h"
#include "nearby/car_info.h"
#include "platform/app_window.h"
#include "platform/audio_player.h"
#include "platform/bluetooth.h"

namespace {

struct Options {
  std::string ip = "192.168.66.150";
  std::string bind = "0.0.0.0";
  uint32_t port = 32400;
  std::string model = "000480";                     // 6 位十六进制 = 3 字节
  std::string sub = "00";                           // 2 位十六进制
  std::string bt = "02:12:34:56:78:9A";             // 6 字节
  std::string link = "usb";
  bool carinfo = false;
  bool serve = false;
  bool phone_sim = false;
  bool bt_info = false;
  bool ble_test = false;
  bool no_ble = false;
  bool app_demo = false;
  bool audio_demo = false;
  int seconds = 60;
};

hicar::Receiver* g_receiver = nullptr;

BOOL WINAPI console_handler(DWORD event) {
  if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
    if (g_receiver != nullptr) g_receiver->stop();
    return TRUE;
  }
  return FALSE;
}

void usage() {
  std::puts(
      "hicar_receiver —— Windows HiCar 接收端\n"
      "用法:\n"
      "  hicar_receiver --carinfo [--ip 192.168.66.150] [--port 32400]\n"
      "                 [--model 000480] [--sub 00] [--bt 02:12:34:56:78:9A]\n"
      "      输出 91 字节 carInfo（USB 控制传输 0x40/0x34/0xA0 的载荷）\n"
      "  hicar_receiver --serve [--bind 0.0.0.0] [--ip 192.168.66.150] [--port 32400]\n"
      "                 [--bt 02:12:34:56:78:9A] [--link usb|bt|wifi] [--no-ble]\n"
      "      起控制通道 TCP 监听，处理 nearby 握手与业务 19/20 的子连接\n"
      "  hicar_receiver --phone-sim --ip 127.0.0.1 --port 32400\n"
      "      本机模拟手机端跑一遍握手与建 socket，用于自测\n"
      "  hicar_receiver --bt-info [--seconds 60]\n"
      "      打印蓝牙地址，开 RFCOMM 监听并发布 SDP（UUID FE35），等待连接\n"
      "  hicar_receiver --ble-test [--seconds 8]\n"
      "      只发 FDEE BLE 发现广播，用来确认手机 HiCar 是否能发现本机\n"
      "  hicar_receiver --app-demo [--seconds 8]\n"
      "      打开应用中心界面预览（华为视频 / 华为音乐固定入口）\n"
      "  hicar_receiver --audio-demo [--seconds 2]\n"
      "      播放 440Hz 测试音，验证 WASAPI/waveOut 输出\n");
}

bool next_value(int argc, char** argv, int& i, std::string& out) {
  if (i + 1 >= argc) return false;
  out = argv[++i];
  return true;
}

bool parse_bluetooth(const std::string& text, std::array<uint8_t, 6>& out) {
  try {
    const auto bytes = hicar::from_hex(text);
    if (bytes.size() != 6) return false;
    std::memcpy(out.data(), bytes.data(), 6);
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace

int main(int argc, char** argv) {
  SetConsoleOutputCP(CP_UTF8);
  setvbuf(stdout, nullptr, _IONBF, 0);  // 日志立即写出，方便重定向与实时观察
  Options opt;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    std::string value;
    if (arg == "--help" || arg == "-h") {
      usage();
      return 0;
    } else if (arg == "--carinfo") {
      opt.carinfo = true;
    } else if (arg == "--serve") {
      opt.serve = true;
    } else if (arg == "--phone-sim") {
      opt.phone_sim = true;
    } else if (arg == "--bt-info") {
      opt.bt_info = true;
    } else if (arg == "--ble-test") {
      opt.ble_test = true;
    } else if (arg == "--no-ble") {
      opt.no_ble = true;
    } else if (arg == "--app-demo") {
      opt.app_demo = true;
    } else if (arg == "--audio-demo") {
      opt.audio_demo = true;
    } else if (arg == "--seconds") {
      if (!next_value(argc, argv, i, value)) return 2;
      opt.seconds = std::stoi(value);
    } else if (arg == "--ip") {
      if (!next_value(argc, argv, i, opt.ip)) return 2;
    } else if (arg == "--bind") {
      if (!next_value(argc, argv, i, opt.bind)) return 2;
    } else if (arg == "--port") {
      if (!next_value(argc, argv, i, value)) return 2;
      opt.port = static_cast<uint32_t>(std::stoul(value));
    } else if (arg == "--model") {
      if (!next_value(argc, argv, i, opt.model)) return 2;
    } else if (arg == "--sub") {
      if (!next_value(argc, argv, i, opt.sub)) return 2;
    } else if (arg == "--bt") {
      if (!next_value(argc, argv, i, opt.bt)) return 2;
    } else if (arg == "--link") {
      if (!next_value(argc, argv, i, opt.link)) return 2;
    } else {
      std::fprintf(stderr, "未知参数: %s\n", arg.c_str());
      usage();
      return 2;
    }
  }

  std::array<uint8_t, 6> bluetooth{};
  const bool has_bluetooth = parse_bluetooth(opt.bt, bluetooth);

  if (opt.audio_demo) {
    hicar::platform::AudioPlayer player;
    std::string error;
    if (!player.open(&error)) {
      std::fprintf(stderr, "打开音频输出失败：%s\n", error.c_str());
      return 1;
    }
    const int frames = 960;  // 20ms @48k
    std::vector<int16_t> pcm(static_cast<size_t>(frames) * 2);
    double phase = 0.0;
    const double step = 2.0 * 3.141592653589793 * 440.0 / 48000.0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opt.seconds);
    while (std::chrono::steady_clock::now() < deadline) {
      for (int i = 0; i < frames; ++i) {
        const int16_t sample = static_cast<int16_t>(std::sin(phase) * 10000.0);
        pcm[static_cast<size_t>(i) * 2] = sample;
        pcm[static_cast<size_t>(i) * 2 + 1] = sample;
        phase += step;
        if (phase > 2.0 * 3.141592653589793) phase -= 2.0 * 3.141592653589793;
      }
      player.write(reinterpret_cast<const uint8_t*>(pcm.data()), pcm.size() * sizeof(int16_t));
      player.pump();
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    player.close();
    std::puts("音频输出测试完成");
    return 0;
  }

  if (opt.app_demo) {
    hicar::platform::AppWindow window;
    std::string error;
    if (!window.create(&error)) {
      std::fprintf(stderr, "打开应用中心失败：%s\n", error.c_str());
      return 1;
    }
    window.set_apps({
        {"com.android.mediacenter", "华为音乐", ""},
        {"com.huawei.himovie", "华为视频", ""},
        {"com.huawei.hicar", "HiCar", ""},
    });
    window.set_status("预览模式：连接手机后应用列表由 dataType 528 返回");
    window.set_start_sink([](const std::string& package_name) {
      std::printf("应用中心点击：%s\n", package_name.c_str());
    });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opt.seconds);
    while (!window.closed() && std::chrono::steady_clock::now() < deadline) {
      window.pump();
      std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    return 0;
  }

  if (opt.ble_test) {
    const auto model = hicar::from_hex(opt.model);
    const auto sub = hicar::from_hex(opt.sub);
    if (model.size() != 3 || sub.size() != 1) {
      std::fputs("model / sub 长度不对\n", stderr);
      return 2;
    }
    std::array<uint8_t, 4> model4{};
    std::memcpy(model4.data(), model.data(), 3);
    model4[3] = sub[0];
    hicar::platform::BleAdvertiser advertiser;
    std::string error;
    if (!advertiser.start(model4, 0, "HiCar-Windows", &error)) {
      std::fprintf(stderr, "BLE 广播启动失败：%s\n", error.c_str());
      return 1;
    }
    std::printf("BLE FDEE 广播已启动 %d 秒，手机 HiCar 里应能看到/弹窗\n", opt.seconds);
    std::fflush(stdout);
    std::this_thread::sleep_for(std::chrono::seconds(opt.seconds));
    advertiser.stop();
    return 0;
  }

  if (opt.bt_info) {
    return hicar::run_bluetooth_probe(opt.seconds);
  }

  if (opt.phone_sim) {
    const hicar::NearbyKeyMaterial keys = hicar::default_nearby_keys();
    return hicar::run_phone_sim(opt.ip, static_cast<uint16_t>(opt.port), bluetooth, keys);
  }

  if (opt.serve) {
    hicar::ReceiverConfig config;
    config.bind_ip = opt.bind;
    config.control_port = static_cast<uint16_t>(opt.port);
    config.host = hicar::default_host_identity();
    config.keys = hicar::default_nearby_keys();
    config.disable_ble = opt.no_ble;
    if (has_bluetooth) config.bluetooth_address = bluetooth;
    if (opt.link == "bt" || opt.link == "bluetooth") {
      config.link = hicar::NearbyLink::kBluetooth;
    } else if (opt.link == "wifi") {
      config.link = hicar::NearbyLink::kWifi;
    }

    hicar::Receiver receiver(config);
    g_receiver = &receiver;
    SetConsoleCtrlHandler(console_handler, TRUE);

    std::string error;
    if (!receiver.start(&error)) {
      std::fprintf(stderr, "启动失败：%s\n", error.c_str());
      return 1;
    }

    hicar::CarInfo info;
    std::memcpy(info.model_id.data(), hicar::from_hex(opt.model).data(), 3);
    info.sub_model_id = hicar::from_hex(opt.sub)[0];
    const bool bt_link = opt.link == "bt" || opt.link == "bluetooth";
    if (bt_link) {
      // 蓝牙链路在 Receiver::start 里已经用 radio 的真实地址重算了 deviceId；
      // 这里必须用同一个值，不能再拿 --bt 的默认占位地址算一遍。
      std::printf("deviceId: %s\n", receiver.device_id().c_str());
    } else {
      const auto id = hicar::derive_device_id(info.model_id, info.sub_model_id, bluetooth);
      const auto id_hex = hicar::device_id_hex(id);
      info.device_id = {};
      std::memcpy(info.device_id.data(), id.data(), 32);
      info.bluetooth_address = bluetooth;
      info.host_ip = opt.ip;
      if (receiver.control_port() != 0) {
        info.port = receiver.control_port();
        std::printf("carInfo(91 字节): %s\n", hicar::to_hex(info.encode()).c_str());
      }
      std::printf("deviceId: %s\n", id_hex.c_str());
    }
    std::fflush(stdout);

    const int code = [&]() {
      try {
        return receiver.run();
      } catch (const std::exception& e) {
        std::fprintf(stderr, "运行异常：%s\n", e.what());
        return 1;
      } catch (...) {
        std::fputs("运行异常：未知类型\n", stderr);
        return 1;
      }
    }();
    g_receiver = nullptr;
    return code;
  }

  if (!opt.carinfo) {
    usage();
    return 0;
  }

  hicar::CarInfo info;
  const auto model = hicar::from_hex(opt.model);
  const auto sub = hicar::from_hex(opt.sub);
  if (model.size() != hicar::CarInfo::kModelIdSize || sub.size() != 1 || !has_bluetooth) {
    std::fputs("model / sub / bt 长度不对\n", stderr);
    return 2;
  }
  info.model_id = {};
  std::memcpy(info.model_id.data(), model.data(), 3);
  info.sub_model_id = sub[0];
  const auto id = hicar::derive_device_id(info.model_id, info.sub_model_id, bluetooth);
  info.device_id = {};
  std::memcpy(info.device_id.data(), id.data(), 32);
  info.bluetooth_address = bluetooth;
  info.host_ip = opt.ip;
  info.port = opt.port;

  const std::vector<uint8_t> bytes = info.encode();
  std::printf("carInfo(%zu 字节):\n%s\n", bytes.size(), hicar::to_hex(bytes).c_str());
  std::printf("deviceId: %s\n", hicar::device_id_hex(id).c_str());
  return 0;
}
