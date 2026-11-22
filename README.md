# HiCar Windows Receiver

Windows 原生 C++ 实现的 HiCar 无线接收端。目标是把 HarmonyOS 手机的 HiCar 画面、触摸回控、音频和应用启动能力投到 Windows，并尽量保持手机原有网络可用。

> 当前状态：计划中的 M0～M6 已实现；构建与 9 项单元测试通过；Windows 移动热点实测通过；HarmonyOS 7 真机联调尚未完成。

## 功能

- 蓝牙 RFCOMM / SDP 无线接入，扫码或 6 位连接码配对
- 启动即弹出置顶配对二维码窗口，同时生成 `pairing_qr.bmp`；蓝牙自动进入可发现/可连接状态
- HiCar Nearby 握手、PAKE / STS 认证、信任库
- Windows 移动热点 + ICS：手机连入热点后仍可通过 Windows 上网
- DMSDP 控制会话、设备/服务协商、保活
- HiSight RTSP 投屏、H.264 硬解、Win32 窗口
- UIBC 触摸与按键回控
- PCM 48 kHz 立体声音频，WASAPI（失败回退 waveOut）
- 应用中心：融合桌面列表、启动应用、前台应用；内置华为视频 / 华为音乐入口
- 音频数据会话与 AES-CTR 控制加密

## 仓库结构

```text
.
├─ hicar-receiver/          # CMake + MSVC 工程（C++20）
│  ├─ src/                  # 协议核心、认证、DMSDP、HiSight、平台层
│  ├─ tests/                # 9 个单元测试
│  └─ CMakeLists.txt
├─ 开发进度.md              # 已实现细节、验证结果、已知约束
├─ 移植方案.md              # 可行性调研与技术路线
└─ THIRD_PARTY_NOTICES.md   # 参考项目与商标声明
```

`ref/`（本地参考仓库）、`hicar-receiver/build/`（构建产物）、`dist/`（打包二进制）不纳入版本控制。

## 构建

依赖：

- Windows 10/11 x64
- Visual Studio 2022（MSVC，C++20）
- CMake 3.20+
- Windows SDK（含 C++/WinRT 投影头文件，默认探测 `10.0.22621.0`）
- OpenSSL libcrypto（MSVC x64 版）

```powershell
cmake -S hicar-receiver -B hicar-receiver/build -G "Visual Studio 17 2022" -A x64 `
  -DHC_OPENSSL_ROOT="D:/ProgramData/anaconda3/Library"

cmake --build hicar-receiver/build --config Release
ctest --test-dir hicar-receiver/build -C Release --output-on-failure
```

`HC_OPENSSL_ROOT` 指向包含 `include/openssl/evp.h` 与 `lib/libcrypto.lib` 的目录；换机器时改这个参数即可。构建后会把 `libcrypto-3-x64.dll` 拷到产物目录。

## 运行

1. 完整解压发布包，不要只把启动脚本单独拖出来。
2. 右键 `启动无线接收端.cmd`，以管理员身份运行（SDP 发布和热点需要权限）。
3. 记下窗口中的蓝牙地址、6 位连接码和二维码内容。
4. 手机打开 HiCar，扫码或输入连接码。
5. 认证成功后 Windows 自动开热点；手机连入该热点，仍可通过 ICS 上网。
6. 连接建立后进入投屏、音频和应用中心。

诊断参数：

```text
hicar_receiver.exe --help
hicar_receiver.exe --app-demo --seconds 8
hicar_receiver.exe --audio-demo --seconds 2
hicar_receiver.exe --bt-info --seconds 5
hicar_receiver.exe --carinfo
```

## 已知限制

- **Windows 不能安装 APK。** 应用中心里的“华为视频 / 华为音乐”是向手机发送启动请求，再把手机画面投到 Windows；应用必须已安装在手机上。华为视频不在 HiCar 官方支持清单内，手机可能拒绝启动，状态栏会显示应答码。
- 真机联调尚未完成。蓝牙连接、认证、热点入网、DMSDP、HiSight、音频、应用数据 528/529/537 仍需 HarmonyOS 7 手机实测确认。
- 热点方案依赖 Windows 移动热点与 ICS；部分无线网卡/驱动不支持，程序会回退到同局域网模式。
- 首次配对需要把 Windows 蓝牙设为“可被发现/可被连接”，程序会自动尝试；若被系统策略拒绝，请右键以管理员身份运行。
- 手机如果只用普通相机扫到 `hicar://` 文本而没有弹出 HiCar，请在 HiCar App 内使用“扫码连接/连接车辆”，而不是微信或普通相机。
- 本项目是协议研究与互操作实现，与华为、HiCar 官方无关。

## 参考项目

协议结构与测试向量参考了 OpenHC、hicar-android-receiver、AllPlay 等开源项目，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。上述项目未作为源码子目录提交。

## License

本仓库暂未声明开源许可证。如需公开发布或再分发，请先补充 `LICENSE` 并确认参考项目的许可证兼容性。
