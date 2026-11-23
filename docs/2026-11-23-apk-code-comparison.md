# `zlink5-5.4.36` APK 与 `hicar_win` 模块级对照

- 日期：2026-11-23
- APK：`zlink5-5.4.36.apk`（包名 `com.zjinnova.zlink`，5.4.36，targetSdk 28）
- 证据：`rea-analysis/apk-inventory.json`、`apk-evidence.json`、各 `lib*.so` 字符串、
  `libHisightSink.so` Ghidra 反编译；REA 的 JADX provider 当前受原生 inspection schema
  阻塞，Java 壳层未做全量方法级反编译，以下以 native 库和清单为准。

| 模块 | APK 侧实现/证据 | `hicar_win` 现状 | 结论 |
|---|---|---|---|
| BLE/发现 | `libnearby.so`、`libzbt_core.so`、`BluetoothHCTService`；BLE 广播 + BR MAC/GATT 发现 | 蓝牙 RFCOMM + SDP 可用；BLE 广播链路不完整，实际以 `--no-ble` 扫码绕过 | 可用但不完整；要补齐 GATT Server/BR MAC 交换 |
| 认证 | `libauthagent.so`、`libHwDeviceAuthSDK.so`、HiChain 消息 | PAKE + 身份交换 + STS + 信任库，OpenHC 向量对齐 | 已对齐 |
| 控制通道 | `libnearby.so` 业务 19/20、通道管理 | Nearby 帧、业务 19 认证、业务 20 DMSDP、RFCOMM/TCP 双承载 | 已对齐 |
| 无线组网 | `libzbt_core.so` 热点/连接串；`libzlink_core.so` 资源层 | Windows 热点 + ICS + BSSID/频率 + WiFi 控制通道 + 连接串 | 已按真实车机同方案实现 |
| DMSDP | `libdmsdp.so`：会话帧、加密控制、OPTIONS、设备/服务、TCP/UDP 保活、音频会话 | 已实现；本次修复合保活投递、`GET_PARAMETER 200`、音频监听通道 | 主要路径对齐 |
| 显示/HiSight | `libHisightSink.so`：RTP 扩展按字节数、PES 固定 14 字节、16 字节 IV + AES-CTR | `video.cpp` 已按反编译修正；本次修复合 GDI 黑闪 | 协议已对齐，渲染剩余真机验收 |
| 视频解码 | APK 车机侧由厂商 HMI/MediaCodec 解码，`libHisightSink` 只负责收流 | Media Foundation H.264 硬解 + BGRA 转换；535 阻塞上报 | 可用；D3D11 是后续性能优化项 |
| 音频 | `libdmsdp.so` 音频数据会话、`AudioTrack` 播放 | DMSDP 音频会话 + WASAPI/waveOut；本次修复合 control 连接触发音频监听 | 主要路径对齐 |
| 应用中心 | `libzlink_core.so`/HiCar SDK 数据交互：528 列表、529 启动、533/537 前台、535 解码能力 | 已实现 528/529/533/537/535/532；失败码 100000/100001/100002 区分 | 已补齐，528 列表仍需真机确认 |
| 管理/OTA | `libmanagement.so`、`ZBTService` | 未实现 OTA/管理服务 | 非投屏主链路；Windows 侧无对应升级通道 |
| 输入/窗口 | `libHisightSink.so` UIBC 触摸/按键 | UIBC 触摸/按键、鼠标 letterbox、媒体键 | 已对齐 |

## 本次代码改动对应的可改进点

1. HiSight 黑屏闪烁：`FrameWindow` 双缓冲 + 禁止 `WM_ERASEBKGND` + 等尺寸
   `SetDIBitsToDevice`；不再每帧在窗口 DC 上先填黑。
2. DMSDP 保活：按 `DmsdpSession` + channel 路由，不再按“当前连接类型”丢弃；补
   `GET_PARAMETER 200`；任意合法加密载荷重置超时计数。
3. 音频：`kOpenAudioListener` 允许从加密 control 连接触发，修复音频 `SETUP` 被误丢。
4. 应用中心：528 空列表自动重试 2 次；529 按 `RespCode` 区分成功/拒绝/未安装；
   533/537 前台应用、532 投屏授权、535 动态帧数全部接入；新增“应用市场”固定入口。
5. 性能：`MfH264Decoder` 记录单帧解码耗时；手机声明 535 支持后，>35ms 上报阻塞，
   连续 30 帧 <15ms 上报恢复，让手机动态降/升帧。

## 仍需真机确认

- 528 融合桌面列表在 Mate 70 Pro / HarmonyOS 7 上是否返回；若不返回，固定入口仍可
  直接发送 529。
- 双缓冲后黑闪是否彻底消失；若仍有撕裂，升级 D3D11 flip swap chain。
- 音频会话在 control 连接触发后的 `SETUP`/RTP 播放链路。
- BLE 自动发现（GATT Server/BR MAC）尚未实现，当前扫码方案可用。
- Windows 不能安装 APK；华为视频/音乐只能在手机上安装，接收端负责启动和投屏。

## 参考接口

- 融合桌面应用列表（528）：<https://developer.huawei.com/consumer/cn/doc/development/HiCar-Guides/get-app-list-0000001606309545>
- 融合桌面应用操作（529，`RespCode=100000/100001/100002`）：<https://device.harmonyos.com/cn/docs/develop/DevicePartner-References/fusion-ui-app-operation-0000001607687489>
- 车机视频流解码能力（535）：<https://developer.huawei.com/consumer/cn/doc/DP-HiCar-Guides/video-stream-decode-0000001918714700>
- 数据交互类型表（532/533/535/537）：<https://developer.huawei.com/consumer/cn/doc/HiCar-References/data-interaction-0000001199330031>

