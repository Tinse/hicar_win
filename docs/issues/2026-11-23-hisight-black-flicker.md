# HiSight 投屏黑屏闪烁

- 状态：Open
- 记录日期：2026-11-23
- 平台：Windows x64 接收端 + Mate 70 Pro / HarmonyOS 7
- 连接方式：无线（蓝牙扫码 + Windows 热点 + ICS）
- 视频参数：1280x720 @ 30fps，Media Foundation H.264 硬解，Win32/GDI 窗口显示
- 关联提交：`b55d05e`（修正 HiSight RTP 扩展长度与 PES 布局）

## 现象

无线连接成功，HiSight 能正常出画面（桌面、地图等可见），但显示过程中会周期性黑屏闪烁。

本次实测期间视频流没有报错，解码帧持续增长：

```text
[HiSight] 视频已收 1072357 字节，解码帧 140
[HiSight] 解码帧 450（1280x720）
```

活跃期间没有出现 `[HiSight] 视频流错误`，说明 RTP 重组、PES 头、AES-CTR 解密已能正常出帧。

首批 RTP/PES 日志也符合 APK 内 `libHisightSink.so` 的正常分支：

```text
[HiSight] RTP b0=90 b1=e0 csrc=0 ext=1 header=32 size=2807 payload=2775 first=000001e00ad18480002571578f2dca88
[HiSight] PES flags1=84 flags2=80 hdrlen=0 size=2775 first=000001e00ad18480002571578f2dca88f3491b06aad87fa9
```

即 `flags1=0x84`、`flags2=0x80`、`PES_header_data_length=0`，ES 从偏移 14 开始。

本次会话最后出现 `[HiSight] 投屏结束（原因 0）`，随后 DMSDP 保活超时。该断连问题单独记录在
`2026-11-23-dmsdp-keepalive-channel-mismatch.md`，暂不作为黑屏闪烁的直接证据。

## 重点排查位置

1. `hicar-receiver/src/platform/frame_window.cpp:148-175`
   `FrameWindow::paint()` 每次 `WM_PAINT` 都先用 `BLACK_BRUSH` 填满整个客户区，再
   `StretchDIBits` 绘制当前帧；窗口类还设置了 `CS_HREDRAW | CS_VREDRAW`，没有双缓冲。
   30fps 下每次整窗重绘都可能把黑色背景暴露给 DWM，形成可见黑闪。

2. `hicar-receiver/src/platform/frame_window.cpp:115-123`
   `set_frame()` 每帧 `resize + memcpy` 后调用 `InvalidateRect(hwnd_, nullptr, FALSE)`，
   整窗失效，没有脏矩形、没有后台缓冲、没有交换链。

3. `hicar-receiver/src/platform/mf_decoder.cpp:208-251`
   NV12/YV12 -> BGRA 是逐像素软转换，转换完成后同步回调 `set_frame()`。转换耗时会让帧到达
   不均匀，但本身不应产生黑帧；如果双缓冲后仍闪烁，需要继续检查解码输出时间和空帧。

## 建议修复（按优先级）

1. 最小改动：窗口双缓冲。创建兼容 DC + DIB section，`set_frame()` 写入后台缓冲，
   `WM_PAINT` 只做一次 `BitBlt`；`WM_ERASEBKGND` 返回 1，禁止系统擦背景。
2. 去掉每帧 `FillRect`，只在窗口尺寸变化或首帧前清黑边。
3. 高性能方案：D3D11 swap chain（`DXGI_SWAP_EFFECT_FLIP_DISCERNIBLE` 或
   `FLIP_SEQUENTIAL`），BGRA 纹理上传 + `Present(1, 0)`，避免 GDI `StretchDIBits`
   的 CPU 缩放和整窗重绘。
4. 若仍闪烁，记录每帧 PTS、解码输出时间和输出尺寸，确认是否存在重复帧、空帧或
   MF decoder 输出类型变化。

## 验收标准

- 30fps 连续投屏 5 分钟，无可见黑屏闪烁。
- 窗口拖动、缩放时不出现整窗黑闪。
- 解码帧数持续增长，视频流错误为 0。
