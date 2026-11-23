# DMSDP 保活动作投递到错误连接

- 状态：Open
- 记录日期：2026-11-23
- 发现场景：HiSight 真机投屏期间
- 关联日志：`debug_receiver/live.log`、`debug_receiver/live.err`

## 现象

HiSight 投屏运行约十余秒后，stderr 连续出现：

```text
[DMSDP] 发送通道与当前连接不符，丢弃
...
[DMSDP] 保活超时
```

随后 HiSight 结束、业务 20 与控制通道关闭。

## 代码原因

`DmsdpSession::on_tick()`（`hicar-receiver/src/dmsdp/session.cpp:729-763`）在控制通道
建立后启动 TCP 保活，并生成 `DmsdpChannel::kControl` 的 `GET_PARAMETER` 发送动作。

但 `Receiver::tick()`（`hicar-receiver/src/app/receiver.cpp:1456-1466`）只在
**session data connection** 上调用 `dmsdp->on_tick()`；控制连接不调用。

`handle_dmsdp_outputs()`（`hicar-receiver/src/app/receiver.cpp:769-774`）只允许当前连接
发送与自身类型一致的通道：

```cpp
if (to_control != connection.dmsdp_control) {
  std::fprintf(stderr, "[DMSDP] 发送通道与当前连接不符，丢弃\n");
  continue;
}
```

因此 session 连接产生的 control 通道保活动作被丢弃，手机收不到 `GET_PARAMETER`，
10 次 1 秒轮询后触发 `kKeepAliveTimeout`。

## 影响

- 无线 DMSDP 会话可能在没有手机侧保活的情况下，约 10 秒后自行超时断开。
- HiSight 随 DMSDP 关闭而结束，表现为投屏突然消失。
- 与黑屏闪烁不是同一个问题；但两者可能在同一场真机联调中先后出现，需要分开修复和验证。

## 建议修复

1. DMSDP 动作不再按“当前连接”丢弃，而是由 `Receiver` 按 `action.channel` 路由到同一
   `DmsdpSession` 对应的 control/session 连接。
2. 或者让 `DmsdpSession` 的定时任务在 control 连接上执行，但输出按 channel 分发。
3. 增加测试：session 连接 tick 产生的 control 保活动作必须实际写入 control socket；
   control 连接关闭后不得继续投递。

## 验收标准

- HiSight 投屏 5 分钟，`[DMSDP] 保活超时` 为 0。
- 不再出现 `[DMSDP] 发送通道与当前连接不符，丢弃`。
- 手机关屏/退出 HiCar 时仍能正常结束，不误报保活失败。
