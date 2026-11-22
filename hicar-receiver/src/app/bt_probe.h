#pragma once

namespace hicar {

// 诊断模式：列出蓝牙无线电、开 RFCOMM 监听并发布 SDP 记录，等待连接并打印字节。
int run_bluetooth_probe(int seconds);

}  // namespace hicar
