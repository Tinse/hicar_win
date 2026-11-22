# Third-party notices

本项目在协议研究、行为对照和测试向量方面参考了以下开源项目。各项目的代码、文档和商标归其各自作者所有。

| 项目 | 用途 | 许可证 |
|---|---|---|
| [Project Nayuki / QR Code generator](https://github.com/nayuki/QR-Code-generator) | 生成配对二维码矩阵（`third_party/qrcodegen`，已 vendored） | MIT |
| [GGBondLab/OpenHC](https://github.com/GGBondLab/OpenHC) | HiCar 车机端协议结构、认证流程与 `accessory-vectors.json` 测试向量 | GPL-3.0-only |
| [huducat586/hicar-android-receiver](https://github.com/huducat586/hicar-android-receiver) | 安卓接收端行为对照；认证部分来自 OpenHarmony | 自有代码 MIT；OpenHarmony 部分 Apache-2.0 |
| [UnmetDecade/AllPlay](https://github.com/UnmetDecade/AllPlay) | 多平台宿主与 Windows 端组织方式参考 | GPL-3.0 |

`ref/` 目录只用于本地研究，已被 `.gitignore` 排除，不随本仓库分发。除 `hicar-receiver/third_party/qrcodegen`（MIT，保留原版权头与 `LICENSE`）外，仓库中没有以子模块或 vendored 源码形式收录上述项目。

“HiCar”“Huawei”等名称与商标归华为技术有限公司所有。本项目与华为及 HiCar 官方无关联，也未获得官方授权或认可。
