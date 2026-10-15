# Claude Network Check v2.2.1

macOS 网络环境诊断桌面工具：分路径核对出口 IP，比较热点与公司网络，识别浏览器 HTTP 与 WebRTC 差异，为单项系统调整提供预览、回读与恢复。

## 功能

- 多路径三轮检查，区分 IPv4 / IPv6、多出口、查询失败与国家来源分歧。
- 固定 IPv4 参考核对，以及网络与代理变化后的重测。
- 热点／公司网络向导与 Chrome 本地自测，结果通过限时会话复制粘贴导入。
- 网站可见、本机可读与未验证证据分层，Markdown 报告默认脱敏。
- 原生 Swift / WebKit + Python 标准库，无本地 HTTP 服务、监听端口或浏览器扩展。

## 下载

- `claude-network-check-v2.2.1-source.zip`：完整公开源码、中英文介绍、文档、设计图、离线测试和构建脚本。
- `Claude-Network-Check-v2.2.1-macos-arm64.zip`：Apple Silicon 预构建应用与简明安装说明。
- `SHA256SUMS.txt`：以上 ZIP 的 SHA-256 校验值。

## 运行条件

构建目标 macOS 13.0+，实际验收在 Apple Silicon、macOS 26.6.1 完成。预构建包仅 arm64，Python 3.9+ 需单独安装；Intel 和其他系统版本待验证。应用采用本地 ad-hoc 签名，尚未经过 Developer ID 签名与 Apple 公证。

## 结果边界

短测不能证明长期稳定或保证固定 IP。IP 归属、WebRTC、时区与语言不能单独证明精确所在地。源码含运行与验证边界，封面及界面设计图使用示例数据。

独立项目，与 Anthropic 无隶属关系。MIT License。完整说明见仓库 README。
