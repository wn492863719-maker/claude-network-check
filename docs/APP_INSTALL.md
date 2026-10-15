# Claude Network Check 2.2.1

macOS 网络环境检查工具。支持三轮出口检测、热点／公司对照、Chrome WebRTC 自测与可恢复的单项设置调整。独立开源项目，与 Anthropic 无隶属关系。

## 运行

1. 当前预构建文件为 Apple Silicon（arm64）。构建目标 macOS 13.0+，实测 macOS 26.6.1；其他版本待验证。
2. 将同目录的 `Claude Network Check.app` 放到“应用程序”或自己选择的位置并打开。
3. 需要独立安装的 Python 3.9+；应用不附带 Python。支持 Homebrew、python.org 和 Apple 开发工具的常见安装位置。
4. 应用为本地 ad-hoc 签名，未经 Apple 公证。请核对下载来源与校验值，参考 Apple 官方说明判断是否打开：https://support.apple.com/en-us/102445 。不要全局关闭 Gatekeeper。

## 使用

先点击检查；对照时保持相同节点与模式，手动切换网络。本机三轮采集后，从应用打开 Chrome 自测页，运行并复制结果，粘贴回应用导入。修改系统设置前核对逐项预览，执行后查看回读与恢复记录。

没有本地监听服务，无需扩展或 API Key。公网检查会连接 ipify、Cloudflare、ipwho.is、ipapi.co 和 Google STUN。短测不能保证长期稳定或固定 IP；浏览器地区线索不证明精确物理位置。

本机状态：`~/Library/Application Support/Network Environment Check/`。默认脱敏报告：`~/Documents/网络环境检查报告/地区暴露对照报告.md`。旧工具与本版沿用同一私有状态路径，请逐一使用。

完整源码、README、使用与隐私说明随本次发布的 source.zip 提供，仓库 Releases 同时提供 `SHA256SUMS.txt`。
