# GitHub 发布资料

## 仓库字段

**Repository name**

```text
claude-network-check
```

**Description · 中文**

```text
macOS 网络环境诊断工具：出口 IP 稳定性检测、热点与公司网络对照、WebRTC 暴露检查及可恢复的单项设置调整。无本地监听端口。
```

**Description · English**

```text
A macOS network diagnostic app for egress IP checks, hotspot/company comparisons, browser WebRTC signals, and reversible system adjustments. No local listening server.
```

**Topics**

```text
macos network-diagnostics egress-ip proxy webrtc privacy swift webkit python claude
```

## 一段式项目介绍

Claude Network Check 是面向 macOS 的网络环境诊断桌面工具。它把系统代理、其他本地代理、IPv4 / IPv6 与浏览器请求分开检测，通过三轮采样和热点／公司网络对照，呈现出口变化、连接失败与浏览器地区线索。工具采用 Swift、WebKit 和 Python 标准库，使用进程标准输入／输出通信，无本地监听服务；单项调整支持变更预览、原值记录、执行回读和恢复，报告默认隐藏地址与公司网络细节。

## 上传源码

新建空仓库，将源码 ZIP 解压后，上传 `claude-network-check/` 内的文件到仓库根目录。README、LICENSE、源码、`docs/`、`scripts/` 和 `.github/` 应位于根目录对应位置；不要把整个 ZIP 当作唯一源码文件上传。

若使用 Git，在此源码目录初始化并提交，再用 GitHub 提供的仓库地址设置远端和推送。建议首次提交说明：`prepare Claude Network Check public release`。上传前使用 `git diff --cached` 核对暂存内容。

不要上传 `dist/`、本机运行记录、浏览器会话或原始公司网络报告。已提供 `.gitignore` 和明确文件清单打包脚本，仍应在上传前检查新增文件。

## 创建 Release

源码进入仓库并完成 Actions 后，在 Releases 创建：

- Tag：`v2.2.1`
- Title：`Claude Network Check v2.2.1`
- Body：复制 [RELEASE_NOTES.md](RELEASE_NOTES.md)
- Assets：源码 ZIP、arm64 应用 ZIP 与 `SHA256SUMS.txt`

Releases 用于分发发布说明和二进制文件；源码 ZIP 与应用 ZIP 含义不同，GitHub 自动提供的源码归档也不等于已构建应用。[GitHub 官方发布说明](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)。

## 可视素材

- `docs/assets/github-cover.png`：项目首页封面，可用于 README 或仓库社交预览。
- `docs/assets/ui-preview.png`：macOS 主界面设计展示。
- 使用时保留“设计展示／示例数据”的上下文；真实截图需另行脱敏。

上传、公开仓库、启用功能和发布 Release 均由仓库所有者按自己的设置执行。
