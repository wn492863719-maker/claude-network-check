# 贡献指南

欢迎提交可复现问题、文档改进与范围明确的 Pull Request。

## 开始前

阅读 [架构](docs/ARCHITECTURE.md)、[隐私](docs/PRIVACY.md) 与 [安全策略](SECURITY.md)。保持原生窗口、stdio 桥接和无监听端口设计。系统操作继续按单项预览、原值记录、回读与冲突恢复组织。

使用 mock 或合成夹具复现网络差异，不把真实公网 IP、SSID、公司 DNS、账号、订阅 URL 或浏览器会话写进测试和仓库。新增网络查询服务需说明用途、发送字段、超时及失败表现，并更新隐私文档。

## 本地验证

需要 macOS、Command Line Tools、Python 3.9+；Node.js 18+ 用于离线前端测试。

```bash
python3 -m unittest -v test_environment.py test_egress.py test_privacy_audit.py
node test_frontend.js
node test_browser_probe.js
python3 scripts/check_release.py
./build_app.command
```

针对修改增加有意义的测试。仅为测试不执行真实管理员修改，不关闭公司保护或改写企业 DNS。涉及浏览器行为时，自动化夹具通过后仍应标明真实 Chrome 验证条件。

## 提交说明

描述具体问题、触发条件、最终行为与验证范围。网络结论需区分观测事实、解释和未验证项；保留地址族、请求路径、时间与来源。截图和日志分享前进行脱敏。

示例提交信息：`fix browser IPv6 candidate import`、`improve egress reference comparison`、`document macOS installation`。

## 许可证

贡献将按项目 [MIT License](LICENSE) 分发。请仅提交有权公开的代码、文档及资产，并说明外部素材来源。
