import AppKit
import WebKit

func compatiblePython() -> URL? {
    let candidates = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3",
                      "/Library/Frameworks/Python.framework/Versions/Current/bin/python3", "/usr/bin/python3"]
    for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
        // Avoid invoking Apple's installer stub on machines without developer tools.
        if path == "/usr/bin/python3",
           !FileManager.default.fileExists(atPath: "/Library/Developer/CommandLineTools/usr/bin/python3"),
           !FileManager.default.fileExists(atPath: "/Applications/Xcode.app/Contents/Developer/usr/bin/python3") { continue }
        let probe = Process()
        probe.executableURL = URL(fileURLWithPath: path)
        probe.arguments = ["-I", "-c", "import sys, zoneinfo; sys.exit(0 if (3, 9) <= sys.version_info[:2] < (4, 0) else 1)"]
        probe.standardOutput = FileHandle.nullDevice
        probe.standardError = FileHandle.nullDevice
        do {
            try probe.run()
            probe.waitUntilExit()
            if probe.terminationStatus == 0 { return probe.executableURL }
        } catch { continue }
    }
    return nil
}

final class AppDelegate: NSObject, NSApplicationDelegate, WKScriptMessageHandler, WKNavigationDelegate {
    private var window: NSWindow!
    private var web: WKWebView!
    private var worker: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private let queue = DispatchQueue(label: "environment.worker")

    func applicationDidFinishLaunching(_ notification: Notification) {
        let controller = WKUserContentController()
        controller.add(self, name: "environment")
        let configuration = WKWebViewConfiguration()
        configuration.userContentController = controller
        configuration.websiteDataStore = .nonPersistent()
        web = WKWebView(frame: .zero, configuration: configuration)
        web.navigationDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 750),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Claude Network Check · 网络环境检查"
        window.minSize = NSSize(width: 510, height: 540)
        window.contentView = web
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        let menu = NSMenu()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "退出 Claude Network Check", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let item = NSMenuItem()
        item.submenu = appMenu
        menu.addItem(item)
        let editMenu = NSMenu(title: "编辑")
        editMenu.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "复制", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        let editItem = NSMenuItem()
        editItem.submenu = editMenu
        menu.addItem(editItem)
        NSApp.mainMenu = menu
        guard let resources = Bundle.main.resourceURL else { return }
        web.loadFileURL(resources.appendingPathComponent("index.html"), allowingReadAccessTo: resources)
        startWorker(resources)
    }

    private func startWorker(_ resources: URL) {
        guard let python = compatiblePython() else {
            showError("未找到 Python 3.9+。请安装受支持的 Python 3（python.org、Homebrew 或 Xcode 命令行工具），然后重新打开。")
            return
        }
        let process = Process()
        process.executableURL = python
        process.arguments = ["-B", "-E", "-s", "-u", resources.appendingPathComponent("environment.py").path]
        let stdin = Pipe(), stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            worker = process
            input = stdin.fileHandleForWriting
            output = stdout.fileHandleForReading
        } catch {
            showError("无法启动 Python 3。请安装 Python 3.9 或更新版本后重新打开。")
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              let url = message.frameInfo.request.url, url.isFileURL,
              url.standardizedFileURL == Bundle.main.resourceURL?.appendingPathComponent("index.html").standardizedFileURL,
              let body = message.body as? [String: Any],
              let id = body["id"] as? String, id.count < 80,
              let method = body["method"] as? String,
              ["scan", "egress", "egress_reference", "privacy_start", "privacy_import", "privacy_summary", "privacy_export", "privacy_browser", "preview", "apply", "restore", "records", "settings"].contains(method),
              let data = try? JSONSerialization.data(withJSONObject: body), data.count <= 32768 else { return }
        guard let worker = worker, worker.isRunning, let input = input, let output = output else {
            reply(["id": id, "ok": false, "error": "本地检测进程未运行，请重新打开应用。"])
            return
        }
        queue.async { [weak self] in
            do {
                var payload = data
                payload.append(10)
                try input.write(contentsOf: payload)
                var response = Data()
                while true {
                    guard let byte = try output.read(upToCount: 1), !byte.isEmpty else {
                        throw NSError(domain: "worker", code: 1)
                    }
                    if byte.first == 10 { break }
                    response.append(byte)
                    if response.count > 262144 { throw NSError(domain: "worker", code: 2) }
                }
                let value = try JSONSerialization.jsonObject(with: response)
                DispatchQueue.main.async { self?.reply(value) }
            } catch {
                DispatchQueue.main.async { self?.reply(["id": id, "ok": false, "error": "检测进程未完成请求，请重新打开应用。"] ) }
            }
        }
    }

    private func reply(_ value: Any) {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]),
              let json = String(data: data, encoding: .utf8) else { return }
        web.evaluateJavaScript("window.nativeResult(\(json));", completionHandler: nil)
    }

    private func showError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = message
        alert.runModal()
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        if url.isFileURL, url.standardizedFileURL == Bundle.main.resourceURL?.appendingPathComponent("index.html").standardizedFileURL {
            decisionHandler(.allow)
        } else {
            if url.scheme == "https", ["www.anthropic.com", "privacy.anthropic.com", "support.claude.com"].contains(url.host ?? "") {
                NSWorkspace.shared.open(url)
            }
            decisionHandler(.cancel)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) {
        input?.closeFile()
        worker?.terminate()
    }
}

if CommandLine.arguments.contains("--version") {
    print("Claude Network Check 2.2.1 · network comparison and browser audit · no listening port")
} else if CommandLine.arguments.contains("--check-runtime") {
    if let python = compatiblePython() {
        print("Compatible Python 3.9+: \(python.path)")
    } else {
        fputs("No compatible Python 3.9+ found.\n", stderr)
        exit(1)
    }
} else {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.regular)
    app.run()
}
