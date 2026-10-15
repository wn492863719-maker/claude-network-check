# Claude Network Check

**Understand your network egress before changing settings.**

[简体中文](README.md) · [User guide](docs/USER_GUIDE.md) · [Privacy](docs/PRIVACY.md) · [Architecture](docs/ARCHITECTURE.md)

![Claude Network Check cover](docs/assets/github-cover.png)

A macOS desktop utility for diagnosing egress IP changes, proxy paths, hotspot / company-network differences, and browser-visible location signals. It separates native HTTP checks from Chrome HTTP and WebRTC observations, then offers reversible, item-specific system adjustments.

Built with Swift, WebKit and the Python standard library. Native and worker processes communicate over stdin/stdout: **no local HTTP server, no listening port, no browser extension and no AI API key**.

## Features

- Three rounds of egress checks, with results separated by request path and IPv4 / IPv6.
- System proxy, detected alternate local proxy and no-explicit-proxy paths shown independently.
- Exact reference-IP matching, partial matches, country disagreement and missing evidence clearly distinguished.
- A manual hotspot / company-network workflow that records conditions and rejects mixed network states.
- A local Chrome probe for HTTP exits, WebRTC candidates, timezone, languages and geolocation permission state.
- Session-bound copy/paste import with size, field, expiration, replay and network-state checks.
- Separate findings for website-visible observations, native-only information and unverified claims.
- Individual timezone, locale and proxy-state previews, original-value records, read-back verification and restoration.
- Redacted Markdown export with stable address aliases.

## Interface design

![Interface design](docs/assets/ui-preview.png)

These AI-assisted visuals use illustrative data and describe the design direction. The running Chinese-language app is authoritative for its layout and fields. Prompts and asset notes are in [VISUALS.md](docs/VISUALS.md).

## Install or build

The supplied prebuilt ZIP targets **Apple Silicon (arm64)** and requires an external Python 3.9+ installation. Python is not bundled. The build target is macOS 13.0+; actual build and launch validation used Apple Silicon and macOS 26.6.1. Other macOS versions and Intel execution remain unverified.

The app has a local ad-hoc signature, without Developer ID signing or Apple notarization. See [Apple's app safety guidance](https://support.apple.com/en-us/102445) and the [installation guide](docs/USER_GUIDE.md). Do not disable Gatekeeper globally.

To build from source, install Xcode Command Line Tools and Python 3.9+, then run:

```bash
cd claude-network-check
chmod +x build_app.command 启动工具.command
./build_app.command
open "dist/Claude Network Check.app"
```

Optional output path:

```bash
./build_app.command "$HOME/Desktop/Claude Network Check.app"
```

The app checks common Python locations for a compatible interpreter. No Python packages are required. Node.js 18+ is only needed for development tests.

## Workflow

1. Inspect the native three-round egress results.
2. Select the current network and record the actual proxy node and mode.
3. Capture native results, open the Chrome probe, run it, then copy and import the result.
4. Manually switch networks while preserving proxy settings, and repeat promptly.
5. Review the findings and export a redacted report. Preview each desired system adjustment before applying it.

A reference IP is a comparison value, not an IP allocation mechanism. Multiple IPs do not by themselves prove a disconnection. Short successful checks do not establish long-term availability. A no-explicit-proxy request may still traverse a VPN, TUN or corporate gateway. WebRTC candidates and IP database cities do not establish a precise physical location.

## Privacy and scope

Checks contact ipify, Cloudflare, ipwho.is and ipapi.co; WebRTC uses Google STUN. These services can observe request source addresses, and location databases receive the queried exit address. Results are stored locally with restrictive permissions. The app does not read account data, cookies, keychain items, chats or proxy subscription credentials, and never requests precise geolocation, camera or microphone access.

Browser imports are structurally validated and session-bound, but manually supplied results are not cryptographic proof of authenticity. Local-file browser behavior does not represent every HTTPS site. Corporate iOA, company DNS, VPN/TUN and Chrome's underlying preference files are not automatically modified. See [PRIVACY.md](docs/PRIVACY.md) and [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m unittest -v test_environment.py test_egress.py test_privacy_audit.py
node test_frontend.js
node test_browser_probe.js
python3 scripts/check_release.py
./build_app.command
codesign --verify --deep --strict "dist/Claude Network Check.app"
```

Tests use mocked network and system operations. Real administrative mutations are not executed just to test a release. GitHub Actions is configured for post-upload checks; local validation does not claim that workflow has already run. See [CONTRIBUTING.md](CONTRIBUTING.md) and [VALIDATION.md](docs/VALIDATION.md).

Version **2.2.1** · [MIT License](LICENSE). An independent project, not affiliated with Anthropic. It diagnoses network conditions relevant to Claude and other applications; detection-service results are not proof of the target application's actual route or service eligibility.
