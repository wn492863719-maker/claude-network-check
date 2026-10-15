# 视觉资产与生成提示词

两张展示图使用内置 imagegen 生成，未使用 CLI 或外部 API Key。画面为设计展示与示例数据，运行版实际布局以应用为准；没有加入真实 IP、个人姓名、公司名称或精确位置。

| 文件 | 用途 |
| --- | --- |
| `assets/github-cover.png` | GitHub 首页封面、产品介绍与社交分享 |
| `assets/ui-preview.png` | macOS 主界面设计展示 |

界面采用白色与浅冷灰底色、深蓝文字、蓝色操作控件、青绿成功和琥珀警示状态。文案区分请求成功、额外候选、待核实与地址族分别检查，不用短测承诺长期稳定。插图不是实际截图，设计中的装饰图标和布局不代表运行版全部实现。

## 主界面生成提示词

```text
Use case: ui-mockup
Asset type: GitHub README macOS desktop application UI design showcase, landscape 16:10, high resolution.
Primary request: Create a beautifully polished, legible Chinese-language macOS app interface design for "Claude Network Check", a real independent open-source network diagnostic utility. Show a single straight-on app window filling the image, with comfortable margins, macOS traffic-light window buttons, refined white and very light cool-gray surfaces, deep navy typography, subtle teal and blue accents, thin borders and restrained soft shadows. Professional calm engineering tool, not a sci-fi dashboard. Main hierarchy mirrors the existing app: header, route-specific egress checks, hotspot/company comparison, privacy findings, and per-item repair preview.
Text (verbatim, use clear modern Chinese typography):
Header: "Claude Network Check"; subheading "网络环境检查"; main button "开始检查".
Main card title: "出口稳定性"; amber status "检测到多个出口"; detail "系统 HTTPS 代理 · IPv4"; two compact address pills "出口 A" and "出口 B"; evidence "6 / 6 请求成功"; three small round indicators "第 1 轮", "第 2 轮", "第 3 轮".
Comparison card: "热点 / 公司网络对照"; two columns "公司网络", "手机热点"; "本机与浏览器已采集"; "同一美国节点 · Global"; note "两轮出口集合相同，尚未证明固定出口".
Lower privacy card: "浏览器地区暴露"; rows "网站可见", "本机应用可读", "尚未验证"; amber detail "WebRTC 发现额外公网候选"; neutral detail "定位权限：未请求".
Small secondary controls "打开 Chrome 自测", "导出脱敏报告", "预览单项修复".
Footer "本地处理 · 无监听端口"; tiny corner label "设计展示 · 示例数据".
Composition: credible desktop app with clear grid; left larger route/results column and right narrower comparison/privacy column. Carefully aligned labels and generous spacing, no invented graphs, no fake uptime scores. Strong typographic hierarchy, detailed crisp realistic UI. Do not use the Anthropic logo or official Claude brand icon. No actual numeric IP addresses, no personal names, no company names, no map, no precise location, no claim of guaranteed fixed IP or no disconnections. This is a design visualization, not a screenshot proof.
```

## 封面生成提示词

```text
Use case: ads-marketing
Asset type: GitHub repository cover / product hero, wide 2:1 landscape, high-resolution raster image.
Primary request: A sophisticated editorial product cover for an independent macOS utility named "Claude Network Check". Crisp, restrained software branding, white and pale cool-gray background, deep ink-navy typography, electric-blue accents with a small teal detail. Premium minimal macOS aesthetic with ample negative space, not a cyber-security alarm poster.
Composition: Left 43 percent is elegant typography, right 57 percent is a large floating straight-on macOS app window with round corners and a subtle natural shadow. UI should be calm and realistic, showing three clearly aligned feature sections, light cards, blue action controls, teal success dots and one amber multi-exit warning. Use a small abstract globe/network glyph of original design, do not use any Anthropic or Claude official symbol. The image should work as a GitHub README banner, large title easily read at small sizes. All text must be meticulously typeset, no random filler.
Exact main title on left, with linebreak after Claude permitted: "Claude Network Check"
Exact Chinese subtitle on left: "看清网络出口，再决定改什么"
Exact small supporting copy: "macOS · 本地处理 · 无监听端口"
Right UI window has exact title "网络环境检查"; cards "出口稳定性", "热点 / 公司网络对照", "浏览器地区暴露"; small readable chips "出口 A", "出口 B", "WebRTC", "IPv4 / IPv6"; clear secondary button "导出脱敏报告".
Small lower-corner label "界面设计展示".
Avoid: fake uptime statistics, speed-test gauges, maps or physical locations, actual numeric IP addresses, personal names, company or proxy-service logos, promises of permanent fixed IP, any hacker motifs, busy gradients, photographic computers or devices, browser framing. Show only the software window and beautiful typography. Design presentation using illustrative sample data.
```

## 封面定向修订提示词

```text
Edit the supplied product cover. Preserve the excellent composition, title, typography, original logo, blue/white palette, macOS window, all geometry and all other labels. Change only a few status texts in the right-side UI to make the diagnostics scientifically accurate. Top card status "连接稳定" must become "请求成功"; "正常" beside each exit becomes "已采集". Bottom browser card status "未发现异常" must become "待核实" in an amber pill; "未暴露" beside WebRTC must become "额外候选" with an amber dot; the word "一致" beside IPv4 / IPv6 must become "分别检查" with a neutral gray dot. Keep the title, tagline, footer "界面设计展示" unchanged. Crisp legible Chinese, no other changes. These statuses are illustrative sample data, no physical-location or long-term-stability claims.
```
