# Html2Apk · 网页打包小工具

把 **网址 / HTML 源码 / ZIP 压缩包** 打包成一个安卓 APK。

**纯前端单文件工具**：打包与签名全部在浏览器本地完成，不需要后端、不需要 JDK/JRE，数据不上传服务器。双击 HTML 即可使用，也可以部署到任意静态托管（当前部署在 GitHub Pages）。

- 在线使用：<https://www.liulian.ink/html2apk/>
- 仓库地址：<https://github.com/52liulian/html2apk>

## 功能

| 内容来源 | 说明 |
| --- | --- |
| 网址 | 应用启动后由内置 WebView 加载该网址，未带协议自动补全 `https://` |
| HTML 源码 | 粘贴源码，或拖入 `.html` / `.htm` 文件自动读取，打包为 `assets/index.html` |
| ZIP 压缩包 | 根目录需包含 `index.html`，内部 css/js/图片等资源解包进 `assets/`，可离线运行 |

可自定义软件名称（支持中文与任意长度）、版本号（versionCode）、版本名称（versionName）、包名（选填，默认 `com.xiao.webview`）以及应用图标（正方形 PNG，96~1024 像素，推荐 256/512）。

权限可勾选 14 项（联网、相机、存储读写、定位、麦克风、电话状态、振动、唤醒锁、NFC、蓝牙及其管理、前台服务等），全部默认不勾选、均可自由选择。勾选的权限会写入安装包，取消勾选则移除声明（包括模板内置的联网权限）。安装后由系统按版本规则授权；部分权限在较新 Android 上还需运行时弹窗确认，勾选框只负责声明。注意：不勾选联网时，网址模式将无法加载在线页面。

生成结果以 v2 签名，点击保存到本地即可安装（安装时需允许“未知来源”）。

## 使用方法

1. 打开 `dist/html2apk.html`（或访问在线地址），需要 Chrome / Edge 103+（依赖 `DecompressionStream`）
2. 选择内容来源：填网址 / 粘贴或拖入 HTML 源码 / 上传 ZIP
3. 填写软件名称、版本号、版本名称，可选填包名、上传图标
4. 点击「生成 APK」，完成后点击「保存到本地」
5. 将 APK 传到安卓手机安装（允许“未知来源”）

快捷键：`Ctrl + Enter` 触发生成。

## 项目结构

```
html2apk/
├── src/
│   ├── core.js          # 核心引擎（axml 修补 + ZIP 重打包 + APK v2 签名）
│   └── ui.html          # 界面模板
├── tools/
│   ├── build.py         # 构建脚本：把引擎/UI/模板/证书注入为单文件
│   └── verify.py        # 独立验证脚本：解析 APK 并重算摘要、验签
├── test/
│   └── node-test.js     # Node 无头测试（三种内容模式 + 异常路径）
├── assets/
│   ├── template.apk     # WebView 模板 APK（内嵌到成品中）
│   ├── signing.crt      # 签名证书
│   └── signing.key      # 签名私钥（PKCS#1）
├── dist/
│   └── html2apk.html    # 最终交付物：单文件工具，双击即用
├── .github/workflows/
│   └── deploy-pages.yml # main 更新后自动部署到 gh-pages 分支
└── README.md
```

## 技术实现

成品 HTML 内嵌了模板 APK 与签名证书（base64），运行时由纯 JS 完成三步：

1. **AXML 修补**：解析模板 `AndroidManifest.xml` 的 UTF-16 字符串池并重建，精确替换应用名、版本名称、包名（applicationId），就地改写 versionCode 整型属性。支持中文与任意长度名称（不受原始字符串长度限制）。

   Activity 类名保持模板原值 `com.parap.webview.MainActivity` 不变。该类已编译进 `classes3.dex`，若随包名一起改写，会导致 `ClassNotFoundException` 并使应用启动闪退。Android 允许 applicationId 与 Activity 实际类名不同，因此自定义包名功能不受影响。

   权限通过复制模板的 `uses-permission` 节点结构动态插入：先把权限名追加进字符串池，再在权限节点区插入 START/END 元素对。取消勾选时，引擎会从节点流中成对删除对应的 START/END 节点（包括模板内置的联网权限），真正移除声明。清单以外的模板权限（如 `ACCESS_NETWORK_STATE`）不受勾选影响，保持原样。
2. **ZIP 追加式重打包**：保留模板原始数据区（确保 `resources.arsc` 保持未压缩且 4 字节对齐，满足 Android 11+ 要求），追加新条目后重写中央目录与 EOCD。
3. **APK v2 签名**：Merkle 分块摘要（0xa5 前缀 1 MB 分块 → 0x5a 聚合）+ WebCrypto `RSASSA-PKCS1-v1_5` / SHA-256 签名。签名块插入 Central Directory 之前并修正 EOCD，私钥由 PKCS#1 转换为 PKCS#8 后导入。

核心引擎 `src/core.js` 浏览器 / Node 通用，无第三方库依赖。

## 开发与构建

```bash
# 1. 构建单文件（改完 src/ 或 assets/ 后执行）
python tools/build.py
# 输出：dist/html2apk.html

# 2. Node 无头测试：三种模式生成 APK（产物在 work/）
node test/node-test.js

# 3. 独立验证：解析 APK、检查内容、重算 Merkle 摘要并用证书公钥验签
python tools/verify.py
```

若 `work/test-icon.png` 不存在，先运行 `python tools/make_test_icon.py` 生成测试图标。

要换用自己的模板或签名证书，替换 `assets/` 下对应文件后重新执行 `build.py`。注意模板 APK 的 manifest 默认字符串需与 `src/core.js` 中的 `TPL_LABEL` / `TPL_VERSION_NAME` / `TPL_PACKAGE` 一致，否则引擎会报“模板文件可能不匹配”。

## 部署

- `main` 分支：完整项目源码（`.workbuddy/`、`github-pages/` 已忽略）
- `gh-pages` 分支：仅站点文件（`index.html` + `.nojekyll`），GitHub Pages 从该分支部署

`.github/workflows/deploy-pages.yml` 会在 main 分支每次 push 后自动把 `dist/html2apk.html` 复制到 gh-pages 根目录并推送，无需手动维护 gh-pages 分支。

## 已知限制

- 使用内置调试证书签名：所有生成的 APK 共享同一签名；同一包名重复安装会被视为同一应用。生产用途请替换 `assets/` 中的证书与私钥。
- ZIP 模式中的资源以 STORED 方式写入，APK 体积略大，不影响功能。
- 需要支持 WebCrypto 与 `DecompressionStream` 的现代浏览器（Chrome / Edge 103+）。
