#!/usr/bin/env python3
"""build.py —— 构建单文件纯前端 HTML 转 APK 工具

用法：python tools/build.py
输入：src/ui.html（UI 模板）、src/core.js（引擎）、assets/template.apk、assets/signing.crt、assets/signing.key
输出：dist/html2apk.html（单文件，双击即用，无任何外部依赖）
"""
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ui = (ROOT / "src" / "ui.html").read_text(encoding="utf-8")
core = (ROOT / "src" / "core.js").read_text(encoding="utf-8")
apk_b64 = base64.b64encode((ROOT / "assets" / "template.apk").read_bytes()).decode("ascii")
cert = (ROOT / "assets" / "signing.crt").read_text(encoding="ascii")
key = (ROOT / "assets" / "signing.key").read_text(encoding="ascii")

# 内嵌资源（JSON 字面量安全嵌入 JS）
assets_json = json.dumps({"apk": apk_b64, "cert": cert, "key": key})

assert "/*__CORE__*/" in ui, "ui.html 缺少核心代码占位符"
assert "__ASSETS_JSON__" in ui, "ui.html 缺少资源占位符"

# 防止 core.js 内容意外截断 script 标签
assert "</script" not in core.lower(), "core.js 中包含 </script>，无法内嵌"

out = ui.replace("/*__CORE__*/", core).replace("__ASSETS_JSON__", assets_json)
dist = ROOT / "dist"
dist.mkdir(exist_ok=True)
target = dist / "html2apk.html"
target.write_text(out, encoding="utf-8")
print(f"构建完成：{target}（{target.stat().st_size / 1024 / 1024:.2f} MB）")
