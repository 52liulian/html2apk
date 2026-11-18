/* 全权限端到端测试：从 UI 源码取全量清单，用 dist 内嵌引擎（线上同款）生成 APK */
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const ROOT = path.join(__dirname, "..");

/* 1. 提取 UI 中定义的 14 项权限 */
const ui = fs.readFileSync(path.join(ROOT, "src/ui.html"), "utf8");
const start = ui.indexOf("var PERMISSIONS = [");
const end = ui.indexOf("];", start);
const block = ui.slice(start, end);
const perms = block.split("\n")
  .map(function (line) {
    const mark = 'value: "';
    const i = line.indexOf(mark);
    return i < 0 ? null : line.slice(i + mark.length).split('"')[0];
  })
  .filter(Boolean);
console.log("权限清单项数:", perms.length);
console.log(perms.map(function (p, i) { return "  " + (i + 1) + ". " + p; }).join("\n"));

/* 2. 加载 dist 中的引擎与内嵌资源（与线上页面完全一致） */
const html = fs.readFileSync(path.join(ROOT, "dist/html2apk.html"), "utf8");
const scripts = [];
let cursor = 0;
while (true) {
  const a = html.indexOf("<script>", cursor);
  if (a < 0) break;
  const b = html.indexOf("</script>", a);
  if (b < 0) break;
  scripts.push(html.slice(a + 8, b));
  cursor = b + 9;
}
const sb = {
  atob: function (s) { return Buffer.from(s, "base64").toString("binary"); },
  TextEncoder: TextEncoder, TextDecoder: TextDecoder,
  Blob: Blob, Response: Response, DecompressionStream: DecompressionStream,
  console: console, Promise: Promise,
  Uint8Array: Uint8Array, Uint32Array: Uint32Array,
  Math: Math, Object: Object, String: String, Number: Number,
  Error: Error, JSON: JSON, Symbol: Symbol, Set: Set, ArrayBuffer: ArrayBuffer
};
sb.globalThis = sb;
sb.window = sb;
sb.crypto = require("crypto").webcrypto;
vm.createContext(sb);
vm.runInContext(scripts[0], sb);
vm.runInContext(scripts[1], sb);

/* 3. 生成全权限 APK */
(async function () {
  const apk = await sb.Html2Apk.build({
    label: "全权限测试",
    versionName: "1.0",
    versionCode: 1,
    "package": "com.xiao.allperms",
    url: "https://example.com",
    permissions: perms,
    permissionCatalog: perms,
    assets: sb.__HTML2APK_ASSETS__
  });
  fs.writeFileSync(path.join(ROOT, "work/out-allperms.apk"), Buffer.from(apk));
  fs.writeFileSync(path.join(ROOT, "work/allperms.json"), JSON.stringify(perms));
  console.log("全权限 APK 生成成功:", apk.length, "字节");
})().catch(function (e) { console.error(e); process.exit(1); });
