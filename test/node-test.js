"use strict";
/**
 * node-test.js —— Node 22 无头测试：三种内容模式生成 APK
 * 运行：node test/node-test.js
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");

/* 加载 core.js（无模块系统，直接在全局执行） */
vm.runInThisContext(fs.readFileSync(path.join(ROOT, "src/core.js"), "utf8"), { filename: "core.js" });
const Engine = globalThis.Html2Apk;
if (!Engine) { console.error("core.js 未正确加载"); process.exit(1); }

/* 内嵌资源 */
const assets = {
  apk: fs.readFileSync(path.join(ROOT, "assets/template.apk")).toString("base64"),
  cert: fs.readFileSync(path.join(ROOT, "assets/signing.crt"), "utf8"),
  key: fs.readFileSync(path.join(ROOT, "assets/signing.key"), "utf8")
};

const OUT = path.join(ROOT, "work");
fs.mkdirSync(OUT, { recursive: true });

/* 测试样本 */
const htmlSample = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>测试页</title></head>
<body style="font-family:sans-serif;padding:40px"><h1>离线测试成功！</h1>
<p>这是由 html2apk 工具打包的本地页面。</p></body></html>`;

/* 生成包含子目录的 zip（需在 Node 中手工构建，仅 STORED 简化） */
function buildTestZip() {
  const files = [
    { name: "index.html", data: Buffer.from('<!DOCTYPE html><html><head><meta charset=utf-8><link rel="stylesheet" href="css/style.css"></head><body><h1>ZIP 模式测试成功</h1></body></html>') },
    { name: "css/style.css", data: Buffer.from("body{background:#eef}") }
  ];
  const parts = []; const central = []; let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name);
    const crcTable = Engine._internals.crc32;
    const crc = crcTable(new Uint8Array(f.data));
    const lh = Buffer.alloc(30 + name.length);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(f.data.length, 18); lh.writeUInt32LE(f.data.length, 22);
    lh.writeUInt16LE(name.length, 26); name.copy(lh, 30);
    parts.push(lh, f.data);
    const cd = Buffer.alloc(46 + name.length);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(f.data.length, 20); cd.writeUInt32LE(f.data.length, 24);
    cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(offset, 42); name.copy(cd, 46);
    central.push(cd);
    offset += lh.length + f.data.length;
  }
  const cdStart = offset;
  const cdBuf = Buffer.concat(central);
  parts.push(cdBuf);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(cdStart, 16);
  parts.push(eocd);
  return new Uint8Array(Buffer.concat(parts));
}

/* 256x256 测试图标（work/test-icon.png，由 tools/make_test_icon.py 生成） */
const iconData = new Uint8Array(fs.readFileSync(path.join(ROOT, "work/test-icon.png")));

const cases = [
  {
    name: "out-url.apk",
    desc: "网址模式 + 中文软件名 + 图标 + 自定义包名",
    opts: { label: "萧易寒工具箱", versionName: "2.3.7-beta", versionCode: 5, "package": "com.xiao.toolkit", url: "https://www.example.com", icon: iconData }
  },
  {
    name: "out-html.apk",
    desc: "HTML 源码模式 + 长软件名",
    opts: { label: "这是一个非常长的中文软件名称测试", versionName: "1.0.0", versionCode: 1, html: new Uint8Array(Buffer.from(htmlSample)) }
  },
  {
    name: "out-zip.apk",
    desc: "ZIP 压缩包模式（含子目录）",
    opts: { label: "ZIP应用", versionName: "1.2.0", versionCode: 3, htmlZip: buildTestZip() }
  }
];

(async () => {
  let failed = 0;
  for (const c of cases) {
    const t0 = Date.now();
    try {
      const apk = await Engine.build({ ...c.opts, assets });
      fs.writeFileSync(path.join(OUT, c.name), Buffer.from(apk));
      console.log(`✔ ${c.desc} -> ${c.name}（${(apk.length / 1024 / 1024).toFixed(2)} MB，${Date.now() - t0} ms）`);
    } catch (e) {
      failed++;
      console.error(`✘ ${c.desc} 失败：`, e.message || e);
    }
  }
  /* 异常路径测试：非法 AXML 应被引擎拒绝 */
  try {
    await Engine._internals.patchManifest(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]), { label: "X" });
    console.error("✘ 异常测试：非法 AXML 未被拦截");
    failed++;
  } catch (e) {
    console.log(`✔ 异常路径：非法 AXML 被拒绝（${e.message}）`);
  }
  console.log(failed ? `\n${failed} 个用例失败` : "\n全部用例通过");
  process.exit(failed ? 1 : 0);
})();
