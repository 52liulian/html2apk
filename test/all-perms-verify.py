"""全权限 APK 静态校验：节点流精确统计 + 独立 v2 验签"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from verify import axml_strings, inflate_raw, parse_zip, verify_apk

APK = ROOT / "work/out-allperms.apk"
want = json.loads((ROOT / "work/allperms.json").read_text())

data = APK.read_bytes()
entries, _, _ = parse_zip(data)
method, csize, usize, loff, dstart = entries["AndroidManifest.xml"]
manifest = data[dstart:dstart + csize]
if method == 8:
    manifest = inflate_raw(manifest)

strings = axml_strings(manifest)
idx_uses = strings.index("uses-permission")
idx_name = strings.index("name")

# 跳过外层 8 字节头 + 整个字符串池，得到 XML 节点流
off = 8 + struct.unpack_from("<I", manifest, 12)[0]
found = []
while off + 8 <= len(manifest):
    typ = struct.unpack_from("<H", manifest, off)[0]
    size = struct.unpack_from("<I", manifest, off + 4)[0]
    if size < 8 or off + size > len(manifest):
        break
    if typ == 0x0102 and struct.unpack_from("<I", manifest, off + 20)[0] == idx_uses:
        attr_start = struct.unpack_from("<H", manifest, off + 24)[0]
        attr_size = struct.unpack_from("<H", manifest, off + 26)[0]
        attr_count = struct.unpack_from("<H", manifest, off + 28)[0]
        for k in range(attr_count):
            ap = off + 16 + attr_start + k * attr_size
            if struct.unpack_from("<I", manifest, ap + 4)[0] == idx_name and manifest[ap + 15] == 3:
                vi = struct.unpack_from("<I", manifest, ap + 16)[0]
                found.append(strings[vi])
    off += size

print("[静态] manifest uses-permission 节点数:", len(found))
for p in found:
    print("   ", p, "(清单内)" if p in want else "(模板固有)")
missing = [p for p in want if p not in found]
assert not missing, "以下权限未写入 manifest: " + ", ".join(missing)
print("[静态] 14 项权限全部命中 ✓")

# 独立验签（结构 + 摘要重算 + RSA 验签）
verify_apk(str(APK), {
    "label": "全权限测试",
    "version_name": "1.0",
    "version_code": 1,
    "package": "com.xiao.allperms",
    "permissions": want,
    "assets": {"assets/url.txt": b"https://example.com"},
})
print("[静态] 全权限 APK 校验通过 ✓")
