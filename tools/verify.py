#!/usr/bin/env python3
"""verify.py —— 端到端验证 html2apk 生成的 APK（独立于 JS 实现，按官方规范复算）

校验项：
  1. ZIP 结构：EOCD/中央目录一致性、模板条目保留、resources.arsc 未压缩且 4 字节对齐
  2. 修补结果：manifest 字符串池中的 label/versionName/包名、versionCode 属性、
     assets/url.txt 或 index.html、图标条目
  3. v2 签名块：magic、size 字段、ID；按官方规范重算 Merkle 分块摘要；
     从证书提取 RSA 公钥对 signedData 做 PKCS#1 v1.5 验签

用法：python tools/verify.py work/out-url.apk [更多apk...]
"""
import hashlib
import struct
import sys
from pathlib import Path

DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
CHUNK = 1048576


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def parse_zip(data):
    """返回 {name: (method, csize, usize, local_offset, data_start)}，并校验 EOCD/CD 一致性"""
    # 找 EOCD
    eocd_off = None
    for i in range(65535):
        start = len(data) - 22 - i
        if start < 0:
            break
        if u32(data, start) == 0x06054b50 and u16(data, start + 20) == i:
            eocd_off = start
            break
    assert eocd_off is not None, "未找到 EOCD"
    cd_off, cd_size = u32(data, eocd_off + 16), u32(data, eocd_off + 12)
    n = u16(data, eocd_off + 10)
    assert u32(data, cd_off) == 0x02014b50, "CD 偏移无效"
    assert cd_off + cd_size == eocd_off, "CD 与 EOCD 不相邻"

    entries = {}
    p = cd_off
    for _ in range(n):
        assert u32(data, p) == 0x02014b50, "CD 记录签名错误"
        name_len, extra_len, comment_len = u16(data, p + 28), u16(data, p + 30), u16(data, p + 32)
        name = data[p + 46:p + 46 + name_len].decode("utf-8")
        method, csize, usize = u16(data, p + 10), u32(data, p + 20), u32(data, p + 24)
        loff = u32(data, p + 42)
        assert u32(data, loff) == 0x04034b50, f"{name} 本地头签名错误"
        ln, le = u16(data, loff + 26), u16(data, loff + 28)
        entries[name] = (method, csize, usize, loff, loff + 30 + ln + le)
        p += 46 + name_len + extra_len + comment_len
    assert p == cd_off + cd_size, "CD 遍历长度不匹配"
    return entries, cd_off, eocd_off


def inflate_raw(csize_data):
    import zlib
    return zlib.decompress(csize_data, -15)


def axml_strings(data):
    off = 8
    assert u16(data, off) == 0x0001, "首个 chunk 非字符串池"
    sc, str_start = u32(data, off + 8), u32(data, off + 20)
    out = []
    for i in range(sc):
        so = u32(data, off + 28 + 4 * i)
        p = off + str_start + so
        n = u16(data, p)
        out.append(data[p + 2:p + 2 + n * 2].decode("utf-16-le"))
    return out


def axml_find_attr(data, elem, attr):
    """返回 (dataType, data) 或 None"""
    off = 8 + u32(data, 12)
    strings = axml_strings(data)
    while off + 8 <= len(data):
        ct, csz = u16(data, off), u32(data, off + 4)
        if csz == 0:
            break
        if ct == 0x0102:
            if strings[u32(data, off + 20)] == elem:
                astart, asize, acount = u16(data, off + 24), u16(data, off + 26), u16(data, off + 28)
                base = off + 16 + astart
                for k in range(acount):
                    p = base + k * asize
                    if strings[u32(data, p + 4)] == attr:
                        return data[p + 15], u32(data, p + 16)
        off += csz
    return None


def merkle_digest(sections):
    """v2 规范：各 section 独立 1MB 分块；块哈希 = SHA256(0xa5||u32le(len)||chunk)；
    总摘要 = SHA256(0x5a||u32le(块数)||块哈希串接)"""
    chunk_hashes = []
    for sec in sections:
        for off in range(0, len(sec), CHUNK):
            chunk = sec[off:off + CHUNK]
            chunk_hashes.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest())
    total = hashlib.sha256(b"\x5a" + struct.pack("<I", len(chunk_hashes)) + b"".join(chunk_hashes)).digest()
    return total


def der_tlv(b, o):
    tag = b[o]; p = o + 1
    l = b[p]; p += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[p:p + n], "big"); p += n
    return tag, p, l


def extract_rsa_pub(cert):
    """从证书 DER 提取 RSA 公钥 (n, e)：Certificate→tbs→…→SPKI→RSAPublicKey"""
    _, p, _ = der_tlv(cert, 0)          # Certificate SEQUENCE
    tag, p2, l2 = der_tlv(cert, p)      # tbsCertificate SEQUENCE
    tbs_end = p2 + l2
    # 枚举 tbs 子元素
    o = p2
    kids = []
    while o < tbs_end:
        tag, cp, l = der_tlv(cert, o)
        kids.append((tag, o, cp, l))
        o = cp + l
    i = 0
    if kids[i][0] == 0xA0:
        i += 1
    idx = i + 1 + 4                     # serial 后跳过 sigAlg/issuer/validity/subject
    tag, _, cp, l = kids[idx]
    assert tag == 0x30, "SPKI 非 SEQUENCE"
    sp = cp
    # SPKI → AlgorithmIdentifier + BIT STRING(RSAPublicKey)
    tag2, sp2, sl2 = der_tlv(cert, sp)  # AlgorithmIdentifier
    bit_o = sp2 + sl2
    tag3, cp3, l3 = der_tlv(cert, bit_o)
    assert tag3 == 0x03, "SPKI 第二元素非 BIT STRING"
    inner = cp3 + 1                     # 跳过 unused-bits 字节
    # RSAPublicKey SEQUENCE → modulus, exponent
    tag4, cp4, l4 = der_tlv(cert, inner)
    assert tag4 == 0x30
    tag5, cp5, l5 = der_tlv(cert, cp4)
    n = int.from_bytes(cert[cp5:cp5 + l5], "big")
    tag6, cp6, l6 = der_tlv(cert, cp5 + l5)
    e = int.from_bytes(cert[cp6:cp6 + l6], "big")
    return n, e


def _tlv_len(b, o):
    tag, cp, l = der_tlv(b, o)
    return cp + l - o


def pkcs1v15_verify(sig, hashed, n, e):
    em = pow(int.from_bytes(sig, "big"), e, n)
    k = (n.bit_length() + 7) // 8
    em_b = em.to_bytes(k, "big")
    assert em_b[0] == 0x00 and em_b[1] == 0x01, "PKCS#1 v1.5 块类型错误"
    idx = 2
    while idx < len(em_b) and em_b[idx] == 0xFF:
        idx += 1
    assert idx >= 10, "PS 填充过短"
    assert em_b[idx] == 0x00, "缺少 0x00 分隔符"
    digest_info = DIGEST_INFO_SHA256 + hashed
    assert em_b[idx + 1:] == digest_info, "DigestInfo 不匹配"


def verify_apk(path, expect):
    print(f"\n===== 验证 {path} =====")
    data = Path(path).read_bytes()
    entries, cd_off, eocd_off = parse_zip(data)

    # --- ZIP 结构 ---
    print("[1] ZIP 结构检查")
    for must in ["AndroidManifest.xml", "classes.dex", "resources.arsc", "res/drawable/ic_launcher.png"]:
        assert must in entries, f"缺少模板条目 {must}"
    print("    模板条目全部保留 ✓")
    m, cs, us, lo, ds = entries["resources.arsc"]
    assert m == 0 and cs == us, "resources.arsc 被重压缩（Android 11+ 安装会失败）"
    assert ds % 4 == 0, f"resources.arsc 未 4 字节对齐（偏移 {ds}）"
    print(f"    resources.arsc STORED 且 4 字节对齐（偏移 {ds}）✓")

    # --- 修补结果 ---
    print("[2] manifest / assets 修补检查")
    m, cs, us, lo, ds = entries["AndroidManifest.xml"]
    manifest = data[ds:ds + cs]
    if m == 8:
        manifest = inflate_raw(manifest)
    strings = axml_strings(manifest)
    label = expect["label"]
    vname = expect["version_name"]
    vercode = expect["version_code"]
    pkg = expect.get("package")
    assert label in strings, f"label 未写入：{label}"
    assert vname in strings, f"versionName 未写入：{vname}"
    if pkg:
        assert pkg in strings, "包名未写入"
        # Activity 类名必须保持模板原值，否则系统找不到 dex 里的类而闪退
        assert "com.parap.webview.MainActivity" in strings, "Activity 类名被误改"
    r = axml_find_attr(manifest, "manifest", "versionCode")
    assert r and r[1] == vercode, f"versionCode 属性不符：{r}"
    print(f"    label={label!r} versionName={vname!r} versionCode={vercode} 包名={pkg or '默认'} ✓")

    for name in expect.get("assets_names", []):
        assert name in entries, f"缺少条目 {name}"
        print(f"    {name} ✓")
    if expect.get("icon"):
        m, cs, us, lo, ds = entries["res/drawable/ic_launcher.png"]
        assert data[ds:ds + cs] == expect["icon"], "图标未被替换"
        print("    图标已替换 ✓")

    # --- v2 签名块 ---
    print("[3] APK v2 签名验签")
    assert data[cd_off - 16:cd_off] == b"APK Sig Block 42", "CD 前无 v2 签名块 magic"
    post_size = u64(data, cd_off - 24)
    pre_off = cd_off - post_size - 8
    pre_size = u64(data, pre_off)
    assert pre_size == post_size, "签名块两个 size 字段不一致"
    # 签名块内容：[u64 pairLen][u32 ID=0x7109871a][u32 signersLen][signers]
    region = data[pre_off + 8:cd_off - 24]
    assert u64(region, 0) == len(region) - 8, "签名块 pair 长度不符"
    assert u32(region, 8) == 0x7109871a, "非 v2 签名块 ID"
    signers_len = u32(region, 12)
    signers = region[16:16 + signers_len]
    # 单 signer：[u32 len][signer]
    slen = u32(signers, 0)
    assert 4 + slen == len(signers), "存在多个 signer 或长度不符"
    signer = signers[4:4 + slen]
    # signer = [u32 sdLen][signedData][u32 sigsLen][sigs][u32 pkLen][publicKey]
    sd_len = u32(signer, 0)
    signed_data = signer[4:4 + sd_len]
    # signed_data = [u32 dgLen][digests][u32 certsLen][certs][u32 attrsLen][attrs]
    dg_len = u32(signed_data, 0)
    dg = signed_data[4:4 + dg_len]
    rec_len = u32(dg, 0)
    alg = u32(dg, 4)
    dlen = u32(dg, 8)
    digest_stored = dg[12:12 + dlen]
    certs_off = 4 + dg_len
    certs_len = u32(signed_data, certs_off)
    certs = signed_data[certs_off + 4:certs_off + 4 + certs_len]
    cert_len = u32(certs, 0)
    cert = certs[4:4 + cert_len]
    assert alg == 0x0103, f"签名算法非 RSA-SHA256: {hex(alg)}"

    # 重算摘要（EOCD 的 CD 偏移修订为签名块起点）
    revised = bytearray(data[eocd_off:])
    struct.pack_into("<I", revised, 16, pre_off)
    digest_calc = merkle_digest([data[:pre_off], data[cd_off:eocd_off], bytes(revised)])
    assert digest_calc == digest_stored, "内容摘要不匹配！"
    print("    Merkle 分块摘要重算一致 ✓")

    # RSA 验签
    sigs_len = u32(signer, 4 + sd_len)
    sigs = signer[8 + sd_len:8 + sd_len + sigs_len]
    sig_len = u32(sigs, 0)
    sig_alg = u32(sigs, 4)
    sig = sigs[12:8 + sig_len]
    assert sig_alg == 0x0103, "签名算法 ID 与摘要不一致"
    pk_len = u32(signer, 8 + sd_len + sigs_len)
    pk = signer[12 + sd_len + sigs_len:12 + sd_len + sigs_len + pk_len]
    # 公钥应与证书 SPKI 一致
    def spki_of(c):
        _, p, _ = der_tlv(c, 0)
        _, p2, l2 = der_tlv(c, p)
        o = p2
        kids = []
        while o < p2 + l2:
            tag, cp, l = der_tlv(c, o)
            kids.append((tag, o, cp + l))
            o = cp + l
        i = 1 if kids[0][0] == 0xA0 else 0
        tag, start, end = kids[i + 1 + 4]
        return c[start:end]
    assert pk == spki_of(cert), "signer 公钥与证书 SPKI 不一致"
    n, e = extract_rsa_pub(cert)
    sd_hash = hashlib.sha256(signed_data).digest()
    pkcs1v15_verify(sig, sd_hash, n, e)
    print(f"    RSA-PKCS1v15-SHA256 验签通过（{len(cert)} 字节证书，{len(sig)} 字节签名）✓")
    print("✔ 全部校验通过")


if __name__ == "__main__":
    icon = Path("work/test-icon.png").read_bytes()
    url = b"https://www.example.com"
    # 与 node-test 中一致的测试 zip 内容
    zip_assets = {
        "assets/index.html": ('<!DOCTYPE html><html><head><meta charset=utf-8>'
                              '<link rel="stylesheet" href="css/style.css"></head>'
                              '<body><h1>ZIP 模式测试成功</h1></body></html>').encode("utf-8"),
        "assets/css/style.css": b"body{background:#eef}",
    }
    html_test = ('<!DOCTYPE html><html><head><meta charset="utf-8"><title>测试页</title></head>\n'
                 '<body style="font-family:sans-serif;padding:40px"><h1>离线测试成功！</h1>\n'
                 '<p>这是由 html2apk 工具打包的本地页面。</p></body></html>').encode("utf-8")

    verify_apk("work/out-url.apk", {
        "label": "萧易寒工具箱", "version_name": "2.3.7-beta", "version_code": 5,
        "package": "com.xiao.toolkit",
        "assets": {"assets/url.txt": url},
        "icon": icon,
    })
    verify_apk("work/out-html.apk", {
        "label": "这是一个非常长的中文软件名称测试", "version_name": "1.0.0", "version_code": 1,
        "assets": {"assets/index.html": html_test},
    })
    verify_apk("work/out-zip.apk", {
        "label": "ZIP应用", "version_name": "1.2.0", "version_code": 3,
        "assets_names": list(zip_assets.keys()),
    })
    print("\n========== 全部 APK 端到端验证通过 ==========")
