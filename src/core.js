"use strict";
/**
 * core.js —— HTML 转 APK 纯前端引擎（浏览器 / Node 通用，零依赖）
 *
 * 全部工作在本地完成，无 JDK/JRE、无后端：
 *   1. axml 修补  ：解析 AndroidManifest.xml 二进制（AXML），重建字符串池，
 *                   精确替换 label / versionName / 包名 / versionCode
 *                   （相较参考项目 apk-editor 的"盲替换"，支持中文与任意长度名称）
 *   2. ZIP 重打包 ：保留模板数据区原样（resources.arsc 保持未压缩对齐），
 *                   仅追加新条目并重写中央目录
 *   3. APK v2 签名：Merkle 分块摘要（0xa5 前缀 1MB 分块 → 0x5a + 块数聚合），
 *                   WebCrypto RSA-PKCS1-v1_5-SHA256 签名，
 *                   签名块插入 Central Directory 之前并修补 EOCD
 *
 * 算法移植自开源项目 apk-editor（github.com/pzx521521/apk-editor，editor/signv2）
 */
(function (global) {

  /* ==================== 常量 ==================== */
  var SIG_LOCAL = 0x04034b50;   // 本地文件头
  var SIG_CD    = 0x02014b50;   // 中央目录条目
  var SIG_EOCD  = 0x06054b50;   // EOCD
  var CHUNK_SIZE = 1048576;     // v2 摘要分块大小 1MB
  var ALG_RSA_SHA256 = 0x0103;  // APK v2 签名算法 ID：RSASSA-PKCS1-v1_5 + SHA256
  var SIG_BLOCK_MAGIC = "APK Sig Block 42";
  var SIG_BLOCK_ID_V2 = 0x7109871a;

  /* 模板 APK 中的默认值（与 WebviewDemo 工程一致） */
  var TPL_LABEL = "WebViewDemo";
  var TPL_VERSION_NAME = "111.111.111";
  var TPL_PACKAGE = "com.parap.webview";      /* 模板自带的原始包名（用于定位） */
  var DEFAULT_PACKAGE = "com.xiao.webview";   /* 未指定包名时使用的默认包名 */

  /* ==================== 字节工具 ==================== */
  function rd16(b, o) { return b[o] | (b[o + 1] << 8); }
  function rd32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

  function wr16(b, o, v) { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; }
  function wr32(b, o, v) { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; }

  /** 64 位小端写入（长度不超过 2^53，本工具足够） */
  function wr64(b, o, v) {
    var lo = v % 4294967296, hi = Math.floor(v / 4294967296);
    wr32(b, o, lo >>> 0); wr32(b, o + 4, hi >>> 0);
  }

  function concatBytes(parts) {
    var total = 0, i;
    for (i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total), p = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], p); p += parts[i].length; }
    return out;
  }

  /** 长度前缀（u32 LE） */
  function push32(data) { var out = new Uint8Array(data.length + 4); wr32(out, 0, data.length); out.set(data, 4); return out; }
  function push64(data) { var out = new Uint8Array(data.length + 8); wr64(out, 0, data.length); out.set(data, 8); return out; }

  function u32le(v) { var b = new Uint8Array(4); wr32(b, 0, v >>> 0); return b; }
  function u64le(v) { var b = new Uint8Array(8); wr64(b, 0, v); return b; }

  function ascii(s) { var b = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff; return b; }
  function utf8(s) { return new TextEncoder().encode(s); }

  /** base64 → Uint8Array（分块处理，避免大字符串栈压力） */
  function b64ToBytes(b64) {
    var clean = b64.replace(/[^A-Za-z0-9+/=]/g, "");
    var len = clean.length, out = [], CHUNK = 0x8000;
    for (var i = 0; i < len; i += CHUNK) {
      out.push(atob(clean.slice(i, i + CHUNK)));
    }
    var bin = out.join("");
    var u8 = new Uint8Array(bin.length);
    for (var j = 0; j < bin.length; j++) u8[j] = bin.charCodeAt(j);
    return u8;
  }

  /** CRC32（ZIP 条目校验用） */
  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(u8) {
    var c = 0xFFFFFFFF;
    for (var i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  /* ==================== PEM / DER ==================== */
  function pemToDer(text) {
    var m = /-----BEGIN [A-Z ]+-----([\s\S]*?)-----END/.exec(text);
    if (!m) throw new Error("PEM 格式不正确");
    return b64ToBytes(m[1]);
  }

  /** 读取一个 DER TLV */
  function derReadTLV(b, off) {
    var p = off;
    var tag = b[p++];
    var len = b[p++];
    if (len & 0x80) {
      var n = len & 0x7f;
      len = 0;
      for (var i = 0; i < n; i++) { len = len * 256 + b[p++]; }
    }
    return { tag: tag, start: off, contentStart: p, len: len, end: p + len };
  }

  /** 枚举某个 TLV 内容里的子 TLV */
  function derChildren(b, tlv) {
    var out = [], p = tlv.contentStart, end = tlv.end;
    while (p < end) {
      var t = derReadTLV(b, p);
      out.push(t);
      p = t.end;
    }
    return out;
  }

  /**
   * 从 X.509 证书 DER 中提取 SubjectPublicKeyInfo（v2 签名块的 public key 字段）
   * Certificate → tbsCertificate → [version][serial][sigAlg][issuer][validity][subject][SPKI]...
   */
  function extractSpki(certDer) {
    var certTlv = derReadTLV(certDer, 0);
    if (certTlv.tag !== 0x30) throw new Error("证书 DER 结构不正确");
    var tbs = derChildren(certDer, certTlv)[0];
    var kids = derChildren(certDer, tbs);
    var i = 0;
    if (kids[i] && kids[i].tag === 0xA0) i++;      // [0] version（可选）
    i += 1 + 4;                                     // serial + sigAlg/issuer/validity/subject
    var spki = kids[i];
    if (!spki || spki.tag !== 0x30) throw new Error("未在证书中找到 SubjectPublicKeyInfo");
    return certDer.subarray(spki.start, spki.end);
  }

  /** PKCS#1 私钥 DER → PKCS#8 DER（WebCrypto importKey 需要 PKCS#8） */
  function pkcs1ToPkcs8(pkcs1) {
    // RSAPrivateKey ::= SEQUENCE —— 直接整包放入 OCTET STRING
    var version = new Uint8Array([0x02, 0x01, 0x00]);                       // INTEGER 0
    var algId = new Uint8Array([
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    ]);                                                                     // rsaEncryption + NULL
    var octetHead;
    if (pkcs1.length < 128) {
      octetHead = new Uint8Array([0x04, pkcs1.length]);
    } else {
      // 长格式：0x04 0x8n + 多字节长度（密钥 < 64KB，最多 2 字节）
      var n2 = pkcs1.length, nb2 = [];
      while (n2 > 0) { nb2.unshift(n2 & 0xff); n2 = Math.floor(n2 / 256); }
      octetHead = new Uint8Array(2 + nb2.length);
      octetHead[0] = 0x04; octetHead[1] = 0x80 | nb2.length;
      octetHead.set(nb2, 2);
    }
    var octet = concatBytes([octetHead, pkcs1]);
    var content = concatBytes([version, algId, octet]);
    var head;
    if (content.length < 128) {
      head = new Uint8Array([0x30, content.length]);
    } else {
      var n = content.length, nb = [];
      while (n > 0) { nb.unshift(n & 0xff); n >>>= 8; }
      head = new Uint8Array(2 + nb.length);
      head[0] = 0x30; head[1] = 0x80 | nb.length;
      head.set(nb, 2);
    }
    return concatBytes([head, content]);
  }

  /* ==================== AXML 修补（移植 axml.go） ==================== */
  var CHUNK_STRING_POOL = 0x0001, CHUNK_XML_RESOURCE = 0x0003, CHUNK_XML_START_ELEM = 0x0102;
  var ATTR_TYPE_INT_DEC = 0x10;

  /**
   * 修补模板 AndroidManifest.xml
   * req: { label, versionName, versionCode, package }
   */
  function patchManifest(data, req) {
    if (data.length < 8 || rd16(data, 0) !== CHUNK_XML_RESOURCE) {
      throw new Error("manifest 不是有效的 AXML 文件");
    }

    /* 1. 解析首个内部 chunk：字符串池（UTF-16） */
    var poolStart = 8;
    if (rd16(data, poolStart) !== CHUNK_STRING_POOL) throw new Error("manifest 首个 chunk 不是字符串池");
    var poolSize = rd32(data, poolStart + 4);
    var poolEnd = poolStart + poolSize;
    if (poolEnd > data.length) throw new Error("字符串池长度越界");
    if (rd32(data, poolStart + 16) & 0x100) throw new Error("模板字符串池为 UTF-8 编码，暂不支持");

    var stringCount = rd32(data, poolStart + 8);
    var stringsStart = rd32(data, poolStart + 20);
    var flags = rd32(data, poolStart + 16);
    var strings = [];
    for (var i = 0; i < stringCount; i++) {
      var rel = rd32(data, poolStart + 28 + 4 * i);
      var abs = poolStart + stringsStart + rel;
      var n = rd16(data, abs);
      var units = [];
      for (var k = 0; k < n; k++) units.push(rd16(data, abs + 2 + k * 2));
      strings.push(String.fromCharCode.apply(null, units));
    }

    /* 2. 按内容定位模板字符串 */
    function idxOf(s) { return strings.indexOf(s); }
    var idxLabel = idxOf(TPL_LABEL);
    var idxVersionName = idxOf(TPL_VERSION_NAME);
    var idxPackage = idxOf(TPL_PACKAGE);
    var idxActivity = idxOf(TPL_PACKAGE + ".MainActivity");
    if (idxLabel < 0 || idxVersionName < 0 || idxPackage < 0 || idxActivity < 0) {
      throw new Error("模板 manifest 中未找到预期的默认字符串，模板文件可能不匹配");
    }

    /* 3. 替换字符串（数量不变）
     * 注意：Activity 类名必须保持模板原值 com.parap.webview.MainActivity。
     * 该类已编译进 classes3.dex，改 manifest 里的类名只会让系统找不到类而闪退。
     * 这里只改 applicationId（package 属性），Android 允许它与 Activity 实际类名不一致。 */
    if (req.label) strings[idxLabel] = req.label;
    if (req.versionName) strings[idxVersionName] = req.versionName;
    var pkg = req["package"] || DEFAULT_PACKAGE;
    strings[idxPackage] = pkg;
    /* idxActivity 对应的字符串保持不变，显式写出以便审阅 */
    void idxActivity;

    /* 3.5 准备权限变更：勾选但模板未声明的新增；模板已声明但取消勾选的移除。
     * permissionCatalog 界定"用户可决定的权限范围"，模板里不在清单中的权限
     * （如 ACCESS_NETWORK_STATE）保持原样，避免误删系统依赖。 */
    var permsToAdd = [], permsToRemove = [];
    var existing = collectExistingPerms(data.subarray(poolEnd), strings);
    var reqPerms = req.permissions || [];
    var checked = {};
    for (var c0 = 0; c0 < reqPerms.length; c0++) checked[reqPerms[c0]] = true;
    var catalog = req.permissionCatalog || reqPerms;
    for (var r0 = 0; r0 < catalog.length; r0++) {
      if (existing[catalog[r0]] && !checked[catalog[r0]]) permsToRemove.push(catalog[r0]);
    }
    for (var pi = 0; pi < reqPerms.length; pi++) {
      var pname = reqPerms[pi];
      if (!pname || existing[pname]) continue;
      var pidx = idxOf(pname);
      if (pidx < 0) { strings.push(pname); pidx = strings.length - 1; } /* 追加在末尾，已有索引不变 */
      permsToAdd.push(pidx);
    }

    /* 4. 重建字符串池：头(28B) + 偏移表 + 逐条 4 字节对齐的 UTF-16 数据 */
    var offsets = new Uint32Array(strings.length);
    var dataParts = [];
    var acc = 0;
    for (var s = 0; s < strings.length; s++) {
      var units2 = [];
      for (var c = 0; c < strings[s].length; c++) units2.push(strings[s].charCodeAt(c));
      var bodyLen = 2 + units2.length * 2 + 2;          // 长度 + 字符 + 终止符
      var padded = bodyLen + ((4 - (bodyLen % 4)) % 4); // 补齐 4 字节
      var entry = new Uint8Array(padded);
      var p2 = 0;
      wr16(entry, p2, units2.length); p2 += 2;
      for (var c2 = 0; c2 < units2.length; c2++) { wr16(entry, p2, units2[c2]); p2 += 2; }
      wr16(entry, p2, 0); p2 += 2;                      // 终止符
      offsets[s] = acc;
      acc += padded;
      dataParts.push(entry);
    }

    var stringsStart2 = 28 + 4 * strings.length;
    var total2 = stringsStart2 + acc;
    var pool = new Uint8Array(total2);
    wr16(pool, 0, CHUNK_STRING_POOL);
    wr16(pool, 2, 28);                // headerSize
    wr32(pool, 4, total2);            // chunk 大小
    wr32(pool, 8, strings.length);    // stringCount
    wr32(pool, 12, 0);                // styleCount
    wr32(pool, 16, flags);            // 沿用原始 flags
    wr32(pool, 20, stringsStart2);
    wr32(pool, 24, 0);                // stylesStart
    for (var o2 = 0; o2 < offsets.length; o2++) wr32(pool, 28 + 4 * o2, offsets[o2]);
    var pp = stringsStart2;
    for (var d2 = 0; d2 < dataParts.length; d2++) { pool.set(dataParts[d2], pp); pp += dataParts[d2].length; }

    /* 5. 在池后的 XML 节点流中插入权限声明，并修补 versionCode */
    var rest = data.subarray(poolEnd);
    if (permsToRemove.length) rest = removePermissions(rest, strings, permsToRemove);
    if (permsToAdd.length) rest = insertPermissions(rest, strings, permsToAdd);
    if (req.versionCode) patchVersionCode(rest, strings, req.versionCode);

    /* 6. 拼接并修正外层 XML chunk 总长度 */
    var out = concatBytes([data.subarray(0, 8), pool, rest]);
    wr32(out, 4, out.length);
    return out;
  }

  /**
   * 扫描 XML 节点流，收集模板中已声明的权限名（避免重复添加联网权限）
   * 节点流相对 poolEnd 起算，各 chunk 顺序：resource map → 元素节点…
   */
  function collectExistingPerms(data, strings) {
    var found = {};
    var idxUses = strings.indexOf("uses-permission");
    var idxName = strings.indexOf("name");
    if (idxUses < 0 || idxName < 0) return found;
    var off = 0;
    while (off + 8 <= data.length) {
      var t = rd16(data, off), size = rd32(data, off + 4);
      if (size < 8 || off + size > data.length) break;
      if (t === CHUNK_XML_START_ELEM && rd32(data, off + 20) === idxUses) {
        var attrStart = rd16(data, off + 24);
        var attrSize = rd16(data, off + 26);
        var attrCount = rd16(data, off + 28);
        for (var k = 0; k < attrCount; k++) {
          var ap = off + 16 + attrStart + k * attrSize;
          if (rd32(data, ap + 4) === idxName && data[ap + 15] === 0x03) {
            var vi = rd32(data, ap + 16);
            if (vi < strings.length) found[strings[vi]] = true;
          }
        }
      }
      off += size;
    }
    return found;
  }

  /**
   * 从节点流中删除指定的 uses-permission 节点对（START + 紧随的 END）。
   * 模板内置的联网权限在用户取消勾选时走这里，保证勾选框与产物一致。
   * uses-permission 是空元素，START 后紧跟对应 END，因此成对跳过即可，无需维护栈。
   */
  function removePermissions(data, strings, names) {
    var idxUses = strings.indexOf("uses-permission");
    var idxName = strings.indexOf("name");
    if (idxUses < 0 || idxName < 0) throw new Error("模板缺少权限节点所需的字符串");
    var want = {};
    for (var w = 0; w < names.length; w++) want[names[w]] = true;

    var blocks = [], off = 0, skipEnd = false;
    while (off + 8 <= data.length) {
      var t = rd16(data, off), size = rd32(data, off + 4);
      if (size < 8 || off + size > data.length) { blocks.push(data.subarray(off)); break; }
      if (skipEnd) { skipEnd = false; off += size; continue; } /* 被删 START 的配对 END */
      if (t === CHUNK_XML_START_ELEM && rd32(data, off + 20) === idxUses) {
        var pname = permNameOf(data, off, idxName, strings);
        if (pname && want[pname]) { skipEnd = true; off += size; continue; }
      }
      blocks.push(data.subarray(off, off + size));
      off += size;
    }
    return blocks.length ? concatBytes(blocks) : new Uint8Array(0);
  }

  /** 读取 uses-permission START 节点的 android:name 属性值 */
  function permNameOf(data, off, idxName, strings) {
    var attrStart = rd16(data, off + 24);
    var attrSize = rd16(data, off + 26);
    var attrCount = rd16(data, off + 28);
    for (var k = 0; k < attrCount; k++) {
      var ap = off + 16 + attrStart + k * attrSize;
      if (rd32(data, ap + 4) === idxName && data[ap + 15] === 0x03) {
        var vi = rd32(data, ap + 16);
        return vi < strings.length ? strings[vi] : null;
      }
    }
    return null;
  }

  /**
   * 在 manifest 节点流中插入 uses-permission 节点对。
   * 模板里已有 INTERNET 与 ACCESS_NETWORK_STATE 两个权限节点，
   * 新节点插在第一个 uses-permission 之前，结构照抄模板（START 56B + END 24B）。
   */
  function insertPermissions(data, strings, nameIndexes) {
    var idxUses = strings.indexOf("uses-permission");
    var idxName = strings.indexOf("name");
    var idxNs = strings.indexOf("http://schemas.android.com/apk/res/android");
    if (idxUses < 0 || idxName < 0 || idxNs < 0) throw new Error("模板缺少构造权限节点所需的字符串");

    /* 定位插入点：第一个 uses-permission START 节点的偏移 */
    var insertAt = -1, off = 0;
    while (off + 8 <= data.length) {
      var t = rd16(data, off), size = rd32(data, off + 4);
      if (size < 8 || off + size > data.length) break;
      if (t === CHUNK_XML_START_ELEM && rd32(data, off + 20) === idxUses) { insertAt = off; break; }
      off += size;
    }
    if (insertAt < 0) throw new Error("模板中未找到 uses-permission 节点，无法插入权限");

    /* 复制模板权限节点的结构，仅替换权限名字符串索引 */
    var templateStart = data.subarray(insertAt, insertAt + 56);
    var templateEnd = data.subarray(insertAt + 56, insertAt + 80);
    if (templateStart.length !== 56 || templateEnd.length !== 80 - 56) throw new Error("模板权限节点结构异常");

    var blocks = [data.subarray(0, insertAt)];
    for (var i = 0; i < nameIndexes.length; i++) {
      var start = new Uint8Array(templateStart);
      var end = new Uint8Array(templateEnd);
      /* rawValue 与 typedValue.data 都要指向新的权限名索引 */
      wr32(start, 36 + 8, nameIndexes[i]);   /* attribute.rawValue */
      wr32(start, 36 + 16, nameIndexes[i]);  /* attribute.typedValue.data */
      blocks.push(start, end);
    }
    blocks.push(data.subarray(insertAt));
    return concatBytes(blocks);
  }

  /** 在 START_ELEMENT chunk 流中定位 manifest 元素的 versionCode 属性并就地修补 */
  function patchVersionCode(data, strings, versionCode) {
    var off = 0;
    while (off + 8 <= data.length) {
      var chunkType = rd16(data, off);
      var chunkSize = rd32(data, off + 4);
      if (chunkSize <= 0 || off + chunkSize > data.length) break;
      if (chunkType === CHUNK_XML_START_ELEM) {
        var chunk = data.subarray(off, off + chunkSize);
        if (patchAttrInElement(chunk, strings, versionCode)) return;
      }
      off += chunkSize;
    }
    throw new Error("未在 manifest 元素中找到 versionCode 属性");
  }

  /**
   * START_ELEMENT 布局（小端）：
   *  [0]u16 type [2]u16 headerSize(16) [4]u32 size [8]u32 line [12]u32 comment
   *  [16]u32 ns [20]u32 name [24]u16 attrStart(自 attrExt 起) [26]u16 attrSize [28]u16 attrCount ...
   *  属性（20B/条）：+0 ns +4 name +8 rawValue +12 size +14 res0 +15 dataType +16 data
   * 返回是否命中并已修补
   */
  function patchAttrInElement(chunk, strings, versionCode) {
    if (chunk.length < 40) return false;
    var nameIdx = rd32(chunk, 20);
    if (nameIdx >= strings.length || strings[nameIdx] !== "manifest") return false;
    var attrStart = rd16(chunk, 24);
    var attrSize = rd16(chunk, 26);
    var attrCount = rd16(chunk, 28);
    if (attrSize !== 20) throw new Error("不支持的属性尺寸: " + attrSize);
    var base = 16 + attrStart;                 // attrStart 自节点扩展头（偏移16）起算
    for (var i = 0; i < attrCount; i++) {
      var p = base + i * attrSize;
      if (p + 20 > chunk.length) throw new Error("属性数据越界");
      var aNameIdx = rd32(chunk, p + 4);
      var dataType = chunk[p + 15];
      if (aNameIdx < strings.length && strings[aNameIdx] === "versionCode" && dataType === ATTR_TYPE_INT_DEC) {
        wr32(chunk, p + 16, versionCode >>> 0);
        return true;
      }
    }
    return false;
  }

  /* ==================== ZIP 解析 / 重打包 ==================== */

  /** 从尾部向前扫描 EOCD，校验 CD 相邻性 */
  function locateZip(u8) {
    if (u8.length < 22) throw new Error("不是合法的 ZIP 文件");
    for (var i = 0; i < 65535; i++) {
      var start = u8.length - 22 - i;
      if (start < 0) break;
      if (rd32(u8, start) !== SIG_EOCD) continue;
      var commentLen = rd16(u8, start + 20);
      if (commentLen !== i) continue;
      var cdOffset = rd32(u8, start + 16);
      var cdSize = rd32(u8, start + 12);
      if (cdOffset + 4 > u8.length || rd32(u8, cdOffset) !== SIG_CD) continue;
      if (cdOffset + cdSize !== start) throw new Error("ZIP 中央目录与 EOCD 不相邻");
      return { cdOffset: cdOffset, cdSize: cdSize, eocdOffset: start, eocdRaw: u8.subarray(start) };
    }
    throw new Error("未找到 ZIP EOCD 记录");
  }

  /** 解析中央目录，返回条目列表（record 为原始 CD 记录字节，便于原样复制） */
  function parseCentralDirectory(u8, z) {
    var entries = [];
    var p = z.cdOffset, end = z.cdOffset + z.cdSize;
    while (p + 46 <= end && rd32(u8, p) === SIG_CD) {
      var nameLen = rd16(u8, p + 28), extraLen = rd16(u8, p + 30), commentLen = rd16(u8, p + 32);
      var recLen = 46 + nameLen + extraLen + commentLen;
      entries.push({
        name: new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nameLen)),
        record: u8.subarray(p, p + recLen),
        localOffset: rd32(u8, p + 42)
      });
      p += recLen;
    }
    return entries;
  }

  function findEntry(u8, name) {
    var z = locateZip(u8);
    var entries = parseCentralDirectory(u8, z);
    for (var i = 0; i < entries.length; i++) if (entries[i].name === name) return entries[i];
    throw new Error("ZIP 中未找到条目 " + name);
  }

  /** 解压 raw deflate（Web API DecompressionStream，Chrome/Edge 103+、Node 22） */
  function inflateRaw(data) {
    if (typeof DecompressionStream === "undefined") {
      return Promise.reject(new Error("当前环境不支持 DecompressionStream，请使用新版 Chrome / Edge 浏览器"));
    }
    var ds = new DecompressionStream("deflate-raw");
    var stream = new Blob([data]).stream().pipeThrough(ds);
    return new Response(stream).arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
  }

  /** 读取 ZIP 条目完整数据（尺寸取自中央目录，兼容数据描述符） */
  function readEntryData(u8, entry) {
    var o = entry.localOffset;
    if (rd32(u8, o) !== SIG_LOCAL) throw new Error("本地文件头签名错误: " + entry.name);
    var method = rd16(u8, o + 8);
    var nameLen = rd16(u8, o + 26), extraLen = rd16(u8, o + 28);
    var dataStart = o + 30 + nameLen + extraLen;
    // 压缩尺寸取 CD 记录（+20 偏移处），避免 data descriptor 置零问题
    var csize = rd32(entry.record, 20);
    var raw = u8.subarray(dataStart, dataStart + csize);
    if (method === 0) return Promise.resolve(raw.slice());
    if (method === 8) return inflateRaw(raw);
    return Promise.reject(new Error("不支持的压缩方法 " + method + "（条目 " + entry.name + "）"));
  }

  /** 构建新条目的中央目录记录（STORED） */
  function buildCDRecord(name, offset, size, crcVal) {
    var nameB = utf8(name);
    var rec = new Uint8Array(46 + nameB.length);
    wr32(rec, 0, SIG_CD);
    wr16(rec, 4, (3 << 8) | 20);      // made by: Unix + ZIP 2.0
    wr16(rec, 6, 20);                 // needed
    wr16(rec, 8, 0);                  // flags
    wr16(rec, 10, 0);                 // method: STORED
    wr16(rec, 12, 0); wr16(rec, 14, 0); // time/date
    wr32(rec, 16, crcVal);
    wr32(rec, 20, size); wr32(rec, 24, size);
    wr16(rec, 28, nameB.length);
    // extra/comment/disk/attrs 全 0
    wr32(rec, 42, offset);
    rec.set(nameB, 46);
    return rec;
  }

  /**
   * 追加式重打包：模板数据区（0..cdOffset）原样保留，
   * 追加新条目（STORED），重写中央目录与 EOCD。同名条目以新条目为准。
   */
  function rebuildZip(u8, newEntries) {
    var z = locateZip(u8);
    var entries = parseCentralDirectory(u8, z);
    var replaceNames = {};
    var i;
    for (i = 0; i < newEntries.length; i++) replaceNames[newEntries[i].name] = true;

    var head = u8.slice(0, z.cdOffset);          // 数据区原样（保持原有对齐）
    var parts = [head];
    var newRecs = [];
    var offset = head.length;
    for (i = 0; i < newEntries.length; i++) {
      var e = newEntries[i];
      var nameB = utf8(e.name);
      var crcVal = crc32(e.data);
      var lh = new Uint8Array(30 + nameB.length);
      wr32(lh, 0, SIG_LOCAL);
      wr16(lh, 4, 20); wr16(lh, 6, 0);
      wr16(lh, 8, 0);                            // STORED
      wr16(lh, 10, 0); wr16(lh, 12, 0);
      wr32(lh, 14, crcVal);
      wr32(lh, 18, e.data.length); wr32(lh, 22, e.data.length);
      wr16(lh, 26, nameB.length); wr16(lh, 28, 0);
      lh.set(nameB, 30);
      parts.push(lh, e.data);
      newRecs.push({ name: e.name, offset: offset, size: e.data.length, crc: crcVal });
      offset += lh.length + e.data.length;
    }

    var cdParts = [];
    var count = 0;
    for (i = 0; i < entries.length; i++) {
      if (!replaceNames[entries[i].name]) { cdParts.push(entries[i].record); count++; }
    }
    for (i = 0; i < newRecs.length; i++) {
      cdParts.push(buildCDRecord(newRecs[i].name, newRecs[i].offset, newRecs[i].size, newRecs[i].crc));
      count++;
    }
    var cdBytes = concatBytes(cdParts);
    var cdOffset2 = offset;
    parts.push(cdBytes);

    var eocd = z.eocdRaw.slice();
    wr16(eocd, 8, count); wr16(eocd, 10, count);
    wr32(eocd, 12, cdBytes.length);
    wr32(eocd, 16, cdOffset2);
    parts.push(eocd);

    return concatBytes(parts);
  }

  /* ==================== APK v2 签名（移植 signv2） ==================== */

  function sha256(data) {
    return crypto.subtle.digest("SHA-256", data).then(function (ab) { return new Uint8Array(ab); });
  }

  /**
   * v2 Merkle 分块摘要：输入按 1MB 分块（三个 section 各自独立分块），
   * 每块计算 SHA256(0xa5 || u32le(len) || chunk)，最终 SHA256(0x5a || u32le(块数) || 所有块哈希)
   */
  function digestAll(sections) {
    var chunkHashes = [];
    var chain = Promise.resolve();
    sections.forEach(function (sec) {
      for (var off = 0; off < sec.length; off += CHUNK_SIZE) {
        (function (start) {
          var chunk = sec.subarray(start, Math.min(start + CHUNK_SIZE, sec.length));
          var prefixed = new Uint8Array(chunk.length + 5);
          prefixed[0] = 0xa5;
          wr32(prefixed, 1, chunk.length);
          prefixed.set(chunk, 5);
          chain = chain.then(function () { return sha256(prefixed); }).then(function (h) { chunkHashes.push(h); });
        })(off);
      }
    });
    return chain.then(function () {
      var countBuf = u32le(chunkHashes.length);
      return sha256(concatBytes([new Uint8Array([0x5a]), countBuf].concat(chunkHashes)));
    });
  }

  /**
   * 对重打包后的 ZIP 做 v2 签名。
   * keyPem/certPem：PEM 文本；返回签名完成的 APK 字节。
   */
  function signV2(apk, keyPem, certPem) {
    var keyDer = pemToDer(keyPem);
    var certDer = pemToDer(certPem);
    var isPkcs1 = /RSA PRIVATE KEY/.test(keyPem);
    var pkcs8 = isPkcs1 ? pkcs1ToPkcs8(keyDer) : keyDer;
    var spki = extractSpki(certDer);

    /* 定位 CD / EOCD（重打包产物无既有 v2 块） */
    var z = locateZip(apk);
    var cdOffset = z.cdOffset, eocdOffset = z.eocdOffset;
    var endOfFiles = cdOffset;

    /* 1. 摘要：文件区 + 中央目录 + 修订版 EOCD（CD 偏移指向 v2 块位置） */
    var eocd = apk.subarray(eocdOffset);
    var revisedEocd = eocd.slice();
    wr32(revisedEocd, 16, endOfFiles);

    var keyPromise = crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    return digestAll([apk.subarray(0, endOfFiles), apk.subarray(cdOffset, eocdOffset), revisedEocd])
      .then(function (digest) {
        /* 2. 组装 signedData：digests + certs + attributes(空) */
        var digestRecord = concatBytes([u32le(ALG_RSA_SHA256), u32le(digest.length), digest]);
        var digestsSeq = push32(push32(digestRecord));
        var certsSeq = push32(push32(certDer));
        var attrsSeq = push32(new Uint8Array(0));
        var signedData = concatBytes([digestsSeq, certsSeq, attrsSeq]);
        /* 3. RSA-PKCS1-v1_5-SHA256 签名 */
        return keyPromise.then(function (key) {
          return crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, signedData);
        }).then(function (sigAb) {
          var sig = new Uint8Array(sigAb);
          /* 4. signer = push32(signedData) + push32(signatures) + push32(publicKey) */
          var sigRecord = concatBytes([u32le(ALG_RSA_SHA256), push32(sig)]);
          var sigsSeq = push32(push32(sigRecord));
          var signer = concatBytes([push32(signedData), sigsSeq, push32(spki)]);
          /* 签名者序列：u32 总长 + [u32 单签名者长 + 签名者]（官方规范两级前缀） */
          var signersSeq = push32(push32(signer));
          /* 5. ID-value 对：u32 ID + 签名者序列，再套 u64 长度 */
          var pair = push32(signersSeq);
          wr32(pair, 0, SIG_BLOCK_ID_V2);
          var asv2 = push64(pair);
          /* 6. 最终块：u64 size + 内容 + u64 size + magic */
          var finalSize = asv2.length + 8 + 16;
          var magic = ascii(SIG_BLOCK_MAGIC);
          var block = concatBytes([u64le(finalSize), asv2, u64le(finalSize), magic]);
          /* 7. 注入 CD 之前，修补 EOCD 的 CD 偏移 */
          var newEocd = eocd.slice();
          wr32(newEocd, 16, endOfFiles + block.length);
          return concatBytes([
            apk.subarray(0, endOfFiles),
            block,
            apk.subarray(cdOffset, eocdOffset),
            newEocd
          ]);
        });
      });
  }

  /* ==================== 主入口 ==================== */

  /** 解析用户上传的 HTML 压缩包，返回 [{name, data}]（跳过目录，防路径穿越） */
  function readZipEntries(data) {
    var z = locateZip(data);
    var entries = parseCentralDirectory(data, z);
    var jobs = [];
    for (var i = 0; i < entries.length; i++) {
      (function (e) {
        if (e.name.endsWith("/")) return;                    // 目录条目
        var name = e.name.replace(/^\/+/, "");
        if (!name || name.indexOf("..") !== -1 || name.indexOf("\\") !== -1) {
          throw new Error("压缩包包含非法路径：" + e.name);
        }
        jobs.push(readEntryData(data, e).then(function (d) {
          return { name: name, data: d };
        }));
      })(entries[i]);
    }
    return Promise.all(jobs);
  }

  /**
   * 构建完整 APK
   * opts: {
   *   label, versionName, versionCode,
   *   package?,                                  包名（可选）
   *   url | html | htmlZip?,                     WebView 内容三选一（html/htmlZip 为 Uint8Array）
   *   icon?                                      PNG 字节（Uint8Array，可选）
   *   assets: { apk, cert, key }                 base64 / PEM 文本
   * }
   */
  function build(opts) {
    if (!opts || !opts.assets || !opts.assets.apk) throw new Error("缺少模板 APK 数据");
    var tpl = typeof opts.assets.apk === "string" ? b64ToBytes(opts.assets.apk) : opts.assets.apk;

    /* 1. 读取并修补 manifest */
    return readEntryData(tpl, findEntry(tpl, "AndroidManifest.xml"))
      .then(function (manifest) {
        var patched = patchManifest(manifest, {
          label: opts.label,
          versionName: opts.versionName,
          versionCode: opts.versionCode,
          "package": opts["package"],
          permissions: opts.permissions,
          permissionCatalog: opts.permissionCatalog
        });

        /* 2. 组装新条目 */
        var entries = [{ name: "AndroidManifest.xml", data: patched }];
        var contentJobs = Promise.resolve();
        if (opts.url) {
          entries.push({ name: "assets/url.txt", data: utf8(opts.url) });
        } else if (opts.html) {
          entries.push({ name: "assets/index.html", data: opts.html });
        } else if (opts.htmlZip) {
          contentJobs = readZipEntries(opts.htmlZip).then(function (items) {
            for (var i = 0; i < items.length; i++) {
              entries.push({ name: "assets/" + items[i].name, data: items[i].data });
            }
          });
        }
        if (opts.icon) entries.push({ name: "res/drawable/ic_launcher.png", data: opts.icon });

        return contentJobs.then(function () {
          /* 3. 追加式重打包 + v2 签名 */
          var unsigned = rebuildZip(tpl, entries);
          return signV2(unsigned, opts.assets.key, opts.assets.cert);
        });
      });
  }

  /* 导出：主入口 + 内部函数（供 Node 测试） */
  global.Html2Apk = {
    build: build,
    _internals: {
      patchManifest: patchManifest,
      rebuildZip: rebuildZip,
      signV2: signV2,
      locateZip: locateZip,
      parseCentralDirectory: parseCentralDirectory,
      readEntryData: readEntryData,
      findEntry: findEntry,
      readZipEntries: readZipEntries,
      crc32: crc32,
      extractSpki: extractSpki,
      pkcs1ToPkcs8: pkcs1ToPkcs8,
      b64ToBytes: b64ToBytes
    }
  };

})(typeof window !== "undefined" ? window : globalThis);
