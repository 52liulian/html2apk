#!/usr/bin/env python3
"""生成一个 256x256 的纯色 PNG，供 node-test.js 与 verify.py 做图标替换测试。

用法：python tools/make_test_icon.py
输出：work/test-icon.png
"""
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "work" / "test-icon.png"
W = H = 256

# 逐行像素：行首 0 为 PNG 过滤器类型，其余为 RGBA
raw = b"".join(b"\x00" + bytes([0x2F, 0x9E, 0x68, 0xFF]) * W for _ in range(H))


def chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


png = (
    b"\x89PNG\r\n\x1a\n"
    + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0))
    + chunk(b"IDAT", zlib.compress(raw, 9))
    + chunk(b"IEND", b"")
)
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_bytes(png)
print(f"已生成 {OUT}（{len(png)} 字节）")
