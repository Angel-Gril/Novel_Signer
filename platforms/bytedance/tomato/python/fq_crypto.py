"""
fq_crypto.py — 番茄小说(com.dragon.read) 签名头与正文解密 纯 Python 实现
=====================================================================
依据:
  1. linzj/fanqie-dl (逆向 libmetasec_ml.so, 番茄 v7.1.3.32) 的 Rust 实现逐行移植
  2. linux.do 帖子《v4-flash硬闯番茄7神纯算！！》截图中披露的 7 神结构
  3. huaerxiela/douyin-algorithm (抖音 23.2.0, 4神社区版) 交叉验证

包含:
  X-Khronos / X-Neptune / X-Gorgon / X-Ladon / X-Argus / X-Helios —— 可纯算
  registerkey 密钥协商 + 章节正文 AES-CBC 解密 + zlib 解压 —— 可纯算
  X-Helios (helios_vm.py) —— 纯算
  X-Medusa (medusa_f13.py + medusa_body.py) —— 旧快照/样本级实现；当前线上 VM 仍需独立参数化
"""
import base64, hashlib, random, struct, time, zlib
from Crypto.Cipher import AES

# ============================================================
# 0. 常量
# ============================================================
# Argus 签名主密钥 (社区公开, 番茄与抖音同一颗, fanqie-dl 在 so 中定位)
SIGN_KEY = bytes([
    0xac,0x1a,0xda,0xae,0x95,0xa7,0xaf,0x94,0xa5,0x11,0x4a,0xb3,0xb3,0xa9,0x7d,0xd8,
    0x00,0x50,0xaa,0x0a,0x39,0x31,0x4c,0x40,0x52,0x8c,0xae,0xc9,0x52,0x56,0xc2,0x8c,
])
ARGUS_SALT = bytes([0xf2, 0x81, 0x61, 0x6f])          # argus 内层 key 派生盐
ARGUS_PREFIX = bytes([0xa6,0x6e,0xad,0x9f,0x77,0x01,0xd0,0x0c,0x18])
ARGUS_MAGIC_PREFIX = bytes([0xf2, 0x81])              # 结果前缀
ARGUS_INNER_PAD = bytes([0xf2,0xf7,0xfc,0xff]*2)

# 内容加密: registerkey 固定密钥 (po4.a / FqCrypto.REG_KEY)
REG_KEY_HEX = "ac25c67ddd8f38c1b37a2348828e222e"

AID = 1967                                             # 番茄 novelapp 的 aid
LICENSE_ID = 1611921764

# ============================================================
# 1. X-Khronos —— 秒级时间戳 (可自选)
# ============================================================
def x_khronos(ts: int | None = None) -> str:
    return str(ts or int(time.time()))

# ============================================================
# 2. X-Neptune —— 本地时间软时间戳 ("-11|HH:MM:SS" 结构)
#    注: imengying/unidbg 在发请求前直接把 X-Neptune 删掉,
#        说明番茄服务端对小说接口不校验它 (6->7 神新增的软校验头)
# ============================================================
def x_neptune(t: float | None = None) -> str:
    lt = time.localtime(t or time.time())
    return time.strftime("%m-%d-%H|%M:%S", lt)         # 如 "08-13-22|08:32"

# ============================================================
# 3. X-Gorgon (0404 版) —— MD5(query/data/cookie)+时间戳 -> 自定义S盒(魔改RC4 KSA/PRGA)
#    输出: "0404" + hex(d0) + hex(e4) + "0001" + 20B hex
# ============================================================
def _nibble_swap(b: int) -> int:                       # fanqie-dl reverse()
    return ((b & 0xF) << 4) | (b >> 4)

class _XG:
    def __init__(self, debug: list[int]):
        self.length = 0x14
        self.debug = debug[:]
        self.hex510 = [0x1E, 0x00, 0xE0, 0xE4, 0x93, 0x45, 0x01, 0xD0]

    def _ksa(self):                                    # addr_920(): 魔改 RC4 KSA
        box = list(range(0x100))
        tmp = None
        for i in range(0x100):
            a = 0 if i == 0 else (tmp if tmp is not None else box[i-1])
            b = self.hex510[i % 8]
            if a == 0x55 and i != 1 and tmp != 0x55:
                a = 0
            c = (a + i + b) % 0x100
            tmp = c if c < i else None
            box[i] = box[c]
        return box

    def _prga(self, box):                              # initial(): 魔改 PRGA
        t = box[:]
        adds = []
        for i in range(self.length):
            a = self.debug[i]
            b = adds[-1] if adds else 0
            c = (box[i+1] + b) % 0x100
            adds.append(c)
            d = t[c]
            t[i+1] = d
            e = (d + d) % 0x100
            f = t[e]
            self.debug[i] = a ^ f
        return self.debug

    def _mix(self):                                    # calculate(): 逐字节混淆
        for i in range(self.length):
            a = self.debug[i]
            b = _nibble_swap(a)
            c = self.debug[(i+1) % self.length]
            d = b ^ c
            e = int(f"{d:08b}"[::-1], 2)               # rbit()
            f_ = e ^ self.length
            self.debug[i] = (~f_) & 0xFF
        return self.debug

    def run(self) -> str:
        box = self._ksa()
        self._prga(box)
        out = self._mix()
        return ("0404" + f"{self.hex510[7]:02x}" + f"{self.hex510[3]:02x}"
                + "0001" + "".join(f"{b:02x}" for b in out))

def x_gorgon(query: str, data: str = "", cookie: str = "", ts: int | None = None) -> str:
    ts = ts or int(time.time())
    g = []
    def md5_4(s: bytes):
        h = hashlib.md5(s).hexdigest()
        return [int(h[2*i:2*i+2], 16) for i in range(4)]
    g += md5_4(query.encode())
    g += md5_4(data.encode())   if data   else [0]*4
    g += md5_4(cookie.encode()) if cookie else [0]*4
    g += [0]*4
    kh = f"{ts:x}"
    g += [int(kh[2*i:2*i+2], 16) if 2*i+2 <= len(kh) else 0 for i in range(4)]
    return _XG(g).run()

# ============================================================
# 4. X-Ladon —— 64 位 Speck 家族变形 (ROR8/ADD/XOR, 34 轮)
#    data = "{khronos}-{license_id}-{aid}", key = MD5(rand4 + str(aid))
#    输出 base64( rand4 || cipher )
# ============================================================
def _ror64(v, c): return ((v >> c) | (v << (64 - c))) & 0xFFFFFFFFFFFFFFFF

def _ladon_block(tab, blk16):
    d0 = int.from_bytes(blk16[:8], "little")
    d1 = int.from_bytes(blk16[8:16], "little")
    for i in range(0x22):
        h = int.from_bytes(tab[i*8:(i+1)*8], "little")
        d1 = (h ^ ((d0 + _ror64(d1, 8)) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        d0 = (d1 ^ _ror64(d0, 0x3D)) & 0xFFFFFFFFFFFFFFFF
    return d0.to_bytes(8, "little") + d1.to_bytes(8, "little")

def x_ladon_trivial() -> str:
    """7.1.3 实测形态: X-Ladon = base64(4 随机字节) (rounds2 捕获, 8 字符)"""
    return base64.b64encode(random.randbytes(4)).decode()


def x_ladon(khronos: int | None = None, lc_id: int = LICENSE_ID, aid: int = AID,
            rnd: bytes | None = None) -> str:
    khronos = khronos or int(time.time())
    rnd = rnd or random.randbytes(4)
    data = f"{khronos}-{lc_id}-{aid}".encode()
    keygen = rnd + str(aid).encode()
    md5hex = hashlib.md5(keygen).hexdigest().encode()   # 32B ASCII hex
    tab = bytearray(272 + 16)
    tab[:32] = md5hex[:32]
    temp = [int.from_bytes(tab[i*8:(i+1)*8], "little") for i in range(4)]
    b0, b8 = temp.pop(0), temp.pop(0)
    for i in range(0x22):
        x9, x8 = b0, b8
        x8 = _ror64(x8, 8)
        x8 = (x8 + x9) & 0xFFFFFFFFFFFFFFFF
        x8 ^= i
        temp.append(x8)
        x8 ^= _ror64(x9, 61)
        tab[(i+1)*8:(i+2)*8] = x8.to_bytes(8, "little")
        b0 = x8
        b8 = temp.pop(0)
    pad = 16 - len(data) % 16
    data += bytes([pad])*pad
    out = bytearray()
    for off in range(0, len(data), 16):
        out += _ladon_block(tab, data[off:off+16])
    return base64.b64encode(rnd + bytes(out)).decode()

def _helios_round_keys(rnd: bytes, aid: int = AID) -> bytes:
    """Generate the 34*u64 table used by the native Helios wrapper.

    The wrapper seeds the same Speck-family schedule as Ladon with the ASCII
    MD5 hex of ``rnd || str(aid)``.  Keeping this as raw bytes preserves the
    native little-endian table layout consumed by the VM.
    """
    if len(rnd) != 4:
        raise ValueError("Helios nonce must be exactly 4 bytes")
    seed = hashlib.md5(rnd + str(aid).encode()).hexdigest().encode()
    tab = bytearray(272 + 16)
    tab[:32] = seed
    temp = [int.from_bytes(tab[i * 8:(i + 1) * 8], "little") for i in range(4)]
    b0, b8 = temp.pop(0), temp.pop(0)
    for i in range(0x22):
        x9, x8 = b0, b8
        x8 = _ror64(x8, 8)
        x8 = (x8 + x9) & 0xFFFFFFFFFFFFFFFF
        x8 ^= i
        temp.append(x8)
        x8 ^= _ror64(x9, 61)
        tab[(i + 1) * 8:(i + 2) * 8] = x8.to_bytes(8, "little")
        b0, b8 = x8, temp.pop(0)
    return bytes(tab[:272])

# ============================================================
# 5. X-Argus —— protobuf(20+ 字段) -> AES-128-ECB(内层, 番茄把社区的 Simon 换成 AES)
#    -> XOR+reverse 混淆 -> 加 9B 头 + "ao" -> AES-128-CBC(外层, key/iv=MD5(SIGN_KEY 两半))
#    -> 前缀 f281 -> base64
#    ※ 注意: 番茄 v7.1.3.32 实测服务端不校验 Argus, 且该版本抓到的 Argus
#      只是 base64(LE u32 时间戳) (fanqie-dl ISSUE.md)。两种都给出。
# ============================================================
def _varint(v: int) -> bytes:
    v &= 0xFFFFFFFF
    out = bytearray()
    while v > 0x80:
        out.append((v & 0x7F) | 0x80); v >>= 7
    out.append(v & 0x7F)
    return bytes(out)

def _pb_field(idx: int, val) -> bytes:
    if isinstance(val, int):
        return _varint(idx << 3) + _varint(val)
    if isinstance(val, str):
        val = val.encode()
    if isinstance(val, list):                          # 嵌套 message
        val = b"".join(_pb_field(i, v) for i, v in val)
    return _varint((idx << 3) | 2) + _varint(len(val)) + bytes(val)

def _pkcs7(b: bytes, bs: int = 16) -> bytes:
    p = bs - len(b) % bs
    return b + bytes([p]) * p

def _sha256_6(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()[:6]

def x_argus(query: str, stub: str | None = None, ts: int | None = None,
            aid: int = AID, device_id: str = "0",
            version_name: str = "7.1.3.32", rand_val: int | None = None) -> str:
    ts = ts or int(time.time())
    rand_val = rand_val if rand_val is not None else random.randint(0, 0x7FFFFFFF)
    body_hash = (_sha256_6(bytes.fromhex(stub)) if stub else _sha256_6(bytes(16)))
    query_hash = _sha256_6(query.encode()) if query else _sha256_6(bytes(16))
    pb = b"".join([
        _pb_field(1, 0x20200929 << 1),                 # magic
        _pb_field(2, 2),                               # version
        _pb_field(3, rand_val),                        # rand
        _pb_field(4, str(aid)),                        # msAppID
        _pb_field(5, device_id),                       # deviceID
        _pb_field(6, str(LICENSE_ID)),                 # licenseID
        _pb_field(7, version_name),                    # appVersion
        _pb_field(8, "v04.04.05-ov-android"),          # sdkVersionStr
        _pb_field(9, 134744640),                       # sdkVersion
        _pb_field(10, bytes(8)),                       # envcode
        _pb_field(11, 0),                              # platform android
        _pb_field(12, ts << 1),                        # createTime
        _pb_field(13, body_hash),                      # bodyHash = SHA256(X-SS-STUB)[:6]
        _pb_field(14, query_hash),                     # queryHash = SHA256(query)[:6]
        _pb_field(15, [(1,1),(2,1),(3,1),(7,3348294860)]),
        _pb_field(16, ""),                             # secDeviceToken
        _pb_field(20, "none"),                         # pskVersion
        _pb_field(21, 738),                            # callType
        _pb_field(23, [(1,"NX551J"),(2,8196),(4,2162219008)]),
        _pb_field(25, 2),
    ])
    pb = _pkcs7(pb)
    inner_key = hashlib.sha256(SIGN_KEY + ARGUS_SALT + SIGN_KEY).digest()[:16]
    ecb = AES.new(inner_key, AES.MODE_ECB)
    enc = b"".join(ecb.encrypt(pb[i:i+16]) for i in range(0, len(pb), 16))
    d = bytearray(ARGUS_INNER_PAD + enc)
    xors = d[:8]
    for i in range(8, len(d)):
        d[i] ^= xors[i % 8]
    d = d[::-1]                                        # reverse
    buf = ARGUS_PREFIX + bytes(d) + b"ao"
    aes_key = hashlib.md5(SIGN_KEY[:16]).digest()
    aes_iv = hashlib.md5(SIGN_KEY[16:]).digest()
    cbc = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    return base64.b64encode(ARGUS_MAGIC_PREFIX + cbc.encrypt(_pkcs7(buf))).decode()

def x_argus_trivial(ts: int | None = None) -> str:
    """番茄 v7.1.3.32 抓包实测形态: base64(timestamp as u32 LE)"""
    ts = ts or int(time.time())
    return base64.b64encode(struct.pack("<I", ts)).decode()

# ============================================================
# 6. 正文/密钥解密 —— registerkey 协商 + 章节 AES-CBC + zlib
# ============================================================
def _iv_from_text(s: str) -> bytes:
    return (s + "0"*16)[:16].encode()                  # po4.a.b(): 补 '0' 到 16 截断

def build_register_content(device_id: str, user_id: str = "0",
                           iv_text: str | None = None) -> str:
    """md5.i.n(): content = base64( iv16 || AES-CBC(LE(did)+LE(uid)) )"""
    iv_text = iv_text or base64.b16encode(random.randbytes(8)).decode()  # 16 位可读字符
    payload = struct.pack("<q", int(device_id)) + struct.pack("<q", int(user_id))
    ct = AES.new(bytes.fromhex(REG_KEY_HEX), AES.MODE_CBC, _iv_from_text(iv_text)
                 ).encrypt(_pkcs7(payload))
    return base64.b64encode(iv_text.encode() + ct).decode()

def decrypt_server_key(encrypted_key_b64: str) -> str:
    """md5.i.k(): 解 registerkey 响应里的 key, 得 32 位大写 hex (v1_key)"""
    raw = base64.b64decode(encrypted_key_b64)
    iv, ct = raw[:16], raw[16:]
    pt = AES.new(bytes.fromhex(REG_KEY_HEX), AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    pt = pt[:-pad] if 0 < pad <= 16 else pt
    return pt.hex().upper()

def decrypt_chapter(encrypted_content_b64: str, v1_key_hex: str,
                    compress_status: int = 1) -> bytes:
    """章节正文: base64 -> [16B IV][AES-CBC 密文] -> 解密 -> (compress_status>0 时) zlib 解压"""
    raw = base64.b64decode(encrypted_content_b64)
    iv, ct = raw[:16], raw[16:]
    pt = AES.new(bytes.fromhex(v1_key_hex), AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 0 < pad <= 16:
        pt = pt[:-pad]
    return zlib.decompress(pt) if compress_status > 0 else pt

# ============================================================
# 7. X-Helios (helios_vm.py) / X-Medusa (medusa_f13.py + medusa_body.py) —— 均已纯算
# ============================================================
def x_helios(r: bytes | None = None, ts: int | None = None,
             dev_reg_id: int = 1394812046,
             round_keys: bytes | None = None) -> str:
    """X-Helios 纯算实现 (helios_vm.py, 已与 Unicorn trace 489步逐位比对 + 200组随机输入交叉验证)
    结构: r(4B nonce) + VM输出前32B -> base64 (48字符)
    VM输入: "{ts}-1394812046-1967" -> PKCS7 填充到 32B -> 分 2 块执行；
    轮密钥表由 md5hex(r+"1967") 按 Speck 34 轮展开
    VM 本体: libmetasec_ml @0x118F50 的 23 条字节码, 34 轮 Speck-128/128 类分组加密,
    轮密钥表(34xu64)位于 packed_args[0]。旧样本为全 0；新样本可通过
    ``round_keys`` 注入 272 字节真机表。"""
    import helios_vm
    r = r or random.randbytes(4)
    ts = ts or int(time.time())
    data = ("%d-%d-1967" % (ts, dev_reg_id)).encode()        # 26B (default)
    pad = 16 - (len(data) % 16)
    if round_keys is None:
        round_keys = _helios_round_keys(r)
    out = helios_vm.helios_compute(data + bytes([pad]) * pad,
                                   round_keys=round_keys) # 32B
    return base64.b64encode(r + out[:32]).decode()

def x_medusa(query: str, verbose: bool = False) -> str:
    """Legacy-snapshot X-Medusa calculator (not the current online VM).
    结构: raw 251B = f13(20B) + f14(6B) + body(225B) -> base64 (336字符)
      f13  = medusa_f13(query): SM3(query) -> BIG VM 纯Python解释 -> key32,
             core16 = key32[0:16]^key32[16:32], tail4 = NAND/NOR 混合尾
      f14  = SM3(query)[0:6]
      body = medusa_body.compute_body(1, query=query): Medusa VM (12a2a000 快照)
             纯Python ARM64解释器, ~1.5M 指令, 225B 输出
             body[0:20] = 设备常量前缀 82501b00eeca302ac7cbb491049a196a4766bffe
             body[20:22] = VM内PRNG nonce (确定性), [22:24] = 000d
    验证: query='aid=1967' 时 body 与真机快照 gold (_g1.txt, e2轮) 225/225 逐字节一致;
          f13('aid=1967') == 1cbf49533e2ff25d82b40593bb08ae38fa213c08
    耗时: body 单轮 ~20s (Python 解释器), f13 ~秒级.

    The current online VM9 body is not parameterized by this function; see
    platforms/bytedance/tomato/SIGNATURE.md.
    """
    import medusa_body
    # 真机 rounds2 捕获证实: X-Medusa = body(225B) 本体, 不含 f13/f14
    # (f13/f14 是 body VM 的上游输入, 已固化在快照内, 不上线)
    return base64.b64encode(
        medusa_body.compute_body(1, verbose=verbose, query=query)).decode()

def x_perseus(verbose: bool = False) -> str:
    """Offline Perseus snapshot helper.
    结构: base64 C-string @ 0x122a4000, raw 611B -> 816 字符
    本体: libmetasec_ml Perseus VM (12d40000 快照, prog 2MB + region1-4 + chain),
          纯 Python ARM64 解释器 (与 medusa_body 同核), ~1.44M 指令
    验证: 与 unicorn 参考 (perseus_emu8.py) 输出 816/816 逐字节一致;
          与真机 gold (run_per11.txt r0) 前 21B 一致 (后续为每轮随机域)
    This has no current online acceptance claim in this repository.
    """
    import perseus_body
    return perseus_body.compute_perseus(verbose=verbose).decode()

# ============================================================
# 自测
# ============================================================
if __name__ == "__main__":
    # 测试向量来自 fanqie-dl src/crypto.rs (Frida 提取)
    c = build_register_content("643680972856619", "0", "1234567890123456")
    assert c == "MTIzNDU2Nzg5MDEyMzQ1NmT9l3XkgzNyg0UjVJC8plSSyMLM14MlZHMvtUg5WT/i", c
    print("[ok] registerkey content 匹配 Frida 实测向量")

    assert x_argus_trivial(1774936134) == "RmDLaQ=="
    print("[ok] X-Argus(实测退化形态) = base64(LE ts) 匹配 fanqie-dl 记录")

    ts = int(time.time())
    print("X-Khronos :", x_khronos(ts))
    print("X-Neptune :", x_neptune())
    print("X-Gorgon  :", x_gorgon("aid=1967&device_id=123", ts=ts))
    print("X-Ladon   :", x_ladon(ts)[:48], "...")
    print("X-Argus   :", x_argus("aid=1967&device_id=123", ts=ts)[:48], "...")
    print("X-Helios  :", x_helios(bytes([0x11,0x22,0x33,0x44]), ts))
    print("全部纯算头生成完毕 (含 X-Medusa / X-Perseus 纯算, 二者各 ~20s 未在自测中运行)")
