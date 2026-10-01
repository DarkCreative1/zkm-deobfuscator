from __future__ import annotations

try:
    from Crypto.Cipher import DES as _PDES

    def _des_cbc_crypt(data: bytes, key8: bytes, decrypt: bool, pad: bool) -> bytes:
        iv = b"\x00" * 8
        if not decrypt and pad:
            padlen = 8 - (len(data) % 8)
            data = data + bytes([padlen]) * padlen
        c = _PDES.new(key8, _PDES.MODE_CBC, iv)
        out = c.decrypt(data) if decrypt else c.encrypt(data)
        if decrypt and pad:
            p = out[-1]
            if 1 <= p <= 8 and out.endswith(bytes([p]) * p):
                out = out[:-p]
        return out

    _HAS_PDES = True
except Exception:
    _HAS_PDES = False

if not _HAS_PDES:

    _SBOX = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    _IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    _FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
           38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
           36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
    _E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    _P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
          2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    _PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    _PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    _ROT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def _perm(bits: int, table, n: int) -> int:
        out = 0
        for pos in table:
            out = (out << 1) | ((bits >> (n - pos)) & 1)
        return out

    def _des_keys(key8: bytes):
        key = int.from_bytes(key8, "big")
        pc = _perm(key, _PC1, 64)
        c = (pc >> 28) & 0xFFFFFFF
        d = pc & 0xFFFFFFF
        keys = []
        for r in _ROT:
            c = ((c << r) | (c >> (28 - r))) & 0xFFFFFFF
            d = ((d << r) | (d >> (28 - r))) & 0xFFFFFFF
            keys.append(_perm((c << 28) | d, _PC2, 56))
        return keys

    def _des_block(block: int, keys, decrypt: bool) -> int:
        b = _perm(block, _IP, 64)
        L = (b >> 32) & 0xFFFFFFFF
        R = b & 0xFFFFFFFF
        for k in (reversed(keys) if decrypt else keys):
            e = _perm(R, _E, 32)
            x = e ^ k
            s = 0
            for i in range(8):
                six = (x >> (42 - 6 * i)) & 0x3F
                row = ((six >> 4) & 2) | (six & 1)
                col = (six >> 1) & 0xF
                s = (s << 4) | _SBOX[i][row * 16 + col]
            R, L = L ^ _perm(s, _P, 32), R
        return _perm((R << 32) | L, _FP, 64)

    def _des_cbc_crypt(data: bytes, key8: bytes, decrypt: bool, pad: bool) -> bytes:
        if not decrypt and pad:
            padlen = 8 - (len(data) % 8)
            data = data + bytes([padlen]) * padlen
        keys = _des_keys(key8)
        iv = 0
        out = bytearray()
        for i in range(0, len(data), 8):
            blk = int.from_bytes(data[i:i + 8], "big")
            if decrypt:
                dec = _des_block(blk, keys, True) ^ iv
                iv = blk
                out += dec.to_bytes(8, "big")
            else:
                enc = _des_block(blk ^ iv, keys, False)
                iv = enc
                out += enc.to_bytes(8, "big")
        res = bytes(out)
        if decrypt and pad and res:
            p = res[-1]
            if 1 <= p <= 8 and res.endswith(bytes([p]) * p):
                res = res[:-p]
        return res

def xor_with_keys(s: str, keys: list[int]) -> str:

    n = len(keys)
    return "".join(chr((ord(c) ^ keys[i % n]) & 0xFFFF) for i, c in enumerate(s))

def derive_xor_keys(xor_keys: list[int], chunk_key: int) -> list[int]:
    return [k ^ chunk_key for k in xor_keys]

def rolling_xor_encrypt(s: str, keys: list[int], use_orig: bool) -> str:

    bb = list(keys)
    bc = len(bb)
    bd = [ord(c) for c in s]
    for i in range(len(bd)):
        bg = i % bc
        bh = bd[i]
        bd[i] = (bd[i] ^ bb[bg]) & 0xFFFF
        bi = ((bb[bg] >> 3) | (bb[bg] << 5)) & 0xFFFFFFFF
        bi ^= bh if use_orig else bd[i]
        bb[bg] = bi & 255
    return "".join(chr(c) for c in bd)

def rolling_xor_decrypt(s: str, keys: list[int]) -> str:

    bb = list(keys)
    bc = len(bb)
    bd = [ord(c) for c in s]
    for i in range(len(bd)):
        bg = i % bc
        e = bd[i]
        bd[i] = (e ^ bb[bg]) & 0xFFFF
        bi = ((bb[bg] >> 3) | (bb[bg] << 5)) & 0xFFFFFFFF
        bi ^= e
        bb[bg] = bi & 255
    return "".join(chr(c) for c in bd)

def rolling_xor_decrypt_orig_variant(s: str, keys: list[int]) -> str:

    bb = list(keys)
    bc = len(bb)
    bd = [ord(c) for c in s]
    for i in range(len(bd)):
        bg = i % bc
        e = bd[i]
        plain = (e ^ bb[bg]) & 0xFFFF
        bd[i] = plain
        bi = ((bb[bg] >> 3) | (bb[bg] << 5)) & 0xFFFFFFFF
        bi ^= plain
        bb[bg] = bi & 255
    return "".join(chr(c) for c in bd)

def long_to_bytes(v: int) -> bytes:
    v &= 0xFFFFFFFFFFFFFFFF
    return bytes([(v >> 56) & 0xFF, (v >> 48) & 0xFF, (v >> 40) & 0xFF,
                  (v >> 32) & 0xFF, (v >> 24) & 0xFF, (v >> 16) & 0xFF,
                  (v >> 8) & 0xFF, v & 0xFF])

def bytes_to_long(b: bytes) -> int:
    v = 0
    for x in b[:8]:
        v = (v << 8) | (x & 0xFF)
    return v

def des_string_encrypt(plain: str, key_long: int) -> str:

    raw = java_modified_utf8_encode(plain)
    enc = _des_cbc_crypt(raw, long_to_bytes(key_long), decrypt=False, pad=True)
    return enc.decode("latin1")

def des_string_decrypt(enc_str: str, key_long: int) -> str:
    raw = enc_str.encode("latin1")
    dec = _des_cbc_crypt(raw, long_to_bytes(key_long), decrypt=True, pad=True)
    return java_modified_utf8_decode(dec)

def des_long_crypt(value: int, key_long: int, decrypt: bool) -> int:

    data = long_to_bytes(value)
    out = _des_cbc_crypt(data, long_to_bytes(key_long), decrypt=decrypt, pad=False)
    return bytes_to_long(out[:8])

def split_chunk(decrypted_chunk: str) -> list[str]:

    if not decrypted_chunk:
        return []
    out = []
    i = 0
    first = True
    while i < len(decrypted_chunk):
        if first:

            out.append(decrypted_chunk[i:])
            break
        ln = ord(decrypted_chunk[i])
        i += 1
        out.append(decrypted_chunk[i:i + ln])
        i += ln
    return out

def split_chunk_multi(decrypted_chunk: str, count: int) -> list[str]:

    if count <= 1:
        return [decrypted_chunk]

    lens: list[int] = []
    tmp = decrypted_chunk
    parts: list[str] = []

    pos = len(tmp)
    rev: list[str] = []
    for _ in range(count - 1):

        break

    return [decrypted_chunk]

def decrypt_chunk_table(outer_plain: str, array_len: int) -> list[str]:

    if array_len <= 1:
        return [outer_plain]
    n = len(outer_plain)

    parts_rev: list[str] = []
    pos = n
    ok = True
    for _ in range(array_len - 1):
        found = -1

        for L in range(0, pos):
            if pos - L - 1 < 0:
                break
            if ord(outer_plain[pos - L - 1]) == L:
                found = L
                break

        break
    return _split_backtrack(outer_plain, array_len)

def _split_backtrack(chunk: str, n: int) -> list[str]:

    res: list[str] | None = None

    def rec(pos: int, idx: int, acc: list[str]) -> bool:
        nonlocal res
        if idx == 0:
            acc.append(chunk[:pos])
            res = list(reversed(acc))
            return True

        cands = [L for L in range(0, pos) if ord(chunk[pos - L - 1]) == L]

        cands.sort(reverse=True)
        for L in cands:
            data = chunk[pos - L:pos]
            acc.append(data)
            if rec(pos - L - 1, idx - 1, acc):
                return True
            acc.pop()
        return False

    if rec(len(chunk), n - 1, []):
        assert res is not None
        return res

    return [chunk]

def all_splits(chunk: str, n: int, cap: int = 300) -> list[list[str]]:

    out: list[list[str]] = []

    def rec(pos: int, idx: int, acc: list[str]) -> None:
        if len(out) >= cap:
            return
        if idx == 0:
            out.append(list(reversed(acc + [chunk[:pos]])))
            return
        for L in range(0, pos):
            if ord(chunk[pos - L - 1]) == L:
                acc.append(chunk[pos - L:pos])
                rec(pos - L - 1, idx - 1, acc)
                acc.pop()

    if n <= 1:
        return [[chunk]]
    rec(len(chunk), n - 1, [])
    return out

def java_modified_utf8_encode(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        o = ord(ch)
        if o == 0:
            out += b"\xc0\x80"
        elif o < 0x80:
            out.append(o)
        elif o < 0x800:
            out.append(0xC0 | (o >> 6))
            out.append(0x80 | (o & 0x3F))
        else:
            out.append(0xE0 | (o >> 12))
            out.append(0x80 | ((o >> 6) & 0x3F))
            out.append(0x80 | (o & 0x3F))
    return bytes(out)

def java_modified_utf8_decode(b: bytes) -> str:

    out: list[str] = []
    i = 0
    n = len(b)
    while i < n:
        a = b[i]
        if a < 0x80:
            if a == 0:
                break
            out.append(chr(a))
            i += 1
        elif (a & 0xE0) == 0xC0:
            c = ((a & 0x1F) << 6) | (b[i + 1] & 0x3F)
            out.append(chr(c))
            i += 2
        else:
            c = ((a & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F)
            out.append(chr(c))
            i += 3
    return "".join(out)

def reference_pack_keys(keys6: list[int], be: int, idx: int) -> int:

    packed = (idx << 46) | (be << 42)
    for j, k in enumerate(keys6):
        packed |= (k & 0x7F) << (7 * j)
    return packed

def reference_unpack_keys(packed: int, idx: int, offset_table: list[int]) -> tuple[list[int], int]:
    be = (packed >> 42) & 0xF
    bf = ((idx & 3) << 4) | be
    off = offset_table[bf & len(offset_table) % 256] if offset_table else 0
    keys = [((packed >> (7 * j)) & 0x7F) - off for j in range(6)]
    keys = [(k + 128) % 128 for k in keys]
    return keys, bf

def reference_decrypt_name(xor_str: str, keys6: list[int]) -> str:
    c = [ord(x) for x in xor_str]
    return "".join(chr((v - keys6[i % 6]) % 128) for i, v in enumerate(c))
