"""Ed25519 签名（RFC 8032）的纯标准库实现。

只依赖 hashlib（SHA-512），不引入任何第三方包，保证服务在任意
Python 3.11 环境中均可启动。密钥为 32 字节种子；签名是确定性的
（不含随机数）；公钥与签名编码遵循 RFC 8032，与 OpenSSL 等实现
互操作（公钥可按 Ed25519 SPKI 封装为 PEM 分发）。

本模块用于审计快照的签发与离线验真：
- public_key_from_seed(seed) -> 32 字节原始公钥
- sign(seed, message)        -> 64 字节签名
- verify(public_key, message, signature) -> bool（任何异常都归为 False）
- is_valid_public_key(public_key) -> bool（严格公钥有效性判定）

公钥有效性（验签与验真共用的安全前提）：只接受 32 字节**规范编码**、
位于曲线上、**非低阶**且**位于素数阶子群**的点。单位元及其他低阶点
（阶 1/2/4/8）必须拒绝——否则伪造者提交低阶公钥并搭配全零标量
（S = 0）的“签名”即可使验签等式对任意消息成立；非规范编码
（y >= q，或 x = 0 而符号位置 1）与不在素数阶子群的“混合阶”点
同样拒绝：合法 Ed25519 公钥必为 [a]B，阶恰为 L。
"""
from __future__ import annotations

import hashlib

# 域参数：q 为域大小，L 为基点阶，D 为 Edwards 曲线参数，I 为 2 的平方根
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int, *, checked: bool) -> int:
    """由 y 坐标恢复 x 坐标；checked=True 时无平方根则抛 ValueError。"""
    xx = (y * y - 1) * pow((_D * y * y + 1) % _Q, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
        if checked and (x * x - xx) % _Q != 0:
            raise ValueError("点不在 Ed25519 曲线上")
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY, checked=False)
# 扩展坐标 (X, Y, Z, T)：x = X/Z, y = Y/Z, xy = T/Z；避免每次加法求逆
_B = (_BX, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _ed_add(P: tuple[int, int, int, int], Q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % _Q
    B = ((Y1 + X1) * (Y2 + X2)) % _Q
    C = (2 * _D * T1 * T2) % _Q
    D = (2 * Z1 * Z2) % _Q
    E = (B - A) % _Q
    F = (D - C) % _Q
    G = (D + C) % _Q
    H = (B + A) % _Q
    return ((E * F) % _Q, (G * H) % _Q, (F * G) % _Q, (E * H) % _Q)


def _scalarmult(P: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    Q = _IDENTITY
    while e:
        if e & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        e >>= 1
    return Q


def _encode_point(P: tuple[int, int, int, int]) -> bytes:
    X, Y, Z, _ = P
    zinv = pow(Z, _Q - 2, _Q)
    x = (X * zinv) % _Q
    y = (Y * zinv) % _Q
    out = bytearray(y.to_bytes(32, "little"))
    out[31] = (out[31] & 0x7F) | ((x & 1) << 7)
    return bytes(out)


def _decode_point(data: bytes) -> tuple[int, int, int, int]:
    """按 RFC 8032 §5.1.3 严格解码：长度、域范围与符号位均为规范编码才接受。"""
    if len(data) != 32:
        raise ValueError("点编码必须为 32 字节")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    if y >= _Q:
        raise ValueError("点编码超出域范围")
    x = _xrecover(y, checked=True)
    if x == 0 and sign:
        # x 为零时符号位必须为零（否则同一单位元/二阶点有两种编码，属非规范编码）
        raise ValueError("点编码非规范：x 为零时符号位必须为零")
    if (x & 1) != sign:
        x = _Q - x
    return (x, y, 1, (x * y) % _Q)


def _clamped_scalar(seed: bytes) -> tuple[int, bytes]:
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _is_small_order(P: tuple[int, int, int, int]) -> bool:
    """P 是否属于阶整除 8 的小子群（含单位元）：[8]P 是否为单位元。"""
    Q = P
    for _ in range(3):
        Q = _ed_add(Q, Q)
    return _encode_point(Q) == _encode_point(_IDENTITY)


def _in_prime_subgroup(P: tuple[int, int, int, int]) -> bool:
    """P 是否位于阶为 L 的素数阶子群：[L]P 是否为单位元。"""
    return _encode_point(_scalarmult(P, _L)) == _encode_point(_IDENTITY)


def is_valid_public_key(public_key: bytes) -> bool:
    """严格公钥有效性判定：32 字节规范编码、曲线上的点、非低阶且在素数阶子群。

    单位元及其他低阶点（阶 1/2/4/8）必须拒绝：此类公钥配合全零标量
    （S = 0）的伪造“签名”可使验签等式对任意消息成立。不在素数阶子群的
    “混合阶”点同样拒绝——合法公钥必为 [a]B，阶恰为 L。任何异常归为 False。
    """
    try:
        A = _decode_point(public_key)
    except (ValueError, IndexError):
        return False
    return not _is_small_order(A) and _in_prime_subgroup(A)


def public_key_from_seed(seed: bytes) -> bytes:
    """由 32 字节种子导出 32 字节原始公钥。"""
    if len(seed) != 32:
        raise ValueError("种子必须为 32 字节")
    a, _ = _clamped_scalar(seed)
    return _encode_point(_scalarmult(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    """确定性签名（RFC 8032）：返回 64 字节签名。"""
    if len(seed) != 32:
        raise ValueError("种子必须为 32 字节")
    a, prefix = _clamped_scalar(seed)
    pk = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    R = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(R + pk + message), "little") % _L
    S = (r + k * a) % _L
    return R + S.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """验签；公钥/签名非法（含低阶或非子群公钥）或等式不成立一律返回 False。"""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        A = _decode_point(public_key)
        # 公钥有效性是验签的安全前提：单位元/低阶点或不在素数阶子群的公钥
        # 会让全零标量（S = 0）伪造签名通过等式，必须在验签层一并拒绝
        if _is_small_order(A) or not _in_prime_subgroup(A):
            return False
        R = _decode_point(signature[:32])
        S = int.from_bytes(signature[32:], "little")
        if S >= _L:
            return False
        k = int.from_bytes(_sha512(signature[:32] + public_key + message), "little") % _L
        return _encode_point(_scalarmult(_B, S)) == _encode_point(_ed_add(R, _scalarmult(A, k)))
    except (ValueError, IndexError):
        return False
