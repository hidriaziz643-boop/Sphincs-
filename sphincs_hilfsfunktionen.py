"""
SLH-DSA / SPHINCS+ (NIST FIPS 205) – gemeinsame Hilfsfunktionen

Enthaelt:
  - Algorithmus 1: gen_len2
  - Algorithmus 2: toInt
  - Algorithmus 3: toByte
  - Algorithmus 4: base_2b
  - ADRS – 32-Byte-Adresse (Abschnitt 4.2 / 4.3)
  - Hash-/PRF-Funktionen H_msg, PRF, PRF_msg, F, H, T (Abschnitt 11.1, SHAKE-Instanz)
  - Algorithmus 5: chain
  - Params – Buendelung der Parameter n, lgw, w, len1, len2, len_, h, h' (hp), d, k, a, m
  - NIST_PARAMETERSAETZE – Referenzwerte aus Tabelle 2

Alle anderen Module (wots.py, xmss.py, hypertree.py, fors.py, slh_dsa.py)
importieren ihre Bausteine aus dieser Datei.
"""

import hashlib
from dataclasses import dataclass, field


# ======================================================================
# Algorithmus 1: gen_len2(n, lgw)
# ======================================================================
def gen_len2(n, lgw):
    w = 2 ** lgw                                              # Gleichung 5.1
    len1 = -(-(8 * n) // lgw)                                 # Gleichung 5.2 (ceil)
    max_checksum = len1 * (w - 1)
    len2 = 1
    capacity = w
    while capacity <= max_checksum:
        len2 += 1
        capacity *= w
    return len2


# ======================================================================
# Algorithmus 2: toInt(X, n)
# ======================================================================
def toInt(X: bytes, n: int) -> int:
    total = 0
    for i in range(n):
        total = 256 * total + X[i]
    return total


# ======================================================================
# Algorithmus 3: toByte(x, n)
# ======================================================================
def toByte(x: int, n: int) -> bytes:
    total = x
    S = bytearray(n)
    for i in range(n):
        S[n - 1 - i] = total % 256
        total >>= 8
    return bytes(S)


# ======================================================================
# Algorithmus 4: base_2b(X, b, out_len)
# ======================================================================
def base_2b(X: bytes, b: int, out_len: int):
    ins = 0
    bits = 0
    total = 0
    baseb = []
    for out in range(out_len):
        while bits < b:
            total = (total << 8) + X[ins]
            ins += 1
            bits += 8
        bits -= b
        baseb.append((total >> bits) % (2 ** b))
    return baseb


# ======================================================================
# ADRS – 32-Byte-Adresse (Abschnitt 4.2 / 4.3)
# ======================================================================
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6


class ADRS:
    """32-Byte Adresse: layer(4) | tree(12) | type(4) | w4(4) | w5(4) | w6(4)"""

    def __init__(self):
        self.layer = 0
        self.tree = 0
        self.type = 0
        self.w4 = 0   # keyPairAddress / padding
        self.w5 = 0   # chainAddress / treeHeight
        self.w6 = 0   # hashAddress / treeIndex

    def to_bytes(self) -> bytes:
        return (toByte(self.layer, 4) + toByte(self.tree, 12) + toByte(self.type, 4)
                + toByte(self.w4, 4) + toByte(self.w5, 4) + toByte(self.w6, 4))

    def copy(self):
        a = ADRS()
        a.layer, a.tree, a.type = self.layer, self.tree, self.type
        a.w4, a.w5, a.w6 = self.w4, self.w5, self.w6
        return a

    def setLayerAddress(self, l):    self.layer = l
    def setTreeAddress(self, t):     self.tree = t
    def setTypeAndClear(self, Y):    self.type = Y; self.w4 = self.w5 = self.w6 = 0
    def setKeyPairAddress(self, i):  self.w4 = i
    def setChainAddress(self, i):    self.w5 = i
    def setTreeHeight(self, i):      self.w5 = i
    def setHashAddress(self, i):     self.w6 = i
    def setTreeIndex(self, i):       self.w6 = i
    def getKeyPairAddress(self):     return self.w4
    def getTreeIndex(self):          return self.w6


def ADRS_zero() -> "ADRS":
    return ADRS()


# ======================================================================
# Abschnitt 4.1 / 11.1: Hash- und PRF-Funktionen (SHAKE-Instanziierung)
# ======================================================================
def PRF_msg(SK_prf: bytes, opt_rand: bytes, M: bytes, n: int) -> bytes:
    return hashlib.shake_256(SK_prf + opt_rand + M).digest(n)


def H_msg(R: bytes, PK_seed: bytes, PK_root: bytes, M: bytes, m: int) -> bytes:
    return hashlib.shake_256(R + PK_seed + PK_root + M).digest(m)


def PRF(PK_seed: bytes, SK_seed: bytes, ADRS: "ADRS", n: int) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS.to_bytes() + SK_seed).digest(n)


def F(PK_seed: bytes, ADRS: "ADRS", M1: bytes, n: int) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS.to_bytes() + M1).digest(n)


def H(PK_seed: bytes, ADRS: "ADRS", M2: bytes, n: int) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS.to_bytes() + M2).digest(n)


def T(PK_seed: bytes, ADRS: "ADRS", Ml: bytes, n: int) -> bytes:
    """T_l aus Abschnitt 4.1 – komprimiert eine Nachricht beliebiger Laenge auf n Bytes."""
    return hashlib.shake_256(PK_seed + ADRS.to_bytes() + Ml).digest(n)


# ======================================================================
# Algorithmus 5: chain(X, i, s, PK.seed, ADRS)
# ======================================================================
def chain(X: bytes, i: int, s: int, PK_seed: bytes, ADRS: "ADRS", n: int) -> bytes:
    tmp = X
    for j in range(i, i + s):
        ADRS.setHashAddress(j)
        tmp = F(PK_seed, ADRS, tmp, n)
    return tmp


# ======================================================================
# Parameter-Objekt (buendelt n, lgw, w, len1, len2, len_, h, hp (=h'), d, k, a, m)
# ======================================================================
@dataclass
class Params:
    n: int      # Sicherheitsparameter (Byte)
    lgw: int    # log2(w), fest = 4
    hp: int     # h' – Hoehe eines einzelnen XMSS-Baumes
    d: int      # Anzahl Schichten des Hypertree
    k: int      # Anzahl FORS-Baeume
    a: int      # Hoehe eines FORS-Baumes (t = 2^a)

    w: int = field(init=False)
    len1: int = field(init=False)
    len2: int = field(init=False)
    len_: int = field(init=False)
    h: int = field(init=False)
    m: int = field(init=False)

    def __post_init__(self):
        self.w = 2 ** self.lgw
        self.len1 = -(-(8 * self.n) // self.lgw)
        self.len2 = gen_len2(self.n, self.lgw)
        self.len_ = self.len1 + self.len2
        self.h = self.hp * self.d
        self.m = (-(-(self.h - self.hp) // 8) + -(-self.hp // 8) + -(-(self.k * self.a) // 8))


# Offizielle NIST-Parametersaetze (Tabelle 2, FIPS 205) – zu gross fuer Live-Demo,
# aber als Referenz hinterlegt.
NIST_PARAMETERSAETZE = {
    "SLH-DSA-SHAKE-128s": dict(n=16, hp=9, d=7, k=14, a=12, lgw=4),
    "SLH-DSA-SHAKE-128f": dict(n=16, hp=3, d=22, k=33, a=6, lgw=4),
    "SLH-DSA-SHAKE-192s": dict(n=24, hp=9, d=7, k=17, a=14, lgw=4),
    "SLH-DSA-SHAKE-192f": dict(n=24, hp=3, d=22, k=33, a=8, lgw=4),
    "SLH-DSA-SHAKE-256s": dict(n=32, hp=8, d=8, k=22, a=14, lgw=4),
    "SLH-DSA-SHAKE-256f": dict(n=32, hp=4, d=17, k=35, a=9, lgw=4),
}
