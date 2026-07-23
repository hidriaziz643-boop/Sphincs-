"""
FORS – Forest of Random Subsets (NIST FIPS 205, Abschnitt 8)

  - Algorithmus 14: fors_skGen
  - Algorithmus 15: fors_node
  - Algorithmus 16: fors_sign
  - Algorithmus 17: fors_pkFromSig
"""

from sphincs_hilfsfunktionen import Params, ADRS, PRF, F, H, T, base_2b, FORS_PRF, FORS_ROOTS


# ======================================================================
# Algorithmus 14: fors_skGen(SK.seed, PK.seed, ADRS, idx)
# ======================================================================
def fors_skGen(SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", idx: int, P: Params) -> bytes:
    skADRS = ADRS.copy()
    skADRS.setTypeAndClear(FORS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    skADRS.setTreeIndex(idx)
    return PRF(PK_seed, SK_seed, skADRS, P.n)


# ======================================================================
# Algorithmus 15: fors_node(SK.seed, i, z, PK.seed, ADRS)
# ======================================================================
def fors_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    if z == 0:
        sk = fors_skGen(SK_seed, PK_seed, ADRS, i, P)
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i)
        node = F(PK_seed, ADRS, sk, P.n)
    else:
        lnode = fors_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS, P)
        rnode = fors_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS, P)
        ADRS.setTreeHeight(z)
        ADRS.setTreeIndex(i)
        node = H(PK_seed, ADRS, lnode + rnode, P.n)
    return node


# ======================================================================
# Algorithmus 16: fors_sign(md, SK.seed, PK.seed, ADRS)
# ======================================================================
def fors_sign(md: bytes, SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params):
    SIG_FORS = []                                              # ▷ als leere Byte-Folge initialisiert
    indices = base_2b(md, P.a, P.k)
    for i in range(P.k):                                       # ▷ Signaturelemente berechnen
        SIG_FORS.append(fors_skGen(SK_seed, PK_seed, ADRS, i * (2 ** P.a) + indices[i], P))
        AUTH = [None] * P.a
        for j in range(P.a):                                   # ▷ Authentifizierungspfad berechnen
            s = (indices[i] // (2 ** j)) ^ 1
            AUTH[j] = fors_node(SK_seed, i * (2 ** (P.a - j)) + s, j, PK_seed, ADRS, P)
        SIG_FORS.append(AUTH)
    return SIG_FORS


# ======================================================================
# Algorithmus 17: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
# ======================================================================
def fors_pkFromSig(SIG_FORS, md: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    indices = base_2b(md, P.a, P.k)
    root = [None] * P.k
    for i in range(P.k):
        sk = SIG_FORS[2 * i]
        ADRS.setTreeHeight(0)                                  # ▷ Blatt berechnen
        ADRS.setTreeIndex(i * (2 ** P.a) + indices[i])
        node = [None, None]
        node[0] = F(PK_seed, ADRS, sk, P.n)
        auth = SIG_FORS[2 * i + 1]
        for j in range(P.a):                                   # ▷ Wurzel aus Blatt und AUTH berechnen
            ADRS.setTreeHeight(j + 1)
            if (indices[i] // (2 ** j)) % 2 == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
                node[1] = H(PK_seed, ADRS, node[0] + auth[j], P.n)
            else:
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
                node[1] = H(PK_seed, ADRS, auth[j] + node[0], P.n)
            node[0] = node[1]
        root[i] = node[0]
    forspkADRS = ADRS.copy()                       # ▷ Adresse fuer FORS Public Key kopieren
    forspkADRS.setTypeAndClear(FORS_ROOTS)
    forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    pk = T(PK_seed, forspkADRS, b"".join(root), P.n)           # ▷ FORS Public Key berechnen
    return pk
