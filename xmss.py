"""
XMSS – eXtended Merkle Signature Scheme / Merkle-Baum (NIST FIPS 205, Abschnitt 6)

  - Algorithmus 9:  xmss_node
  - Algorithmus 10: xmss_sign
  - Algorithmus 11: xmss_pkFromSig
"""

from sphincs_hilfsfunktionen import Params, ADRS, H, WOTS_HASH, TREE
from wots import wots_pkGen, wots_sign, wots_pkFromSig


# ======================================================================
# Algorithmus 9: xmss_node(SK.seed, i, z, PK.seed, ADRS)
# ======================================================================
def xmss_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    if z == 0:
        ADRS.setTypeAndClear(WOTS_HASH)
        ADRS.setKeyPairAddress(i)
        node = wots_pkGen(SK_seed, PK_seed, ADRS, P)
    else:
        lnode = xmss_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS, P)
        rnode = xmss_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS, P)
        ADRS.setTypeAndClear(TREE)
        ADRS.setTreeHeight(z)
        ADRS.setTreeIndex(i)
        node = H(PK_seed, ADRS, lnode + rnode, P.n)
    return node


# ======================================================================
# Algorithmus 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
# ======================================================================
def xmss_sign(M: bytes, SK_seed: bytes, idx: int, PK_seed: bytes, ADRS: "ADRS", P: Params):
    AUTH = [None] * P.hp
    for j in range(P.hp):                                      # ▷ Authentifizierungspfad aufbauen
        k = (idx // (2 ** j)) ^ 1
        AUTH[j] = xmss_node(SK_seed, k, j, PK_seed, ADRS, P)
    ADRS.setTypeAndClear(WOTS_HASH)
    ADRS.setKeyPairAddress(idx)
    sig = wots_sign(M, SK_seed, PK_seed, ADRS, P)
    SIG_XMSS = (sig, AUTH)
    return SIG_XMSS


# ======================================================================
# Algorithmus 11: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)
# ======================================================================
def xmss_pkFromSig(idx: int, SIG_XMSS, M: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    ADRS.setTypeAndClear(WOTS_HASH)                            # ▷ WOTS+ Public Key aus WOTS+ sig
    ADRS.setKeyPairAddress(idx)
    sig = SIG_XMSS[0]
    AUTH = SIG_XMSS[1]
    node = [None, None]
    node[0] = wots_pkFromSig(sig, M, PK_seed, ADRS, P)

    ADRS.setTypeAndClear(TREE)                                 # ▷ Wurzel aus WOTS+ pk und AUTH
    ADRS.setTreeIndex(idx)
    for k in range(P.hp):
        ADRS.setTreeHeight(k + 1)
        if (idx // (2 ** k)) % 2 == 0:
            ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
            node[1] = H(PK_seed, ADRS, node[0] + AUTH[k], P.n)
        else:
            ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
            node[1] = H(PK_seed, ADRS, AUTH[k] + node[0], P.n)
        node[0] = node[1]
    return node[0]
