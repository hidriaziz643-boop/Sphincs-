"""
Hypertree (HT) – SLH-DSA-Hypertree aus XMSS-Baeumen (NIST FIPS 205, Abschnitt 7)

  - Algorithmus 12: ht_sign
  - Algorithmus 13: ht_verify
"""

from sphincs_hilfsfunktionen import Params, ADRS_zero
from xmss import xmss_sign, xmss_pkFromSig


# ======================================================================
# Algorithmus 12: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
# ======================================================================
def ht_sign(M: bytes, SK_seed: bytes, PK_seed: bytes, idx_tree: int, idx_leaf: int, P: Params):
    ADRS = ADRS_zero()
    ADRS.setTreeAddress(idx_tree)
    SIG_tmp = xmss_sign(M, SK_seed, idx_leaf, PK_seed, ADRS, P)
    SIG_HT = [SIG_tmp]
    root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS, P)
    for j in range(1, P.d):
        idx_leaf = idx_tree % (2 ** P.hp)                      # ▷ h' niederwertigste Bits von idx_tree
        idx_tree = idx_tree >> P.hp                            # ▷ h' niederwertigste Bits entfernen
        ADRS.setLayerAddress(j)
        ADRS.setTreeAddress(idx_tree)
        SIG_tmp = xmss_sign(root, SK_seed, idx_leaf, PK_seed, ADRS, P)
        SIG_HT.append(SIG_tmp)
        if j < P.d - 1:
            root = xmss_pkFromSig(idx_leaf, SIG_tmp, root, PK_seed, ADRS, P)
    return SIG_HT


# ======================================================================
# Algorithmus 13: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
# ======================================================================
def ht_verify(M: bytes, SIG_HT, PK_seed: bytes, idx_tree: int, idx_leaf: int, PK_root: bytes, P: Params) -> bool:
    ADRS = ADRS_zero()
    ADRS.setTreeAddress(idx_tree)
    SIG_tmp = SIG_HT[0]
    node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS, P)
    for j in range(1, P.d):
        idx_leaf = idx_tree % (2 ** P.hp)
        idx_tree = idx_tree >> P.hp
        ADRS.setLayerAddress(j)
        ADRS.setTreeAddress(idx_tree)
        SIG_tmp = SIG_HT[j]
        node = xmss_pkFromSig(idx_leaf, SIG_tmp, node, PK_seed, ADRS, P)
    if node == PK_root:
        return True
    else:
        return False
