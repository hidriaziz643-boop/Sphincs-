"""
HINWEIS: Diese Datei wurde durch mehrere kleinere, konzeptgetrennte Module ersetzt:

  - sphincs_hilfsfunktionen.py   (gen_len2, toInt, toByte, base_2b, ADRS, Hashfunktionen, chain, Params)
  - wots.py                      (WOTS+: wots_pkGen, wots_sign, wots_pkFromSig)
  - xmss.py                      (Merkle-Baum / XMSS: xmss_node, xmss_sign, xmss_pkFromSig)
  - hypertree.py                 (Hypertree: ht_sign, ht_verify)
  - fors.py                      (FORS: fors_skGen, fors_node, fors_sign, fors_pkFromSig)
  - slh_dsa.py                   (SLH-DSA Kernfunktionen: slh_keygen, slh_sign, slh_verify, ...)

Diese Datei dient nur noch der Abwaertskompatibilitaet und reicht alle Namen an die
neuen Module weiter. Bitte in neuem Code direkt aus den obigen Modulen importieren.
"""

from sphincs_hilfsfunktionen import (  # noqa: F401
    gen_len2, toInt, toByte, base_2b, ADRS, ADRS_zero,
    PRF_msg, H_msg, PRF, F, H, T, chain,
    Params, NIST_PARAMETERSAETZE,
    WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF,
)
from wots import wots_pkGen, wots_sign, wots_pkFromSig  # noqa: F401
from xmss import xmss_node, xmss_sign, xmss_pkFromSig  # noqa: F401
from hypertree import ht_sign, ht_verify  # noqa: F401
from fors import fors_skGen, fors_node, fors_sign, fors_pkFromSig  # noqa: F401
from slh_dsa import (  # noqa: F401
    slh_keygen_internal, slh_sign_internal, slh_verify_internal,
    slh_keygen, slh_sign, hash_slh_sign, slh_verify, hash_slh_verify,
)
