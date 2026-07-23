"""
WOTS+ – Winternitz One-Time Signature Plus Scheme (NIST FIPS 205, Abschnitt 5)

  - Algorithmus 6: wots_pkGen
  - Algorithmus 7: wots_sign
  - Algorithmus 8: wots_pkFromSig
"""

from sphincs_hilfsfunktionen import (
    Params, ADRS, PRF, chain, T, base_2b, toByte,
    WOTS_HASH, WOTS_PK, WOTS_PRF,
)


# ======================================================================
# Algorithmus 6: wots_pkGen(SK.seed, PK.seed, ADRS)
# ======================================================================
def wots_pkGen(SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    skADRS = ADRS.copy()                       # ▷ Adresse fuer Schluesselerzeugung kopieren
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    tmp = [None] * P.len_
    for i in range(P.len_):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS, P.n)                # ▷ Geheimwert fuer Kette i
        ADRS.setChainAddress(i)
        tmp[i] = chain(sk, 0, P.w - 1, PK_seed, ADRS, P.n)     # ▷ Oeffentlicher Wert der Kette i
    wotspkADRS = ADRS.copy()                   # ▷ Adresse fuer WOTS+ Public Key kopieren
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    pk = T(PK_seed, wotspkADRS, b"".join(tmp), P.n)            # ▷ Public Key komprimieren
    return pk


def _msg_und_checksumme(M: bytes, P: Params):
    """Gemeinsamer Teil von wots_sign und wots_pkFromSig (Zeilen 1-7 in Alg. 7/8)."""
    csum = 0
    msg = base_2b(M, P.lgw, P.len1)                            # ▷ Nachricht zur Basis w
    for i in range(P.len1):                                    # ▷ Checksumme berechnen
        csum += P.w - 1 - msg[i]
    csum = csum << ((8 - ((P.len2 * P.lgw) % 8)) % 8)
    msg = msg + base_2b(toByte(csum, -(-(P.len2 * P.lgw) // 8)), P.lgw, P.len2)
    return msg


# ======================================================================
# Algorithmus 7: wots_sign(M, SK.seed, PK.seed, ADRS)
# ======================================================================
def wots_sign(M: bytes, SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params):
    msg = _msg_und_checksumme(M, P)
    skADRS = ADRS.copy()
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sig = [None] * P.len_
    for i in range(P.len_):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS, P.n)                # ▷ Geheimwert der Kette i
        ADRS.setChainAddress(i)
        sig[i] = chain(sk, 0, msg[i], PK_seed, ADRS, P.n)      # ▷ Signaturwert der Kette i
    return sig


# ======================================================================
# Algorithmus 8: wots_pkFromSig(sig, M, PK.seed, ADRS)
# ======================================================================
def wots_pkFromSig(sig, M: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    msg = _msg_und_checksumme(M, P)
    tmp = [None] * P.len_
    for i in range(P.len_):
        ADRS.setChainAddress(i)
        tmp[i] = chain(sig[i], msg[i], P.w - 1 - msg[i], PK_seed, ADRS, P.n)
    wotspkADRS = ADRS.copy()
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    pksig = T(PK_seed, wotspkADRS, b"".join(tmp), P.n)
    return pksig
