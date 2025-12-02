# dnssec_tool/analyzer.py

from collections import defaultdict
from datetime import datetime, timezone

# Algoritmos según RFCs / práctica actual
ALGO_MAP = {
    5: "RSA/SHA-1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    13: "ECDSA P-256/SHA-256",
    14: "ECDSA P-384/SHA-384",
    15: "Ed25519",
    16: "Ed448",
}

ALLOWED_ALGOS = {8, 10, 13, 14, 15, 16}   # “autorizados” modernos

def _int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


# ==============================
# 1) DNSKEY
# ==============================
def analyze_dnskey(records):
    dnskeys = records.get("DNSKEY", [])
    out = []

    for k in dnskeys:
        alg = _int(k.get("algorithm", 0))
        flags = _int(k.get("flags", 0))
        proto = _int(k.get("proto", 0))
        ttl = _int(k.get("ttl", 0))

        alg_name = ALGO_MAP.get(alg, "UNKNOWN")
        algo_ok = alg in ALLOWED_ALGOS

        if flags == 257:
            role = "KSK"
        elif flags == 256:
            role = "ZSK"
        else:
            role = f"Desconocido ({flags})"

        proto_ok = (proto == 3)
        ttl_ok = (ttl > 0)

        out.append({
            "name": k.get("name"),
            "algorithm": alg,
            "algorithm_name": alg_name,
            "algorithm_allowed": algo_ok,
            "flags": flags,
            "role": role,
            "proto": proto,
            "proto_ok": proto_ok,
            "ttl": ttl,
            "ttl_ok": ttl_ok,
        })

    return out


# ==============================
# 2) RRSIG
# ==============================
def _parse_rrsig_time(s):
    """
    Formato RFC4034: YYYYMMDDHHMMSS en UTC.
    """
    try:
        dt = datetime.strptime(s, "%Y%m%d%H%M%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def analyze_rrsig(records, now=None):
    rrsigs = records.get("RRSIG", [])
    out = []

    if now is None:
        now = datetime.now(timezone.utc)

    for r in rrsigs:
        alg = _int(r.get("algorithm", 0))
        alg_name = ALGO_MAP.get(alg, "UNKNOWN")

        exp = _parse_rrsig_time(r.get("sig_exp", ""))
        inc = _parse_rrsig_time(r.get("sig_inc", ""))

        if exp and now > exp:
            status = "expired"
        elif inc and now < inc:
            status = "not_yet_valid"
        elif exp and inc:
            status = "valid"
        else:
            status = "unknown"

        out.append({
            "name": r.get("name"),
            "type_covered": r.get("type_covered"),
            "algorithm": alg,
            "algorithm_name": alg_name,
            "key_tag": _int(r.get("key_tag", 0)),
            "signer_name": r.get("signer_name"),
            "orig_ttl": _int(r.get("orig_ttl", 0)),
            "sig_inception": r.get("sig_inc"),
            "sig_expiration": r.get("sig_exp"),
            "status": status,
        })

    return out


# ==============================
# 3) NSEC / NSEC3 / NSEC3PARAM
# ==============================
def analyze_nsec(records):
    has_nsec = bool(records.get("NSEC"))
    has_nsec3 = bool(records.get("NSEC3"))
    has_nsec3param = bool(records.get("NSEC3PARAM"))

    if has_nsec3 or has_nsec3param:
        mode = "NSEC3"
    elif has_nsec:
        mode = "NSEC"
    else:
        mode = "none"

    return {
        "has_nsec": has_nsec,
        "has_nsec3": has_nsec3,
        "has_nsec3param": has_nsec3param,
        "mode": mode,
    }


# ==============================
# 4) TTLs por tipo
# ==============================
def analyze_ttl(records):
    """
    Recorre todos los registros con campo ttl y calcula métricas simples.
    """
    ttl_stats = defaultdict(lambda: {"min": None, "max": None, "count": 0, "sum": 0})

    for rtype, items in records.items():
        for item in items:
            ttl = _int(item.get("ttl", 0), 0)
            if ttl <= 0:
                continue

            st = ttl_stats[rtype]
            st["count"] += 1
            st["sum"] += ttl
            if st["min"] is None or ttl < st["min"]:
                st["min"] = ttl
            if st["max"] is None or ttl > st["max"]:
                st["max"] = ttl

    # calcular promedio
    for rtype, st in ttl_stats.items():
        if st["count"] > 0:
            st["avg"] = st["sum"] / st["count"]
        else:
            st["avg"] = 0

    return dict(ttl_stats)


# ==============================
# 5) DS / Cadena de confianza
# ==============================
from .validator import validate_chain  # ya la tienes

def analyze_ds_and_chain(domain, records):
    """
    Usa tu validator para ver si la cadena es íntegra.
    """
    status, detail = validate_chain(domain)

    ds_records = records.get("DS", [])
    has_ds = len(ds_records) > 0

    return {
        "has_ds": has_ds,
        "chain_status": status,   # "valid", "broken", "no_dnssec"
        "detail": detail,
        "ds_count": len(ds_records),
    }


# ==============================
# 6) Empaquetar todo en un “summary”
# ==============================
def audit_domain(domain, records, now=None):
    return {
        "domain": domain,
        "dnskey": analyze_dnskey(records),
        "rrsig": analyze_rrsig(records, now=now),
        "nsec": analyze_nsec(records),
        "ttl_stats": analyze_ttl(records),
        "ds_chain": analyze_ds_and_chain(domain, records),
    }
