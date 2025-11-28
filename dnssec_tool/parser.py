# dnssec_tool/parser.py

import re
from collections import defaultdict

records = ["DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM"]

# ===========================
# REGEX universales
# ===========================

# Linux/macOS format (with parentheses)
DNSKEY_UNIX = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+DNSKEY\s+"
    r"(?P<flags>\d+)\s+(?P<proto>\d+)\s+(?P<algorithm>\d+)\s+\((?P<key>[^)]+)\)"
)

# Windows format (flat, no parentheses)
DNSKEY_WIN = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+DNSKEY\s+"
    r"(?P<flags>\d+)\s+(?P<proto>\d+)\s+(?P<algorithm>\d+)\s+(?P<key>[A-Za-z0-9+/=]+)"
)


DS_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+DS\s+"
    r"(?P<keytag>\d+)\s+(?P<algorithm>\d+)\s+(?P<digest_type>\d+)\s+(?P<digest>[A-Fa-f0-9]+)"
)

RRSIG_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+RRSIG\s+"
    r"(?P<type>\S+)\s+(?P<algorithm>\d+)\s+(?P<labels>\d+)"
)

NSEC_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+NSEC\s+(?P<next>\S+)"
)

NSEC3_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+NSEC3\s+"
    r"(?P<algorithm>\d+)\s+(?P<flags>\d+)\s+(?P<iter>\d+)\s+(?P<salt>\S+)"
)

NSEC3PARAM_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+NSEC3PARAM\s+"
    r"(?P<algorithm>\d+)\s+(?P<flags>\d+)\s+(?P<iter>\d+)\s+(?P<salt>\S+)"
)

# ===========================
# PARSER PRINCIPAL
# ===========================

# ===========================
# NUEVOS REGEX
# ===========================

NS_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+NS\s+(?P<ns>\S+)"
)

SOA_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+SOA\s+(?P<mname>\S+)\s+(?P<rname>\S+)\s+(?P<serial>\d+)"
)

A_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+A\s+(?P<addr>\S+)"
)

AAAA_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+AAAA\s+(?P<addr>\S+)"
)

CNAME_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+CNAME\s+(?P<cname>\S+)"
)

MX_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+MX\s+(?P<prio>\d+)\s+(?P<exchange>\S+)"
)

TXT_RE = re.compile(
    r"(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+TXT\s+\"(?P<text>.+)\""
)


def parse_dig_output(output: str):
    """
    Analiza la salida de `dig` y devuelve un diccionario con TODOS los registros.
    """
    results = defaultdict(list)

    for line in output.splitlines():

        # === DNSSEC ===
        m = DNSKEY_UNIX.search(line) or DNSKEY_WIN.search(line)
        if m:
            results["DNSKEY"].append(m.groupdict()); continue

        m = DS_RE.search(line)
        if m:
            results["DS"].append(m.groupdict()); continue

        m = RRSIG_RE.search(line)
        if m:
            results["RRSIG"].append(m.groupdict()); continue

        m = NSEC_RE.search(line)
        if m:
            results["NSEC"].append(m.groupdict()); continue

        m = NSEC3_RE.search(line)
        if m:
            results["NSEC3"].append(m.groupdict()); continue

        m = NSEC3PARAM_RE.search(line)
        if m:
            results["NSEC3PARAM"].append(m.groupdict()); continue


        # === REGISTROS NORMALES ===
        m = NS_RE.search(line)
        if m:
            results["NS"].append(m.groupdict()); continue

        m = SOA_RE.search(line)
        if m:
            results["SOA"].append(m.groupdict()); continue

        m = A_RE.search(line)
        if m:
            results["A"].append(m.groupdict()); continue

        m = AAAA_RE.search(line)
        if m:
            results["AAAA"].append(m.groupdict()); continue

        m = CNAME_RE.search(line)
        if m:
            results["CNAME"].append(m.groupdict()); continue

        m = MX_RE.search(line)
        if m:
            results["MX"].append(m.groupdict()); continue

        m = TXT_RE.search(line)
        if m:
            results["TXT"].append(m.groupdict()); continue

    return dict(results)


def parse_pcap(path):
    """
    Placeholder provisional—no analiza PCAP todavía.
    El CLI usará fallback a parseo de texto.
    """
    return {}
