# dnssec_tool/validator.py

import dns.resolver
import dns.dnssec
import dns.name
import hashlib
import base64

def fetch_dnskeys(domain):
    try:
        return dns.resolver.resolve(domain, "DNSKEY")
    except:
        return []


def fetch_ds(domain):
    try:
        return dns.resolver.resolve(domain, "DS")
    except:
        return []


def calc_digest(dnskey, algorithm):
    public_key = dnskey.to_text().split(" ", 3)[-1]
    key_bytes = base64.b64decode(public_key)

    if algorithm == 1:
        return hashlib.sha1(key_bytes).hexdigest()
    elif algorithm == 2:
        return hashlib.sha256(key_bytes).hexdigest()
    return None

def validate_chain(domain):
    name = dns.name.from_text(domain)

    # ---------- 1. Obtener DS ----------
    try:
        ds_rrset = dns.resolver.resolve(domain, "DS").rrset
    except dns.resolver.NoAnswer:
        # No DS = NO usa DNSSEC (no es error)
        return ("no_dnssec", "El dominio NO implementa DNSSEC (no hay DS en el TLD).")
    except Exception:
        return ("broken", "No se pudieron obtener los DS del dominio.")

    # ---------- 2. Obtener DNSKEY ----------
    try:
        dnskey_rrset = get_dnskey_no_validation(domain)
        if dnskey_rrset is None:
            return ("broken", "El dominio tiene DS pero NO se pudo obtener DNSKEY (algunos dominios rotos ocultan DNSKEY).")

    except dns.resolver.NoAnswer:
        return ("broken", "El dominio tiene DS pero NO tiene DNSKEY — cadena rota.")
    except Exception:
        return ("broken", "No se pudieron obtener los DNSKEY del dominio.")

    # ---------- 3. Validar cada DS ----------
    for ds in ds_rrset:
        for dnskey in dnskey_rrset:
            try:
                generated = dns.dnssec.make_ds(name, dnskey, ds.digest_type)
            except Exception:
                continue

            if generated.digest == ds.digest:
                return ("valid", f"DS coincide con DNSKEY (keytag {ds.key_tag}).")

    # ---------- 4. Si ningún DS coincide ----------
    return ("broken", "Ningún DNSKEY coincide con el DS — cadena rota.")

def get_dnskey_no_validation(domain):
    name = dns.name.from_text(domain)

    resolver = dns.resolver.Resolver()
    resolver.flags = 0  # DO flag off
    resolver.use_edns(edns=0)

    # hacemos query manual SIN DNSSEC
    q = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=False)

    # usar primer nameserver de /etc/resolv.conf o Windows
    ns = resolver.nameservers[0]

    try:
        r = dns.query.udp(q, ns, timeout=2)
        rrset = r.find_rrset(
            r.answer, name, dns.rdataclass.IN, dns.rdatatype.DNSKEY
        )
        return rrset
    except Exception:
        return None
