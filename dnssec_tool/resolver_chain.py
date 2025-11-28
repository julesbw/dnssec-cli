import dns.name
import dns.resolver
import dns.dnssec

# ------------------------------------------
# Obtiene DS (si existe) para name desde su padre
# ------------------------------------------
def get_ds_from_parent(name):
    if name == dns.name.root:
        return None
    try:
        q = dns.message.make_query(
            name,
            dns.rdatatype.DS,
            want_dnssec=True
        )
        response = dns.query.udp(q, "8.8.8.8")
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.DS:
                return rrset
    except:
        return None




# ------------------------------------------
# Obtiene DNSKEY del dominio (sin validación)
# ------------------------------------------
def get_dnskey(name):
    try:
        q = dns.message.make_query(
            name,
            dns.rdatatype.DNSKEY,
            want_dnssec=True      # <- LO MÁS IMPORTANTE
        )
        response = dns.query.udp(q, "8.8.8.8", timeout=3)
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                return rrset
    except Exception:
        return None


def validate_link(name, ds_rrset, dnskey_rrset):
    if not ds_rrset:
        return False, "No DS"
    if not dnskey_rrset:
        return False, "No DNSKEY"

    for ds in ds_rrset:
        for key in dnskey_rrset:
            try:
                generated = dns.dnssec.make_ds(name, key, ds.digest_type)
                if generated.digest == ds.digest:
                    return True, f"DS OK (keytag {ds.key_tag})"
            except:
                continue
    return False, "DS mismatch"

# ------------------------------------------
def build_trust_tree(domain):
    name = dns.name.from_text(domain)
    labels = name.labels

    # ROOT -> TLD -> ... -> SLD
    nodes = []
    for i in range(len(labels), 0, -1):
        nodes.append(dns.name.Name(labels[i-1:]))

    tree = []
    
    for node in nodes:    
        if node == dns.name.root:
            tree.append({
                "name": ".",
                "ds": None,
                "dnskey": None,
                "valid": True,
                "detail": "Root trusted (ICANN KSK)"
            })
            continue

        ds = get_ds_from_parent(node)
        dnskey = get_dnskey(node)
        valid, detail = validate_link(node, ds, dnskey)

        tree.append({
            "name": str(node),
            "ds": ds,
            "dnskey": dnskey,
            "valid": valid,
            "detail": detail
        })

    return tree[::-1]   # reverse for printing ROOT → ...

# ------------------------------------------
def print_trust_tree(tree):
    print("\n🌳 Árbol de Confianza DNSSEC:\n")

    prefix = ""
    for i, node in enumerate(tree):
        last = (i == len(tree) - 1)

        print(prefix + "└── " + node["name"])
        prefix += "    "

        if node["valid"]:
            print(prefix + f"✔ {node['detail']}")
        else:
            print(prefix + f"✘ {node['detail']}")

