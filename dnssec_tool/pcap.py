from rich.console import Console
import subprocess, json

console = Console()

def tshark_exists():
    return subprocess.call(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def parse_pcap(pcap_path):
    if not tshark_exists():
        console.print("[red]❌ tshark no está disponible.[/red]")
        return {}

    cmd = ["tshark", "-r", pcap_path, "-T", "json", "-Y", "dns"]
    
    try:
        output = subprocess.check_output(cmd, text=True)
        packets = json.loads(output)
    except Exception as e:
        console.print(f"[red]❌ Error leyendo PCAP:[/red] {e}")
        return {}

    records = { "DNSKEY":[],"DS":[],"RRSIG":[],"NSEC":[],"NSEC3":[],"NSEC3PARAM":[] }

    for pkt in packets:
        layers = pkt["_source"]["layers"]
        if "dns" not in layers:
            continue
        dns = layers["dns"]

        # Detectar tipo
        if "dns.resp_type" not in dns:
            continue

        rtype = dns["dns.resp_type"]

        # ----- DNSKEY -----
        if rtype == "DNSKEY":
            records["DNSKEY"].append({
                "name": dns.get("dns.resp_name"),
                "ttl": dns.get("dns.resp.ttl"),
                "flags": dns.get("dns.resp.flags"),
                "algorithm": dns.get("dns.resp.algorithm"),
                "key": dns.get("dns.resp.data"),
            })

        # ----- DS -----
        elif rtype == "DS":
            records["DS"].append({
                "name": dns.get("dns.resp_name"),
                "ttl": dns.get("dns.resp.ttl"),
                "keytag": dns.get("dns.resp.keyid"),
                "algorithm": dns.get("dns.resp.algorithm"),
                "digest_type": dns.get("dns.resp.digesttype"),
                "digest": dns.get("dns.resp.data"),
            })

        # ----- RRSIG -----
        elif rtype == "RRSIG":
            records["RRSIG"].append({
                "name": dns.get("dns.resp_name"),
                "ttl": dns.get("dns.resp.ttl"),
                "type_covered": dns.get("dns.resp.typecovered"),
                "algorithm": dns.get("dns.resp.algorithm"),
                "keytag": dns.get("dns.resp.keyid"),
                "sig": dns.get("dns.resp.data"),
            })

        # ----- NSEC -----
        elif rtype == "NSEC":
            records["NSEC"].append({
                "name": dns.get("dns.resp_name"),
                "ttl": dns.get("dns.resp.ttl"),
                "next": dns.get("dns.resp.nextdomain")
            })

        # ----- NSEC3 -----
        elif rtype == "NSEC3":
            records["NSEC3"].append({
                "name": dns.get("dns.resp_name"),
                "ttl": dns.get("dns.resp.ttl"),
                "salt": dns.get("dns.resp.salt"),
                "hash_alg": dns.get("dns.resp.hashalgo")
            })

        # ----- NSEC3PARAM -----
        elif rtype == "NSEC3PARAM":
            records["NSEC3PARAM"].append({
                "name": dns.get("dns.resp_name"),
                "ttl": dns.get("dns.resp.ttl"),
                "salt": dns.get("dns.resp.salt"),
                "hash_alg": dns.get("dns.resp.hashalgo"),
                "iterations": dns.get("dns.resp.iterations")
            })

    return records
