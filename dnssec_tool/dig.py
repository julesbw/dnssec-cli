# dnssec_tool/dig.py

import subprocess
import shutil
import tempfile
import os
import time
from rich.console import Console

console = Console()


def dig_exists():
    return shutil.which("dig") is not None


def tshark_exists():
    return shutil.which("tshark") is not None


# ---------------------------
# Función completa
# ---------------------------
def dig_full(domain):
    """
    Ejecuta TODAS las consultas relevantes del dominio.
    """
    commands = [
        ["dig", domain, "SOA", "+dnssec"],
        ["dig", domain, "NS", "+dnssec"],
        ["dig", domain, "A", "+dnssec"],
        ["dig", domain, "AAAA", "+dnssec"],
        ["dig", domain, "TXT", "+dnssec"],
        ["dig", domain, "MX", "+dnssec"],
        ["dig", domain, "DNSKEY", "+dnssec"],
        ["dig", domain, "DS", "+dnssec"],
        ["dig", domain, "NSEC", "+dnssec"],
        ["dig", domain, "NSEC3", "+dnssec"],
        ["dig", domain, "NSEC3PARAM", "+dnssec"],

        # Incluye ANY (aunque RFC 8482 minimiza)
        ["dig", domain, "ANY", "+dnssec"],
    ]

    full_output = []

    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            full_output.append(result.stdout)
        except Exception as e:
            console.print(f"[red]Error ejecutando {cmd}:[/] {e}")

    return "\n".join(full_output)


# ---------------------------
# Captura PCAP
# ---------------------------
def dig_capture(domain):
    if not tshark_exists():
        return None

    pcap = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{domain}.pcapng").name

    console.print("[cyan]📡 Iniciando captura con tshark...[/]")

    capture = subprocess.Popen(
        ["tshark", "-w", pcap, "udp port 53"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(0.3)

    # Ejecutar todas las consultas
    commands = [
        ["dig", domain, "SOA", "+dnssec"],
        ["dig", domain, "NS", "+dnssec"],
        ["dig", domain, "A", "+dnssec"],
        ["dig", domain, "AAAA", "+dnssec"],
        ["dig", domain, "TXT", "+dnssec"],
        ["dig", domain, "MX", "+dnssec"],
        ["dig", domain, "DNSKEY", "+dnssec"],
        ["dig", domain, "DS", "+dnssec"],
        ["dig", domain, "NSEC", "+dnssec"],
        ["dig", domain, "NSEC3", "+dnssec"],
        ["dig", domain, "NSEC3PARAM", "+dnssec"],
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

    time.sleep(0.3)
    capture.terminate()

    if os.path.getsize(pcap) < 200:
        return None

    console.print(f"[green]✔ Captura completada:[/] {pcap}")
    return pcap
