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

#
# Captura de interface
#
def pick_interface():
    import subprocess, re

    result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)

    lines = result.stdout.splitlines()

    # 1) Preferimos Wi-Fi
    for line in lines:
        if "Wi-Fi" in line or "Wireless" in line:
            match = re.match(r"(\d+)\.", line)
            if match:
                return match.group(1)

    # 2) Luego Ethernet
    for line in lines:
        if "Ethernet" in line and "vEthernet" not in line:
            match = re.match(r"(\d+)\.", line)
            if match:
                return match.group(1)

    # 3) Fallback: la primera interfaz
    return "1"


# ---------------------------
# Captura PCAP
# ---------------------------
def dig_capture(domain):
    if not tshark_exists():
        return None

    # Detecta la mejor interfaz automáticamente
    iface = pick_interface()

    # Archivo temporal .pcapng
    pcap = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{domain}.pcapng").name

    console.print(f"[cyan]📡 Iniciando captura con tshark en interfaz {iface}...[/]")

    # Inicia captura con interfaz correcta
    capture = subprocess.Popen(
        [
            "tshark",
            "-i", iface,          # <---- interfaz correcta
            "-w", pcap,
            "-f", "udp port 53"   # <---- filtro BPF correcto
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(0.50)  # ligera espera para iniciar captura

    # Lanza las consultas reales
    queries = [
        "SOA", "NS", "A", "AAAA", "TXT", "MX",
        "DNSKEY", "DS", "NSEC", "NSEC3", "NSEC3PARAM"
    ]

    for q in queries:
        try:
            subprocess.run(
                ["dig", domain, q, "+dnssec"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass

    time.sleep(0.50)
    capture.terminate()

    if os.path.getsize(pcap) < 300:  # si aún tiene muy poquito…
        console.print("[yellow]⚠ El PCAP está vacío o casi vacío, usando modo texto.[/]")
        return None

    console.print(f"[green]✔ Captura completada:[/] {pcap}")
    return pcap
