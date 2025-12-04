# dnssec_tool/cli.py

import click
import json
from rich.console import Console
from rich.table import Table

from dnssec_tool.dig import dig_capture, dig_full
from dnssec_tool.parser import parse_pcap, parse_dig_output
from dnssec_tool.validator import validate_chain
from dnssec_tool.resolver_chain import build_trust_tree, print_trust_tree
from dnssec_tool.analyzer import audit_domain

console = Console()


@click.group()
def cli():
    """DNSSEC Toolkit CLI mejorado."""


# =======================================================
# SUBCOMANDO: VALIDATE
# =======================================================
@cli.command()
@click.argument("domain")
@click.option("--json", "as_json", is_flag=True,
              help="Salida en JSON para la validación de cadena.")
def validate(domain, as_json):
    """
    Valida únicamente la cadena DNSSEC (root → TLD → dominio),
    sin escanear registros A/NS/MX/etc.
    """
    console.print(f"[bold cyan]🔐 Validando DNSSEC para:[/] {domain}")

    tree = build_trust_tree(domain)

    if as_json:
        # Exportación en formato JSON
        import dnssec_tool.resolver_chain as rc
        console.print(
            json.dumps(rc.export_tree_json(tree), indent=4),
            style="bold white on black"
        )
    else:
        print_trust_tree(tree)


# =======================================================
# SCAN COMPLETO
# =======================================================
@cli.command()
@click.argument("domain")
@click.option("--json", "as_json", is_flag=True, help="Salida en formato JSON.")
@click.option("--validate", is_flag=True, help="Valida la cadena DNSSEC.")
def scan(domain, as_json, validate):
    """Escanea completamente un dominio."""

    console.print(f"[bold cyan]🔍 DNSSEC Scan para:[/] {domain}")

    # 1) Intentar captura PCAP
    pcap = dig_capture(domain)
    if pcap:
        records = parse_pcap(pcap)
        if records:
            if as_json:
                return print_json(records)
            else:
                return print_tables(records, domain, validate)

    console.print("[yellow]⚠ No se pudo usar PCAP. Usando salida de texto.[/]")

    # 2) Fallback a modo texto
    output = dig_full(domain)
    records = parse_dig_output(output)

    if as_json:
        return print_json(records)

    print_tables(records, domain, validate)


# =======================================================
# PRINT JSON
# =======================================================
def print_json(records):
    console.print(
        json.dumps(records, indent=4),
        style="bold white on black"
    )


# =======================================================
# PRINT TABLAS BONITAS
# =======================================================
def print_tables(records, domain, validate):
    console.print("\n[green]=== RESULTADOS DNS ===[/]\n")

    # Validación opcional
    if validate:
        status, detail = validate_chain(domain)

        if status == "valid":
            console.print(f"[bold green]✔ DNSSEC válido:[/] {detail}")

        elif status == "no_dnssec":
            console.print(f"[bold yellow]⚠ El dominio no usa DNSSEC:[/] {detail}")

        elif status == "broken":
            console.print(f"[bold red]✘ DNSSEC roto:[/] {detail}")

        console.print()

    # Tablas
    for rtype, items in records.items():
        if not items:
            continue

        table = Table(title=f"{rtype} ({len(items)})", header_style="bold cyan")

        # Encabezados dinámicos
        keys = sorted({k for item in items for k in item.keys()})
        for k in keys:
            table.add_column(k)

        # Filas
        for item in items:
            row = [str(item.get(k, "")) for k in keys]
            table.add_row(*row)

        console.print(table)
        console.print()


# =======================================================
# TREE (visualización simple)
# =======================================================
@cli.command()
@click.argument("domain")
def tree(domain):
    console.print(f"[bold cyan]🌳 Árbol de Confianza para:[/] {domain}")

    trust_tree = build_trust_tree(domain)
    print_trust_tree(trust_tree)

# =======================================================
# CHAIN – Cadena de confianza resumida
# =======================================================
@cli.command()
@click.argument("domain")
@click.option("--extended", "-e", is_flag=True, help="Muestra detalles del estado de cada eslabón de la cadena.")
def chain(domain, extended):
    console.print(f"[bold cyan]🔗 Cadena de Confianza para:[/] {domain}\n")

    tree = build_trust_tree(domain)

    # Determinar si la cadena está rota
    broken = any(not node["valid"] for node in tree if node["name"] != ".")

    # =============================
    # MODO EXTENDIDO
    # =============================
    if extended:
        for i, node in enumerate(tree):
            name = node["name"]
            detail = node["detail"]

            console.print(f"[bold]{name}[/] ({detail})")

            if i < len(tree) - 1:
                console.print("  ↓")

        status = (
            "[bold green]trusted[/]"
            if not broken
            else "[bold red]BROKEN[/]"
        )

        console.print(f"\n→ {status}")
        return

    # =============================
    # MODO SIMPLE
    # =============================
    parts = [node["name"] for node in tree]
    status = (
        "[green]trusted[/]"
        if not broken
        else "[red]BROKEN[/]"
    )
    chain_str = " → ".join(parts) + f" → {status}"

    console.print(chain_str)

# =======================================================
# ANALYZE: analizar un PCAP/PCAPNG externo
# =======================================================
@cli.command()
@click.argument("pcap_file")
@click.option("--json", "as_json", is_flag=True, help="Salida en JSON.")
def analyze(pcap_file, as_json):
    """Analiza un archivo PCAP/PCAPNG y extrae registros DNS."""

    import os
    from dnssec_tool.parser import parse_pcap

    if not os.path.exists(pcap_file):
        console.print(f"[red]❌ Archivo no encontrado:[/] {pcap_file}")
        return

    console.print(f"[cyan]📎 Analizando PCAP:[/] {pcap_file}")

    records = parse_pcap(pcap_file)

    if not records or all(len(v) == 0 for v in records.values()):
        console.print("[yellow]⚠ No se encontraron paquetes DNS en el archivo.[/]")
        return

    if as_json:
        print_json(records)
    else:
        print_tables(records, f"PCAP: {pcap_file}", validate=False)


# =======================================================
# AUDIT: análisis completo por RFC
# =======================================================
@cli.command()
@click.argument("domain")
@click.option("--json", "as_json", is_flag=True, help="Salida en formato JSON.")
def audit(domain, as_json):
    """
    Analiza un dominio según las especificaciones de DNSSEC (Act 4).
    Usa dig + parser y corre validaciones sobre DNSKEY, RRSIG, NSEC/NSEC3, DS y TTL.
    """
    console.print(f"[bold cyan]🧪 Auditoría DNSSEC para:[/] {domain}")

    output = dig_full(domain)
    records = parse_dig_output(output)

    summary = audit_domain(domain, records)

    if as_json:
        console.print_json(data=summary)
        return

    # ----- Imprimir resumen humano bonito -----
    # 1) DS / cadena
    ds = summary["ds_chain"]
    if ds["chain_status"] == "valid":
        console.print(f"[bold green]✔ Cadena de confianza íntegra:[/] {ds['detail']}")
    elif ds["chain_status"] == "no_dnssec":
        console.print(f"[yellow]⚠ El dominio no usa DNSSEC:[/] {ds['detail']}")
    else:
        console.print(f"[bold red]✘ Cadena de confianza rota:[/] {ds['detail']}")
    console.print()

    # 2) DNSKEY
    if summary["dnskey"]:
        table = Table(title="DNSKEY", header_style="bold cyan")
        table.add_column("name")
        table.add_column("alg")
        table.add_column("alg_name")
        table.add_column("allowed")
        table.add_column("role")
        table.add_column("proto_ok")
        table.add_column("ttl")

        for k in summary["dnskey"]:
            table.add_row(
                k["name"] or "",
                str(k["algorithm"]),
                k["algorithm_name"],
                "✔" if k["algorithm_allowed"] else "✘",
                k["role"],
                "✔" if k["proto_ok"] else "✘",
                str(k["ttl"]),
            )
        console.print(table)
        console.print()
    else:
        console.print("[yellow]No se encontraron DNSKEY.[/]\n")

    # 3) RRSIG
    if summary["rrsig"]:
        table = Table(title="RRSIG", header_style="bold cyan")
        table.add_column("name")
        table.add_column("type")
        table.add_column("alg")
        table.add_column("status")
        table.add_column("inception")
        table.add_column("expiration")
        table.add_column("signer")
        table.add_column("key_tag")

        for r in summary["rrsig"]:
            table.add_row(
                r["name"] or "",
                r["type_covered"] or "",
                f"{r['algorithm']} ({r['algorithm_name']})",
                r["status"],
                r["sig_inception"] or "",
                r["sig_expiration"] or "",
                r["signer_name"] or "",
                str(r["key_tag"]),
            )
        console.print(table)
        console.print()
    else:
        console.print("[yellow]No se encontraron firmas RRSIG.[/]\n")

    # 4) NSEC / NSEC3
    nsec = summary["nsec"]
    console.print(
        f"[bold]NSEC/NSEC3:[/] modo = {nsec['mode']} "
        f"(NSEC={nsec['has_nsec']}, NSEC3={nsec['has_nsec3']}, NSEC3PARAM={nsec['has_nsec3param']})\n"
    )

    # 5) TTL stats
    ttl_stats = summary["ttl_stats"]
    if ttl_stats:
        table = Table(title="TTL por tipo de registro", header_style="bold cyan")
        table.add_column("Tipo")
        table.add_column("Min")
        table.add_column("Max")
        table.add_column("Avg")
        table.add_column("Count")

        for rtype, st in ttl_stats.items():
            table.add_row(
                rtype,
                str(st["min"]),
                str(st["max"]),
                f"{st['avg']:.1f}",
                str(st["count"]),
            )
        console.print(table)
    else:
        console.print("[yellow]No se pudieron calcular métricas de TTL.[/]")

# =======================================================
# Subcomando: batch
# Procesa un archivo .txt con una lista de dominios
# =======================================================
@cli.command()
@click.argument("file_path")
@click.option("--json", "json_out", default=None,
              help="Guardar resultados en un archivo JSON")
def batch(file_path, json_out):
    """
    Lee un archivo .txt y ejecuta audit() para cada dominio.
    """

    console.print(f"[bold cyan]📁 Ejecutando batch DNSSEC desde:[/] {file_path}")

    # Cargar dominios del archivo
    try:
        with open(file_path, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]No se pudo leer el archivo:[/] {e}")
        return

    if not domains:
        console.print("[yellow]El archivo no contiene dominios.[/]")
        return

    console.print(f"[green]✔ Dominios cargados:[/] {len(domains)}\n")

    results = []

    # Ejecutar auditoría para cada dominio
    for domain in domains:
        console.print(f"[cyan]🔍 Analizando:[/] {domain}")

        dig_output = dig_full(domain)
        records = parse_dig_output(dig_output)
        summary = audit_domain(domain, records)

        results.append(summary)

    # Guardar JSON si el usuario lo pidió
    if json_out:
        try:
            with open(json_out, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            console.print(f"\n[bold green]✔ Resultados guardados en:[/] {json_out}")
        except Exception as e:
            console.print(f"[red]Error escribiendo JSON:[/] {e}")

    console.print("\n[bold green]✔ Batch finalizado.[/]")


@cli.command()
def help():
    """Muestra ayuda detallada del DNSSEC Toolkit."""

    console.print("[bold cyan]📘 DNSSEC Toolkit – Ayuda General[/]\n")

    console.print("[bold]Comandos disponibles:[/]\n")

    table = Table(header_style="bold cyan")
    table.add_column("Comando", style="bold")
    table.add_column("Descripción")

    table.add_row(
        "scan <domain>",
        "Escanea un dominio y muestra todos sus registros DNS.\n"
        "Opciones: --validate (valida cadena DNSSEC), --json (salida JSON)."
    )

    table.add_row(
        "validate <domain>",
        "Valida la cadena DNSSEC y muestra árbol de confianza resumido."
    )

    table.add_row(
        "tree <domain>",
        "Imprime el árbol de confianza DNSSEC desde la raíz hasta el dominio."
    )

    table.add_row(
        "chain <domain>",
        "Muestra la cadena de confianza en una sola línea.\n"
        "Opciones: --extended (muestra detalles de cada nivel)."
    )

    table.add_row(
        "help",
        "Muestra esta ayuda extendida."
    )

    console.print(table)
    console.print()

    console.print("[bold green]Ejemplos de uso:[/]\n")

    console.print("  • Escanear un dominio:")
    console.print("      [cyan]dnssec-cli scan unam.mx[/]\n")

    console.print("  • Validar DNSSEC:")
    console.print("      [cyan]dnssec-cli scan unam.mx --validate[/]\n")

    console.print("  • Imprimir árbol de confianza:")
    console.print("      [cyan]dnssec-cli tree unam.mx[/]\n")

    console.print("  • Cadena en una línea:")
    console.print("      [cyan]dnssec-cli chain unam.mx[/]\n")

    console.print("  • Cadena extendida:")
    console.print("      [cyan]dnssec-cli chain unam.mx --extended[/]\n")

    console.print("\n[bold magenta]Para ayuda individual, usa:[/]  [yellow]dnssec-cli <comando> --help[/]")



# =======================================================
# MAIN
# =======================================================
def main():
    cli()


if __name__ == "__main__":
    main()
