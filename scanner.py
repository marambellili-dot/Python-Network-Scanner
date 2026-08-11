"""
Python Network Scanner V9 — Service Fingerprinting Engine
============================================================
Passe d'une simple correspondance port -> service a une vraie
detection basee sur des signatures (probe + regex + confidence),
inspiree du fonctionnement de `nmap-service-probes`.

Usage:
    python scanner_v9.py <target> [options]

Exemples:
    python scanner_v9.py 127.0.0.1
    python scanner_v9.py scanme.nmap.org -p 20-100
    python scanner_v9.py scanme.nmap.org -p 1-1000 --json -o result.json
    python scanner_v9.py 192.168.1.1 -p 1-65535 -t 200 --timeout 1.5
"""

import argparse
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional


# ==========================================
# Probable service (port-based, avant analyse)
# ==========================================

PORT_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}


# ==========================================
# Probes envoyees selon le port avant lecture
# de la banniere
# ==========================================

PROBES = {
    21: b"\r\n",
    22: b"\r\n",
    23: b"\r\n",
    25: b"EHLO scanner.local\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"\r\n",
    143: b"a001 CAPABILITY\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}


# ==========================================
# Moteur de signatures
# ==========================================
#
# Chaque signature est testee dans l'ordre. La premiere qui
# matche gagne. `version_group` pointe vers le groupe regex
# contenant le numero de version, si disponible -> confidence HIGH.
# Sans groupe de version mais match certain -> MEDIUM.
# Aucun match, uniquement le port -> LOW (fallback).

@dataclass
class ServiceSignature:
    pattern: str
    service: str
    app: Optional[str] = None
    version_group: Optional[int] = None
    flags: int = re.IGNORECASE

    def __post_init__(self):
        self.compiled = re.compile(self.pattern, self.flags)


SIGNATURES = [
    # --- SSH ---
    ServiceSignature(
        pattern=r"^SSH-[\d.]+-OpenSSH[_-]([\w.]+)",
        service="SSH", app="OpenSSH", version_group=1,
    ),
    ServiceSignature(
        pattern=r"^SSH-([\d.]+)",
        service="SSH", app=None, version_group=None,
    ),

    # --- FTP ---
    ServiceSignature(
        pattern=r"220.*vsFTPd\s+([\d.]+)",
        service="FTP", app="vsFTPd", version_group=1,
    ),
    ServiceSignature(
        pattern=r"220.*ProFTPD\s+([\d.]+)",
        service="FTP", app="ProFTPD", version_group=1,
    ),
    ServiceSignature(
        pattern=r"220.*FileZilla",
        service="FTP", app="FileZilla Server",
    ),
    ServiceSignature(
        pattern=r"^220[\s\-].*FTP",
        service="FTP", app=None,
    ),

    # --- SMTP ---
    ServiceSignature(
        pattern=r"220.*Postfix",
        service="SMTP", app="Postfix",
    ),
    ServiceSignature(
        pattern=r"220.*Exim\s+([\d.]+)",
        service="SMTP", app="Exim", version_group=1,
    ),
    ServiceSignature(
        pattern=r"^220[\s\-].*(ESMTP|SMTP)",
        service="SMTP", app=None,
    ),

    # --- HTTP ---
    ServiceSignature(
        pattern=r"^HTTP/1\.[01]\s+\d{3}",
        service="HTTP", app=None,
    ),

    # --- POP3 ---
    ServiceSignature(
        pattern=r"^\+OK.*Dovecot",
        service="POP3", app="Dovecot",
    ),
    ServiceSignature(
        pattern=r"^\+OK",
        service="POP3", app=None,
    ),

    # --- IMAP ---
    ServiceSignature(
        pattern=r"^\*\s+OK.*Dovecot",
        service="IMAP", app="Dovecot",
    ),
    ServiceSignature(
        pattern=r"^\*\s+OK",
        service="IMAP", app=None,
    ),

    # --- Telnet ---
    ServiceSignature(
        pattern=r"login:|username:",
        service="Telnet", app=None,
    ),

    # --- MySQL (banniere binaire, on cherche juste le marqueur) ---
    ServiceSignature(
        pattern=r"mysql_native_password|MariaDB",
        service="MySQL", app=None,
    ),

    # --- Redis ---
    ServiceSignature(
        pattern=r"-ERR unknown command|-NOAUTH",
        service="Redis", app=None,
    ),
]

# Extraction du header "Server:" pour les reponses HTTP,
# independamment de la signature principale.
HTTP_SERVER_RE = re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE)


@dataclass
class FingerprintResult:
    probable_service: str
    detected_service: str
    application: Optional[str]
    version: Optional[str]
    confidence: str  # HIGH / MEDIUM / LOW
    banner: str


class FingerprintEngine:
    """Analyse une banniere brute et retourne un FingerprintResult."""

    def __init__(self, signatures=None):
        self.signatures = signatures or SIGNATURES

    def analyze(self, banner: str, port: int) -> FingerprintResult:
        probable = PORT_SERVICES.get(port, "Unknown")

        if not banner or banner == "No Banner":
            return FingerprintResult(
                probable_service=probable,
                detected_service=probable,
                application=None,
                version=None,
                confidence="LOW",
                banner="No Banner",
            )

        for sig in self.signatures:
            match = sig.compiled.search(banner)
            if not match:
                continue

            version = None
            confidence = "MEDIUM"

            if sig.version_group:
                try:
                    version = match.group(sig.version_group)
                    confidence = "HIGH"
                except IndexError:
                    version = None

            app = sig.app

            # Cas particulier HTTP : on essaie d'extraire le header Server
            if sig.service == "HTTP":
                server_match = HTTP_SERVER_RE.search(banner)
                if server_match:
                    server_value = server_match.group(1).strip()
                    app = server_value.split("/")[0].strip()
                    version_match = re.search(r"/([\d.]+)", server_value)
                    if version_match:
                        version = version_match.group(1)
                        confidence = "HIGH"
                    else:
                        confidence = "MEDIUM"

            return FingerprintResult(
                probable_service=probable,
                detected_service=sig.service,
                application=app,
                version=version,
                confidence=confidence,
                banner=banner,
            )

        # Aucune signature ne matche : on retombe sur le port,
        # mais on garde la banniere brute car elle a de la valeur
        # meme non identifiee.
        return FingerprintResult(
            probable_service=probable,
            detected_service=probable,
            application=None,
            version=None,
            confidence="LOW",
            banner=banner,
        )


# ==========================================
# Lecture de la banniere sur un port ouvert
# ==========================================

def grab_banner(scanner: socket.socket, port: int) -> str:
    try:
        scanner.settimeout(2)

        if port in PROBES:
            scanner.sendall(PROBES[port])

        data = scanner.recv(2048)

        if not data:
            return "No Banner"

        banner = data.decode(errors="ignore").strip()
        return banner if banner else "No Banner"

    except Exception:
        return "No Banner"


# ==========================================
# Scan d'un port TCP + fingerprinting
# ==========================================

def scan_port(target: str, port: int, timeout: float,
              engine: FingerprintEngine) -> Optional[dict]:
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(timeout)

    try:
        result = scanner.connect_ex((target, port))

        if result != 0:
            return None

        banner = grab_banner(scanner, port)
        fingerprint = engine.analyze(banner, port)

        return {
            "port": port,
            "state": "OPEN",
            **asdict(fingerprint),
        }

    except OSError:
        return None

    finally:
        scanner.close()


# ==========================================
# Resolution du nom d'hote
# ==========================================

def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# ==========================================
# Rapports
# ==========================================

def generate_txt_report(path, target, target_ip, start_port,
                         end_port, results, duration):
    with open(path, "w", encoding="utf-8") as report:
        report.write("Python Network Scanner V9 — Fingerprinting Engine\n")
        report.write("=" * 60 + "\n")
        report.write(f"Target       : {target}\n")
        report.write(f"Resolved IP  : {target_ip}\n")
        report.write(f"Port range   : {start_port}-{end_port}\n")
        report.write(f"Scan time    : {duration:.2f} seconds\n")
        report.write("=" * 60 + "\n\n")

        for r in results:
            report.write(f"Port {r['port']:<5} {r['state']:<6}\n")
            report.write(f"Probable service : {r['probable_service']}\n")
            report.write(f"Detected service : {r['detected_service']}\n")
            report.write(f"Application      : {r['application'] or '-'}\n")
            report.write(f"Version          : {r['version'] or '-'}\n")
            report.write(f"Confidence       : {r['confidence']}\n")
            report.write(f"Banner           : {r['banner']}\n")
            report.write("-" * 60 + "\n")

        report.write(f"\nTotal open ports : {len(results)}\n")


def generate_json_report(path, target, target_ip, start_port,
                          end_port, results, duration):
    payload = {
        "target": target,
        "resolved_ip": target_ip,
        "port_range": f"{start_port}-{end_port}",
        "scan_duration_seconds": round(duration, 2),
        "total_open_ports": len(results),
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


# ==========================================
# CLI
# ==========================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Python Network Scanner V9 — Service Fingerprinting Engine"
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port range, e.g. 20-100 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                         help="Number of worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=0.7,
                         help="Per-port connection timeout in seconds (default: 0.7)")
    parser.add_argument("--json", action="store_true",
                         help="Also export results as JSON")
    parser.add_argument("-o", "--output", default="report",
                         help="Output file base name without extension (default: report)")

    args = parser.parse_args()

    try:
        start_port, end_port = args.ports.split("-")
        start_port, end_port = int(start_port), int(end_port)
    except ValueError:
        parser.error("--ports must be formatted as START-END, e.g. 20-100")

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        parser.error("Invalid port range")

    return args, start_port, end_port


# ==========================================
# Main
# ==========================================

def main():
    args, start_port, end_port = parse_args()

    print("\nPython Network Scanner V9 — Fingerprinting Engine")
    print("=" * 60)

    target_ip = resolve_target(args.target)
    if target_ip is None:
        print("Error: unable to resolve target.")
        sys.exit(1)

    print(f"Target      : {args.target}")
    print(f"Resolved IP : {target_ip}")
    print(f"Port range  : {start_port}-{end_port}")
    print(f"Threads     : {args.threads}")
    print(f"Timeout     : {args.timeout}s")
    print("=" * 60)

    engine = FingerprintEngine()
    results = []
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, args.timeout, engine): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)
                print(f"\nPort {result['port']:<5} OPEN")
                print(f"Detected service : {result['detected_service']}")
                print(f"Application      : {result['application'] or '-'}")
                print(f"Version          : {result['version'] or '-'}")
                print(f"Confidence       : {result['confidence']}")
                print(f"Banner           : {result['banner'][:150]}")

    results.sort(key=lambda item: item["port"])
    duration = time.perf_counter() - start_time

    txt_path = f"{args.output}.txt"
    generate_txt_report(txt_path, args.target, target_ip,
                         start_port, end_port, results, duration)

    if args.json:
        json_path = f"{args.output}.json"
        generate_json_report(json_path, args.target, target_ip,
                              start_port, end_port, results, duration)

    print("\n" + "=" * 60)
    print("Scan completed.")
    print(f"Total open ports : {len(results)}")
    print(f"Scan duration    : {duration:.2f} seconds")
    print(f"Report saved to  : {txt_path}")
    if args.json:
        print(f"JSON report saved to : {args.output}.json")


if __name__ == "__main__":
    main()