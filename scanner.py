"""
Python Network Scanner — Final Version
============================================================
TCP/UDP port scanner with protocol-specific probing, banner
grabbing, TLS handshake analysis and signature-based service
fingerprinting (service, application, version, confidence).

Usage:
    python scanner.py <target> [options]

Examples:
    python scanner.py 127.0.0.1
    python scanner.py scanme.nmap.org -p 20-100
    python scanner.py scanme.nmap.org -p 1-1000 --json
    python scanner.py example.com -p 440-450 --udp
    python scanner.py 2001:db8::1 -p 20-100
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

VERSION = "9.0"

# ==========================================
# Probable service (port-based, avant analyse)
# ==========================================

PORT_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

TLS_PORTS = {443, 8443}

# ==========================================
# Probes TCP envoyees selon le port avant
# lecture de la banniere
# ==========================================

TCP_PROBES = {
    21: b"\r\n",
    22: b"\r\n",
    23: b"\r\n",
    25: b"EHLO scanner.local\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"\r\n",
    143: b"a001 CAPABILITY\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}

# HEAD request envoyee a l'interieur du tunnel TLS pour les ports HTTPS
HTTPS_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"

# ==========================================
# Probes UDP — un service UDP ne repond que
# si on lui envoie une requete qu'il reconnait
# ==========================================

# Requete DNS minimale (question "example.com A") — format standard,
# utilisee uniquement pour verifier qu'un service DNS repond.
DNS_PROBE = bytes.fromhex(
    "0001" "0100" "0001" "0000" "0000" "0000"
    "076578616d706c6503636f6d00" "0001" "0001"
)

# Requete client NTP standard (paquet de 48 octets, premier octet 0x1B)
NTP_PROBE = b"\x1b" + b"\x00" * 47

UDP_PROBES = {
    53: DNS_PROBE,
    123: NTP_PROBE,
}


# ==========================================
# Moteur de signatures
# ==========================================
#
# Chaque signature est testee dans l'ordre ; la premiere qui
# matche gagne.
#
# Regle de confiance (volontairement stricte) :
#   HIGH   -> service + application + version identifies
#   MEDIUM -> service identifie, mais application et/ou version manquants
#   LOW    -> aucune signature ne correspond, seule la supposition
#             basee sur le port est disponible

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
    ServiceSignature(r"^SSH-[\d.]+-OpenSSH[_-]([\w.]+)", "SSH", "OpenSSH", 1),
    ServiceSignature(r"^SSH-([\d.]+)", "SSH"),

    ServiceSignature(r"220.*vsFTPd\s+([\d.]+)", "FTP", "vsFTPd", 1),
    ServiceSignature(r"220.*ProFTPD\s+([\d.]+)", "FTP", "ProFTPD", 1),
    ServiceSignature(r"220.*FileZilla", "FTP", "FileZilla Server"),
    ServiceSignature(r"^220[\s\-].*FTP", "FTP"),

    ServiceSignature(r"220.*Postfix", "SMTP", "Postfix"),
    ServiceSignature(r"220.*Exim\s+([\d.]+)", "SMTP", "Exim", 1),
    ServiceSignature(r"^220[\s\-].*(ESMTP|SMTP)", "SMTP"),

    ServiceSignature(r"^HTTP/1\.[01]\s+\d{3}", "HTTP"),

    ServiceSignature(r"^\+OK.*Dovecot", "POP3", "Dovecot"),
    ServiceSignature(r"^\+OK", "POP3"),

    ServiceSignature(r"^\*\s+OK.*Dovecot", "IMAP", "Dovecot"),
    ServiceSignature(r"^\*\s+OK", "IMAP"),

    ServiceSignature(r"login:|username:", "Telnet"),

    ServiceSignature(r"mysql_native_password|MariaDB", "MySQL"),
    ServiceSignature(r"-ERR unknown command|-NOAUTH", "Redis"),

    # Exemple de signature ajoutee suite a un cas reel rencontre
    # pendant les tests (voir README) : VMware Authentication Daemon
    ServiceSignature(
        r"VMware Authentication Daemon(?:\s+Version)?\s+([\d.]+)",
        "VMware Auth Daemon", "VMware Authentication Daemon", 1,
    ),
]

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

    def _unknown(self, probable, banner):
        return FingerprintResult(
            probable_service=probable,
            detected_service="Unknown",
            application=None,
            version=None,
            confidence="LOW",
            banner=banner,
        )

    def analyze(self, banner: str, port: int) -> FingerprintResult:
        probable = PORT_SERVICES.get(port, "Unknown")

        if not banner or banner == "No Banner":
            return self._unknown(probable, "No Banner")

        for sig in self.signatures:
            match = sig.compiled.search(banner)
            if not match:
                continue

            version = None
            if sig.version_group:
                try:
                    version = match.group(sig.version_group)
                except IndexError:
                    version = None

            app = sig.app

            if sig.service == "HTTP":
                server_match = HTTP_SERVER_RE.search(banner)
                if server_match:
                    server_value = server_match.group(1).strip()
                    app = server_value.split("/")[0].strip()
                    version_match = re.search(r"/([\d.]+)", server_value)
                    if version_match:
                        version = version_match.group(1)

            # Regle de confiance stricte : HIGH seulement si app + version
            if app and version:
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

        # Aucune signature ne correspond : c'est un resultat valide,
        # pas une erreur. On le dit explicitement plutot que de
        # deviner a partir du port.
        return self._unknown(probable, banner)


# ==========================================
# Resolution du nom d'hote (IPv4 + IPv6)
# ==========================================

def resolve_target(target: str):
    """Retourne (ip, socket_family) ou (None, None) si echec."""
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ip = infos[0][4][0]
        family = infos[0][0]
        return ip, family
    except socket.gaierror:
        return None, None


# ==========================================
# Banniere TCP simple
# ==========================================

def grab_tcp_banner(scanner: socket.socket, port: int) -> str:
    try:
        scanner.settimeout(2)
        if port in TCP_PROBES:
            scanner.sendall(TCP_PROBES[port])
        data = scanner.recv(2048)
        if not data:
            return "No Banner"
        banner = data.decode(errors="ignore").strip()
        return banner if banner else "No Banner"
    except Exception:
        return "No Banner"


# ==========================================
# Handshake TLS (443 / 8443) — nmap detecte
# la couche SSL puis continue l'identification
# derriere cette couche ; on fait la version
# simplifiee ici.
# ==========================================

def grab_tls_banner(target: str, port: int, family: int, timeout: float):
    """Retourne (banner, tls_info) ou (None, None) si le handshake echoue."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            raw_sock.connect((target, port))
            with context.wrap_socket(raw_sock) as tls_sock:
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()[0] if tls_sock.cipher() else None

                tls_sock.settimeout(2)
                try:
                    tls_sock.sendall(HTTPS_PROBE)
                    data = tls_sock.recv(2048)
                    banner = data.decode(errors="ignore").strip() or "No Banner"
                except Exception:
                    banner = "No Banner"

                tls_info = f"{tls_version} ({cipher})" if tls_version else None
                return banner, tls_info

    except Exception:
        return None, None


# ==========================================
# Scan d'un port TCP + fingerprinting
# ==========================================

def scan_tcp_port(target: str, port: int, family: int, timeout: float,
                   engine: FingerprintEngine) -> Optional[dict]:

    if port in TLS_PORTS:
        banner, tls_info = grab_tls_banner(target, port, family, timeout)
        if banner is None:
            return None  # handshake TLS impossible -> port considere ferme/filtre

        fingerprint = engine.analyze(banner, port)
        # Le handshake TLS reussi est en soi une confirmation forte du protocole
        if fingerprint.detected_service == "Unknown":
            fingerprint.detected_service = "HTTPS"
            fingerprint.confidence = "MEDIUM"
        if tls_info:
            fingerprint.banner = f"[TLS: {tls_info}] {fingerprint.banner}"

        return {"port": port, "protocol": "tcp", "state": "OPEN", **asdict(fingerprint)}

    scanner = socket.socket(family, socket.SOCK_STREAM)
    scanner.settimeout(timeout)
    try:
        result = scanner.connect_ex((target, port))
        if result != 0:
            return None

        banner = grab_tcp_banner(scanner, port)
        fingerprint = engine.analyze(banner, port)
        return {"port": port, "protocol": "tcp", "state": "OPEN", **asdict(fingerprint)}

    except OSError:
        return None
    finally:
        scanner.close()


# ==========================================
# Scan d'un port UDP
# ==========================================
#
# UDP n'a pas de handshake : on envoie une requete adaptee au
# service attendu et on attend une reponse.
#   - une reponse arrive          -> OPEN
#   - le port est explicitement fermé (ICMP unreachable) -> ferme
#   - rien ne repond dans le delai -> OPEN|FILTERED (ambigu, comme nmap :
#     un service peut tres bien ignorer les paquets qu'il ne comprend pas)

def scan_udp_port(target: str, port: int, family: int, timeout: float,
                   engine: FingerprintEngine) -> Optional[dict]:
    probe = UDP_PROBES.get(port, b"\x00")
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(probe, (target, port))
        try:
            data, _ = sock.recvfrom(2048)
            banner = data.decode(errors="ignore").strip() or "No Banner"
            state = "OPEN"
        except socket.timeout:
            banner = "No Banner"
            state = "OPEN|FILTERED"
        except ConnectionResetError:
            return None  # ICMP port unreachable -> ferme

        fingerprint = engine.analyze(banner, port)
        return {"port": port, "protocol": "udp", "state": state, **asdict(fingerprint)}

    except OSError:
        return None
    finally:
        sock.close()


# ==========================================
# Rapports
# ==========================================

def build_metadata(target, target_ip, start_port, end_port, results, duration, protocols):
    return {
        "target": target,
        "resolved_ip": target_ip,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "port_range": f"{start_port}-{end_port}",
        "protocols_scanned": protocols,
        "scan_duration_seconds": round(duration, 2),
        "ports_scanned": (end_port - start_port + 1) * len(protocols),
        "open_ports": len(results),
    }


def generate_txt_report(path, metadata, results):
    with open(path, "w", encoding="utf-8") as report:
        report.write(f"Python Network Scanner v{VERSION} — Fingerprinting Engine\n")
        report.write("=" * 60 + "\n")
        for key, value in metadata.items():
            report.write(f"{key:<20}: {value}\n")
        report.write("=" * 60 + "\n\n")

        for r in results:
            report.write(f"Port {r['port']:<5}/{r['protocol']:<3} {r['state']:<14}\n")
            report.write(f"Probable service : {r['probable_service']}\n")
            report.write(f"Detected service : {r['detected_service']}\n")
            report.write(f"Application      : {r['application'] or '-'}\n")
            report.write(f"Version          : {r['version'] or '-'}\n")
            report.write(f"Confidence       : {r['confidence']}\n")
            report.write(f"Banner           : {r['banner']}\n")
            report.write("-" * 60 + "\n")

        report.write(f"\nTotal open ports : {len(results)}\n")


def generate_json_report(path, metadata, results):
    payload = {"scan_metadata": metadata, "results": results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


# ==========================================
# CLI
# ==========================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Python Network Scanner — TCP/UDP scanning with service fingerprinting"
    )
    parser.add_argument("target", help="IP address (v4/v6) or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port range, e.g. 20-100 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                         help="Number of worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=0.7,
                         help="Per-port timeout in seconds (default: 0.7)")
    parser.add_argument("--udp", action="store_true",
                         help="Also scan UDP ports (slower, results can be ambiguous)")
    parser.add_argument("--json", action="store_true",
                         help="Also export results as JSON")
    parser.add_argument("-o", "--output", default="report",
                         help="Output file base name without extension (default: report)")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Do not print each open port during the scan")
    parser.add_argument("--version", action="version",
                         version=f"Python Network Scanner v{VERSION}\nService Fingerprinting Engine")

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

    print(f"\nPython Network Scanner v{VERSION} — Fingerprinting Engine")
    print("=" * 60)

    target_ip, family = resolve_target(args.target)
    if target_ip is None:
        print("Error: unable to resolve target.")
        sys.exit(1)

    ip_kind = "IPv6" if family == socket.AF_INET6 else "IPv4"
    protocols = ["tcp", "udp"] if args.udp else ["tcp"]

    print(f"Target      : {args.target}")
    print(f"Resolved IP : {target_ip} ({ip_kind})")
    print(f"Port range  : {start_port}-{end_port}")
    print(f"Protocols   : {', '.join(protocols)}")
    print(f"Threads     : {args.threads}")
    print(f"Timeout     : {args.timeout}s")
    print("=" * 60)

    engine = FingerprintEngine()
    results = []
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}

        for port in range(start_port, end_port + 1):
            futures[executor.submit(
                scan_tcp_port, target_ip, port, family, args.timeout, engine
            )] = port

            if args.udp:
                futures[executor.submit(
                    scan_udp_port, target_ip, port, family, args.timeout, engine
                )] = port

        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)
                if not args.quiet:
                    print(f"\nPort {result['port']:<5}/{result['protocol']:<3} {result['state']}")
                    print(f"Detected service : {result['detected_service']}")
                    print(f"Application      : {result['application'] or '-'}")
                    print(f"Version          : {result['version'] or '-'}")
                    print(f"Confidence       : {result['confidence']}")
                    print(f"Banner           : {result['banner'][:150]}")

    results.sort(key=lambda item: (item["port"], item["protocol"]))
    duration = time.perf_counter() - start_time

    metadata = build_metadata(args.target, target_ip, start_port, end_port,
                               results, duration, protocols)

    txt_path = f"{args.output}.txt"
    generate_txt_report(txt_path, metadata, results)

    if args.json:
        json_path = f"{args.output}.json"
        generate_json_report(json_path, metadata, results)

    print("\n" + "=" * 60)
    print("Scan completed.")
    print(f"Total open ports : {len(results)}")
    print(f"Scan duration    : {duration:.2f} seconds")
    print(f"Report saved to  : {txt_path}")
    if args.json:
        print(f"JSON report saved to : {args.output}.json")


if __name__ == "__main__":
    main()