"""
Python Network Security Scanner — single-file version
============================================================
TCP/UDP port scanner with protocol-specific probing, banner
grabbing, TLS handshake analysis, signature-based service
fingerprinting, basic host discovery and educational CVE mapping.

Usage:
    python scanner.py <target> [options]

Examples:
    python scanner.py 127.0.0.1
    python scanner.py scanme.nmap.org --quick
    python scanner.py scanme.nmap.org -p 1-1000 --json
    python scanner.py 192.168.1.0/24 --discover
    python scanner.py 2001:db8::1 -p 20-100
"""

import argparse
import ipaddress
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


# ============================================================
# PROBES — tables de ports/services et requetes protocolaires
# ============================================================

PORT_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

# Ports "frequents" pour le mode --quick (equivalent simplifie du
# top-ports de nmap)
QUICK_PORTS = sorted(PORT_SERVICES.keys())

TLS_PORTS = {443, 8443}

# Probes TCP envoyees selon le port avant lecture de la banniere
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

# Ports utilises pour le "host discovery" leger : on considere un
# hote "up" s'il repond (ouvert OU refuse activement) sur au moins
# un de ces ports frequents.
DISCOVERY_PORTS = [80, 443, 22, 445, 3389]


# ============================================================
# FINGERPRINT ENGINE — detection service/application/version
# ============================================================
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

    # Signature ajoutee suite a un cas reel rencontre pendant les tests
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

            confidence = "HIGH" if (app and version) else "MEDIUM"

            return FingerprintResult(
                probable_service=probable,
                detected_service=sig.service,
                application=app,
                version=version,
                confidence=confidence,
                banner=banner,
            )

        # Aucune signature ne correspond : resultat valide, pas une erreur.
        return self._unknown(probable, banner)


# ============================================================
# VULNERABILITY LOOKUP — mapping educatif version -> CVE connues
# ============================================================
#
# IMPORTANT : ceci est un lookup de reference, pas un vrai scanner
# de vulnerabilites. Un "match" signifie seulement que cette version
# exacte a un CVE connu dans cette petite table locale — ce n'est
# PAS une preuve que la cible est reellement exploitable (elle peut
# etre patchee, backportee, ou configuree differemment). Toujours
# verifier aupres de sources faisant autorite (NVD, avis editeur).

@dataclass
class VulnerabilityMatch:
    cve: str
    severity: str  # Critical / High / Medium / Low
    description: str


VULNERABILITY_DB = {
    "vsftpd": [
        {
            "version": "2.3.4",
            "cve": "CVE-2011-2523",
            "severity": "Critical",
            "description": "vsftpd 2.3.4 contains a backdoor introduced "
                            "into the source archive; widely used as a "
                            "textbook example in security training.",
        },
    ],
    "openssh": [
        {
            "version": "7.2",
            "cve": "CVE-2016-6210",
            "severity": "Medium",
            "description": "User enumeration via timing differences "
                            "during authentication.",
        },
    ],
    "proftpd": [
        {
            "version": "1.3.3",
            "cve": "CVE-2010-4221",
            "severity": "High",
            "description": "Stack buffer overflow in the response pool "
                            "handling code.",
        },
    ],
    "nginx": [
        {
            "version": "1.3.9",
            "cve": "CVE-2013-2028",
            "severity": "Critical",
            "description": "Stack buffer overflow in chunked transfer "
                            "encoding handling.",
        },
    ],
}


def check_vulnerabilities(application, version):
    """Retourne une liste de VulnerabilityMatch pour (application, version)."""
    if not application or not version:
        return []

    entries = VULNERABILITY_DB.get(application.lower(), [])
    return [
        VulnerabilityMatch(cve=e["cve"], severity=e["severity"], description=e["description"])
        for e in entries
        if e["version"] == version
    ]


def summarize_risk(all_matches):
    """all_matches : liste de listes de VulnerabilityMatch -> comptage par severite."""
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for matches in all_matches:
        for m in matches:
            if m.severity in summary:
                summary[m.severity] += 1
    return summary


# ============================================================
# REPORTS — construction des metadonnees et export TXT / JSON
# ============================================================

def build_metadata(target, target_ip, start_port, end_port, results,
                    duration, protocols, risk_summary):
    return {
        "target": target,
        "resolved_ip": target_ip,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "port_range": f"{start_port}-{end_port}",
        "protocols_scanned": protocols,
        "scan_duration_seconds": round(duration, 2),
        "ports_scanned": (end_port - start_port + 1) * len(protocols),
        "open_ports": len(results),
        "risk_summary": risk_summary,
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

            vulns = r.get("vulnerabilities") or []
            if vulns:
                report.write("Known CVEs       :\n")
                for v in vulns:
                    report.write(f"   - {v['cve']} ({v['severity']}) — {v['description']}\n")
            else:
                report.write("Known CVEs       : none found in local reference table\n")

            report.write("-" * 60 + "\n")

        report.write(f"\nTotal open ports : {len(results)}\n")
        report.write(
            "\nNote: the CVE list above is a small educational reference "
            "table, not a real vulnerability scan result. A match does "
            "not confirm the target is actually exploitable.\n"
        )


def generate_json_report(path, metadata, results):
    payload = {"scan_metadata": metadata, "results": results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


# ============================================================
# RESOLUTION DE CIBLE (IPv4 + IPv6)
# ============================================================

def resolve_target(target: str):
    """Retourne (ip, socket_family) ou (None, None) si echec."""
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return infos[0][4][0], infos[0][0]
    except socket.gaierror:
        return None, None


# ============================================================
# HOST DISCOVERY (leger, sans ICMP/raw socket)
# ============================================================
#
# On considere un hote "up" s'il repond (ouvert OU refuse activement,
# ce qui prouve qu'une machine ecoute la pile TCP) sur au moins un
# port frequent. Un vrai "ping sweep" ICMP demanderait des privileges
# administrateur, donc cette approche reste volontairement simple.

def is_host_up(ip: str, timeout: float) -> bool:
    for port in DISCOVERY_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def discover_hosts(network_str: str, timeout: float, threads: int):
    network = ipaddress.ip_network(network_str, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    up_hosts = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(is_host_up, ip, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                up_hosts.append(ip)

    return sorted(up_hosts, key=lambda ip: ipaddress.ip_address(ip))


# ============================================================
# BANNIERE TCP SIMPLE
# ============================================================

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


# ============================================================
# HANDSHAKE TLS (443 / 8443)
# ============================================================

def grab_tls_banner(target: str, port: int, family: int, timeout: float):
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


# ============================================================
# SCAN TCP / UDP + fingerprinting + CVE lookup
# ============================================================

def _attach_vulnerabilities(result: dict) -> dict:
    matches = check_vulnerabilities(result["application"], result["version"])
    result["vulnerabilities"] = [asdict(m) for m in matches]
    return result


def scan_tcp_port(target, port, family, timeout, engine):
    if port in TLS_PORTS:
        banner, tls_info = grab_tls_banner(target, port, family, timeout)
        if banner is None:
            return None

        fingerprint = engine.analyze(banner, port)
        if fingerprint.detected_service == "Unknown":
            fingerprint.detected_service = "HTTPS"
            fingerprint.confidence = "MEDIUM"
        if tls_info:
            fingerprint.banner = f"[TLS: {tls_info}] {fingerprint.banner}"

        result = {"port": port, "protocol": "tcp", "state": "OPEN", **asdict(fingerprint)}
        return _attach_vulnerabilities(result)

    scanner = socket.socket(family, socket.SOCK_STREAM)
    scanner.settimeout(timeout)
    try:
        if scanner.connect_ex((target, port)) != 0:
            return None

        banner = grab_tcp_banner(scanner, port)
        fingerprint = engine.analyze(banner, port)
        result = {"port": port, "protocol": "tcp", "state": "OPEN", **asdict(fingerprint)}
        return _attach_vulnerabilities(result)

    except OSError:
        return None
    finally:
        scanner.close()


def scan_udp_port(target, port, family, timeout, engine):
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
            return None

        fingerprint = engine.analyze(banner, port)
        result = {"port": port, "protocol": "udp", "state": state, **asdict(fingerprint)}
        return _attach_vulnerabilities(result)

    except OSError:
        return None
    finally:
        sock.close()


# ============================================================
# CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Python Network Security Scanner — TCP/UDP scanning, "
                     "fingerprinting, host discovery and CVE reference lookup"
    )
    parser.add_argument("target", help="IP/hostname (v4/v6), or a CIDR range with --discover")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port range, e.g. 20-100 (default: 1-1024)")
    parser.add_argument("--quick", action="store_true",
                         help="Scan only common ports instead of a range")
    parser.add_argument("--full", action="store_true",
                         help="Scan all 65535 ports (overrides -p)")
    parser.add_argument("--discover", action="store_true",
                         help="Treat target as a CIDR range and discover live hosts "
                              "instead of scanning ports")
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

    if args.discover:
        return args, None, None

    if args.full:
        start_port, end_port = 1, 65535
    elif args.quick:
        start_port, end_port = None, None  # gere via QUICK_PORTS
    else:
        try:
            start_port, end_port = args.ports.split("-")
            start_port, end_port = int(start_port), int(end_port)
        except ValueError:
            parser.error("--ports must be formatted as START-END, e.g. 20-100")

        if start_port < 1 or end_port > 65535 or start_port > end_port:
            parser.error("Invalid port range")

    return args, start_port, end_port


# ============================================================
# MAIN
# ============================================================

def run_discovery(args):
    print(f"\nPython Network Scanner v{VERSION} — Host Discovery")
    print("=" * 60)
    print(f"Network     : {args.target}")
    print(f"Threads     : {args.threads}")
    print("=" * 60)

    start_time = time.perf_counter()
    try:
        hosts = discover_hosts(args.target, args.timeout, args.threads)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    duration = time.perf_counter() - start_time

    print(f"\n{len(hosts)} host(s) up:")
    for ip in hosts:
        print(f"  {ip}")

    print("\n" + "=" * 60)
    print(f"Discovery duration : {duration:.2f} seconds")
    print(
        "\nNote: discovery is based on common-port TCP responses, not "
        "ICMP echo — a host with every probed port firewalled may be "
        "missed."
    )


def run_port_scan(args, start_port, end_port):
    print(f"\nPython Network Scanner v{VERSION} — Fingerprinting Engine")
    print("=" * 60)

    target_ip, family = resolve_target(args.target)
    if target_ip is None:
        print("Error: unable to resolve target.")
        sys.exit(1)

    ip_kind = "IPv6" if family == socket.AF_INET6 else "IPv4"
    protocols = ["tcp", "udp"] if args.udp else ["tcp"]

    if args.quick:
        ports_to_scan = QUICK_PORTS
        range_label = f"{len(QUICK_PORTS)} common ports"
        start_port, end_port = min(QUICK_PORTS), max(QUICK_PORTS)
    else:
        ports_to_scan = list(range(start_port, end_port + 1))
        range_label = f"{start_port}-{end_port}"

    print(f"Target      : {args.target}")
    print(f"Resolved IP : {target_ip} ({ip_kind})")
    print(f"Port range  : {range_label}")
    print(f"Protocols   : {', '.join(protocols)}")
    print(f"Threads     : {args.threads}")
    print(f"Timeout     : {args.timeout}s")
    print("=" * 60)

    engine = FingerprintEngine()
    results = []
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for port in ports_to_scan:
            futures[executor.submit(scan_tcp_port, target_ip, port, family, args.timeout, engine)] = port
            if args.udp:
                futures[executor.submit(scan_udp_port, target_ip, port, family, args.timeout, engine)] = port

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
                    if result["vulnerabilities"]:
                        for v in result["vulnerabilities"]:
                            print(f"  ! {v['cve']} ({v['severity']}) — {v['description']}")

    results.sort(key=lambda item: (item["port"], item["protocol"]))
    duration = time.perf_counter() - start_time

    risk_summary = summarize_risk([r["vulnerabilities"] for r in results])
    metadata = build_metadata(args.target, target_ip, start_port, end_port,
                               results, duration, protocols, risk_summary)

    txt_path = f"{args.output}.txt"
    generate_txt_report(txt_path, metadata, results)

    if args.json:
        json_path = f"{args.output}.json"
        generate_json_report(json_path, metadata, results)

    print("\n" + "=" * 60)
    print("Scan completed.")
    print(f"Total open ports : {len(results)}")
    print(f"Scan duration    : {duration:.2f} seconds")
    print(f"Risk summary     : {risk_summary}")
    print(f"Report saved to  : {txt_path}")
    if args.json:
        print(f"JSON report saved to : {args.output}.json")


def main():
    args, start_port, end_port = parse_args()

    if args.discover:
        run_discovery(args)
    else:
        run_port_scan(args, start_port, end_port)


if __name__ == "__main__":
    main()