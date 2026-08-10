import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==========================================
# Known services
# ==========================================

SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}


# ==========================================
# Protocol probes
# ==========================================

PROBES = {

    21: b"\r\n",

    22: b"\r\n",

    23: b"\r\n",

    25: b"EHLO scanner\r\n",

    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",

    110: b"\r\n",

    143: b"a001 CAPABILITY\r\n"
}


# ==========================================
# Read banner from an open port
# ==========================================

def grab_banner(scanner, port):

    try:

        scanner.settimeout(2)

        # Send a protocol-specific probe
        if port in PROBES:

            scanner.sendall(PROBES[port])

        data = scanner.recv(2048)

        if not data:

            return "No Banner"

        banner = data.decode(
            errors="ignore"
        ).strip()

        if banner == "":

            return "No Banner"

        return banner

    except:

        return "No Banner"


# ==========================================
# Detect service from response
# ==========================================

def detect_service(banner, default_service):

    banner_upper = banner.upper()

    if "SSH-" in banner_upper:

        return "SSH"

    if "FTP" in banner_upper or banner_upper.startswith("220"):

        return "FTP / SMTP"

    if "SMTP" in banner_upper:

        return "SMTP"

    if "HTTP/" in banner_upper:

        return "HTTP"

    if "POP3" in banner_upper:

        return "POP3"

    if "IMAP" in banner_upper:

        return "IMAP"

    return default_service


# ==========================================
# Scan one TCP port
# ==========================================

def scan_port(target, port):

    scanner = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    scanner.settimeout(0.7)

    try:

        result = scanner.connect_ex(
            (target, port)
        )

        if result != 0:

            return None

        probable_service = SERVICES.get(
            port,
            "Unknown"
        )

        banner = grab_banner(
            scanner,
            port
        )

        detected_service = detect_service(
            banner,
            probable_service
        )

        return {
            "port": port,
            "state": "OPEN",
            "probable_service": probable_service,
            "detected_service": detected_service,
            "banner": banner
        }

    except OSError:

        return None

    finally:

        scanner.close()


# ==========================================
# Resolve hostname
# ==========================================

def resolve_target(target):

    try:

        return socket.gethostbyname(
            target
        )

    except socket.gaierror:

        return None


# ==========================================
# Generate report
# ==========================================

def generate_report(
    target,
    target_ip,
    start_port,
    end_port,
    results,
    duration
):

    with open(
        "report.txt",
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "Python Network Scanner V8\n"
        )

        report.write(
            "=" * 60 + "\n"
        )

        report.write(
            f"Target       : {target}\n"
        )

        report.write(
            f"Resolved IP  : {target_ip}\n"
        )

        report.write(
            f"Port range   : "
            f"{start_port}-{end_port}\n"
        )

        report.write(
            f"Scan time    : "
            f"{duration:.2f} seconds\n"
        )

        report.write(
            "=" * 60 + "\n\n"
        )

        for result in results:

            report.write(
                f"Port {result['port']:<5} "
                f"{result['state']:<6}\n"
            )

            report.write(
                f"Probable service : "
                f"{result['probable_service']}\n"
            )

            report.write(
                f"Detected service : "
                f"{result['detected_service']}\n"
            )

            report.write(
                f"Banner           : "
                f"{result['banner']}\n"
            )

            report.write(
                "-" * 60 + "\n"
            )

        report.write(
            f"\nTotal open ports : "
            f"{len(results)}\n"
        )


# ==========================================
# Main
# ==========================================

def main():

    print("\nPython Network Scanner V8")
    print("=" * 60)

    target = input(
        "Enter IP address or hostname: "
    ).strip()

    try:

        start_port = int(
            input("Start port: ")
        )

        end_port = int(
            input("End port: ")
        )

    except ValueError:

        print(
            "Error: ports must be numbers."
        )

        return

    if (
        start_port < 1
        or end_port > 65535
        or start_port > end_port
    ):

        print(
            "Error: invalid port range."
        )

        return

    target_ip = resolve_target(
        target
    )

    if target_ip is None:

        print(
            "Error: unable to resolve target."
        )

        return

    print(
        f"\nTarget      : {target}"
    )

    print(
        f"Resolved IP : {target_ip}"
    )

    print(
        f"Port range  : "
        f"{start_port}-{end_port}"
    )

    print("=" * 60)

    start_time = time.perf_counter()

    results = []

    # ======================================
    # Multithreaded scan
    # ======================================

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        futures = {

            executor.submit(
                scan_port,
                target_ip,
                port
            ): port

            for port in range(
                start_port,
                end_port + 1
            )
        }

        for future in as_completed(
            futures
        ):

            result = future.result()

            if result is not None:

                results.append(
                    result
                )

                print(
                    f"\nPort "
                    f"{result['port']:<5} "
                    f"OPEN"
                )

                print(
                    f"Probable service : "
                    f"{result['probable_service']}"
                )

                print(
                    f"Detected service : "
                    f"{result['detected_service']}"
                )

                print(
                    f"Banner : "
                    f"{result['banner'][:150]}"
                )

    # ======================================
    # Sort results
    # ======================================

    results.sort(
        key=lambda item: item["port"]
    )

    duration = (
        time.perf_counter()
        - start_time
    )

    # ======================================
    # Report
    # ======================================

    generate_report(
        target,
        target_ip,
        start_port,
        end_port,
        results,
        duration
    )

    # ======================================
    # Final result
    # ======================================

    print("\n" + "=" * 60)

    print("Scan completed.")

    print(
        f"Total open ports : "
        f"{len(results)}"
    )

    print(
        f"Scan duration    : "
        f"{duration:.2f} seconds"
    )

    print(
        "Report saved to report.txt"
    )


if __name__ == "__main__":

    main()