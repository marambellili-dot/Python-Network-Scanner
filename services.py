import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================
# Configuration
# =========================

SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}


# =========================
# Scan d'un seul port
# =========================

def scan_port(target, port):

    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    scanner.settimeout(1)

    try:

        result = scanner.connect_ex((target, port))

        if result == 0:

            service = SERVICES.get(port, "Unknown")

            banner = "No Banner"

            try:

                if port == 80:

                    scanner.send(b"HEAD / HTTP/1.0\r\n\r\n")

                    data = scanner.recv(1024)

                    banner = data.decode(errors="ignore").strip()

                    if banner == "":
                        banner = "No Banner"

            except:

                banner = "No Banner"

            return (port, service, banner)

        return None

    except socket.gaierror:

        return "INVALID_HOST"

    except Exception:

        return None

    finally:

        scanner.close()


# =========================
# Programme principal
# =========================

print("\nPython Network Scanner")
print("-" * 40)

target = input("Enter IP address or hostname: ")

start_port = int(input("Start port: "))
end_port = int(input("End port: "))

print("\nResolving target...")

try:

    target_ip = socket.gethostbyname(target)

except socket.gaierror:

    print("Error: Invalid hostname or IP address.")
    exit()


print(f"Target hostname : {target}")
print(f"Target IP       : {target_ip}")
print(f"Port range      : {start_port}-{end_port}")
print("-" * 40)

start_time = time.time()

open_ports = []

# =========================
# Multithreaded scanning
# =========================

with ThreadPoolExecutor(max_workers=20) as executor:

    futures = {
        executor.submit(scan_port, target_ip, port): port
        for port in range(start_port, end_port + 1)
    }

    for future in as_completed(futures):

        result = future.result()

        if result == "INVALID_HOST":

            print("Error: Unable to resolve target.")
            exit()

        if result is not None:

            open_ports.append(result)

            port, service, banner = result

            print(f"Port {port:<5} OPEN   {service}")

            if banner != "No Banner":

                print(f"Banner : {banner}\n")


# =========================
# Tri des résultats
# =========================

open_ports.sort(key=lambda x: x[0])


end_time = time.time()

scan_time = end_time - start_time


# =========================
# Génération du rapport
# =========================

report = open("report.txt", "w")

report.write("Python Network Scanner - Version 7\n")
report.write("=" * 40 + "\n")

report.write(f"Target hostname : {target}\n")
report.write(f"Target IP       : {target_ip}\n")
report.write(f"Port range      : {start_port}-{end_port}\n")
report.write("\n")

report.write("OPEN PORTS\n")
report.write("-" * 40 + "\n")

for port, service, banner in open_ports:

    report.write(f"Port {port:<5} OPEN   {service}\n")

    if banner != "No Banner":

        report.write(f"Banner : {banner}\n")

    report.write("\n")


report.write("-" * 40 + "\n")
report.write(f"Total open ports : {len(open_ports)}\n")
report.write(f"Scan duration    : {scan_time:.2f} seconds\n")

report.close()


# =========================
# Résultat final
# =========================

print("-" * 40)
print("Scan completed.")
print(f"Total open ports : {len(open_ports)}")
print(f"Scan duration    : {scan_time:.2f} seconds")
print("Report saved to report.txt")