import socket
import threading

target = input("Enter IP address or hostname: ")

services = {
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

open_ports = []
threads = []


def scan_port(port):

    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    scanner.settimeout(1)

    result = scanner.connect_ex((target, port))

    if result == 0:

        service = services.get(port, "Unknown")

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

        print(f"Port {port:<5} OPEN   {service}")
        print(f"Banner : {banner}\n")

        open_ports.append((port, service, banner))

    scanner.close()


print("\nPython Network Scanner")
print("-" * 35)
print(f"Target : {target}\n")

for port in range(20, 101):

    thread = threading.Thread(target=scan_port, args=(port,))

    threads.append(thread)

    thread.start()

for thread in threads:

    thread.join()

report = open("report.txt", "w")

report.write("Python Network Scanner\n")
report.write("-" * 35 + "\n")
report.write(f"Target : {target}\n\n")

for port, service, banner in sorted(open_ports):

    report.write(f"Port {port:<5} OPEN   {service}\n")
    report.write(f"Banner : {banner}\n\n")

report.write("-" * 35 + "\n")
report.write(f"Total open ports : {len(open_ports)}\n")

report.close()

print("-" * 35)
print("Scan completed.")
print(f"Total open ports : {len(open_ports)}")
print("Report saved to report.txt")