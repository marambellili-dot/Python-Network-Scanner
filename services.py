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
    80: "HTTP"
}

open_ports = []
threads = []


def scan_port(port):

    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    scanner.settimeout(0.5)

    result = scanner.connect_ex((target, port))

    if result == 0:

        service = services.get(port, "Unknown")

        print(f"Port {port:<5} OPEN   {service}")

        open_ports.append((port, service))

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

for port, service in sorted(open_ports):

    report.write(f"Port {port:<5} OPEN   {service}\n")

report.write("\n")
report.write("-" * 35 + "\n")
report.write(f"Total open ports : {len(open_ports)}\n")

report.close()

print("-" * 35)
print("Scan completed.")
print(f"Total open ports : {len(open_ports)}")
print("Report saved to report.txt")