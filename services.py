import socket

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
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy"
}

print("\nPython Network Scanner")
print("-" * 35)
print(f"Target : {target}\n")

for port in range(20, 101):

    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    scanner.settimeout(0.5)

    result = scanner.connect_ex((target, port))

    if result == 0:

        service = services.get(port, "Unknown")

        print(f"Port {port:<5} OPEN   {service}")

    scanner.close()