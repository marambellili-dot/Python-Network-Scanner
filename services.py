import socket

# Ask the user for the target
target = input("Enter IP address or hostname: ")

# Common network services
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

# Counter for open ports
nbport = 0

# Create the report file
report = open("report.txt", "w")

# Display header
print("\nPython Network Scanner")
print("-" * 35)
print(f"Target : {target}\n")

# Write header to the report
report.write("Python Network Scanner\n")
report.write("-" * 35 + "\n")
report.write(f"Target : {target}\n\n")

# Scan ports
for port in range(20, 101):

    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    scanner.settimeout(0.5)

    result = scanner.connect_ex((target, port))

    if result == 0:

        service = services.get(port, "Unknown")

        print(f"Port {port:<5} OPEN   {service}")

        report.write(f"Port {port:<5} OPEN   {service}\n")

        nbport += 1

    scanner.close()

# Footer
print("-" * 35)
print("Scan completed.")
print(f"Total open ports : {nbport}")
print("Report saved to report.txt")

report.write("\n")
report.write("-" * 35 + "\n")
report.write(f"Total open ports : {nbport}\n")

report.close()