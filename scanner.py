import socket

# Ask the user for the target IP address
target = input("Enter the target IP address: ")

print(f"\nScanning {target}...\n")

# Scan ports from 20 to 100
for port in range(20, 101):

    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    scanner.settimeout(0.5)

    result = scanner.connect_ex((target, port))

    if result == 0:
        print(f"Port {port}: OPEN")

    scanner.close()

print("\nScan completed.")