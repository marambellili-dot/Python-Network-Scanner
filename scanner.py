import socket

target = input("Enter target IP: ")

port = int(input("Enter port: "))

scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

result = scanner.connect_ex((target, port))

if result == 0:
    print("Port OPEN")
else:
    print("Port CLOSED")

scanner.close()