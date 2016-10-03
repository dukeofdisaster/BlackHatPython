import socket

target_host = "0.0.0.0"
target_port = 9999

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client
client.connect((target_host, target_port))

# sned some data
client.send("Go Shawty, It's YA birfday")

# receive some data
response = client.recv(4096)

print response
