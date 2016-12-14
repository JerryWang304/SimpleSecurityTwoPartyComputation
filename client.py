import socket
HOST = '127.0.0.1'
PORT = 8001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
msg = s.recv(1024) 
print msg
while True:
    num = raw_input("Please input one bit:")
    s.send(num)  
    data = s.recv(1024)
    print data
