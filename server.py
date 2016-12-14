import socket

HOST = '127.0.0.1'
PORT = 8001
 # AF_INET: local 
 # SOCK_STREAM: TCP based
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

print 'Alice at: %s:%s' %(HOST, PORT)
print 'waiting for Bob...'
n = input("How many bits: ")


conn, addr = s.accept()
print 'Connected by Bob', addr
conn.send("At most %d bits" % n)
while True:
    data = int(conn.recv(1024))
    print data
    
    conn.send("Alice received you message.") 
conn.close() 