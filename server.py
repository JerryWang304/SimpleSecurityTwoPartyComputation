import socket
import random
import rsa
from Crypto.Cipher import AES
from numpy.random import permutation
from binascii import b2a_hex, a2b_hex
mode = AES.MODE_CBC

HOST = '127.0.0.1'
PORT = 8007
 # AF_INET: local 
 # SOCK_STREAM: TCP based
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

print 'Alice at: %s:%s' %(HOST, PORT)

n = input("How many bits: ")
print 'waiting for Bob...'

conn, addr = s.accept()
print 'Connected by Bob', addr
conn.send(str(n))

def double_encode(k1,k2,plaintext):
    encryptor = AES.new(k1,mode,b'0000000000000000')
    ciphertext1 = encryptor.encrypt(plaintext)
    # cipher1 = b2a_hex(ciphertext1)
    encryptor = AES.new(k2,mode,b'0000000000000000')
    ciphertext2 = encryptor.encrypt(ciphertext1)
    return ciphertext2


alice_wealth = raw_input("Input Alice's wealth in binary format: ")
print "alice wealth = ",alice_wealth
i = 0
result = 1
while True:
    print '#############################'
    print "##### %d-th comparision #####" % (i+1)
    print '#############################'
    #conn.send(str(i))
    # generate 6 random numbers
    k = []
    chars = [str(j) for j in range(0,10)]
    chars.extend([chr(j) for j in range(97,123)])
    for j in range(6):
        temp_k = ''
        for j in range(16):
            temp_k += random.choice(chars)
        k.append(temp_k)

    # k[0]: 0
    # k[1]: 1
    # k[2]: 0
    # k[3]: 1
    # k[4]: 0
    # k[5]: 1
    print "all the keys: "
    print k
    # four encoded numbers
    # round 1
    c1 = double_encode(k[2],k[0],k[4])
    # round 2
    c2 = double_encode(k[3],k[0],k[5])
    # round 3
    c3 = double_encode(k[2],k[1],k[5])
    # round 4
    c4 = double_encode(k[3],k[1],k[5])
    # garble_table = [c1,c2,c3,c4]
    # garble_table = permutation(garble_table)
    # send garble circuit to Bob
    print "Sending garble circuit"
    print "c1 = ",b2a_hex(c1)
    print "c2 = ",b2a_hex(c2)
    print "c3 = ",b2a_hex(c3)
    print "c4 = ",b2a_hex(c4)
    print "sending c2"
    conn.send(b2a_hex(c2))
    print "sending c1"
    conn.send(b2a_hex(c1))
    print "sending c3"
    conn.send(b2a_hex(c3))
    print "sending c4"
    conn.send(b2a_hex(c4))
    # send one key that represents 0 or 1
    print "sending one key: ",
    if alice_wealth[i] == '0':
        conn.send(k[0])
        print k[0],
        print ":  0"
    elif alice_wealth[i] == '1':
        conn.send(k[1])
        print k[1],
        print ":  1"
    # send k[2] or k[3]
    print "Run OT to sent next key"
    
    length_key = int(conn.recv(10))
    print "the received length is",length_key
    print "Receiving public key 1"
    #length1 = int(conn.recv(1024))
    n1 = int(conn.recv(length_key))
    print "n1 = ",n1
    #e1 = int(conn.recv(5))
    #print "e1 = ",e1
    public_key1 = rsa.PublicKey(n1,65537)
    
    
    print "Receiving public key 2"
    n2 = int(conn.recv(length_key))
    print "n2 = ",n2
    #e2 = int(conn.recv(5))
    #print "e2 = ",e2
    public_key2 = rsa.PublicKey(n2,65537)
    
    

    # encode k[2] and k[3]
    print "k[2] = ",k[2]
    print "k[3] = ",k[3]
    cipher1 = rsa.encrypt(k[2],public_key1)
    cipher2 = rsa.encrypt(k[3],public_key2)
    print "sending encrypted keys..."
    
    l1 = len(cipher1)
    # send length firstly
    conn.send(str(l1))
    print "l1 = ",l1
    conn.send(cipher1)
    print "cipher1 = ",b2a_hex(cipher1)
    l2 = len(cipher2)
    print "l2 = ",l2
    conn.send(str(l2))
    conn.send(cipher2)
    print "cipher2 = ",b2a_hex(cipher2)
    
    print "Receiving Bob's decrypted keys"
    p1 = conn.recv(16)
    p2 = conn.recv(16)
    p3 = conn.recv(16)
    p4 = conn.recv(16)
    p = [p1,p2,p3,p4]
    print "p = ",p
    # if we get p4, it means that f(a,b) = 0. Thus, a<b
    # and we should stop now 
    for pi in p:
        if pi in k and pi == k[4]:
            result = 0
    # send result to Bob
    conn.send(str(result))
    if result == 0:
        break
    if (i+1) >= n:
        break
    i = i+1

conn.close()
print "result = ",result