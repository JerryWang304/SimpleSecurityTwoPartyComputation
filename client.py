import socket
import rsa
import random
from Crypto.Cipher import AES
from numpy.random import permutation
from binascii import b2a_hex, a2b_hex
mode = AES.MODE_CBC
HOST = '127.0.0.1'
PORT = 8001

 
def double_decode(k1,k2,ciphertext):
     decryptor = AES.new(k1,mode,b'0000000000000000')
     plain_text = decryptor.decrypt(ciphertext)
     decryptor = AES.new(k2,mode,b'0000000000000000')
     plain_text = decryptor.decrypt(plain_text)
     return plain_text

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
num_bits = int(s.recv(1))
print "At most %d bits" % num_bits
bob_wealth = raw_input("Input Bob's wealth: ")
print "Bob's wealth = ",bob_wealth
while True:
    # receive i
    i = s.recv(1)
    print i
    i = int(i)
    print "##### %d-th comparision #####" % (i+1)
    print "Receiving garble circuit (permutation)"
    c1 = s.recv(32)
    print "c1 = ",c1
    c2 = s.recv(32)
    print "c2 = ",c2
    c3 = s.recv(32)
    print "c3 = ",c3
    c4 = s.recv(32)
    print "c4 = ",c4
    print "Receiving one key representing Alice's input: "
    alice_key = s.recv(16)
    print alice_key
    print "Run OT to get next key"
    print "generating public and private keys..."
    (public_key,private_key) = rsa.newkeys(1024)
    
    # for 0, Bob should get the key representing 1
    if bob_wealth[i] == '1':
        print "sending public key 1"
        print "n = ",public_key['n']
        #print "e = ",public_key1['e']
        s.send(str(public_key['n']))
        #s.send(str(public_key1['e']))
        print "\n"
        print "sending public key 2"
        n = random.randint(10**90,10**100)
        print "n = ", n
        #print "e = ",public_key2['e']
        s.send(str(n))
        #s.send(str(public_key2['e']))
        print "\n"
    # for 1, Bob should get the key representing  0
    else:
        print "sending public key 2"
        n = random.randint(10**90,10**100)
        print "n = ",n
        #print "e = ",public_key2['e']
        s.send(str(n))
        #s.send(str(public_key2['e']))
        print "\n"
        print "sending public key 1"
        print "n = ",public_key['n']
        #print "e = ",public_key1['e']
        s.send(str(public_key['n']))
        #s.send(str(public_key1['e']))
        print "\n"                
    print "Receiving two encryped keys..."
    x1 = s.recv(1024)
    print "x1 = ",(x1)

    x2 = s.recv(1024)
    print "x2 = ",(x2)
    # encode to get key representing bob's 0 or 1
    if bob_wealth[i] == '0':
        bob_key = rsa.decrypt(x2,private_key)
    elif bob_wealth[i] == '1':
        bob_key = rsa.decrypt(x1,private_key)
    print "bob_key = ", bob_key

    # Now Bob tries to decode c1, c2, c3, c4 respectively 
    # using two keys achieved
    p1 = double_decode(alice_key,bob_key,a2b_hex(c1))
    print "p1 = ",p1
    p2 = double_decode(alice_key,bob_key,a2b_hex(c2))
    print "p2 = ",p2
    p3 = double_decode(alice_key,bob_key,a2b_hex(c3))
    print "p3 = ",p3
    p4 = double_decode(alice_key,bob_key,a2b_hex(c4))
    print "p4 = ",p4
    # send the decoded keys to Alice
    s.send(p1)
    s.send(p2)
    s.send(p3)
    s.send(p4)
    result = s.recv(1)
    
    if result == '0':
        break
    
    if (i+1) >= num_bits:
        break
s.close()
print "result = ",result
