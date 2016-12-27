#!usr/bin/python
# encoding: utf8
import socket
import rsa
import random
from decToBin import dec_to_bin
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
num_bits = int(s.recv(20))


bob_wealth = input("Please input a number between 0 and %d: " % (2**num_bits-1))
assert type(bob_wealth) == int and bob_wealth >= 0 and bob_wealth <= (2**num_bits-1)
bob_wealth = dec_to_bin(bob_wealth,num_bits)
print "bob wealth = ",bob_wealth

i = 0
while True:
    # receive i
    #i = s.recv(100)
    #i = int(i)
    print '#############################'
    print "##### %d-th comparision #####" % (i+1)
    print '#############################'
    # XOR comparison
    print "Receiving garble circuit for comparison"
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
    
    ######## OT
    print "Run OT to get next key"
    print "generating public and private keys..."
    (public_key,private_key) = rsa.newkeys(1024)
    # length = 308
    print "lenght of public key = ",len(str(public_key['n']))
    # for 0, Bob should get the key representing 1
    length_pub_key = len(str(public_key['n']))
    # send length
    s.send(str(length_pub_key))
    choices = [str(j) for j in range(0,10)]
    random_key = ''
    for j in range(length_pub_key):
        random_key += random.choice(choices)
    # randomly generate 308 numbers
    if bob_wealth[i] == '0':
        print "sending public key 1"
        print "n = ",public_key['n']
        #print "e = ",public_key1['e']
        # compute length
        # length = len(str(public_key['n']))
        # s.send(str(length))
        s.send(str(public_key['n']))
        #s.send(str(public_key1['e']))
        print "\n"
        print "sending public key 2"
        
        print "n = ", random_key
        #print "e = ",public_key2['e']
        s.send(random_key)
        #s.send(str(public_key2['e']))
        print "\n"
    # for 1, Bob should get the key representing  0
    elif bob_wealth[i] == '1':
        print "sending public key 2"
        print "n = ",random_key
        #print "e = ",public_key2['e']
        s.send(random_key)
        #s.send(str(public_key2['e']))
        print "\n"
        print "sending public key 1"
        print "n = ",public_key['n']
        #print "e = ",public_key1['e']
        s.send(str(public_key['n']))
        #s.send(str(public_key1['e']))
        print "\n"                
    print "Receiving two encrypted keys..."
    l1 = s.recv(3) # length 1
    print "l1 received is ",l1
    x1 = s.recv(int(l1))
    print "x1 = ",b2a_hex(x1)

    l2 = s.recv(3) # length 2
    print "l2 received is ",l2
    x2 = s.recv(int(l2))
    print "x2 = ",b2a_hex(x2)

    # 获取bob端的key
    if bob_wealth[i] == '1':
        bob_key = rsa.decrypt(x2,private_key)
    elif bob_wealth[i] == '0':
        bob_key = rsa.decrypt(x1,private_key)
    print "bob_key = ", bob_key
    
    # Bob解出key
    # Now Bob tries to decode c1, c2, c3, c4 respectively 
    # using two keys achieved
    p1 = double_decode(alice_key,bob_key,a2b_hex(c1))
    print "p1 = ",b2a_hex(p1)
    p2 = double_decode(alice_key,bob_key,a2b_hex(c2))
    print "p2 = ",b2a_hex(p2)
    p3 = double_decode(alice_key,bob_key,a2b_hex(c3))
    print "p3 = ",b2a_hex(p3)
    p4 = double_decode(alice_key,bob_key,a2b_hex(c4))
    print "p4 = ",b2a_hex(p4)
    # send the decoded keys to Alice
    s.send(p1)
    s.send(p2)
    s.send(p3)
    s.send(p4)


    is_equal = int(s.recv(1))
    if is_equal:
        result = 1
        if (i+1) >= num_bits:
            break
        else:
            i = i+1
            continue

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
    # length = 308
    print "lenght of public key = ",len(str(public_key['n']))
    # for 0, Bob should get the key representing 1
    length_pub_key = len(str(public_key['n']))
    # send length
    s.send(str(length_pub_key))
    choices = [str(j) for j in range(0,10)]
    random_key = ''
    for j in range(length_pub_key):
        random_key += random.choice(choices)
    # randomly generate 308 numbers
    if bob_wealth[i] == '1':
        print "sending public key 1"
        print "n = ",public_key['n']
        #print "e = ",public_key1['e']
        # compute length
        # length = len(str(public_key['n']))
        # s.send(str(length))
        s.send(str(public_key['n']))
        #s.send(str(public_key1['e']))
        print "\n"
        print "sending public key 2"
        
        print "n = ", random_key
        #print "e = ",public_key2['e']
        s.send(random_key)
        #s.send(str(public_key2['e']))
        print "\n"
    # for 1, Bob should get the key representing  0
    elif bob_wealth[i] == '0':
        print "sending public key 2"
        print "n = ",random_key
        #print "e = ",public_key2['e']
        s.send(random_key)
        #s.send(str(public_key2['e']))
        print "\n"
        print "sending public key 1"
        print "n = ",public_key['n']
        #print "e = ",public_key1['e']
        s.send(str(public_key['n']))
        #s.send(str(public_key1['e']))
        print "\n"                
    print "Receiving two encrypted keys..."
    
    # l1 = s.recv(10)
    # print "receiving length of cipher1: ",l1
    # l1 = int(l1)
    # x1 = s.recv(l1)
    # print "x1 = ",b2a_hex(x1)
   
    # l2 = s.recv(10)
    # print "receiving length of cipher2: ",l2
    # l2 = int(l2)
    # x2 = s.recv(l2) 
    # print "x2 = ",b2a_hex(x2)
    l1 = s.recv(3)
    print "l1 received is ",l1
    x1 = s.recv(int(l1))
    print "x1 = ",b2a_hex(x1)

    l2 = s.recv(3)
    print "l2 received is ",l2
    x2 = s.recv(int(l2))
    print "x2 = ",b2a_hex(x2)
    # encode to get key representing bob's 0 or 1
    if bob_wealth[i] == '0':
        bob_key = rsa.decrypt(x2,private_key)
    elif bob_wealth[i] == '1':
        bob_key = rsa.decrypt(x1,private_key)
    print "bob_key = ", bob_key

    # Now Bob tries to decode c1, c2, c3, c4 respectively 
    # using two keys achieved
    p1 = double_decode(alice_key,bob_key,a2b_hex(c1))
    print "p1 = ",b2a_hex(p1)
    p2 = double_decode(alice_key,bob_key,a2b_hex(c2))
    print "p2 = ",b2a_hex(p2)
    p3 = double_decode(alice_key,bob_key,a2b_hex(c3))
    print "p3 = ",b2a_hex(p3)
    p4 = double_decode(alice_key,bob_key,a2b_hex(c4))
    print "p4 = ",b2a_hex(p4)
    # send the decoded keys to Alice
    s.send(p1)
    s.send(p2)
    s.send(p3)
    s.send(p4)
    result = s.recv(1)
    # 如果前面都相等，当前位置不相等，则比较晚就不用比较了
    break
s.close()
print '*'*15
print "result = ",result

