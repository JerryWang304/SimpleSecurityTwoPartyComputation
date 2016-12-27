#!usr/bin/python
# encoding: utf8
import socket
import random
import rsa
from decToBin import dec_to_bin
from Crypto.Cipher import AES
from numpy.random import permutation
from binascii import b2a_hex, a2b_hex
mode = AES.MODE_CBC

HOST = '127.0.0.1'
PORT = 8001
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

def random_keys():
    k = []
    chars = [str(j) for j in range(0,10)]
    chars.extend([chr(j) for j in range(97,123)])
    for j in range(6):
        temp_k = ''
        for j in range(16):
            temp_k += random.choice(chars)
        k.append(temp_k)
    return k

alice_wealth = input("Please input a number between 0 and %d: " % (2**n-1))
assert type(alice_wealth) == int and alice_wealth >= 0 and alice_wealth <= (2**n-1)
alice_wealth = dec_to_bin(alice_wealth,n)
print "alice wealth = ",alice_wealth
i = 0
result = 1

while True:
    is_euqal = False
    print '#############################'
    print "##### %d-th comparision #####" % (i+1)
    print '#############################'
    # 第一步：异或比较。如果结果为1，说明两者不能，继续运行下面的garbled circuit部分
    # 如果为0，说明两者相等，则跳过继续比较的部分，进入到下一个循环
    
    print "*"*31
    print '*'*10,"异或比较begin",
    print '*'*8
    print "*"*31
    # 生成6个keys
    k = random_keys()
    # four encoded keys
    print "keys = "
    print k
    send1 = double_encode(k[2],k[0],k[4])
    send2 = double_encode(k[2],k[1],k[5])
    send3 = double_encode(k[3],k[1],k[4])
    send4 = double_encode(k[3],k[0],k[5])
    # 打乱发送
    print "Sending garble circuit for XOR operation"
    print "c1 = ",b2a_hex(send1)
    print "c2 = ",b2a_hex(send2)
    print "c3 = ",b2a_hex(send3)
    print "c4 = ",b2a_hex(send4)
    print "sending c2"
    conn.send(b2a_hex(send2))
    print "sending c1"
    conn.send(b2a_hex(send1))
    print "sending c3"
    conn.send(b2a_hex(send3))
    print "sending c4"
    conn.send(b2a_hex(send4))

    # 发送代表自己是0还是1的key
    
    print "sending one key: ",
    if alice_wealth[i] == '0':
        conn.send(k[0])
        print k[0],
        print ":  0"
    elif alice_wealth[i] == '1':
        conn.send(k[1])
        print k[1],
        print ":  1"

    ###########  OT
    ###########
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
    conn.send(str(l1)) # send length1
    print "l1 = ",l1
    conn.send(cipher1)
    print "cipher1 = ",b2a_hex(cipher1)
    l2 = len(cipher2)
    print "l2 = ",l2
    conn.send(str(l2)) # send length2
    conn.send(cipher2)
    print "cipher2 = ",b2a_hex(cipher2)

    print "Receiving Bob's decrypted keys"
    p1 = conn.recv(16)
    p2 = conn.recv(16)
    p3 = conn.recv(16)
    p4 = conn.recv(16)
    p = [p1,p2,p3,p4]
    print "p = ",p
    # 遍历收到的解密数据
    for el in p:
        if el == k[4]:
            is_euqal = True
    # 如果相等，继续比较下一位
    print "*"*31
    print '*'*10,"异或比较end",
    print '*'*8
    print "*"*31
    print '\n'
    if is_euqal:

        print '*'*30
        print "*"*12,"Equal Now",
        print '*'*7
        print "*"*30
        result = 1
        conn.send(str(1))
        #  如果比较到最后一位，则停止
        if (i+1) >= n:
            break
        else:
            i = i+1
            continue
    else:
        print '*'*30
        print "*"*12,"Not Equal Now",
        print '*'*3
        print "*"*30
        conn.send(str(0))


    #conn.send(str(i))
    # generate 6 random numbers

    k = random_keys()
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
    for el in p:
        if el == k[4]:
            result = 0
        elif el == k[5]:
            result = 1
    # send result to Bob
    conn.send(str(result))
    # 如果前面都相等，当前位置不相等，则比较晚就不用比较了
    break

conn.close()
print '*'*15
print "result = %d" % result