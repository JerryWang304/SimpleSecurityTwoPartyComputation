def dec_to_bin(n,bits):
     assert type(n) == int
     binary = bin(n)[2:]
     length = len(binary)
     prefix = ''
     padding_num = bits - length
     if padding_num > 0:
         while padding_num:
             prefix += '0'
             padding_num -= 1
     return prefix + binary

if __name__ == '__main__':
    print len(dec_to_bin(100,100))