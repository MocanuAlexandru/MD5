import math


'''
    To test for a desired string just change the value of MESSAGE to that input.

    If a local python3 interpreter is not available, an online version can be found at the following link:
    https://www.programiz.com/python-programming/online-compiler/
'''
MESSAGES = [
    b"Modern Technologies for Information Security",
    b"Security and Applied Logics",
    b"MD5 is not secure."
]




MODULUS = 1<<32

def t(index):
    return math.floor(abs(math.sin(index+1)) * MODULUS)

def s(index):
    # Return the number of rotations depending on the round and step number
    tabel = [
        [7,12,17,22],
        [5,9,14,20],
        [4,11,16,23],
        [6,10,15,21]
    ]
    return tabel[index//16][index%4]

def rotate_left(number, offset):
    # Rotate the number bitwise circular to the left with a number of `offset` bits
    return (number << offset) | (number >> (32-offset))

def F(b, c, d):
    return (b & c) | (~b & d)

def G(b, c, d):
    return (b & d) | (c & ~d)

def H(b, c, d):
    return b ^ c ^ d

def I(b, c, d):
    return c ^ (b | ~d)

# Initialization values for the hash MD5
a0 = 0x67452301
b0 = 0xefcdab89
c0 = 0x98badcfe
d0 = 0x10325476

def compression_function(m, iv):
    '''
        m is a message on 512 bits represented as a vector of 16 elements (each with 32 bits)
        iv is the initialization vector for the compression function (4 elements on 32 bits each)
    '''

    q = [0] * 68 # intermediate states for hash
    q[0], q[1], q[2], q[3] = iv[0], iv[3], iv[2], iv[1]

    for idx in range(4, 68):
        index = idx - 4
        # Steps from round 1
        if 0 <= index < 16:
            func_result = F(q[idx-1], q[idx-2], q[idx-3])
            index_message = index

        # Steps from round 2
        elif 16 <= index < 32:
            func_result = G(q[idx-1], q[idx-2], q[idx-3])
            index_message = (5 * index + 1) % 16
        
        # Steps from round 3
        elif 32 <= index < 48:
            func_result = H(q[idx-1], q[idx-2], q[idx-3])
            index_message = (3 * index + 5) % 16
        
        # Steps from round 4
        else:
            func_result = I(q[idx-1], q[idx-2], q[idx-3])
            index_message = (7 * index) % 16
        
        q[idx] = (q[idx-4] + func_result + m[index_message] + t(index)) % MODULUS
        q[idx] = rotate_left(q[idx], s(index))
        q[idx] = (q[idx-1] + q[idx]) % MODULUS


    aa = (iv[0] + q[64]) % MODULUS
    bb = (iv[1] + q[67]) % MODULUS
    cc = (iv[2] + q[66]) % MODULUS
    dd = (iv[3] + q[65]) % MODULUS

    return [aa, bb, cc, dd]



def MD5(M):
    '''
        We assume M is a sequence of bytes
    '''
    # Before starting the compression, we apply the padding method
    original_length = 8 * len(M) # we multiply the length of M with 8 to obtain the number of bits
    M = bytearray(M)

    M.append(0x80) # First padding byte is 1 bit with value 1 and others have value 0
    while len(M) % 64 != 56:
        M.append(0x0) # Padding with 0 bits
    M.extend(original_length.to_bytes(8, byteorder="little")) # Appending the initial length of the message

    
    
    # The initialization vector for the first call to the compression function uses standard IV for MD5
    no_blocks = len(M) // 64
    IV = [[0,0,0,0]] * (no_blocks+1)
    IV[0] = [a0,b0,c0,d0]

    # Iteratively call the compression function on each block
    for i in range(no_blocks):
        block = [int.from_bytes(M[64*i + 4*k: 64*i + 4*(k+1)], byteorder='little') for k in range(16)]
        IV[i+1] = compression_function(block, IV[i])
    
    result = IV[no_blocks]
    return (result[0].to_bytes(4,"little") + result[1].to_bytes(4,"little") + result[2].to_bytes(4,"little") + result[3].to_bytes(4,"little")).hex()


for MESSAGE in MESSAGES:
    print()
    print(MESSAGE.decode('utf-8'))
    print(MD5(MESSAGE))
    # print(MESSAGE.decode('utf-8').ljust(45), '->', MD5(MESSAGE))
print()
