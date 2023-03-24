#===================================================#
# Project Assignment: Authenticated Key Exchange    #
# Student: Francesco Invitto                        #
# Badge Number: 325559                              #
#===================================================#

import random
import binascii
import codecs
from datetime import datetime
import socket as sock

from Crypto.Cipher import AES

#--------------------------------------------------------#
# Function 'sub_bytes'                                   #
# The function is used to take bytes of an hexadecimal   #
# value of a specific interval defined by start & end    #
#--------------------------------------------------------#
def sub_bytes(i, start, end):  
    i_sub = i[start: end] #Get the bytes we need
    return i_sub

#--------------------------------------------------------#
# Function 'pad'                                         #
# The function is used to pad the plaintext message      #
# according to PKCS#5: the value of each added byte (pad #
# data) is the number of bytes that are added            #
#--------------------------------------------------------#
def pad(plaintext):
    blocksize = 32
    ptsize = int(len(plaintext))
    to_pad = int((blocksize - (ptsize % blocksize)) / 2)
    pad_data = ('0' + hex(to_pad).rstrip("L").lstrip("0x")) * to_pad
    return plaintext + pad_data

host = "netsec.unipr.it"
port = 7021
clientname = "francesco.invitto@studenti.unipr.it".encode('utf-8')
with open("info.log", "a") as logfile:
    timestamp = datetime.now()
    timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
    logstring = str(timestamp) + " ----- NEW RUN ----- \n"
    logfile.write(logstring)
    
#Load from values.csv the values for p, g, n, e
values = []

print("Loading values from values.csv file...")
with open("values.csv", "r") as file:
    for line in file:
        splitted = line.split(",")
        for v in splitted:
            values.append(v)
print("Done.")

p = int(values[0])
g = int(values[1])
n = int(values[2])
e = int(values[3])

print("Read values:")
print("(Diffie-Hellman modulus) p:" + str(p))
print("(Diffie-Hellman generator) g:" + str(g))
print("(RSA modulus) n:" + str(n))
print("(RSA exponent) e:" + str(e))

print("--------------------")
print("Generating Diffie-Hellman client private value (x_c)...")

#Generation of the DH client private value
#x_c is a random integer smaller than p
x_c = random.randint(0, p)
print("x_c:" + str(x_c))

with open("info.log", "a") as logfile:
    timestamp = datetime.now()
    timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
    logstring = str(timestamp) + " - Generated DH client private value - Status: OK" + "\n"
    logfile.write(logstring)
    

print("--------------------")
print("Generating Diffie-Hellman client public value (y_c)...")

#Generation of the DH client public value
#y_c = g^x_c mod p
y_c = pow(g, x_c, p)
print("y_c:" + str(y_c))

with open("info.log", "a") as logfile:
    timestamp = datetime.now()
    timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
    logstring = str(timestamp) + " - Generated DH client public value - Status: OK" + "\n"
    logfile.write(logstring)

print("--------------------")
print("Generating message M1...")

#Generation of the message M1
#Message format: DATA <space> <hex encoding of the value> <CRLF>
enc = codecs.getencoder('hex')
m1 = "DATA " + hex(y_c).rstrip("L").lstrip("0x") + "\r\n"

print("M1:" + m1)

with open("info.log", "a") as logfile:
    timestamp = datetime.now()
    timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
    logstring = str(timestamp) + " - Generated message M1 - Status: OK" + "\n"
    logfile.write(logstring)
    
print("--------------------")

#Creation of the socket and connection to the server
with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as s:
    s.connect((host, port))
    print("Connected to '" + host + ":" + str(port) + "'")

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Connected to '" + host + ":" + str(port) + "'\n"
        logfile.write(logstring)

    io = s.makefile('rw')
    
    io.write(m1)
    io.flush()

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Sent M1 - Status: OK" + "\n"
        logfile.write(logstring)

    m2 = ''
    count = 0

    while("ERROR" not in m2 and count < 3):
        line = io.readline().strip()
        m2 += line
        count = count + 1

    timestamp = datetime.now()
    timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))

    if("ERROR" in m2):
        print(m2)
        logstring = str(timestamp) + " - Received M2 - " + m2 + "\n"
    else:
        print("M2:" + m2)
        logstring = str(timestamp) + " - Received M2 - Status: OK" + "\n"

    with open("info.log", "a") as logfile:
        logfile.write(logstring)
        
    val = []
    splitted = m2.split("DATA ")
    for i in splitted:
        if i != '':
            val.append(i)
            
    #Extraction of the 3 fields of the message M2 and conversion from hexadecimal to integer
    y_s = int(val[0], 16)
    sign_s = int(val[1], 16)
    auth_s = int(val[2], 16)

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Extracted y_s - Status: OK" + "\n"
        logfile.write(logstring)
        logstring = str(timestamp) + " - Extracted sign_s - Status: OK" + "\n"
        logfile.write(logstring)
        logstring = str(timestamp) + " - Extracted auth_s - Status: OK" + "\n"
        logfile.write(logstring)

    print("--------------------")
    print("y_s:" + str(y_s) + "\n")
    print("sign_s:" + str(sign_s) + "\n")
    print("auth_s:" + str(auth_s) + "\n")

    print("--------------------")
    print("Generating Diffie-Hellman secret...")

    #Generation of the DH secret --> k_dh = (y_s ^ x_c) mod p
    k_dh = pow(y_s, x_c, p)
    print("k_dh:" + str(k_dh) + "\n")

    k_dh = hex(k_dh).rstrip("L").lstrip("0x")

    print("k_dh (hex):" + str(k_dh) + "\n")

    len_k_dh = len(k_dh)
    k_m = sub_bytes(k_dh, len_k_dh - 32, len_k_dh)

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Generated secret key - Status: OK" + "\n"
        logfile.write(logstring)
        
    print("k_m:" + str(k_m) + "\n")
    
    print("--------------------")

    iv =b'\0' * 16 #IV = 0 (16 zero bytes)
    print("Iv: " + str(iv))
    print("Plaintext: " + str(clientname.hex()))
    print("Key: " + str(binascii.hexlify(bytes.fromhex(k_m))))
    k_s= bytes.fromhex(k_m)
    print("Key length: " + str(len(k_s)))
    cipher = AES.new(k_s, AES.MODE_CBC, iv)
    
    padded = pad(clientname.hex())
    print("Padded: " + str(padded))
    ciphertext = cipher.encrypt(bytes.fromhex(padded))

    m3 = "DATA " + ciphertext.hex() + "\r\n"
    print("Ciphertext: " + m3)

    io.write(m3)
    io.flush()

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Sent M3 - Status: OK" + "\n"
        logfile.write(logstring)

    string = "hello"

    text = "DATA " + string.encode('utf-8').hex() + "\r\n"

    io.write(text)
    io.flush()

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Sent string '" + string + "' - Status: OK" + "\n"
        logfile.write(logstring)
    
    line = io.readline().strip()
    print("Server response: " + line)

    line = line.rstrip("L").lstrip("DATA ")

    received = bytes.fromhex(line).decode("ascii")
    print("Received: " + received)

    with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Received string '" + received + "' - Status: OK" + "\n"
        logfile.write(logstring)

    s.close()

print("Connection closed.")

with open("info.log", "a") as logfile:
        timestamp = datetime.now()
        timestamp.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (timestamp.microsecond / 10000))
        logstring = str(timestamp) + " - Disconnetted from '" + host + ":" + str(port) + "'\n"
        logfile.write(logstring)



