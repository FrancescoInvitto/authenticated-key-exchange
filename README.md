# authenticated-key-exchange
A project developed for the Network Security course of master degree at University of Parma.

The objective of this project is to implement an authenticated DH key exchange between a client and a server using TCP.
Ephemeral DH is used (new DH private values are created for each exchange) and it is authenticated using the server RSA public key.
The client side can be tested using an online server.

# Key exchange

In order to establish a secure communication between a client and a server, through a TCP connection, the following authenticated DH key exchange is used:

C -> S: M1 = y_c
S -> C: M2 = y_s, sign_s, auth_s
C -> S: M3 = auth_c

where:

y_c = DH public value of the client = g^x_c mod p
y_s = DH public value of the server = g^x_s mod p
x_c = DH private value of the client
x_s = DH private value of the server
g = DH base (primitive root)
p = DH modulus (prime)
sign_s = Sign(KS-,yc||y_s)
y_c||y_s = concatenation of the two arrays of bytes corresponding to the two values y_c and y_s
Sign(KS-,data) = SHA1withRSA signature of the given data with the key K-
K+ = RSA public key of the server = (n,e)
K- = RSA private key of the server = (n,d)
auth_s = E(k_m,SN)
auth_c = E(k_m,CN)
SN = server name (e.g. netsec.unipr.it)
CN = client name (e.g. alice@studenti.unipr.it)
E(k,data) = encryption of data using AES128 in CBC mode with key k and IV=0, with PKCS#5 padding
k_m = a 128bit secret key derived from the DH secret value k_dh, taking the rightmost 16 bytes of k_dh
k_dh = DH secret value = g^(x_c*x_s) mod p

# Protocol description
The client and server already share the DH modulus p and generator g values. The client already got the server RSA public key K+ {e,n}.

All protocol fields (y_c, y_s, sign_s, etc) are exchanged between A and B through a TCP connection encoded as described in the next section.

The key exchange is initiated by the client that, after establishing a TCP connection, sends M1 to the server, containing its DH public value y_c.

The server responds with M2 containing its DH public value y_c, followed by the the signature sig_s computed on the concatenation of the two DH public values y_c||y_s, followed by the server authentication tag auth_s computed by encrypting in AES128-CBC-PKCS5Padding the server name.

The AES key is formed by the last 16 bytes of the DH secret. The IV is 0 (16 zero bytes).

The client replies with M3 containing the client authentication tag auth_c computed by encrypting in AES128-CBC-PKCS5Padding the client name.

The following values for p, g, n, and e should be considered, where the {n,e} pair is the RSA public key K+ of the server; both p (DH modulus) and n (RSA modulus) are 1024bit numbers; integer values are hereafter provided in decimal format:
p: 171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303
g: 2
n: 124707504124669832754048695488399386164061423841169546038891068096834606767261496699177787906147155900810427155846472626268461648947351779285831186645370253900907225651414326315567347500644048892622078969207402655779488768619122448970469844534518521138137334979874147868026856237563055452930295726223017536251
e: 65537

A key exchange server running according to this protocol is available at: netsec.unipr.it:7021 (host netsec.unipr.it, TCP port 7021).

Note: the private exponent 'd' of the server corresponding to the above public key {n,e} is:
d: 58486196297905793361436146063009346371341256438076005417571079985722698225407775188762508034901490513256775394999728132825540339686677819981526578157866539979200719826097314892721324233611845126640394657682208604539908948119357733136926780732893645589189889778361529296029330071625566174471367471002630573185

# Message format
Each message consist one or more fields (e.g. y_c, y_s, sign_s, etc.). Each field is formatted by concatenating the string "DATA", a space (SP), the base64 encoding of the byte array containing the field value, and the 2-char CRLF sequence, that is the carriage return (CR) '\r' character followed by the line feed (LF) '\n' character.

For example M2 is formed as follows:
DATA Base64(y_s)CRLF
DATA Base64(sign_s)CRLF
DATA Base64(auth_s)CRLF



Example:

Here there is an example of data exchange from C to S and from S to C; the data is within quotes; spaces and lines are not part of the messages, '\r' and '\n' are the carriage return and line feed characters:

M1:
"DATA 5d6f6b48bc458a9be287a28275d981e24bb7a591777b2c0c06e35e8fd8ccaa2a
14d751dd253979dc3a9856ddd7c13e663714ec2e366f1e70fb969918fddcda80
a1f7c37d828651e9b34bcd080ce8efaabcc009e3ed1bffa59b289f229cbdf56d
8dae8027837d6b8ab8d93fe9ec7c174cfbd25c23a99de22e9b7bc5ca30d2c00f
\r\n"

M2:
"DATA cf1d1e594a8025bb82fa0406c17a095f2823faf97c493fec51ae11350cfad4ca
c06f215833d9522e534418a8334cc5874d0508d0ae9c851ef70324320688c691
69a106b2fb457d77ceb273654478845199dc76dfa52958210b28aa898a55c95a
531c84ed86196fc996622fc3bfef4b2c01add46feeb4381bdb7b38bb113b1174
\r\n
DATA 49c0aa95cb4d4591676f3ce4b524a22397cb227489c637ce658461f0087fd795
cc788debc50eabefe4b3b21d4081df2aa17b33025c989b385495b22b0bbcce2f
0eb61caf57dd49e5e1fd304182fc3354357558bf5c40cefdf4168f0ee288ef49
3190e3c85ffe0c341afd7418d4789c649c9797ca6c1a37b5e17d15939d0d41e6
\r\n
DATA 5e1885ed9211e1440cccb06dc24149a3
\r\n"

M3:
"DATA 4a0b3ad6df572f4fe4fefb77f228feea7e7249537d2f864e6e159617eb58c425
\r\n"



In the previous exchange the following values have been used:
x_a: 55629729998412737931266981464610107605645226097287448227119270229792482619440812624449096618299171674023472669636932729861787401526890884243414501585215711044695790232655057608085666280235018390806176710912442899253339175010504342958976486170414401063659047499455178052569819493920175277577942713969280315873
server name: netsec.unipr.it
client name: luca.veltri@unipr.it

The resulting DH secret is:
57176019064091332505387479292344347539604676900260683183915386763194982791345879855657598168904422489284142593865801136884191142991698935502319153104095167813145874190591273294476559260391208249025865243539910551661237461256225969288101485301131943950048628504541245200344761655003898583734380975347058494950

in hexadecimal: 516bddd8266c51b25850cddde9f0aa999d2d112b590a5f977766faf4c46b46151a88972e150652b2095569438b8d6f173de4a42dfedbd243c6a59e9fdc365fc8c7e9a5c563c6acba563549b5c437476e3b5f12258754008d20a9bbb62909eefa993d3a218cf37e8a47f7b73f06d243a92fa27da99e3f1eb13e456ea06eb24de6

The last 16 bytes of the DH secret (that the bytes from from 112 to 127) were used as k_m: 2fa27da99e3f1eb13e456ea06eb24de6

#Additional notes
  - When an array of bytes is obtained as representation of an integer an vice versa, attention must be payed to the order of bytes (big-endian or little-    endian) and the sign bit.
   In particular in the proposed protocol we consider the integers encoded in byte arrays in big-endian byte-order (also called "network order"): the most    significant byte is in the zeroth element of the array (note: the BigInteger of Java handles the conversion done by the method toByteArray() in this      way).
   When converting a positive integer to a byte array, if the most significant bit of the most significant byte of the array (the 0th byte) is 1,            sometimes   an extra 0x00 byte is added at the beginning as new 0th byte in order to have a two's-complement representation of a positive number. The      length of the   resulting array is then increased by 1

  - for the same reason attention must to be paid when an array of bytes has be converted to an integer. If we know that the integer is positive, the sign     must not depend on the most significant bit. In case of Java, this can be assured by using the BigInteger constructor that has the sign as first           argument (1 for positive).
    When concatenating y_a and y_b, the same exchanged ya and y_b arrays must be used, regardless a zero byte was added by the sender at the beginning of     the array for representing the integer or not.
