import asyncio
import base64
import math
from collections import Counter

#table source: https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py
FREQUENCY_TABLE = {
    b'a':  0.08167,
    b'b':  0.01492,
    b'c':  0.02782,
    b'd':  0.04253,
    b'e':  0.1270,
    b'f':  0.02228,
    b'g':  0.02015,
    b'h':  0.06094,
    b'i':  0.06966,
    b'j':  0.00153,
    b'k':  0.00772,
    b'l':  0.04025,
    b'm':  0.02406,
    b'n':  0.06749,
    b'o':  0.07507,
    b'p':  0.01929,
    b'q':  0.00095,
    b'r':  0.05987,
    b's':  0.06327,
    b't':  0.09056,
    b'u':  0.02758,
    b'v':  0.00978,
    b'w':  0.02360,
    b'x':  0.00150,
    b'y':  0.01974,
    b'z':  0.00074,
}


def hex2base64(hex):
    b = bytes.fromhex(hex)
    return base64.b64encode(b)

def xor(a, b):
	return bytes(i ^ j for i, j in zip(a, b))

#single-byte xor
def sxor(a, byte):
	return bytes(i ^ byte for i in a)

def score_frequency(a):
	f = Counter(a.lower())
	length = len(a)

	return sum((n - FREQUENCY_TABLE.get(char, 0) * length)**2 / FREQUENCY_TABLE.get(char, 0) * length for char, n in f.items())

#challenge 1
#print(hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

#challenge 2
#print(bytes.fromhex("1c0111001f010100061a024b53535009181c"), bytes.fromhex("686974207468652062756c6c277320657965"))
#print(xor(bytes.fromhex("1c0111001f010100061a024b53535009181c"), bytes.fromhex("686974207468652062756c6c277320657965")))
#print(bytes.fromhex("746865206b696420646f6e277420706c6179"))

#challenge 3
results = ((sxor(bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), byte), byte) for byte in range(256))
print(str(results))
emap = [(score_frequency(r[0]), r[0], r[1]) for r in results]
emap.sort(key=lambda x: x[0], reverse=True)
for i in range(5):
	print(emap[i])
