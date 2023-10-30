import asyncio
import base64
import math
import string
from collections import Counter


englishFreq = {
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
if isinstance(b'a'[0], int):
    englishFreq = {x[0]: y for x, y in englishFreq.items()}


def hex2base64(hex):
    b = bytes.fromhex(hex)
    return base64.b64encode(b)

def xor(a, b):
	return bytes(i ^ j for i, j in zip(a, b))

# single-byte xor
def sxor(a, byte):
	return bytes(i ^ byte for i in a)

# repeating-key xor
def rkxor(a, key):
	result = b''
	for i in range(len(a)):
		result += (a[i] ^ key[i % len(key)]).to_bytes()
	return result

# retorna verdadeiro caso a string de bytes contenha apenas caracteres printaveis ou falso caso contrario
def isPrintable(bytestring):
	result = True
	for char in bytestring:
		try:
			dchar = char.to_bytes().decode()
		except:
			return False
		result = result and (dchar in string.printable)
	return result

# utiliza o coeficiente bhattacharyya para atribuir uma pontuação a um input 'a', segundo analise de frequencia de caracteres
# quanto maior o coeficiente maior a proximidade da amostra com o esperado na lingua inglesa
def scoreFrequency(a):
	frequency = Counter(a.lower())          #gera um dicionario com caracter nas chaves e frequencia nos valores
	length = len(a)
	coefficient = sum(
        math.sqrt(englishFreq.get(char, 0) * y/length)
        for char, y in frequency.items()
    )
	return coefficient

# recebe um vetor de strings de bytes e retorna uma tupla contendo a string mais provavel de estar em ingles,
# seu indice no array de resultados (que representa o byte usado no xor para decodifica-la) e sua pontuação
# segundo o coeficiente bhattacharyya
def mostLikely(results):
	printable = [r for r in results if isPrintable(r)]                      # seleciona apenas os resultados printaveis
	if len(printable) > 0:
		scores = list(map(scoreFrequency, printable))
		score = max(scores)
		result = printable[scores.index(score)]
		byte = results.index(result).to_bytes()
		return (score, byte, result)


# challenge 1

'''
hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
b64 = hex2base64(hex)
print("hex = ", hex)
print("b64 = ", b64)
'''

# challenge 2

'''
a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
b = bytes.fromhex("686974207468652062756c6c277320657965")
expected = bytes.fromhex("746865206b696420646f6e277420706c6179")
result = xor(a, b)
print("a = ", a, ", b = ", b)
print("a xor b = ", result)
print("expected = ", expected)
'''

# challenge 3

'''
hex = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
results = [sxor(hex, byte) for byte in range(256)]
print(mostLikely(results))
'''

# challenge 4

'''
f = open("4.txt")
results = {}
count = 0
for line in f:
	hex = bytes.fromhex(line)
	partial = mostLikely([sxor(hex, byte) for byte in range(256)])
	if partial is not None:
	    print(count, partial)
	count += 1
'''

#challenge 5

'''
input = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
key = b'ICE'
cryptogram = rkxor(input, key)
expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

print("result   = ", cryptogram.hex())
print("expected = ", expected)
'''

# challenge 6


