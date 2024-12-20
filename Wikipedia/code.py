import hashlib
from sympy import isprime
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA

print("\n\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")
print("- - - - - - - - - - - - - - - - - - - - - - - - - - APARTADO 1 - - - - - - - - - - - - - - - - - - - - - - - - - -")
print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")

print("\n- - - - - - - - - - - - - - - - - - - Sha256(mensaje.bin) - - - - - - - - - - - - - - - - - - - \n")

file_path = "./Wikipedia/mensaje.bin"

sha256_hash = hashlib.sha256()

with open(file_path, "rb") as file:
    for chunk in iter(lambda: file.read(4096), b""):
        sha256_hash.update(chunk)

hash_hex = sha256_hash.hexdigest()
print(f"SHA-256 hash of the file: {hash_hex}")

mensaje256 = sha256_hash.digest()


print("\n\n- - - - - - - - - - - - - - - - - - - CALCULO DEL PREAMBULO - - - - - - - - - - - - - - - - - - - \n")

byte_20 = bytes([0x20] * 64)
text = 'TLS 1.3, server CertificateVerify'.encode('ascii') 
byte_00 = bytes([0x00])
preambulo = byte_20 + text + byte_00
print(preambulo.hex())


print("\n\n- - - - - - - - - - - - - - - - - - - Sha256(preambulo + mensaje256) - - - - - - - - - - - - - - - - - - - \n")

final_data = preambulo + mensaje256
m_hash = hashlib.sha256(final_data).hexdigest()
m_bytes = bytes.fromhex(m_hash)
print(f'm is: {m_hash}')


print("\n\n- - - - - - - - - - - - - - - - - - - Extracción de Qx y Qy  - - - - - - - - - - - - - - - - - - -\n") 

Q = "29fef70279c982b52644e9c9bf063ecf49a2d2eafe3154e353dd7bef217923a820d71e3974bf5c0f856ba16c518548c2b81110a8c32de52208beab40cf3c440e"
Q_bytes = bytes.fromhex(Q)

Qx_bytes = Q_bytes[:32]
Qy_bytes = Q_bytes[32:]
Qx = int.from_bytes(Qx_bytes, byteorder='big')
Qy = int.from_bytes(Qy_bytes, byteorder='big')

print("qx (first 32 bytes):", Qx_bytes.hex())
print("qy (last 32 bytes):", Qy_bytes.hex())


print("\n\n- - - - - - - - - - - - - - - - - - - Extracción de la firma, f1 y f2 - - - - - - - - - - - - - - - - - - -\n") 

F = "3044022034cec4f05a1408da4cc3ac4bc955ace84c9790293c5136b978f9ef91a1aef2c502200805d335ff94925127c37946e7f086db18ba845015c7df16123821ce96ecedf2"
F_bytes = bytes.fromhex(F)

f1_bytes = F_bytes[4:36]
f2_bytes = F_bytes[38:70]
f1 = int.from_bytes(f1_bytes, byteorder='big')
f2 = int.from_bytes(f2_bytes, byteorder='big')

print("f1 (first 32 bytes):", f1_bytes.hex())
print("f2 (last 32 bytes):", f2_bytes.hex())

from pyasn1.type import univ, namedtype
from pyasn1.codec.der.encoder import encode

class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )
signature = ECDSASignature()
signature['r'] = f1
signature['s'] = f2
signature = encode(signature)
print("Encoded ASN.1 DER signature:", signature)

# Para sacar f1 inverso: int(pow(f1, -1, n) % n)


print("\n\n- - - - - - - - - - - - - - - - - - - Comprobación de la firma Y EJERCICIOS - - - - - - - - - - - - - - - - - - -\n") 

cv = Curve.get_curve('secp256r1')

"""
APARTADO 1.a.
"""
curve_order = cv.order
print(f"APARTADO 1.a: La curva tiene orden: {curve_order}, it is a prime: {isprime(curve_order)}")

punto = Point(Qx, Qy, cv)

"""
APARTADO 1.b.
"""
try: 
    pub_key = ECPublicKey(punto)
    print("APARTADO 1.b: El punto es de la curva: TRUE")
except:
    print("APARTADO 1.b: El punto es de la curva: FALSE")

"""
APARTADO 1.c.
"""
if isprime(curve_order):
    print(f"APARTADO 1.c: El orden del punto Q es: {curve_order}, que es el mismo que el de la curva")
else:
    print("APARTADO 1.c: El orden de la curva no es primo y por tanto es un poco más complicado de calcular")
    
    
"""
APARTADO 1.d.
"""
cv = Curve.get_curve('secp256r1')
pub_key = ECPublicKey(Point(Qx, Qy, cv))
signer = ECDSA()
is_valid = signer.verify(
    m_bytes,
    signature,
    pub_key
)

print(f"APARTADO 1.d: La firma es válida: {is_valid}")

print("\n\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")
print("- - - - - - - - - - - - - - - - - - - - - - - - - - APARTADO 2 - - - - - - - - - - - - - - - - - - - - - - - - - -")
print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")

hex_modulus = "E5E03B19B9D56FB72B7263A095FBCDD5008EEAB3877162DD396F83EB3CFCA94A7654D43A6475EFDE5F475EBAEB1915C6CF91BED263AAFA170A2D1E27E6D9014CA4F3F906B6474723253A6A0DD2EAD2F09D56D399D4BCB4F30C9E14F2603172EC0AC3B932F24198A5AAF05B41198EFF17A76F813B7F9DF0952DCB114F231707AC4F39D29646887A6A686206ED31D5561CF78B2B3A43912EE39FBD3DBD02E8CA3B358AB30EB03A33DB14DFC8376D29623BCB4F2AEF23976BBC30846E74894FCF04E8ED34A9209B787CE00D912B30BFF174AEB1BFB94BFE14567C98E3C6F173E3645162870A2A65F9228069F985870579BBFA714B42327CE946CF3E319727594C4DC0AC1B658D5A8501D7975205976E19795A6194553007C516F018ACB6B177249B92FF4A0AA49717BEE0C5FAB32C1ACB9CD24E024FBECAA3951BF357DDA5736AF53E3FAAAFDEAA3B92A3E42B9A9A2CC4A59C61D89BD98C910DF57A2809B104F7AFB9EECCA705948CEA0D7539E90033F67E06A7DB62E85185041DCDA8D2063F839B"
decimal_modulus = int(hex_modulus, 16)

bin_pubExp = "010001"
decimal_pubExp = int(bin_pubExp, 2)

print(f"APARTADO 2.a: El módulo del certificado del servidor de la FIB en base 10 es:\n\n{decimal_modulus}\n \
\ny el exponente público: {decimal_pubExp}")

print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")