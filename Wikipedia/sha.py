import hashlib


print("- - - - - - - - - - - - - - - - - - - Sha256(mensaje.bin) - - - - - - - - - - - - - - - - - - - \n")

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
print(f'm is: {m_hash}')



print("\n\n- - - - - - - - - - - - - - - - - - - Extracción de Qx y Qy  - - - - - - - - - - - - - - - - - - -\n") 

Q = "29fef70279c982b52644e9c9bf063ecf49a2d2eafe3154e353dd7bef217923a820d71e3974bf5c0f856ba16c518548c2b81110a8c32de52208beab40cf3c440e"
Q_bytes = bytes.fromhex(Q)

Qx = Q_bytes[:32]
Qy = Q_bytes[32:]

print("qx (first 32 bytes):", Qx.hex())
print("qy (last 32 bytes):", Qy.hex())


print("\n\n- - - - - - - - - - - - - - - - - - - Extracción de la firma, f1 y f2 - - - - - - - - - - - - - - - - - - -\n") 

F = "3044022034cec4f05a1408da4cc3ac4bc955ace84c9790293c5136b978f9ef91a1aef2c502200805d335ff94925127c37946e7f086db18ba845015c7df16123821ce96ecedf2"
F_bytes = bytes.fromhex(F)

f1 = F_bytes[4:36]
f2 = F_bytes[38:70]

print("f1 (first 32 bytes):", f1.hex())
print("f2 (last 32 bytes):", f2.hex())


print("\n\n- - - - - - - - - - - - - - - - - - - Comprobación de la firma - - - - - - - - - - - - - - - - - - -\n") 

w1 = 