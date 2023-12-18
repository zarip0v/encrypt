from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.backends import default_backend

def der_to_pem(der_bytes):
    private_key = serialization.load_der_private_key(
        der_bytes,
        password=None,
        backend=default_backend()
    )
    
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return pem_bytes.decode('utf-8')

result = b''
file_names = [
    (1, "keys/private_1.txt"),
    (2, "keys/private_2.txt"),
    (5, "keys/private_5.txt"),
    (8, "keys/private_8.txt"),
    (9, "keys/private_9.txt"),
    (10, "keys/private_10.txt"),
    (11, "keys/private_11.txt"),
    (12, "keys/private_12.txt"),
    (13, "keys/private_13.txt"),
    (15, "keys/private_15.txt"),
    (16, "keys/private_16.txt"),
    (17, "keys/private_17.txt"),
]
files = [open(j[1], 'r') for j in file_names]
lines = len(open(file_names[0][1], 'r').readlines())
for i in range(lines):
    chunks = [bytes.fromhex(j.readline()) for j in files]
    result += Shamir.combine([(file_names[n][0], chunks[n]) for n in range(len(chunks))])
print(der_to_pem(result))
