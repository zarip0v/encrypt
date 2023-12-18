from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Protocol.SecretSharing import Shamir

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def split_private_key(private_key):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    chunk_size = 16
    chunks = [private_key_bytes[i:i+chunk_size] for i in range(0, len(private_key_bytes), chunk_size)]
    
    if len(chunks[-1]) < chunk_size:
        chunks[-1] = chunks[-1].ljust(chunk_size, b'\x00')
    
    shares = [""] * 17

    for chunk in chunks:
        sh = Shamir.split(12, 17, chunk)
        for s in sh:
            shares[s[0] - 1] = shares[s[0] - 1] + s[1].hex() + "\n"
    return shares

private_key, public_key = generate_key_pair()

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize and split private key
private_key_shares = split_private_key(private_key)

# Print or save keys and shares as needed
print("Public Key:")
print(public_key_bytes.decode('utf-8'))
with open('keys/public.txt', 'w') as f:
    f.write(public_key_bytes.decode('utf-8'))

for i, share in enumerate(private_key_shares):
    with open('keys/private_' + str(i + 1) + '.txt', 'w') as f:
        f.write(share)
print("\nPrivate Key was splitted in 17 pieces.")
