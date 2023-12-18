from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_text_with_rsa(public_key_path, plaintext):
    # Load the public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Encrypt the plaintext
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

if __name__ == "__main__":
    # Specify the path to the public key file
    public_key_path = "keys/public.txt"

    # Input the text to be encrypted
    plaintext = "555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444555444"

    # Encrypt the text
    ciphertext = encrypt_text_with_rsa(public_key_path, plaintext)

    # Print the encrypted text
    print(f"Encrypted Text: {ciphertext.hex()}")
