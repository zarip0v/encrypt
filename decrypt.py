from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

def decrypt_with_rsa_private_key(encoded_string, private_key_path):
    # Read the private key from the file
    with open(private_key_path, 'rb') as key_file:
        private_key_bytes = key_file.read()

    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,  # If your private key is password-protected, provide the password here
        backend=default_backend()
    )

    # Decode the Base64-encoded string
    encoded_bytes = base64.b64decode(encoded_string)

    # Decrypt the message using RSA private key and OPENSSL_PKCS1_PADDING
    decrypted_message = private_key.decrypt(
        encoded_bytes,
        padding.PKCS1v15()
    )

    return decrypted_message.decode('utf-8')  # Assuming the decrypted message is a string

# Example usage
base64_encoded_string = "aRXSU4lADRzflZB2Oj7szhYw0CzIuFspLKTJioqKWDrHn6RH9I3gIsYCdXYIqk26h87ZKzmEfVBiUtm+DqgVe/lfAite4LI6WR+G4Yiin9w7kuwNvF0jkVL7T7TNZjYpWsS9TDKZYdtReqj1qSQ1K1bnz4S2EXYoQTqUu2dHiAnufEQ6ULxFMMVIoowDbrYfzT8alONK92ruPgC8zX/SS/zJJBPVHo83HJY8xZF8ERrw1xxu1lfEp09mq82lKNMOBhY1XAQoga95X1LX064AMIi3wBRfGjZeMpt2KlvcGJFsJ2g7XvXCMNXakdCPrGJZV4y2zBnHqAEgHcH4ZXHoMw=="
private_key_path = "keys/private.txt"

decrypted_message = decrypt_with_rsa_private_key(base64_encoded_string, private_key_path)
print("Decrypted Message:", decrypted_message)
