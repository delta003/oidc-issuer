import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Extract the public key
public_key = private_key.public_key()

# Serialize keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# JWKS JSON representation
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "your-key-id",
            "use": "sig",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).rstrip(b'=').decode('utf-8'),
            "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(4, 'big')).rstrip(b'=').decode('utf-8'),
        }
    ]
}

# Print or save the JWKS JSON and keys
print(json.dumps(jwks, indent=4))
print(private_pem)
print(public_pem)
