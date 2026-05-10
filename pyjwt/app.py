from flask import Flask, request, jsonify
import jwt, datetime, requests as req
from jwt.algorithms import RSAAlgorithm
import json

app = Flask(__name__)

with open('/keys/public.pem', 'rb') as f:
    PUBLIC_KEY = f.read()
with open('/keys/private.pem', 'rb') as f:
    PRIVATE_KEY = f.read()

@app.route('/login', methods=['POST'])
def login():
    token = jwt.encode({
        'user': 'testuser',
        'role': 'user',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, PRIVATE_KEY, algorithm='RS256')
    return jsonify({'token': token})

@app.route('/verify', methods=['POST'])
def verify():
    token = request.json.get('token')
    try:
        # Ranljiva implementacija 
        header = jwt.get_unverified_header(token)
        if 'jku' in header:
            jwks_response = req.get(header['jku'])
            jwks = jwks_response.json()
            key_data = jwks['keys'][0]
            verify_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
        else:
            verify_key = PUBLIC_KEY

        payload = jwt.decode(token, verify_key, algorithms=['RS256'])
        return jsonify({'valid': True, 'payload': payload})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})

@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        # Ranljiva implementacija
        header = jwt.get_unverified_header(token)
        if 'jku' in header:
            jwks_response = req.get(header['jku'])
            jwks = jwks_response.json()
            key_data = jwks['keys'][0]
            verify_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
        else:
            verify_key = PUBLIC_KEY

        payload = jwt.decode(token, verify_key, algorithms=['RS256'])
        if payload.get('role') == 'admin':
            return jsonify({'message': 'Dobrodošel, admin!'})
        return jsonify({'error': 'Nisi admin'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)