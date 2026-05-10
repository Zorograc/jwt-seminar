from flask import Flask, request, jsonify
import jwt, datetime, os

app = Flask(__name__)

with open('/keys/private.pem', 'rb') as f:
    PRIVATE_KEY = f.read()
with open('/keys/public.pem', 'rb') as f:
    PUBLIC_KEY = f.read()

def get_key_from_kid(kid):
    # Ranljiva implementacija - direktno bere datoteko glede na kid
    key_path = f"/keys/{kid}"
    with open(key_path, 'rb') as f:
        return f.read()

@app.route('/login', methods=['POST'])
def login():
    token = jwt.encode({
        'user': 'testuser',
        'role': 'user',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, PRIVATE_KEY, algorithm='RS256', headers={'kid': 'public.pem'})
    return jsonify({'token': token})

@app.route('/verify', methods=['POST'])
def verify():
    token = request.json.get('token')
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', 'public.pem')
        verify_key = get_key_from_kid(kid)
        payload = jwt.decode(token, verify_key, algorithms=['RS256', 'HS256'])
        return jsonify({'valid': True, 'payload': payload})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})

@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', 'public.pem')
        verify_key = get_key_from_kid(kid)
        payload = jwt.decode(token, verify_key, algorithms=['RS256', 'HS256'])
        if payload.get('role') == 'admin':
            return jsonify({'message': 'Dobrodošel, admin!'})
        return jsonify({'error': 'Nisi admin'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)