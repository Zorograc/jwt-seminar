from flask import Flask, request, jsonify
import jwt, datetime

app = Flask(__name__)
SECRET = "supersecretkey123"

@app.route('/login', methods=['POST'])
def login():
    token = jwt.encode({
        'user': 'testuser',
        'role': 'user',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/verify', methods=['POST'])
def verify():
    token = request.json.get('token')
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        return jsonify({'valid': True, 'payload': payload})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})

@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        if payload.get('role') == 'admin':
            return jsonify({'message': 'Dobrodošel, admin!'})
        return jsonify({'error': 'Nisi admin'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)