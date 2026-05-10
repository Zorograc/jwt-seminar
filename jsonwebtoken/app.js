const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const https = require('https');
const http = require('http');
const app = express();
app.use(express.json());

const PRIVATE_KEY = fs.readFileSync('/keys/private.pem');
const PUBLIC_KEY = fs.readFileSync('/keys/public.pem');

function fetchJwks(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        client.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });
}

app.post('/login', (req, res) => {
    const token = jwt.sign({ user: 'testuser', role: 'user' }, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h' });
    res.json({ token });
});

app.post('/verify', (req, res) => {
    try {
        const payload = jwt.verify(req.body.token, PUBLIC_KEY, { algorithms: ['RS256'] });
        res.json({ valid: true, payload });
    } catch (e) {
        res.json({ valid: false, error: e.message });
    }
});

app.get('/admin', async (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    try {
        const decoded = jwt.decode(token, { complete: true });
        let verifyKey;

        if (decoded?.header?.kid) {
            const fs = require('fs');
            const keyPath = `/keys/${decoded.header.kid}`;
            verifyKey = fs.readFileSync(keyPath);
        } else {
            verifyKey = PUBLIC_KEY;
        }

        const payload = jwt.verify(token, verifyKey, { algorithms: ['RS256', 'HS256'] });
        if (payload.role === 'admin') return res.json({ message: 'Dobrodošel, admin!' });
        res.status(403).json({ error: 'Nisi admin' });
    } catch (e) {
        res.status(401).json({ error: e.message });
    }
});

app.listen(3000, '0.0.0.0');