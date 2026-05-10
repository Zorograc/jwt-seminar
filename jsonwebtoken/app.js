const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const app = express();
app.use(express.json());

const PRIVATE_KEY = fs.readFileSync('/keys/private.pem');
const PUBLIC_KEY = fs.readFileSync('/keys/public.pem');

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

app.get('/admin', (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    try {
        const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
        if (payload.role === 'admin') return res.json({ message: 'Dobrodošel, admin!' });
        res.status(403).json({ error: 'Nisi admin' });
    } catch (e) {
        res.status(401).json({ error: e.message });
    }
});

app.listen(3000, '0.0.0.0');