const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

const SECRET = 'supersecretkey123';

app.post('/login', (req, res) => {
    const token = jwt.sign({ user: 'testuser', role: 'user' }, SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.post('/verify', (req, res) => {
    try {
        const payload = jwt.verify(req.body.token, SECRET);
        res.json({ valid: true, payload });
    } catch (e) {
        res.json({ valid: false, error: e.message });
    }
});

app.get('/admin', (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    try {
        const payload = jwt.verify(token, SECRET);
        if (payload.role === 'admin') return res.json({ message: 'Dobrodošel, admin!' });
        res.status(403).json({ error: 'Nisi admin' });
    } catch (e) {
        res.status(401).json({ error: e.message });
    }
});

app.listen(3000, '0.0.0.0');