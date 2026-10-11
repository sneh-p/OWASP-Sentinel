// Sample vulnerable Node.js Express server
const express = require('express');
const child_process = require('child_process');
const app = express();

// A02: Hardcoded AWS token
const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";

// A01: Broken Access Control - Wildcard CORS
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    next();
});

// A03: Command Injection via child_process.exec
app.get('/system-diagnostic', (req, res) => {
    const cmd = req.query.cmd;
    child_process.exec(`traceroute ${req.query.cmd}`, (err, stdout) => {
        res.send(stdout);
    });
});

// A07: Identification and Auth - Cookie without HttpOnly
app.get('/session', (req, res) => {
    res.cookie('token', 'sample_auth_token_9999', { httpOnly: false });
    res.json({ status: 'ok' });
});

// A10: Cloud Metadata Reference
app.get('/metadata', (req, res) => {
    const metaUrl = "http://169.254.169.254/latest/meta-data/";
    fetch(metaUrl).then(r => r.text()).then(t => res.send(t));
});

// A03: Prototype Pollution
app.post('/api/settings', (req, res) => {
    Object.assign(req.userConfig, req.body);
    res.json({ updated: true });
});

// A07: Insecure JWT configuration allowing 'none' algorithm
app.post('/api/verify-token', (req, res) => {
    const token = req.headers['authorization'];
    jwt.verify(token, "secret", { algorithms: ['none'] });
    res.json({ valid: true });
});

app.listen(3000);
