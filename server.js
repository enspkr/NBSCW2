require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const db = require('./database.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'a-default-secret-for-local-testing';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const protectRoute = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) { return res.redirect('/'); }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) { return res.redirect('/'); }
        req.user = decoded;
        next();
    });
};

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username = ?";
    db.get(sql, [username], (err, user) => {
        if (!user) { return res.status(401).json({ status: 'error', message: 'Invalid credentials' }); }
        bcrypt.compare(password, user.password_hash, (err, result) => {
            if (result) {
                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
                res.cookie('token', token, { httpOnly: true });
                res.json({ status: 'success', token: token });
            } else {
                res.status(401).json({ status: 'error', message: 'Invalid credentials' });
            }
        });
    });
});

app.get('/call', protectRoute, (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'call.html'));
});

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) { return next(new Error('Authentication error: No token provided.')); }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) { return next(new Error('Authentication error: Invalid token.')); }
        socket.user = decoded;
        next();
    });
});

const activeUsers = {};
io.on('connection', (socket) => {
    console.log(`✅ User connected: ${socket.user.username} (${socket.id})`);
    
    socket.emit('existing-users', activeUsers);
    activeUsers[socket.id] = socket.user.username;
    socket.broadcast.emit('user-joined', socket.id, socket.user.username);
    socket.on('mute-status-changed', ({ isMuted }) => {
        // Just relay the message to everyone else with the user's ID
        socket.broadcast.emit('user-mute-status', socket.id, isMuted);
    });
    socket.on('webrtc-offer', (toSocketId, offer) => socket.to(toSocketId).emit('webrtc-offer', socket.id, offer));
    socket.on('webrtc-answer', (toSocketId, answer) => socket.to(toSocketId).emit('webrtc-answer', socket.id, answer));
    socket.on('webrtc-ice-candidate', (toSocketId, candidate) => socket.to(toSocketId).emit('webrtc-ice-candidate', socket.id, candidate));

    socket.on('disconnect', () => {
        if (socket.user) console.log(`❌ User disconnected: ${socket.user.username} (${socket.id})`);
        delete activeUsers[socket.id];
        socket.broadcast.emit('user-left', socket.id);
    });
});

server.listen(PORT, () => {
    console.log(`🚀 Server is live and listening on http://localhost:${PORT}`);
});