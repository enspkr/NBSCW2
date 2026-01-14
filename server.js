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

// At the top with your other requires
const sqlite3 = require('sqlite3').verbose();

// ...

// Near your userDb connection
const chatDb = new sqlite3.Database('./chat.db', (err) => {
    if (err) console.error(err.message);
    else console.log('✅ Connected to the chat database.');
    chatDb.run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, username TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

// ...

// Inside your existing io.on('connection', ...) block
io.on('connection', (socket) => {
    // ... (all your existing video call listeners like 'existing-users', 'webrtc-offer', etc. stay here)

    // --- ADD THIS CHAT LOGIC ---

    // Send recent chat history to the newly connected user
    chatDb.all("SELECT username, message FROM messages ORDER BY timestamp DESC LIMIT 50", [], (err, rows) => {
        if (err) return console.error(err.message);
        socket.emit('chat history', rows.reverse());
    });

    // Listen for new chat messages from a client
    socket.on('chat message', (message) => {
        const username = socket.user.username;
        chatDb.run("INSERT INTO messages (username, message) VALUES (?, ?)", [username, message], (err) => {
            if (err) return console.error(err.message);
            // Broadcast the message to everyone in the call
            io.emit('chat message', { username, message });
        });
    });
});

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

app.get('/api/ice-config', protectRoute, (req, res) => {
    // In production, you would generate a short-lived TURN token here (e.g. using Twilio API)
    // For now, we return valid STUN servers and placeholders for TURN if configured.
    const iceServers = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' }
    ];

    if (process.env.TURN_URL && process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) {
        iceServers.push({
            urls: process.env.TURN_URL,
            username: process.env.TURN_USERNAME,
            credential: process.env.TURN_CREDENTIAL
        });
    }

    res.json(iceServers);
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

    // Tell the new user about everyone who is already here, including their mute status
    socket.emit('existing-users', activeUsers);

    // Add the new user to our list, defaulting to unmuted
    const userData = { username: socket.user.username, isMuted: false };
    activeUsers[socket.id] = userData;

    // Tell everyone else that a new user has joined, sending the full user data object
    socket.broadcast.emit('user-joined', socket.id, userData);

    // Add a new listener for mute status changes
    socket.on('mute-status-changed', ({ isMuted }) => {
        if (activeUsers[socket.id]) {
            activeUsers[socket.id].isMuted = isMuted;
            socket.broadcast.emit('user-mute-status', socket.id, isMuted);
        }
    });

    // The rest of your signaling listeners remain the same
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