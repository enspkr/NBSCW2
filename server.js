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
        // Check permissions
        const userPermissions = activeUsers[socket.id]?.permissions;
        if (userPermissions && !userPermissions.chat) {
            socket.emit('error-message', 'You are muted from chat.');
            return;
        }

        // --- ADMIN COMMANDS ---
        if (message.trim() === '/clear') {
            if (socket.user.role !== 'admin') {
                socket.emit('error-message', 'Unauthorized: Admin only.');
                return;
            }
            chatDb.run("DELETE FROM messages", [], (err) => {
                if (err) return console.error(err.message);
                io.emit('chat cleared'); // Notify all clients
                io.emit('chat message', { username: 'System', message: 'Chat history has been cleared.' });
            });
            return; // Stop normal processing
        }

        // --- PUBLIC COMMANDS ---

        // --- ROLL COMMAND ---
        if (message.startsWith('/roll')) {
            const parts = message.trim().split(/\s+/);
            let max = 6; // Default to 0-6
            if (parts.length > 1) {
                const parsed = parseInt(parts[1], 10);
                if (!isNaN(parsed) && parsed > 0) {
                    max = parsed;
                }
            }

            // Range 0 to max inclusive
            const roll = Math.floor(Math.random() * (max + 1));
            const rollMessage = `🎲 rolled ${roll} (0-${max})`;

            chatDb.run("INSERT INTO messages (username, message) VALUES (?, ?)", [username, rollMessage], (err) => {
                if (err) return console.error(err.message);
                io.emit('chat message', { username, message: rollMessage });
            });
            return; // Stop normal processing
        }

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
                // Include role and permissions in the returned data (token payload is small, so query DB on connect or just trust token?)
                // Better to query DB on socket connect for fresh permissions.
                // For now, let's put role in token.
                const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
                res.cookie('token', token, { httpOnly: true });
                res.json({ status: 'success', token: token, role: user.role, permissions: JSON.parse(user.permissions || '{}') });
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
    // Fetch latest permissions from DB to be sure
    const sql = "SELECT role, permissions FROM users WHERE username = ?";
    db.get(sql, [socket.user.username], (err, row) => {
        const role = row ? row.role : 'user';
        let permissions = { chat: true, video: true, audio: true, screen: true };
        try { permissions = JSON.parse(row.permissions); } catch (e) { }

        // Update socket.user with fresh role
        socket.user.role = role;

        const userData = { username: socket.user.username, isMuted: false, role, permissions };
        activeUsers[socket.id] = userData;

        // Tell everyone else that a new user has joined
        socket.broadcast.emit('user-joined', socket.id, userData);

        // Tell the user their own permissions/role immediately
        socket.emit('my-identity', { role, permissions, username: socket.user.username });
    });

    // Add a new listener for mute status changes
    socket.on('mute-status-changed', ({ isMuted }) => {
        if (activeUsers[socket.id]) {
            activeUsers[socket.id].isMuted = isMuted;
            socket.broadcast.emit('user-mute-status', socket.id, isMuted);
        }
    });

    // --- ADMIN: Update Permissions ---
    // --- ADMIN: Update Permissions ---
    socket.on('admin-update-permission', ({ targetUsername, feature, value }) => {
        // 1. Verify sender is admin or superuser
        if (socket.user.role !== 'admin' && socket.user.role !== 'superuser') {
            return socket.emit('error-message', 'Unauthorized: Admin or Superuser only.');
        }

        // 1.5 Prevent Self-Lockout
        if (targetUsername === socket.user.username) {
            return socket.emit('error-message', 'Operation Denied: You cannot modify your own permissions.');
        }

        // 1.6 Role Hierarchy Check
        // If sender is 'admin', they cannot modify 'superuser'
        // We need to check target's role. 
        const sqlCheck = "SELECT role FROM users WHERE username = ?";
        db.get(sqlCheck, [targetUsername], (err, row) => {
            if (err || !row) return socket.emit('error-message', 'Target user not found.');

            // NEW LOGIC: Admins CAN manage Superusers/Admins, BUT NOT CHAT
            if (socket.user.role === 'admin' && (row.role === 'superuser' || row.role === 'admin')) {
                if (feature === 'chat') {
                    return socket.emit('error-message', 'Unauthorized: Admins cannot disable chat for other privileged users.');
                }
                // Allowed to change video/audio/screen
            }

            // Proceed with update...
            updateUserPermission(targetUsername, feature, value, socket);
        });
    });

    function updateUserPermission(targetUsername, feature, value, socket) {
        // 2. Update Database (find by username) - Do this FIRST so it persists even if offline
        // Retrieve current perms first to merge? Or just assume client sent full state?
        // Client sends ONE feature update. We need to fetch, update, save.

        const sql = "SELECT permissions FROM users WHERE username = ?";
        db.get(sql, [targetUsername], (err, row) => {
            if (err || !row) {
                return socket.emit('error-message', `User ${targetUsername} not found.`);
            }

            let permissions = { chat: true, video: true, audio: true, screen: true };
            try { permissions = JSON.parse(row.permissions || '{}'); } catch (e) { }

            // Update the specific feature
            permissions[feature] = value;

            const permString = JSON.stringify(permissions);
            db.run("UPDATE users SET permissions = ? WHERE username = ?", [permString, targetUsername], (err) => {
                if (err) return console.error("DB Update Error", err);

                // 3. Notify the target user IF ONLINE
                // Find socket ID by username
                const targetSocketId = Object.keys(activeUsers).find(id => activeUsers[id].username === targetUsername);

                if (targetSocketId) {
                    // Update In-Memory
                    if (activeUsers[targetSocketId]) {
                        activeUsers[targetSocketId].permissions = permissions;
                    }
                    io.to(targetSocketId).emit('permission-update', { feature, value });
                }

                // 4. Notify the admin (ack)
                socket.emit('admin-action-success', `Updated ${targetUsername} ${feature} to ${value}`);
            });
        });
    }

    // --- SUPERUSER: Change Password ---
    socket.on('superuser-change-password', ({ targetUsername, newPassword }) => {
        if (socket.user.role !== 'superuser') {
            return socket.emit('error-message', 'Unauthorized: Superuser only.');
        }

        bcrypt.hash(newPassword, 10, (err, hash) => {
            if (err) return console.error("Hashing error", err);

            const sql = "UPDATE users SET password_hash = ? WHERE username = ?";
            db.run(sql, [hash, targetUsername], function (err) {
                if (err) return socket.emit('error-message', 'Database error.');

                socket.emit('admin-action-success', `Updated password for ${targetUsername}`);
                console.log(`Superuser ${socket.user.username} reset password for ${targetUsername}`);
            });
        });
    });

    // --- ADMIN: Get All Users ---
    socket.on('get-all-users', () => {
        if (socket.user.role !== 'admin' && socket.user.role !== 'superuser') {
            return socket.emit('error-message', 'Unauthorized: Admin only.');
        }

        db.all("SELECT username, permissions FROM users", [], (err, rows) => {
            if (err) return console.error(err);

            const usersList = rows.map(row => {
                let permissions = { chat: true, video: true, audio: true, screen: true };
                try { permissions = JSON.parse(row.permissions); } catch (e) { }

                // Check if online
                const isOnline = Object.values(activeUsers).some(u => u.username === row.username);

                return {
                    username: row.username,
                    permissions,
                    isOnline
                };
            });

            socket.emit('all-users-data', usersList);
        });
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