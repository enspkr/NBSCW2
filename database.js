// database.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// The name of our database file
const DB_SOURCE = "synapse.db";

// Connect to the database. The file will be created if it doesn't exist.
const db = new sqlite3.Database(DB_SOURCE, (err) => {
    if (err) {
        // Cannot open database
        console.error(err.message);
        throw err;
    } else {
        console.log('✅ Connected to the SQLite database.');
        // Create the users table
        db.run(`CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, 
            password_hash TEXT,
            role TEXT DEFAULT 'user',
            permissions TEXT DEFAULT '{"chat":true,"video":true,"audio":true,"screen":true}'
            )`,
            (err) => {
                if (err) {
                    // Table already created
                    console.log('Users table exists. Checking for schema updates...');

                    // Attempt to add 'role' column (will fail if exists, which is fine)
                    db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'", (err) => {
                        if (!err) console.log("Added 'role' column.");
                        // Ensure admin has admin role
                        db.run("UPDATE users SET role='admin' WHERE username='admin'");
                    });

                    // Attempt to add 'permissions' column
                    db.run("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT '{\"chat\":true,\"video\":true,\"audio\":true,\"screen\":true}'", (err) => {
                        if (!err) console.log("Added 'permissions' column.");
                    });

                } else {
                    // Table just created, creating the first user (you)
                    console.log('Users table created, now adding the admin user.');
                    const saltRounds = 10;
                    // IMPORTANT: Change this password to something secure!
                    const adminPassword = process.env.ADMIN_PASSWORD || "changeThisPasswordNow";

                    bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
                        if (err) {
                            console.error("Error hashing password:", err);
                            return;
                        }
                        const insert = 'INSERT INTO users (username, password_hash, role, permissions) VALUES (?,?,?,?)';
                        db.run(insert, ['admin', hash, 'admin', JSON.stringify({ chat: true, video: true, audio: true, screen: true })]);
                        console.log('🔑 Admin user created. Username: admin');
                    });
                }
            });
    }
});

module.exports = db;
