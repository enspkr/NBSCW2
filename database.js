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
            CONSTRAINT username_unique UNIQUE (username)
            )`,
        (err) => {
            if (err) {
                // Table already created
                console.log('Users table already exists.');
            } else {
                // Table just created, creating the first user (you)
                console.log('Users table created, now adding the admin user.');
                const saltRounds = 10;
                // IMPORTANT: Change this password to something secure!
                const adminPassword = "changeThisPasswordNow"; 

                bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
                    if (err) {
                        console.error("Error hashing password:", err);
                        return;
                    }
                    const insert = 'INSERT INTO users (username, password_hash) VALUES (?,?)';
                    db.run(insert, ['admin', hash]);
                    console.log('🔑 Admin user created. Username: admin');
                });
            }
        });  
    }
});

module.exports = db;
