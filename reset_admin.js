const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const DB_SOURCE = "synapse.db";

const db = new sqlite3.Database(DB_SOURCE, (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});

const newPassword = "admin123";
const saltRounds = 10;

bcrypt.hash(newPassword, saltRounds, (err, hash) => {
    if (err) {
        console.error("Error hashing password:", err);
        return;
    }
    const sql = `UPDATE users SET password_hash = ? WHERE username = 'admin'`;
    db.run(sql, [hash], function (err) {
        if (err) {
            return console.error(err.message);
        }
        console.log(`Row(s) updated: ${this.changes}`);
        console.log(`Admin password has been reset to: ${newPassword}`);
    });
});
