const sqlite3 = require('sqlite3').verbose();
const DB_SOURCE = "synapse.db";

const db = new sqlite3.Database(DB_SOURCE, (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});

// Promote 'enes' to 'superuser'
const sql = `UPDATE users SET role = 'superuser' WHERE username = 'enes'`;

db.run(sql, [], function (err) {
    if (err) {
        return console.error(err.message);
    }
    console.log(`Row(s) updated: ${this.changes}`);
    if (this.changes > 0) {
        console.log(`User 'enes' has been promoted to 'superuser'.`);
    } else {
        console.log(`User 'enes' not found.`);
    }
});
