const sqlite3 = require('sqlite3').verbose();
const DB_SOURCE = "synapse.db";

const db = new sqlite3.Database(DB_SOURCE, (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});

const defaultPermissions = JSON.stringify({ chat: true, video: true, audio: true, screen: true });

const sql = `UPDATE users SET permissions = ? WHERE username = 'admin'`;

db.run(sql, [defaultPermissions], function (err) {
    if (err) {
        return console.error(err.message);
    }
    console.log(`Row(s) updated: ${this.changes}`);
    console.log(`Admin permissions have been restored to default.`);
});
