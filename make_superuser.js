const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./chat.db');

const username = process.argv[2];

if (!username) {
    console.log('Usage: node make_superuser.js <username>');
    process.exit(1);
}

db.run("UPDATE users SET role = 'superuser' WHERE username = ?", [username], function (err) {
    if (err) {
        console.error('Error:', err.message);
    } else if (this.changes === 0) {
        console.log(`User "${username}" not found.`);
    } else {
        console.log(`Success! User "${username}" is now a superuser.`);
    }
    db.close();
});
