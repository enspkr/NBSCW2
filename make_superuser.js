const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./synapse.db');

const username = process.argv[2];

if (!username) {
    console.log('Usage: node make_superuser.js <username>');
    process.exit(1);
}

function updateRole() {
    db.run("UPDATE users SET role = 'superuser' WHERE username = ?", [username], function (err) {
        if (err) {
            console.error('Error updating role:', err.message);
        } else if (this.changes === 0) {
            console.log(`User "${username}" not found.`);
        } else {
            console.log(`Success! User "${username}" is now a superuser.`);
        }
        db.close();
    });
}

// Check schema and migrate if needed
db.all("PRAGMA table_info(users)", (err, rows) => {
    if (err) {
        console.error("Error checking schema:", err.message);
        // Try update anyway in case pragma fails but table is fine
        return updateRole();
    }

    const hasRole = rows.some(col => col.name === 'role');

    if (!hasRole) {
        console.log("Schema mismatch: 'role' column missing. Attempting to add it...");
        db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'", (alterErr) => {
            if (alterErr) {
                console.error("Failed to add 'role' column:", alterErr.message);
                db.close();
            } else {
                console.log("Column 'role' added successfully.");
                updateRole();
            }
        });
    } else {
        updateRole();
    }
});
