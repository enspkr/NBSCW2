// createUser.js

const db = require('./database.js');
const bcrypt = require('bcrypt');
const saltRounds = 10; // The cost factor for hashing

// Get username and password from command-line arguments
const username = process.argv[2];
const password = process.argv[3];

// --- Validation ---
if (!username || !password) {
    console.error('❌ Error: Please provide both a username and a password.');
    console.log('Usage: node createUser.js <username> <password>');
    process.exit(1); // Exit with an error code
}

// --- Create User ---
console.log(`Attempting to create user: ${username}...`);

bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err);
        return;
    }

    const insert = 'INSERT INTO users (username, password_hash) VALUES (?,?)';
    db.run(insert, [username, hash], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                console.error(`❌ Error: Username '${username}' already exists.`);
            } else {
                console.error(err.message);
            }
            return;
        }
        console.log(`✅ Success! User '${username}' created with ID: ${this.lastID}`);
    });
});