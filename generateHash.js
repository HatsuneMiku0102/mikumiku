// generateHash.js
const bcrypt = require('bcryptjs');

// Replace this with your desired admin password
const adminPassword = 'CV01';

// Number of salt rounds (higher is more secure but slower)
const saltRounds = 12;

bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err);
        process.exit(1);
    } else {
        console.log('Hashed Password:', hash);
        process.exit(0);
    }
});
