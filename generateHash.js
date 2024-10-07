// generateHash.js
const bcrypt = require('bcryptjs');

const adminPassword = 'CV01'; // Replace with your desired password
const saltRounds = 12; // You can adjust the salt rounds as needed

bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err);
    } else {
        console.log('Hashed Password:', hash);
    }
});
