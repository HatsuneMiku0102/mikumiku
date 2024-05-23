const fs = require('fs');
const path = require('path');

// Path to the admin login HTML file
const adminLoginHtmlPath = path.join(__dirname, 'public', 'admin-login.html');

// Read the admin login HTML file (no modification of environment variables)
let adminLoginHtml = fs.readFileSync(adminLoginHtmlPath, 'utf8');

// Optionally, you can perform other build steps here if needed

// Write the (potentially modified) HTML file back to the filesystem
fs.writeFileSync(adminLoginHtmlPath, adminLoginHtml, 'utf8');

console.log('Admin login HTML file has been processed.');
