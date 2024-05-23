const fs = require('fs');
const path = require('path');

// Read environment variables
const adminUsername = process.env.ADMIN_USERNAME;
const adminPassword = process.env.ADMIN_PASSWORD;

// Read the admin login HTML file
const adminLoginHtmlPath = path.join(__dirname, 'public', 'admin-login.html');
let adminLoginHtml = fs.readFileSync(adminLoginHtmlPath, 'utf8');

// Inject the environment variables into the HTML file
adminLoginHtml = adminLoginHtml.replace(
    '<script src="admin-login.js"></script>',
    `<script>
        const ADMIN_USERNAME = "${adminUsername}";
        const ADMIN_PASSWORD = "${adminPassword}";
    </script>
    <script src="admin-login.js"></script>`
);

// Write the modified HTML file back to the filesystem
fs.writeFileSync(adminLoginHtmlPath, adminLoginHtml, 'utf8');

console.log('Admin login HTML file has been updated with environment variables.');

