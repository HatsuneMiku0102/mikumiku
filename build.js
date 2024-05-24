const fs = require('fs');
const path = require('path');


const adminLoginHtmlPath = path.join(__dirname, 'public', 'admin-login.html');


let adminLoginHtml = fs.readFileSync(adminLoginHtmlPath, 'utf8');




fs.writeFileSync(adminLoginHtmlPath, adminLoginHtml, 'utf8');

console.log('Admin login HTML file has been processed.');
