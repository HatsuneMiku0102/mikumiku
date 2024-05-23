const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

const users = [
    {
        username: process.env.ADMIN_USERNAME,
        password: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 8)
    }
];

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        console.error('Invalid username:', username);
        return res.status(400).send({ message: 'Invalid username or password' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        console.error('Invalid password for username:', username);
        return res.status(400).send({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.username }, process.env.JWT_SECRET, { expiresIn: 86400 });
    res.status(200).send({ auth: true, token: token });
});

function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) {
        console.error('No token provided');
        return res.status(403).send('No token provided');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Failed to authenticate token:', err);
            return res.status(500).send('Failed to authenticate token');
        }
        req.userId = decoded.id;
        next();
    });
}

app.post('/api/videos', verifyToken, (req, res) => {
    const newVideo = req.body;
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    console.log('Received request to add video:', newVideo);

    // Ensure the file exists
    if (!fs.existsSync(videosFilePath)) {
        console.log('videos.json does not exist. Creating a new one.');
        fs.writeFileSync(videosFilePath, JSON.stringify([], null, 2));
    }

    fs.readFile(videosFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading video data:', err);
            return res.status(500).send({ message: 'Error reading video data', error: err });
        }

        console.log('Video data read successfully:', data);

        let videos;
        try {
            videos = JSON.parse(data);
        } catch (parseErr) {
            console.error('Error parsing video data:', parseErr);
            return res.status(500).send({ message: 'Error parsing video data', error: parseErr });
        }

        videos.push(newVideo);

        fs.writeFile(videosFilePath, JSON.stringify(videos, null, 2), (err) => {
            if (err) {
                console.error('Error saving video data:', err);
                return res.status(500).send({ message: 'Error saving video data', error: err });
            }

            console.log('Video added successfully:', newVideo);
            res.status(201).send('Video added');
        });
    });
});

app.get('/api/videos', (req, res) => {
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    fs.readFile(videosFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading video data:', err);
            return res.status(500).send({ message: 'Error reading video data', error: err });
        }

        console.log('Video data retrieved successfully:', data);
        res.json(JSON.parse(data));
    });
});

app.get('/admin-login.html', (req, res) => {
    const adminLoginHtmlPath = path.join(__dirname, 'public', 'admin-login.html');
    fs.readFile(adminLoginHtmlPath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading admin-login.html:', err);
            return res.status(500).send('Internal Server Error');
        }

        let modifiedHtml = data.replace(
            '<script id="credentials-script" type="text/javascript"></script>',
            `<script id="credentials-script" type="text/javascript">
                const ADMIN_USERNAME = "${process.env.ADMIN_USERNAME}";
                const ADMIN_PASSWORD = "${process.env.ADMIN_PASSWORD}";
            </script>`
        );

        res.send(modifiedHtml);
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
