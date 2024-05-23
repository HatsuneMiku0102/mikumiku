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

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.json());

const users = [
    {
        username: process.env.ADMIN_USERNAME,
        password: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 8)
    }
];

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send('Invalid username or password');

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.status(400).send('Invalid username or password');

    const token = jwt.sign({ id: user.username }, process.env.JWT_SECRET, { expiresIn: 86400 });
    res.status(200).send({ auth: true, token: token });
});

function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send('No token provided');

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(500).send('Failed to authenticate token');
        req.userId = decoded.id;
        next();
    });
}

app.post('/api/videos', verifyToken, (req, res) => {
    const newVideo = req.body;
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    fs.readFile(videosFilePath, 'utf8', (err, data) => {
        if (err) return res.status(500).send('Error reading video data');

        const videos = JSON.parse(data);
        videos.push(newVideo);

        fs.writeFile(videosFilePath, JSON.stringify(videos, null, 2), (err) => {
            if (err) return res.status(500).send('Error saving video data');

            res.status(201).send('Video added');
        });
    });
});

app.get('/api/videos', (req, res) => {
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    fs.readFile(videosFilePath, 'utf8', (err, data) => {
        if (err) return res.status(500).send('Error reading video data');

        res.json(JSON.parse(data));
    });
});

// Handle requests to the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
