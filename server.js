const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const users = [
    {
        username: process.env.ADMIN_USERNAME,
        password: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 8)
    }
];

const generateAccessToken = (username) => {
    return jwt.sign({ username }, process.env.TOKEN_SECRET, { expiresIn: '1h' });
};

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    const token = generateAccessToken(user.username);
    res.status(200).send({ auth: true, token });
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send({ auth: false, message: 'No token provided' });

    jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).send({ auth: false, message: 'Failed to authenticate token' });
        req.user = user;
        next();
    });
};

app.get('/admin-dashboard.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.post('/api/videos', authenticateToken, async (req, res) => {
    const videoMetadata = {
        url: req.body.url.replace('youtu.be', 'youtube.com/embed'),
        title: req.body.title,
        description: req.body.description,
        category: req.body.category,
        uploadedAt: new Date()
    };

    try {
        const client = await pool.connect();
        const queryText = 'INSERT INTO videos(url, title, description, category, uploaded_at) VALUES($1, $2, $3, $4, $5) RETURNING *';
        const values = [videoMetadata.url, videoMetadata.title, videoMetadata.description, videoMetadata.category, videoMetadata.uploadedAt];
        const result = await client.query(queryText, values);
        client.release();
        res.status(201).send({ message: 'Video added', video: result.rows[0] });
    } catch (err) {
        console.error('Error saving video metadata to PostgreSQL:', err);
        res.status(500).send({ error: 'Error saving video metadata' });
    }
});

app.get('/api/videos', async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT * FROM videos');
        client.release();
        res.json(result.rows);
    } catch (err) {
        console.error('Error retrieving video metadata from PostgreSQL:', err);
        res.status(500).send({ error: 'Error retrieving video metadata' });
    }
});

app.post('/logout', authenticateToken, (req, res) => {
    res.send({ message: 'Logged out' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
