const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret-key';
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// PostgreSQL Configuration
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

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).send({ auth: false, message: 'Invalid username or password' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        return res.status(401).send({ auth: false, message: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).send({ auth: true, token });
});

function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).send({ auth: false, message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ auth: false, message: 'Failed to authenticate token' });
        }

        req.username = decoded.username;
        next();
    });
}

app.get('/admin-dashboard.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.post('/api/videos', verifyToken, async (req, res) => {
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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
