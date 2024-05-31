const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

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
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    req.session.user = {
        username: user.username
    };
    res.status(200).send({ auth: true });
});

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/admin-login.html');
    }
}

app.get('/admin-dashboard.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.post('/api/videos', isAuthenticated, async (req, res) => {
    const videoMetadata = {
        url: req.body.url.replace('youtu.be', 'youtube.com/embed'),
        title: req.body.title,
        description: req.body.description,
        uploadedAt: new Date()
    };

    try {
        const client = await pool.connect();
        const queryText = 'INSERT INTO videos(url, title, description, uploaded_at) VALUES($1, $2, $3, $4) RETURNING *';
        const values = [videoMetadata.url, videoMetadata.title, videoMetadata.description, videoMetadata.uploadedAt];
        const result = await client.query(queryText, values);
        client.release();
        res.status(201).send({ message: 'Video added', video: result.rows[0] });
    } catch (err) {
        console.error('Error saving video metadata to PostgreSQL:', err);
        res.status(500).send({ error: 'Error saving video metadata', details: err.message });
    }
});

app.get('/api/videos', async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT * FROM videos');
        client.release();
        res.json(result.rows); // Ensure it always returns an array
    } catch (err) {
        console.error('Error retrieving video metadata from PostgreSQL:', err);
        res.status(500).send({ error: 'Error retrieving video metadata', details: err.message });
    }
});



app.delete('/api/videos/:id', isAuthenticated, async (req, res) => {
    const videoId = req.params.id;
    try {
        const client = await pool.connect();
        const queryText = 'DELETE FROM videos WHERE id = $1 RETURNING *';
        const values = [videoId];
        const result = await client.query(queryText, values);
        client.release();

        if (result.rowCount === 0) {
            return res.status(404).send({ message: 'Video not found' });
        }

        res.status(200).send({ message: 'Video deleted', video: result.rows[0] });
    } catch (err) {
        console.error('Error deleting video from PostgreSQL:', err);
        res.status(500).send({ error: 'Error deleting video', details: err.message });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send({ message: 'Failed to log out' });
        }
        res.redirect('/admin-login.html');
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
