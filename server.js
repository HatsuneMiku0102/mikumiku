const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const AWS = require('aws-sdk');
const multer = require('multer');
const multerS3 = require('multer-s3');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // set true if using https
}));

app.use(express.static(path.join(__dirname, 'public')));

// AWS S3 Configuration
AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});

const s3 = new AWS.S3();

// PostgreSQL Configuration
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Multer S3 Storage
const upload = multer({
    storage: multerS3({
        s3: s3,
        bucket: process.env.S3_BUCKET_NAME,
        acl: 'public-read',
        key: function (req, file, cb) {
            cb(null, Date.now().toString() + '-' + file.originalname);
        }
    })
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

app.post('/api/videos', isAuthenticated, upload.single('video'), async (req, res) => {
    const videoMetadata = {
        url: req.file.location,
        filename: req.file.originalname,
        uploadedAt: new Date()
    };

    try {
        const client = await pool.connect();
        const queryText = 'INSERT INTO videos(url, filename, uploaded_at) VALUES($1, $2, $3) RETURNING *';
        const values = [videoMetadata.url, videoMetadata.filename, videoMetadata.uploadedAt];
        await client.query(queryText, values);
        client.release();
        res.status(201).send({ message: 'Video added', video: videoMetadata });
    } catch (err) {
        console.error('Error saving video metadata to PostgreSQL:', err);
        res.status(500).send('Error saving video metadata');
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
        res.status(500).send('Error retrieving video metadata');
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
