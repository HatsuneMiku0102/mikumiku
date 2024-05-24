const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const fs = require('fs').promises; // Use promises with fs
const path = require('path');
const dotenv = require('dotenv');
const { createClient } = require('redis');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Create Redis client using the URL from environment variables
const redisClient = createClient({
    url: process.env.REDIS_URL
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));

(async () => {
    await redisClient.connect();
})();

app.use(bodyParser.json());

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true, sameSite: 'None' }
}));

// Middleware to log session details
app.use((req, res, next) => {
    console.log('Session ID:', req.sessionID);
    console.log('Session Data:', req.session);
    next();
});

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
        console.log('Invalid username');
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        console.log('Invalid password');
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    req.session.user = {
        username: user.username
    };
    console.log('Session created:', req.session);
    res.status(200).send({ auth: true });
});

function isAuthenticated(req, res, next) {
    console.log('Checking authentication:', req.session);
    if (req.session.user) {
        next();
    } else {
        console.log('User not authenticated, redirecting to login');
        res.redirect('/admin-login.html');
    }
}

// Protecting the admin dashboard route
app.get('/admin-dashboard.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.post('/api/videos', isAuthenticated, async (req, res) => {
    const newVideo = req.body;
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    try {
        let videos = [];
        if (await fs.access(videosFilePath).then(() => true).catch(() => false)) {
            const data = await fs.readFile(videosFilePath, 'utf8');
            videos = JSON.parse(data);
        }

        videos.push(newVideo);

        await fs.writeFile(videosFilePath, JSON.stringify(videos, null, 2));
        res.status(201).send({ message: 'Video added' });
    } catch (err) {
        console.error('Error handling video data:', err);
        res.status(500).send({ message: 'Error handling video data', error: err });
    }
});

app.get('/api/videos', async (req, res) => {
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    try {
        const data = await fs.readFile(videosFilePath, 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading video data:', err);
        res.status(500).send({ message: 'Error reading video data', error: err });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log('Failed to destroy session:', err);
            return res.status(500).send({ message: 'Failed to log out' });
        }
        console.log('Session destroyed');
        res.redirect('/admin-login.html');
    });
});

app.listen(PORT, (err) => {
    if (err) {
        console.error('Server failed to start:', err);
    } else {
        console.log(`Server is running on http://localhost:${PORT}`);
    }
});
