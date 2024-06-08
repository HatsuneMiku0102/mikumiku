const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const MemoryStore = require('memorystore')(session);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-key',
    resave: false,
    saveUninitialized: false,
    store: new MemoryStore({
        checkPeriod: 86400000 // prune expired entries every 24h
    }),
    cookie: { secure: true, sameSite: 'strict' } // Secure cookies for HTTPS
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

// OAuth Configuration
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://mikumiku.dev/callback';  // Ensure this matches the URL in your Bungie app settings

// OAuth Login Route
app.get('/login', (req, res) => {
    const state = generateRandomString(16);
    req.session.state = state;
    req.session.save(err => {
        if (err) {
            console.error('Error saving session:', err);
        } else {
            console.log(`Generated state: ${state}`); // Logging state
            const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
            res.redirect(authorizeUrl);
        }
    });
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    console.log(`Received state: ${state}`); // Logging received state
    console.log(`Session state: ${req.session.state}`); // Logging session state
    console.log(`Complete session: ${JSON.stringify(req.session)}`);

    if (state !== req.session.state) {
        return res.status(400).send('State mismatch. Potential CSRF attack.');
    }

    try {
        const tokenData = await getBungieToken(code);
        if (!tokenData.access_token) {
            throw new Error('Failed to obtain access token');
        }
        const accessToken = tokenData.access_token;
        const userInfo = await getBungieUserInfo(accessToken);
        
        if (!userInfo.Response || !userInfo.Response.bungieNetUser) {
            throw new Error('Failed to obtain user information');
        }

        const bungieName = userInfo.Response.bungieNetUser.displayName;
        const membershipId = userInfo.Response.bungieNetUser.membershipId;
        const platformType = userInfo.Response.primaryMembershipType;

        // Store the user information in the database
        const client = await pool.connect();
        const queryText = 'INSERT INTO users(bungie_name, membership_id, platform_type) VALUES($1, $2, $3) ON CONFLICT (membership_id) DO UPDATE SET bungie_name = EXCLUDED.bungie_name, platform_type = EXCLUDED.platform_type RETURNING *';
        const values = [bungieName, membershipId, platformType];
        const result = await client.query(queryText, values);
        client.release();

        res.json({
            bungie_name: bungieName,
            membership_id: membershipId,
            platform_type: platformType
        });
    } catch (error) {
        console.error('Error during callback:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/oauth-callback', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'callback.html'));
});

function generateRandomString(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

async function getBungieToken(code) {
    const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
    const payload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI
    });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const response = await axios.post(url, payload.toString(), { headers });
    return response.data;
}

async function getBungieUserInfo(accessToken) {
    const url = 'https://www.bungie.net/Platform/User/GetCurrentBungieNetUser/';
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': CLIENT_ID
    };
    const response = await axios.get(url, { headers });
    return response.data;
}

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

    const token = jwt.sign({ id: user.username }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
        expiresIn: 86400 // 24 hours
    });

    res.cookie('token', token, {
        httpOnly: true,
        secure: false, // Set to true if using HTTPS
        maxAge: 86400 * 1000 // 24 hours
    });

    res.status(200).send({ auth: true, token });
});

function verifyToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send({ redirect: '/admin-login.html' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret-key', (err, decoded) => {
        if (err) {
            return res.status(401).send({ redirect: '/admin-login.html' });
        }
        req.userId = decoded.id;
        next();
    });
}

// Public route for fetching videos
app.get('/api/videos/public', async (req, res) => {
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

// Protected route for adding videos
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

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
