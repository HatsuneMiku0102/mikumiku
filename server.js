const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const mongoose = require('mongoose');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Set trust proxy and configure session
app.set('trust proxy', 1);
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URL || 'mongodb://localhost:27017/myfirstdatabase',
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60, // 14 days
        autoRemove: 'native'
    }),
    cookie: {
        secure: true,
        sameSite: 'None',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Set CSP headers using helmet
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "https://*"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://*"],
        frameSrc: ["'self'", "https://discord.com"],
        frameAncestors: ["'self'", "https://discord.com"]
    }
}));

// MongoDB connection
mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost:27017/myfirstdatabase', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Error connecting to MongoDB:', err);
});

// User model
const userSchema = new mongoose.Schema({
    bungie_name: { type: String, required: true },
    membership_id: { type: String, unique: true, required: true },
    platform_type: { type: Number, required: true }
});
const User = mongoose.model('User', userSchema);

// OAuth Configuration
const CLIENT_ID = '46399';
const CLIENT_SECRET = 'C7.3J-mlb6CsrnxWskNeBnYRENEARjHDELMaggh9fGs';
const REDIRECT_URI = 'https://mikumiku.dev/callback';

// OAuth Login Route
app.get('/login', (req, res) => {
    const state = generateRandomString(16);
    req.session.state = state;
    req.session.save(err => {
        if (err) {
            console.error('Error saving session:', err);
            return res.status(500).send('Internal Server Error');
        } else {
            console.log(`Generated state: ${state}`);
            console.log(`Session after saving state: ${JSON.stringify(req.session)}`);
            const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
            res.redirect(authorizeUrl);
        }
    });
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    console.log(`Received state: ${state}`);
    console.log(`Session state: ${req.session.state}`);

    if (!req.session.state) {
        console.error('Session state is missing.');
        return res.status(400).send('Session state is missing.');
    }

    if (state !== req.session.state) {
        console.error('State mismatch. Potential CSRF attack.');
        return res.status(400).send('State mismatch. Potential CSRF attack.');
    }

    // Check session expiry
    if (!req.session) {
        console.error('Session expired.');
        return res.status(401).send('Session expired.');
    }

    try {
        const tokenData = await getBungieToken(code);
        if (!tokenData.access_token) {
            throw new Error('Failed to obtain access token');
        }
        const accessToken = tokenData.access_token;
        const userInfo = await getBungieUserInfo(accessToken);

        if (!userInfo.Response || !userInfo.Response.membershipId) {
            throw new Error('Failed to obtain user information');
        }

        const bungieName = userInfo.Response.uniqueName;
        const membershipId = userInfo.Response.membershipId;
        const platformType = userInfo.Response.primaryMembershipType || 1;

        const user = await User.findOneAndUpdate(
            { membership_id: membershipId },
            { bungie_name: bungieName, platform_type: platformType },
            { new: true, upsert: true }
        );

        res.json({
            bungie_name: user.bungie_name,
            membership_id: user.membership_id,
            platform_type: user.platform_type
        });
    } catch (error) {
        console.error('Error during callback:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Helper function to generate random string
function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Helper functions for Bungie OAuth
async function getBungieToken(code) {
    const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
    const payload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI
    });
    const headers = { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-API-Key': 'Your-API-Key'
    };

    try {
        const response = await axios.post(url, payload.toString(), { headers });
        console.log('Token Response:', response.data);
        return response.data;
    } catch (error) {
        console.error('Error fetching Bungie token:', error);
        throw new Error('Failed to fetch Bungie token');
    }
}

async function getBungieUserInfo(accessToken) {
    const url = 'https://www.bungie.net/Platform/User/GetCurrentBungieNetUser/';
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': 'Your-API-Key',
        'User-Agent': 'axios/0.21.4'
    };

    try {
        const response = await axios.get(url, { headers });
        console.log('User Info Response:', response.data);
        return response.data;
    } catch (error) {
        console.error('Error fetching Bungie user info:', error);
        throw new Error('Failed to fetch Bungie user info');
    }
}

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
