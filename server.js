// Import required modules
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
        // CSP directives here
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

// OAuth Configuration
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
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
            const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
            res.redirect(authorizeUrl);
        }
    });
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    if (state !== req.session.state) {
        return res.status(400).send('State mismatch. Potential CSRF attack.');
    }

    // Check session expiry
    if (!req.session) {
        return res.status(401).send('Session expired');
    }

    try {
        // Process callback
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
        const platformType = userInfo.Response.primaryMembershipType || 1; // Defaulting to 1 if not provided

        // Store or update user information in MongoDB
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
    // Implementation
}

async function getBungieUserInfo(accessToken) {
    // Implementation
}

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
