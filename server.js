// Required dependencies
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
const crypto = require('crypto');
const fs = require('fs');
const winston = require('winston');

// Configure logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'app.log' })
    ]
});

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1); // Trust the first proxy for secure cookies

app.use(bodyParser.json());
app.use(cookieParser());

const mongoUrl = process.env.MONGO_URL || 'mongodb://localhost:27017/myfirstdatabase';

// Connect to MongoDB
mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false  // Address deprecation warning
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error('Error connecting to MongoDB:', err);
});

const sessionStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60, // 14 days
    autoRemove: 'native'
});

sessionStore.on('connected', () => {
    logger.info('Session store connected to MongoDB');
});

sessionStore.on('error', (error) => {
    logger.error('Session store error:', error);
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-key',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: true, // Ensure secure flag is true for HTTPS
        sameSite: 'None', // Adjusting SameSite attribute
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use((req, res, next) => {
    logger.info(`Session ID: ${req.session.id}`);
    logger.info(`Session Data before modification: ${JSON.stringify(req.session)}`);
    logger.info(`Cookies: ${JSON.stringify(req.cookies)}`);
    next();
});

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

app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Schema and Model
const userSchema = new mongoose.Schema({
    discord_id: { type: String, required: true },
    bungie_name: { type: String, required: true },
    membership_id: { type: String, unique: true, required: true },
    platform_type: { type: Number, required: true }
});

const User = mongoose.model('User', userSchema);

const sessionSchema = new mongoose.Schema({
    state: { type: String, required: true, unique: true },
    user_id: { type: String, required: true },
    session_id: { type: String, required: true },
    created_at: { type: Date, default: Date.now, expires: 86400 }, // 24 hours
    ip_address: { type: String },
    user_agent: { type: String }
});

const Session = mongoose.model('Session', sessionSchema, 'sessions'); // Explicitly specify the collection name

// OAuth Login Route
app.get('/login', async (req, res) => {
    const state = generateRandomString(16);
    const user_id = req.query.user_id; // Assume user_id is passed in the query for simplicity
    const ip_address = req.ip;
    const user_agent = req.get('User-Agent');

    const sessionData = new Session({
        state,
        user_id,
        session_id: req.session.id,
        ip_address,
        user_agent
    });

    try {
        await sessionData.save();
        logger.info(`Generated state: ${state}`);
        logger.info(`Inserted session: ${JSON.stringify(sessionData)}`);
        const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
        res.redirect(authorizeUrl);
    } catch (err) {
        logger.error('Error saving session to DB:', err);
        res.status(500).send('Internal Server Error');
    }
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    logger.info(`Received state: ${state}`);
    logger.info(`Received code: ${code}`);

    try {
        const sessionData = await Session.findOne({ state });
        logger.info(`Session data from DB: ${JSON.stringify(sessionData)}`);

        if (!sessionData) {
            logger.warn("State mismatch. Potential CSRF attack.");
            return res.status(400).send('State mismatch. Potential CSRF attack.');
        }

        const tokenData = await getBungieToken(code);
        logger.info(`Token data: ${JSON.stringify(tokenData)}`);

        if (!tokenData.access_token) {
            throw new Error('Failed to obtain access token');
        }

        const accessToken = tokenData.access_token;
        const userInfo = await getBungieUserInfo(accessToken);
        logger.info('User Info Response:', userInfo);

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error('Incomplete user info response:', userInfo);
            throw new Error('Failed to obtain user information');
        }

        const bungieGlobalDisplayName = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayName;
        const bungieGlobalDisplayNameCode = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode;
        const bungieName = `${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode}`;

        let primaryMembership = userInfo.Response.destinyMemberships.find(
            membership => membership.membershipId === userInfo.Response.primaryMembershipId
        );

        if (!primaryMembership) {
            // If no primary membership is found, fallback to the first membership
            primaryMembership = userInfo.Response.destinyMemberships[0];
        }

        if (!primaryMembership) {
            throw new Error('Failed to obtain platform-specific membership ID');
        }

        const membershipId = primaryMembership.membershipId;
        const platformType = primaryMembership.membershipType;

        logger.info(`Extracted bungieName: ${bungieName}, membershipId: ${membershipId}, platformType: ${platformType}`);

        const discordId = sessionData.user_id;

        const user = await User.findOneAndUpdate(
            { membership_id: membershipId },
            {
                discord_id: discordId,
                bungie_name: bungieName,
                platform_type: platformType
            },
            { upsert: true, new: true }
        );

        await Session.deleteOne({ state });

        const token = generateRandomString(16);
        res.redirect(`/confirmation?token=${token}`);
    } catch (error) {
        logger.error('Error during callback:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        res.status(500).send('Internal Server Error');
    }
});

app.get('/confirmation', async (req, res) => {
    const token = req.query.token;

    try {
        const user = await User.findOne({ token });
        if (!user) {
            logger.warn('No user found with given token.');
            return res.status(400).send('Invalid token.');
        }

        const { bungie_name } = user;

        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Registration Confirmation</title>
                <link rel="stylesheet" href="/styles.css">
                <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
                <style>
                    body {
                        font-family: 'Roboto', sans-serif;
                        margin: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        background: url('/confbackground.webp') no-repeat center center fixed;
                        background-size: cover;
                    }
                    .confirmation-box {
                        background: rgba(0, 0, 0, 0.7);
                        padding: 20px 40px;
                        border-radius: 10px;
                        text-align: center;
                        color: gold;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
                    }
                    .confirmation-box h2 {
                        margin: 0 0 10px;
                        font-size: 2em;
                    }
                    .confirmation-box p {
                        margin: 0;
                        font-size: 1.2em;
                    }
                    .highlight {
                        display: inline-block;
                        background-color: #ffd700;
                        color: #000;
                        padding: 5px 10px;
                        border-radius: 5px;
                        font-weight: bold;
                    }
                    .channel-link {
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        margin-top: 20px;
                        padding: 10px 20px;
                        background-color: #7289da;
                        color: #fff;
                        text-decoration: none;
                        font-size: 1.2em;
                        border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
                        transition: all 0.3s ease;
                    }
                    .channel-link:hover {
                        background-color: #5a6ea6;
                        transform: scale(1.1);
                    }
                    .next-steps, .support, .feedback {
                        margin-top: 20px;
                    }
                    .next-steps p, .support p, .feedback p {
                        font-size: 1em;
                        color: #ccc;
                    }
                    .social-links a {
                        margin: 0 10px;
                        color: gold;
                        text-decoration: none;
                    }
                    .social-links a:hover {
                        color: #ffd700;
                    }
                </style>
            </head>
            <body>
                <div class="confirmation-box">
                    <h2>Registration Was Successful!</h2>
                    <p>Hello, ${bungie_name}!</p>
                    <p>Thank you for registering. Please go back to our Discord and use the <span class="highlight">/authorize</span> command to complete your registration.</p>
                    <a href="discord://discordapp.com/channels/your-server-id/1201121345619103805" class="channel-link">
                        Click to go back to Discord
                    </a>
                    <div class="next-steps">
                        <h3>Next Steps</h3>
                        <p>Make sure to check our #welcome channel for more information about our community and guidelines.</p>
                    </div>
                    <div class="support">
                        <h3>Need Help?</h3>
                        <p>If you encounter any issues, please contact our support team at <a href="mailto:support@example.com">support@example.com</a>.</p>
                    </div>
                    <div class="feedback">
                        <h3>We Value Your Feedback</h3>
                        <p>Let us know about your registration experience by filling out <a href="https://example.com/feedback">this short form</a>.</p>
                    </div>
                    <div class="social-links">
                        <h3>Follow Us</h3>
                        <a href="https://twitter.com/yourprofile" target="_blank">Twitter</a>
                        <a href="https://facebook.com/yourprofile" target="_blank">Facebook</a>
                        <a href="https://instagram.com/yourprofile" target="_blank">Instagram</a>
                    </div>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        logger.error('Error fetching user by token:', err);
        res.status(500).send('Internal Server Error');
    }
});

function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex');
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
    const headers = { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.post(url, payload.toString(), { headers });
        logger.info('Token Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error fetching Bungie token:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch Bungie token');
    }
}

async function getBungieUserInfo(accessToken) {
    const url = 'https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/';
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY,
        'User-Agent': 'axios/0.21.4'
    };

    try {
        const response = await axios.get(url, { headers });
        logger.info('User Info Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error fetching Bungie user info:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch Bungie user info');
    }
}

app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
