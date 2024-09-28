'use strict';

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
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
const { DateTime } = require('luxon');
const fetch = require('node-fetch');
const retry = require('async-retry');
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: [
            "chrome-extension://ealgoodedcojbceodddhbpcklnpneocp",
            "https://mikumiku.dev/"
        ],
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    }
});

const PORT = process.env.PORT || 3000;

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'server.log' })
    ]
});

app.get('/api/keys', (req, res) => {
    res.json({
        YOUTUBE_API_KEY: process.env.YOUTUBE_API_KEY,
        OPENWEATHER_API_KEY: process.env.OPENWEATHER_API_KEY,
    });
});

app.set('trust proxy', 1);

app.use(bodyParser.json());
app.use(cookieParser());

const mongoUrl = process.env.MONGO_URL;

mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error(`Error connecting to MongoDB: ${err}`);
});

const sessionStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'native'
});

sessionStore.on('connected', () => {
    logger.info('Session store connected to MongoDB');
});

sessionStore.on('error', (error) => {
    logger.error(`Session store error: ${error}`);
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com",
                "https://www.youtube.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "https://i.ytimg.com",
                "https://img.youtube.com",
                "https://openweathermap.org"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com"
            ],
            connectSrc: [
                "'self'",
                "https://www.googleapis.com",
                "https://*.youtube.com",
                "https://api.openweathermap.org"
            ],
            frameSrc: [
                "'self'",
                "https://discord.com",
                "https://www.youtube.com"
            ],
            mediaSrc: [
                "'self'",
                "https://www.youtube.com"
            ],
            frameAncestors: [
                "'self'",
                "https://discord.com"
            ],
            upgradeInsecureRequests: []
        }
    })
);

app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 0,
    lastModified: false
}));

const userSchema = new mongoose.Schema({
    discord_id: { type: String, required: true },
    bungie_name: { type: String, required: true },
    membership_id: { type: String, unique: true, required: true },
    platform_type: { type: Number, required: true },
    token: { type: String, unique: true },
    registration_date: { type: Date, default: Date.now },
    access_token: { type: String, required: true },
    refresh_token: { type: String, required: true },
    token_expiry: { type: Date, required: true }
});

const User = mongoose.model('User', userSchema);

const pendingMemberSchema = new mongoose.Schema({
    membershipId: { type: String, required: true },
    displayName: { type: String, required: true },
    joinDate: { type: Date, required: true }
});

const PendingMember = mongoose.model('PendingMember', pendingMemberSchema);

const sessionSchema = new mongoose.Schema({
    state: { type: String, required: true, unique: true },
    user_id: { type: String, required: true },
    session_id: { type: String, required: true },
    created_at: { type: Date, default: Date.now, expires: 86400 },
    ip_address: { type: String },
    user_agent: { type: String }
});

const Session = mongoose.model('Session', sessionSchema, 'sessions');

const commentSchema = new mongoose.Schema({
    username: { type: String, required: true },
    comment: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    approved: { type: Boolean, default: true }
});

const Comment = mongoose.model('Comment', commentSchema);

function generateRandomString(size = 16) {
    return crypto.randomBytes(size).toString('hex');
}

function hashPassword(password, salt) {
    return crypto.createHmac('sha256', salt)
        .update(password)
        .digest('hex');
}

const plainPassword = 'Aria';
const salt = 'random_salt';
const hashedPassword = hashPassword(plainPassword, salt);
logger.info(`Hashed Password: ${hashedPassword}`);

function verifyToken(req, res, next) {
    const token = req.cookies.token;
    logger.info(`Token from cookie: ${token}`);

    if (!token) {
        logger.info('Token not found. Redirecting to login.');
        return res.redirect('/admin-login.html');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            logger.info(`Token verification failed: ${err.message}`);
            return res.redirect('/admin-login.html');
        }
        logger.info(`Token successfully verified. User ID: ${decoded.id}`);
        req.userId = decoded.id;
        next();
    });
}

app.post('/api/gpt', async (req, res) => {
    const userMessage = req.body.message;

    if (!userMessage) {
        return res.status(400).json({ error: 'Message is required' });
    }

    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-3.5-turbo',
                messages: [{ role: 'user', content: userMessage }]
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            logger.error('OpenAI API Error:', errorData);
            return res.status(response.status).json({ error: 'Error from OpenAI API' });
        }

        const responseData = await response.json();
        const botMessage = responseData.choices[0].message.content;
        res.json({ message: botMessage });

    } catch (error) {
        logger.error('Server Error:', error);
        res.status(500).json({ error: 'Server error while processing request.' });
    }
});

app.get('/api/youtube', async (req, res) => {
    const videoId = req.query.videoId;

    if (!videoId) {
        return res.status(400).json({ error: 'videoId parameter is required.' });
    }

    const apiKey = process.env.YOUTUBE_API_KEY;
    if (!apiKey) {
        logger.error('YOUTUBE_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://www.googleapis.com/youtube/v3/videos?id=${encodeURIComponent(videoId)}&part=snippet,statistics,contentDetails&key=${apiKey}`;

    try {
        const data = await retry(
            async (bail, attempt) => {
                try {
                    logger.info(`Attempt ${attempt}: Fetching data from YouTube API for videoId: ${videoId}`);
                    const response = await axios.get(apiUrl);

                    if (response.status === 200) {
                        const responseData = response.data;

                        if (
                            !responseData.items ||
                            responseData.items.length === 0 ||
                            !responseData.items[0].snippet
                        ) {
                            throw new Error('Unexpected response structure from YouTube API.');
                        }

                        logger.info(`YouTube API data fetched successfully for videoId: ${videoId}`);
                        return responseData;
                    } else if (response.status === 403) {
                        bail(new Error('YouTube API quota exceeded or access forbidden.'));
                    } else {
                        throw new Error(`Failed to fetch data from YouTube API. Status: ${response.status}`);
                    }
                } catch (err) {
                    if (err.response) {
                        if (err.response.status === 404) {
                            bail(new Error('Video not found.'));
                        } else if (err.response.status >= 500) {
                            logger.warn(`Attempt ${attempt}: YouTube API returned a server error. Retrying...`);
                            throw err;
                        } else {
                            bail(err);
                        }
                    } else {
                        logger.warn(`Attempt ${attempt}: Network error or unknown issue occurred. Retrying...`);
                        throw err;
                    }
                }
            },
            {
                retries: 3,
                factor: 2,
                minTimeout: 1000,
                maxTimeout: 5000,
            }
        );

        const videoData = data.items[0];
        const snippet = videoData.snippet;
        const statistics = videoData.statistics;
        const contentDetails = videoData.contentDetails;

        const duration = contentDetails.duration;
        const title = snippet.title;
        const description = snippet.description;
        const channelTitle = snippet.channelTitle;
        const publishedAt = snippet.publishedAt;
        const viewCount = statistics.viewCount;
        const thumbnailUrl = snippet.thumbnails.high.url;
        const categoryId = snippet.categoryId;
        const liveBroadcastContent = snippet.liveBroadcastContent;

        res.status(200).json({
            duration,
            title,
            description,
            channelTitle,
            publishedAt,
            viewCount,
            thumbnailUrl,
            categoryId,
            liveBroadcastContent
        });
    } catch (error) {
        logger.error(`Error fetching YouTube video data for videoId ${videoId}: ${error.message}`);

        if (error.message.includes('quota')) {
            return res.status(403).json({ error: 'YouTube API quota exceeded. Please try again later.' });
        } else if (error.message.includes('not found')) {
            return res.status(404).json({ error: 'The requested video was not found.' });
        } else if (error.message.includes('forbidden')) {
            return res.status(403).json({ error: 'YouTube API access forbidden. Please check your API key.' });
        } else {
            return res.status(500).json({ error: 'Internal Server Error' });
        }
    }
});

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://mikumiku.dev/callback';

const membershipFilePath = path.join(__dirname, 'membership_mapping.json');

function updateMembershipMapping(discordId, userInfo) {
    let membershipMapping = {};

    if (fs.existsSync(membershipFilePath)) {
        const data = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info(`Read existing membership mapping file: ${data}`);
        try {
            membershipMapping = JSON.parse(data);
        } catch (err) {
            logger.error(`Error parsing membership mapping file: ${err}`);
            membershipMapping = {};
        }
    } else {
        logger.info('Membership mapping file does not exist. A new one will be created.');
    }

    membershipMapping[discordId] = {
        "membership_id": userInfo.membershipId,
        "platform_type": userInfo.platformType,
        "bungie_name": userInfo.bungieName,
        "registration_date": new Date(),
        "clan_id": "4900827"
    };

    try {
        fs.writeFileSync(membershipFilePath, JSON.stringify(membershipMapping, null, 2), 'utf8');
        logger.info(`Updated membership mapping file: ${JSON.stringify(membershipMapping, null, 2)}`);
    } catch (err) {
        logger.error(`Error writing to membership mapping file: ${err}`);
    }

    try {
        const updatedData = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info(`Verified membership mapping file content: ${updatedData}`);
    } catch (err) {
        logger.error(`Error reading membership mapping file after update: ${err}`);
    }
}

async function sendUserInfoToDiscordBot(discordId, userInfo) {
    logger.info(`User info ready to be sent to Discord bot: ${JSON.stringify(userInfo)}`);
}

app.get('/login', async (req, res) => {
    const state = generateRandomString(16);
    const user_id = req.query.user_id;
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
        logger.error(`Error saving session to DB: ${err}`);
        res.status(500).send('Internal Server Error');
    }
});

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
        const refreshToken = tokenData.refresh_token;
        const expiresIn = tokenData.expires_in;
        const tokenExpiry = DateTime.now().plus({ seconds: expiresIn }).toJSDate();

        const userInfo = await getBungieUserInfo(accessToken);
        logger.info('User Info Response:', JSON.stringify(userInfo));

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error('Incomplete user info response:', JSON.stringify(userInfo));
            throw new Error('Failed to obtain user information');
        }

        const bungieGlobalDisplayName = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayName;
        const bungieGlobalDisplayNameCode = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode.toString().padStart(4, '0');
        const bungieName = `${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode}`;

        let primaryMembership = userInfo.Response.destinyMemberships.find(
            membership => membership.membershipId === userInfo.Response.primaryMembershipId
        );

        if (!primaryMembership) {
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
                platform_type: platformType,
                token: generateRandomString(16),
                registration_date: new Date(),
                access_token: accessToken,
                refresh_token: refreshToken,
                token_expiry: tokenExpiry
            },
            { upsert: true, new: true }
        );

        await sendUserInfoToDiscordBot(discordId, { bungieName, platformType, membershipId });

        updateMembershipMapping(discordId, { bungieName, platformType, membershipId });

        await Session.deleteOne({ state });

        res.redirect(`/confirmation.html?token=${user.token}`);
    } catch (error) {
        logger.error(`Error during callback: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        res.status(500).send('Internal Server Error');
    }
});

app.get('/confirmation.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'confirmation.html'));
});

app.get('/api/bungie-name', async (req, res) => {
    const token = req.query.token;

    try {
        const user = await User.findOne({ token });
        if (!user) {
            return res.status(400).send({ error: 'Invalid token' });
        }

        res.send({ bungie_name: user.bungie_name });
    } catch (err) {
        logger.error(`Error fetching Bungie name: ${err}`);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

app.post('/api/comments', async (req, res) => {
    try {
        const { username, comment } = req.body;
        const newComment = new Comment({ username, comment });
        await newComment.save();
        res.status(201).send(newComment);
    } catch (error) {
        logger.error(`Error saving comment: ${error}`);
        res.status(500).send({ error: 'Error saving comment' });
    }
});

app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error(`Error fetching comments: ${error}`);
        res.status(500).send({ error: 'Error fetching comments' });
    }
});

app.delete('/api/comments/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        await Comment.findByIdAndDelete(id);
        res.status(200).send({ message: 'Comment deleted' });
    } catch (error) {
        logger.error(`Error deleting comment: ${error}`);
        res.status(500).send({ error: 'Error deleting comment' });
    }
});

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
        logger.info(`Token Response: ${JSON.stringify(response.data)}`);
        return response.data;
    } catch (error) {
        logger.error(`Error fetching Bungie token: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to fetch Bungie token');
    }
}

async function refreshBungieToken(refreshToken) {
    const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
    const payload = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.post(url, payload.toString(), { headers });
        logger.info(`Refresh Token Response: ${JSON.stringify(response.data)}`);
        return response.data;
    } catch (error) {
        logger.error(`Error refreshing Bungie token: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to refresh Bungie token');
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
        logger.info(`User Info Response: ${JSON.stringify(response.data)}`);
        return response.data;
    } catch (error) {
        logger.error(`Error fetching Bungie user info: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to fetch Bungie user info');
    }
}

async function getAccessTokenForUser(user) {
    const now = DateTime.now();
    const tokenExpiry = DateTime.fromJSDate(user.token_expiry);

    if (now >= tokenExpiry) {
        const newTokenData = await refreshBungieToken(user.refresh_token);
        user.access_token = newTokenData.access_token;
        user.refresh_token = newTokenData.refresh_token;
        user.token_expiry = DateTime.now().plus({ seconds: newTokenData.expires_in }).toJSDate();
        await user.save();
        logger.info(`Refreshed access token for user ${user.discord_id}`);
    }

    return user.access_token;
}

async function getPendingClanMembers(accessToken, groupId) {
    const url = `https://www.bungie.net/Platform/GroupV2/${groupId}/Members/Pending/`;
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.get(url, { headers });
        logger.info(`Pending Clan Members Response: ${JSON.stringify(response.data)}`);
        return response.data.Response.results;
    } catch (error) {
        logger.error(`Error fetching pending clan members: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to fetch pending clan members');
    }
}

app.get('/api/clan/pending', verifyToken, async (req, res) => {
    const userId = req.userId;

    try {
        const user = await User.findOne({ discord_id: userId });
        if (!user) {
            return res.status(400).send({ error: 'User not found' });
        }

        const accessToken = await getAccessTokenForUser(user);
        const pendingMembers = await getPendingClanMembers(accessToken, '5236471');

        await PendingMember.deleteMany();
        const pendingMemberDocs = pendingMembers.map(member => ({
            membershipId: member.destinyUserInfo.membershipId,
            displayName: member.destinyUserInfo.displayName,
            joinDate: new Date(member.joinDate)
        }));
        await PendingMember.insertMany(pendingMemberDocs);

        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error(`Error fetching pending clan members: ${err}`);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

app.get('/api/clan/pending/fromdb', verifyToken, async (req, res) => {
    try {
        const pendingMembers = await PendingMember.find();
        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error(`Error retrieving pending clan members from DB: ${err}`);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect(`https://${req.headers.host}${req.url}`);
        }
    }
    next();
});

app.get('/admin-dashboard-:random.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPasswordHash = process.env.ADMIN_PASSWORD;
    const salt = 'random_salt';

    if (username !== adminUsername) {
        logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
        return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    }

    const hashedInputPassword = hashPassword(password, salt);

    if (hashedInputPassword !== adminPasswordHash) {
        logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
        return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
        expiresIn: 86400
    });

    const dashboardURL = `/admin-dashboard-${generateRandomString()}.html`;

    req.session.dashboardURL = dashboardURL;
    logger.info(`Stored dashboardURL in session: ${req.session.dashboardURL}`);

    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 86400 * 1000
    });

    app.get(dashboardURL, verifyToken, (req, res) => {
        res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
    });

    req.session.save((err) => {
        if (err) {
            logger.error(`Error saving session: ${err}`);
            return res.status(500).json({ auth: false, message: 'Error saving session' });
        }
        res.status(200).json({ auth: true, redirect: dashboardURL });
    });
});

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy();
    res.redirect('/admin-login.html');
});

let currentVideoTitle = 'Loading...';
let currentVideoUrl = '';
let videoStartTimestamp = Date.now();
let isVideoPaused = false;
let isOffline = false;

let activeUsers = [];

io.on('connection', async (socket) => {
    const ip = socket.request.headers['x-forwarded-for'] || socket.request.connection.remoteAddress;
    logger.info(`New client connected: ${socket.id}, IP: ${ip}`);

    socket.emit('nowPlayingUpdate', {
        title: currentVideoTitle,
        videoUrl: currentVideoUrl,
        startTimestamp: videoStartTimestamp,
        currentTime: (Date.now() - videoStartTimestamp) / 1000,
        isOffline: isOffline,
        isPaused: isVideoPaused
    });

    socket.on('updateVideoTitle', (data) => {
        logger.info(`Received "updateVideoTitle" event from client ${socket.id}: ${JSON.stringify(data)}`);

        const { title, videoUrl, currentTime, isPaused, isOffline: offlineStatus } = data;

        logger.info(`Title: ${title}, Video URL: ${videoUrl}, Current Time: ${currentTime}, Is Paused: ${isPaused}, Is Offline: ${offlineStatus}`);

        const validCurrentTime = typeof currentTime === 'number' ? currentTime : 0;

        if (!offlineStatus) {
            if (typeof title !== 'string' || title.trim() === '' || typeof videoUrl !== 'string' || videoUrl.trim() === '' ||
                typeof validCurrentTime !== 'number' || typeof isPaused !== 'boolean' || typeof offlineStatus !== 'boolean') {

                logger.warn(`Invalid data received from client ${socket.id}: ${JSON.stringify(data)}`);
                return;
            }

            logger.info(`Handling online state: Title="${title}", URL="${videoUrl}", CurrentTime=${validCurrentTime}`);
        } else {
            if (title === 'Offline' && videoUrl === '') {
                logger.info(`Received valid "offline" state from client ${socket.id}`);
            } else {
                logger.warn(`Invalid offline data received from client ${socket.id}: ${JSON.stringify(data)}`);
                return;
            }
        }

        currentVideoTitle = title;
        currentVideoUrl = videoUrl;
        videoStartTimestamp = Date.now() - (validCurrentTime * 1000);
        isVideoPaused = isPaused;
        isOffline = offlineStatus;

        logger.info(`Updated server state: Title="${currentVideoTitle}", URL="${currentVideoUrl}", StartTimestamp=${videoStartTimestamp}, isPaused=${isVideoPaused}, isOffline=${isOffline}`);

        io.emit('nowPlayingUpdate', {
            title: currentVideoTitle,
            videoUrl: currentVideoUrl,
            startTimestamp: videoStartTimestamp,
            currentTime: validCurrentTime,
            isOffline: isOffline,
            isPaused: isVideoPaused
        });

        logger.info(`Emitted "nowPlayingUpdate" to all clients: Title="${currentVideoTitle}", URL="${currentVideoUrl}", isPaused=${isVideoPaused}, isOffline=${isOffline}`);
    });

    const locationData = await fetchLocationData(ip);
    logger.info(`Location data fetched: ${JSON.stringify(locationData)}`);

    const user = {
        id: socket.id,
        ip: locationData.ip,
        city: locationData.city,
        region: locationData.region,
        country: locationData.country
    };

    activeUsers.push(user);
    io.emit('activeUsersUpdate', { users: activeUsers });

    socket.on('disconnect', () => {
        logger.info(`Client disconnected: ${socket.id}`);
        activeUsers = activeUsers.filter(u => u.id !== socket.id);
        io.emit('activeUsersUpdate', { users: activeUsers });
    });
});

app.post('/api/update', (req, res) => {
    const data = req.body;
    io.emit('updateData', data);
    res.status(200).send({ message: 'Data sent to clients' });
});

app.get('/api/videos/public', async (req, res) => {
    try {
        res.json([]);
    } catch (err) {
        logger.error(`Error retrieving video metadata: ${err}`);
        res.status(500).send({ error: 'Error retrieving video metadata' });
    }
});

app.post('/api/videos',
    verifyToken,
    [
        body('url').isURL().withMessage('Invalid URL format'),
        body('title').isString().notEmpty().withMessage('Title is required'),
        body('description').isString().optional(),
        body('category').isString().notEmpty().withMessage('Category is required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const sanitizedUrl = sanitizeHtml(req.body.url.replace('youtu.be', 'youtube.com/embed'));
        const sanitizedTitle = sanitizeHtml(req.body.title);
        const sanitizedDescription = req.body.description ? sanitizeHtml(req.body.description) : '';
        const sanitizedCategory = sanitizeHtml(req.body.category);

        const videoMetadata = {
            url: sanitizedUrl,
            title: sanitizedTitle,
            description: sanitizedDescription,
            category: sanitizedCategory,
            uploadedAt: new Date()
        };

        try {
            res.status(201).json({ message: 'Video added successfully', video: videoMetadata });
        } catch (err) {
            logger.error(`Error saving video metadata: ${err.message}`);
            res.status(500).json({ error: 'Error saving video metadata' });
        }
    }
);

const IPINFO_API_KEY = process.env.IPINFO_API_KEY;

async function fetchLocationData(ip) {
    try {
        const ipList = ip.split(',');
        const validIp = ipList[0].trim();

        const response = await axios.get(`https://ipinfo.io/${validIp}?token=${IPINFO_API_KEY}`);
        const { ip: userIP, city, region, country } = response.data;

        return {
            ip: userIP,
            city: city || 'Unknown',
            region: region || 'Unknown',
            country: country || 'Unknown'
        };
    } catch (error) {
        logger.error(`Error fetching location data for IP ${ip}:`, error);
        return {
            ip,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown'
        };
    }
}

async function attachLocationData(req, res, next) {
    const clientIp = getClientIp(req);

    if (clientIp) {
        logger.info(`Client IP detected: ${clientIp}`);

        const locationData = await fetchLocationData(clientIp);
        req.location = locationData;
    } else {
        logger.info('No valid public IP detected.');
    }

    next();
}

function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
        return ip.replace('::ffff:', '');
    }
    return ip;
}

app.get('/admin-dashboard', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/api/check-youtube', async (req, res) => {
    try {
        const youtubeApiStatus = true;
        res.json({
            available: youtubeApiStatus,
            status: youtubeApiStatus ? 'YouTube API is working' : 'YouTube API is unavailable'
        });
    } catch (error) {
        logger.error(`Error checking YouTube API: ${error}`);
        res.status(500).json({
            available: false,
            status: 'Error checking YouTube API'
        });
    }
});

app.get('/api/check-bungie', async (req, res) => {
    const bungieApiKey = process.env.X_API_KEY;
    const url = 'https://www.bungie.net/Platform/Destiny2/Manifest/';

    try {
        const response = await axios.get(url, {
            headers: { 'X-API-Key': bungieApiKey }
        });
        if (response.status === 200) {
            return res.json({ status: 'Bungie API is working', available: true });
        }
    } catch (error) {
        logger.error(`Error checking Bungie API: ${error}`);
        return res.json({ status: 'Bungie API is unavailable', available: false });
    }
});

app.get('/api/weather', async (req, res) => {
    const city = req.query.city || 'Leeds';
    const units = 'metric';
    const apiKey = process.env.OPENWEATHER_API_KEY;

    if (!apiKey) {
        logger.error('OPENWEATHER_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            let errorMsg = 'Failed to fetch weather data';
            try {
                const errorData = await response.json();
                errorMsg = errorData.message || errorMsg;
            } catch (e) {
                logger.error('Error parsing error response:', e);
            }
            return res.status(response.status).json({ error: errorMsg });
        }
        const data = await response.json();
        res.json(data);
    } catch (error) {
        logger.error(`Error fetching weather data for city ${city}:`, error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

const processedIPs = new Set();

function getValidIpAddress(req) {
    let ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (ipAddress.includes(',')) {
        ipAddress = ipAddress.split(',').map(ip => ip.trim())[0];
    }

    if (ipAddress.startsWith('::ffff:')) {
        ipAddress = ipAddress.replace('::ffff:', '');
    }

    if (processedIPs.has(ipAddress)) {
        logger.info(`Duplicate IP detected: ${ipAddress}, skipping processing.`);
        return null;
    }

    processedIPs.add(ipAddress);
    return ipAddress;
}

app.get('/api/location', async (req, res) => {
    const clientIp = getValidIpAddress(req);

    if (!clientIp) {
        return res.status(400).send('Duplicate IP detected, location not processed.');
    }

    try {
        const locationData = await fetchLocationData(clientIp);
        res.json(locationData);
    } catch (error) {
        logger.error(`Error fetching location for IP ${clientIp}:`, error);
        res.status(500).send('Error fetching location data');
    }
});

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = forwarded ? forwarded.split(',')[0] : req.connection.remoteAddress;

    if (ip.includes("::ffff:")) {
        ip = ip.split("::ffff:")[1];
    }

    return ip;
}

async function fetchUserLocation(ip) {
    try {
        const response = await axios.get(`https://ipinfo.io/${ip}/geo?token=${process.env.IPINFO_API_KEY}`);
        const { city, region, country } = response.data;
        return { ip, city, region, country };
    } catch (error) {
        logger.error(`Error fetching location data for IP ${ip}:`, error);
        return { ip, city: 'Unknown', region: 'Unknown', country: 'Unknown' };
    }
}

async function getActiveUsersWithLocations() {
    const userPromises = activeUsers.map(user => fetchUserLocation(user.ip));
    return await Promise.all(userPromises);
}

server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
