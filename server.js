// server.js

'use strict';

// ----------------------
// Import Dependencies
// ----------------------
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
const dialogflow = require('@google-cloud/dialogflow');
const uuid = require('uuid');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// ----------------------
// Load Environment Variables
// ----------------------
dotenv.config();

// ----------------------
// Initialize Express App and Server
// ----------------------
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*", // Adjust in production for specific origins
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    }
});

const PORT = process.env.PORT || 3000;

// ----------------------
// Configure Logging with Winston
// ----------------------
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

// ----------------------
// Connect to MongoDB
// ----------------------
const mongoUrl = process.env.MONGO_URL;

mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error(`Error connecting to MongoDB: ${err}`);
    process.exit(1); // Exit if unable to connect
});

// ----------------------
// Configure Session Store
// ----------------------
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
    logger.error(`Session store error: ${error}`);
});

// ----------------------
// Configure Express Middlewares
// ----------------------

// Body Parser Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Cookie Parser Middleware
app.use(cookieParser());

// CORS Middleware
app.use(cors());

// Helmet for Security Headers
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                // Remove 'unsafe-inline' in production and use nonces or hashes
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com",
                "https://www.youtube.com",
                "https://unpkg.com",
                "https://cdn.jsdelivr.net",
                "https://cdn.skypack.dev"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com"
            ],
            imgSrc: [
                "'self'",
                "'blob:'",
                "data:",
                "https://i.ytimg.com",
                "https://img.youtube.com",
                "https://openweathermap.org",
                "https://i.postimg.cc",
                "https://threejs.org"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com",
                "https://cdnjs.cloudflare.com"
            ],
            connectSrc: [
                "'self'",
                "'blob:'",
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


app.set('trust proxy', 1);

// Serve Static Files
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 0,
    lastModified: false
}));


app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict', // Prevent CSRF
        maxAge: 86400 * 1000 // 24 hours
    }
}));


// ----------------------
// Rate Limiting Middleware
// ----------------------
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per window
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

// ----------------------
// Define Mongoose Schemas and Models
// ----------------------
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
    created_at: { type: Date, default: Date.now, expires: 86400 }, // Expires after 1 day
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

// ----------------------
// Helper Functions
// ----------------------

// Generate Random String (for state parameter in OAuth)
function generateRandomString(size = 16) {
    return crypto.randomBytes(size).toString('hex');
}

// Convert ISO 8601 Duration to Seconds
function convertISO8601ToSeconds(isoDuration) {
    const matches = isoDuration.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
    const hours = parseInt(matches[1] || 0, 10);
    const minutes = parseInt(matches[2] || 0, 10);
    const seconds = parseInt(matches[3] || 0, 10);
    return hours * 3600 + minutes * 60 + seconds;
}

// ----------------------
// JWT Verification Middleware
// ----------------------
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

// ----------------------
// OAuth Helper Functions
// ----------------------
async function getBungieToken(code) {
    const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
    const payload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI || 'https://mikumiku.dev/callback'
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
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET
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

// ----------------------
// OAuth Configuration
// ----------------------
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://mikumiku.dev/callback';

// Membership Mapping File Path
const membershipFilePath = path.join(__dirname, 'membership_mapping.json');

// Update Membership Mapping Function
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

// Send User Info to Discord Bot (Implementation Needed)
async function sendUserInfoToDiscordBot(discordId, userInfo) {
    logger.info(`User info ready to be sent to Discord bot: ${JSON.stringify(userInfo)}`);
    // Implement the logic to send user info to your Discord bot here
}

// ----------------------
// Define OAuth Routes
// ----------------------

// Login Route
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
        const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
        res.redirect(authorizeUrl);
    } catch (err) {
        logger.error(`Error saving session to DB: ${err}`);
        res.status(500).send('Internal Server Error');
    }
});

// Callback Route
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
        logger.info(`User Info Response: ${JSON.stringify(userInfo)}`);

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error(`Incomplete user info response: ${JSON.stringify(userInfo)}`);
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

// Confirmation Route
app.get('/confirmation.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'confirmation.html'));
});

// Get Bungie Name Route
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

// ----------------------
// Admin Login Route
// ----------------------
app.post('/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            logger.warn(`Missing username or password in login attempt.`);
            return res.status(400).json({ auth: false, message: 'Username and password are required.' });
        }

        const adminUsername = process.env.ADMIN_USERNAME;
        const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

        if (username !== adminUsername) {
            logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
            return res.status(401).json({ auth: false, message: 'Invalid username or password.' });
        }

        // Validate password using bcrypt
        const isPasswordValid = await bcrypt.compare(password, adminPasswordHash);

        if (!isPasswordValid) {
            logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
            return res.status(401).json({ auth: false, message: 'Invalid username or password.' });
        }

        // Generate a JWT token for the admin user
        const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
            expiresIn: 86400 // 24 hours
        });

        // Set the JWT as a cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 86400 * 1000 // 24 hours
        });

        // Check if req.session exists before calling save
        if (req.session) {
            req.session.save((err) => {
                if (err) {
                    logger.error(`Error saving session: ${err}`);
                    return res.status(500).json({ auth: false, message: 'Error saving session.' });
                }
                res.status(200).json({ auth: true, redirect: '/admin-dashboard.html' });
            });
        } else {
            logger.error(`Session object is undefined during login.`);
            return res.status(500).json({ auth: false, message: 'Internal Server Error: Session not found.' });
        }
    } catch (error) {
        logger.error(`Unexpected error during login: ${error}`);
        res.status(500).json({ auth: false, message: 'Internal Server Error.' });
    }
});

// ----------------------
// Logout Route
// ----------------------
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy((err) => {
        if (err) {
            logger.error(`Error destroying session: ${err}`);
            return res.status(500).json({ message: 'Error logging out' });
        }
        res.redirect('/admin-login.html');
    });
});

// ----------------------
// Comment Routes
// ----------------------

// Create a New Comment
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

// Get Approved Comments
app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error(`Error fetching comments: ${error}`);
        res.status(500).send({ error: 'Error fetching comments' });
    }
});

// Delete a Comment
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

// ----------------------
// OAuth Routes Continued
// ----------------------

// Admin Dashboard Route (Protected)
app.get('/admin-dashboard.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// ----------------------
// Additional Routes
// ----------------------

// Check YouTube API Status
app.get('/api/check-youtube', async (req, res) => {
    try {
        const youtubeApiStatus = true; // Implement actual check if necessary
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

// Check Bungie API Status
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

// Weather Route
app.get('/api/weather', async (req, res) => {
    const city = req.query.city || 'Leeds';
    const units = 'metric'; // or 'imperial' for Fahrenheit
    const apiKey = process.env.OPENWEATHER_API_KEY;

    if (!apiKey) {
        logger.error('OPENWEATHER_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            // Attempt to parse error message from response
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

// ----------------------
// Active Users Tracking
// ----------------------

// Set to store unique IPs
const processedIPs = new Set();

// Function to get Valid IP Address
function getValidIpAddress(req) {
    let ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (ipAddress.includes(',')) {
        // Extract first valid IP from the list
        ipAddress = ipAddress.split(',').map(ip => ip.trim())[0];
    }

    // Normalize IPv6-mapped IPv4 addresses
    if (ipAddress.startsWith('::ffff:')) {
        ipAddress = ipAddress.replace('::ffff:', '');
    }

    // Check for duplicates
    if (processedIPs.has(ipAddress)) {
        logger.warn(`Duplicate IP detected: ${ipAddress}, skipping processing.`);
        return null; // Indicate duplicate IP
    }

    // Add to processed IPs
    processedIPs.add(ipAddress);
    return ipAddress;
}

// Function to Fetch Location Data from IPInfo API
async function fetchLocationData(ip) {
    try {
        const response = await axios.get(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_API_KEY}`);
        const { ip: userIP, city, region, country } = response.data;

        return {
            ip: userIP,
            city: city || 'Unknown',
            region: region || 'Unknown',
            country: country || 'Unknown'
        };
    } catch (error) {
        logger.error(`Error fetching location data for IP ${ip}: ${error}`);
        return {
            ip,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown'
        };
    }
}

// Function to Attach Location Data Middleware (Unused in Current Routes)
async function attachLocationData(req, res, next) {
    const clientIp = getClientIp(req);

    if (clientIp) {
        logger.info(`Client IP detected: ${clientIp}`);

        const locationData = await fetchLocationData(clientIp);
        req.location = locationData; // Attach location data to the request object
    } else {
        logger.info('No valid public IP detected.');
    }

    next();
}

// Normalize IP Address Function
function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
        return ip.replace('::ffff:', '');
    }
    return ip;
}

// ----------------------
// WebSocket (Socket.IO) Configuration
// ----------------------
let activeUsers = []; // Initialize an empty array to track active users

// Heartbeat Configuration
const HEARTBEAT_TIMEOUT = 60000; // 60 seconds
const BROWSING_UPDATE_INTERVAL = 30000; // 30 seconds

let currentVideo = null;
let currentBrowsing = null;
const videoHeartbeat = {};
let lastBrowsingUpdateTime = 0;

// Socket.IO Connection Handling
io.on('connection', async (socket) => {
    logger.info(`[Socket.IO] New client connected: ${socket.id}`);

    // Fetch client IP and location data
    const ip = socket.request.headers['x-forwarded-for'] || socket.request.connection.remoteAddress;
    const locationData = await fetchLocationData(ip);
    logger.info(`[Socket.IO] Location data fetched: ${JSON.stringify(locationData)}`);

    // Add the user with location data to active users list
    const user = {
        id: socket.id,
        ip: locationData.ip,
        city: locationData.city,
        region: locationData.region,
        country: locationData.country
    };

    activeUsers.push(user);
    io.emit('activeUsersUpdate', { users: activeUsers });

    // Emit current presence state to the newly connected client
    if (currentVideo) {
        socket.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
    } else if (currentBrowsing) {
        socket.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });
    } else {
        socket.emit('presenceUpdate', { presenceType: 'offline' });
    }

    // Update Browsing Presence
    socket.on('updateBrowsingPresence', (data) => {
        const now = Date.now();

        // Only update if no video is playing or after a certain interval
        if (data.presenceType === 'browsing' && (now - lastBrowsingUpdateTime > BROWSING_UPDATE_INTERVAL)) {
            logger.info(`[Socket.IO] Browsing presence detected.`);

            // Clear current video presence if any
            if (currentVideo) {
                logger.info(`[Socket.IO] Clearing current video presence to switch to browsing.`);
                currentVideo = null;
            }

            // Set current browsing presence
            currentBrowsing = {
                title: data.title || 'YouTube',
                description: data.description || 'Browsing videos',
                thumbnail: 'https://i.postimg.cc/GpgNPv0R/custom-browsing-thumbnail.png',
                timeElapsed: data.timeElapsed || 0,
                presenceType: 'browsing'
            };

            // Emit browsing presence to all clients
            io.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });

            // Update the last browsing update time
            lastBrowsingUpdateTime = now;
        }
    });

    // Update Video Progress or Mark New Video Presence
    socket.on('updateVideoProgress', (data) => {
        logger.info(`[Socket.IO] Video update received: ${JSON.stringify(data)}`);
    
        const { videoId, title, description, channelTitle, viewCount, likeCount, publishedAt, category, thumbnail, currentTime, duration, isPaused } = data;

        // Check if the video is already being tracked
        if (currentVideo && currentVideo.videoId === videoId) {
            // Update existing video details
            currentVideo.currentTime = currentTime;
            currentVideo.duration = duration;
            currentVideo.isPaused = isPaused;

            // Update additional info
            currentVideo.title = title;
            currentVideo.description = description;
            currentVideo.channelTitle = channelTitle;
            currentVideo.viewCount = viewCount;
            currentVideo.likeCount = likeCount;
            currentVideo.publishedAt = publishedAt;
            currentVideo.category = category;
            currentVideo.thumbnail = thumbnail;

            logger.info(`[Socket.IO] Updated video information for ID: ${videoId} - Title: ${title}, Channel: ${channelTitle}`);
        } else {
            // New video detected
            logger.info(`[Socket.IO] New video presence detected: ${videoId}`);
            currentVideo = {
                videoId,
                title,
                description,
                channelTitle,
                viewCount,
                likeCount,
                publishedAt,
                category,
                thumbnail,
                currentTime,
                duration,
                isPaused,
                presenceType: 'video'
            };

            // Clear browsing presence
            currentBrowsing = null;

            logger.info(`[Socket.IO] Browsing presence cleared due to new video presence.`);
        }

        // Emit updated video presence to all clients
        io.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
    });

    // Handle Heartbeat Signals
    socket.on('heartbeat', (data, callback) => {
        const { videoId } = data;
        if (videoId && currentVideo && currentVideo.videoId === videoId) {
            videoHeartbeat[videoId] = Date.now();
            logger.info(`[Socket.IO] Heartbeat received for video ID: ${videoId}`);
            if (callback) callback({ status: "ok" });
        } else {
            logger.warn(`[Socket.IO] Received heartbeat for unknown or inactive video ID: ${videoId}`);
            if (callback) callback({ status: "error", message: "Unknown video ID" });
        }
    });

    // Handle Client Disconnection
    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Client disconnected: ${socket.id}`);
        // Remove user from active list
        activeUsers = activeUsers.filter(u => u.id !== socket.id);
        io.emit('activeUsersUpdate', { users: activeUsers });
    });
});

// Handle Video Heartbeat Expiration
setInterval(() => {
    const now = Date.now();
    for (const [videoId, lastHeartbeat] of Object.entries(videoHeartbeat)) {
        if (now - lastHeartbeat > HEARTBEAT_TIMEOUT) {
            logger.warn(`[Heartbeat] No heartbeat received for video ID ${videoId} within timeout. Marking as offline.`);
            if (currentVideo && currentVideo.videoId === videoId) {
                currentVideo = null;
                currentBrowsing = null; // Clear browsing to fully reset state
                io.emit('presenceUpdate', { presenceType: 'offline' });
                logger.info(`[Heartbeat] Emitted "presenceUpdate" with offline status to all clients.`);
            }
            delete videoHeartbeat[videoId];
        }
    }
}, HEARTBEAT_TIMEOUT / 2);

// ----------------------
// Real-time Data Endpoint
// ----------------------
app.post('/api/update', (req, res) => {
    const data = req.body;
    io.emit('updateData', data);
    res.status(200).send({ message: 'Data sent to clients' });
});

// ----------------------
// Video Routes
// ----------------------

// Get Public Videos (Implementation Needed)
app.get('/api/videos/public', async (req, res) => {
    try {
        // Implement logic to retrieve public videos
        res.json([]);
    } catch (err) {
        logger.error(`Error retrieving video metadata: ${err}`);
        res.status(500).send({ error: 'Error retrieving video metadata' });
    }
});

// Add a New Video (Protected)
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

        const sanitizedUrl = req.body.url.replace('youtu.be', 'youtube.com/embed');
        const sanitizedTitle = req.body.title;
        const sanitizedDescription = req.body.description ? req.body.description : '';
        const sanitizedCategory = req.body.category;

        const videoMetadata = {
            url: sanitizedUrl,
            title: sanitizedTitle,
            description: sanitizedDescription,
            category: sanitizedCategory,
            uploadedAt: new Date()
        };

        try {
            // Implement logic to save video metadata to the database
            res.status(201).json({ message: 'Video added successfully', video: videoMetadata });
        } catch (err) {
            logger.error(`Error saving video metadata: ${err.message}`);
            res.status(500).json({ error: 'Error saving video metadata' });
        }
    }
);

// ----------------------
// Weather API Route
// ----------------------
app.get('/api/weather', async (req, res) => {
    const city = req.query.city || 'Leeds';
    const units = 'metric'; // or 'imperial' for Fahrenheit
    const apiKey = process.env.OPENWEATHER_API_KEY;

    if (!apiKey) {
        logger.error('OPENWEATHER_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            // Attempt to parse error message from response
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

// ----------------------
// Web Search Functionality with Dialogflow Integration
// ----------------------

// Initialize Dialogflow Session Client
let credentials;

try {
    credentials = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
    logger.info("Credentials loaded successfully.");
} catch (error) {
    logger.error("Error parsing credentials JSON from environment variable:", error);
    process.exit(1);
}

let sessionClient;

try {
    sessionClient = new dialogflow.SessionsClient({
        credentials: {
            client_email: credentials.client_email,
            private_key: credentials.private_key,
        },
    });
    logger.info("Dialogflow session client initialized successfully.");
} catch (error) {
    logger.error("Error initializing Dialogflow session client:", error);
    process.exit(1);
}

const projectId = 'haru-ai-sxjr'; // Ensure this matches your Dialogflow project ID
logger.info(`Using project ID: ${projectId}`);

// Web Search Function using Google Custom Search API
async function getWebSearchResults(query) {
    const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
    const GOOGLE_CSE_ID = process.env.GOOGLE_CSE_ID;

    if (!GOOGLE_API_KEY || !GOOGLE_CSE_ID) {
        logger.error("Missing Google API Key or CSE ID.");
        return 'Configuration error: Missing Google API Key or CSE ID.';
    }

    const SEARCH_ENDPOINT = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(query)}&key=${GOOGLE_API_KEY}&cx=${GOOGLE_CSE_ID}`;

    try {
        logger.info(`Fetching web search results for query: "${query}"`);
        const response = await fetch(SEARCH_ENDPOINT);

        if (!response.ok) {
            logger.error(`Error fetching web search results: ${response.status} - ${response.statusText}`);
            return `Error: Received status code ${response.status}. Please check the request or try again later.`;
        }

        const data = await response.json();
        logger.info("Received web search data.");

        if (data.items && data.items.length > 0) {
            const topResults = data.items.slice(0, 3).map((item, index) => {
                return `<b>${index + 1}. <a href="${item.link}" target="_blank">${item.title}</a></b><br>${item.snippet}`;
            }).join("<br><br>");

            return `Here are the top results I found for "<b>${query}</b>":<br><br>${topResults}`;
        } else {
            return 'Sorry, I couldn’t find anything relevant.';
        }
    } catch (error) {
        logger.error('Error fetching web search results:', error);
        return 'Sorry, something went wrong while searching the web.';
    }
}

// Handle Incoming Dialogflow Requests
app.post('/api/dialogflow', async (req, res) => {
    const userMessage = req.body.message;
    logger.info(`Received user message: ${userMessage}`);

    if (!userMessage) {
        logger.error("No user message provided in request.");
        return res.status(400).json({ response: 'No message provided.' });
    }

    const sessionId = uuid.v4();
    const sessionPath = sessionClient.projectAgentSessionPath(projectId, sessionId);
    logger.info(`Generated session path: ${sessionPath}`);

    const request = {
        session: sessionPath,
        queryInput: {
            text: {
                text: userMessage,
                languageCode: 'en-US',
            },
        },
    };

    try {
        logger.info("Sending request to Dialogflow...");
        const responses = await sessionClient.detectIntent(request);
        logger.info("Received response from Dialogflow.");

        const result = responses[0].queryResult;
        logger.info(`Query Result: ${JSON.stringify(result, null, 2)}`);

        if (result && result.fulfillmentText) {
            logger.info(`Sending fulfillment text back to client: ${result.fulfillmentText}`);
            // Send the interim response back while search is being performed
            res.json({ response: result.fulfillmentText });

            // If the action is web.search, initiate the search
            if (result.action === 'web.search') {
                logger.info("Handling web search action...");
                const parameters = result.parameters.fields;

                if (parameters && parameters.q && parameters.q.stringValue) {
                    const searchQuery = parameters.q.stringValue;
                    logger.info(`Performing web search for query: "${searchQuery}"`);

                    // Perform web search using Google Custom Search API
                    const webSearchResponse = await getWebSearchResults(searchQuery);
                    logger.info("Received web search data.");

                    // Notify the client via WebSocket with the search results
                    io.emit('webSearchResult', { userMessage, response: webSearchResponse });
                } else {
                    logger.error("Missing search query parameter.");
                }
            }
        } else {
            logger.warn("Dialogflow response did not contain fulfillment text or actionable intent.");
            res.json({ response: 'Sorry, I couldn’t understand that.' });
        }
    } catch (error) {
        logger.error('Dialogflow API error:', error);
        res.status(500).json({ response: 'Sorry, something went wrong.' });
    }
});

// ----------------------
// Additional Utility Functions
// ----------------------

// Function to Get Client IP (Utility)
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = forwarded ? forwarded.split(',')[0].trim() : req.connection.remoteAddress;

    // Normalize IPv6-mapped IPv4 addresses
    if (ip.includes("::ffff:")) {
        ip = ip.split("::ffff:")[1];
    }

    return ip;
}

// ----------------------
// Membership Mapping Functions
// ----------------------

// Read, Update, and Write Membership Mapping
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

// ----------------------
// Import and Use External Routes (If Any)
// ----------------------
// const authRoutes = require('./routes/auth');
// app.use('/auth', authRoutes);

// ----------------------
// Start the Server
// ----------------------
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
