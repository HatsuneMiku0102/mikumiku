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
                "https://threejs.org",
                "https://www.youtube.com"
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


app.set('trust proxy', true);

// Serve Static Files
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 0,
    lastModified: false
}));


const adminSessionStore = MongoStore.create({
    mongoUrl: process.env.MONGO_URL,
    collectionName: 'admin_sessions', // Separate collection for admin sessions
    ttl: 14 * 24 * 60 * 60 // 14 days
});

// Then, use it in the admin panel session
app.use(session({
    name: 'admin_session_cookie', // Different cookie name for admin
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    store: adminSessionStore, // Use the defined admin session store
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set this according to your environment
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000 // 1 hour
    }
}));


const geoDataSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    city: { type: String, required: true },
    region: { type: String, required: true },
    country: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});


const GeoData = mongoose.model('GeoData', geoDataSchema);
module.exports = GeoData;

async function getGeoLocation(ip) {
    try {
        const response = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_API_KEY}`);
        const locationData = response.data;

        // Save the location data to the GeoData collection
        const geoEntry = new GeoData({
            ip: ip,
            city: locationData.city,
            region: locationData.region,
            country: locationData.country
        });

        await geoEntry.save();
        return locationData;
    } catch (error) {
        console.error('Error fetching geolocation from IPinfo:', error);
        return {
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown'
        };
    }
}


// ----------------------
// Rate Limiting Middleware
// ----------------------
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 10 login requests per window
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

// JWT Verification Middleware
function verifyToken(req, res, next) {
    const token = req.cookies.token; // Read the JWT from the cookie

    if (!token) {
        logger.warn('Token not found. Redirecting to login page.');
        return res.redirect('/admin-login.html');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            logger.error(`Token verification failed: ${err.message}. Redirecting to login.`);
            return res.redirect('/admin-login.html');
        }
        req.userId = decoded.id; // Add the user ID to the request object
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

// ----------------------
// Membership Mapping Functions
// ----------------------

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
// Geolocation Functions
// ----------------------

// Ensure IPINFO_API_KEY is defined
const IPINFO_API_KEY = process.env.IPINFO_API_KEY;

if (!IPINFO_API_KEY) {
    logger.error("IPINFO_API_KEY environment variable is not set.");
    process.exit(1); // Exit if the key isn't available
}

// Get Client IP Function
const getClientIp = (req) => {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        return forwardedFor.split(',')[0].trim();
    }
    return req.connection.remoteAddress;
};

// Get Geolocation Data
async function getAccurateGeoLocation(ip) {
    try {
        // IPinfo as the primary source
        const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_API_KEY}`);
        const ipInfoData = ipInfoResponse.data;

        // Optionally, you can add MaxMind or another API for more robust location or VPN detection
        const maxMindApiResponse = await axios.get(`https://geoip.maxmind.com/geoip/v2.1/city/${ip}?apikey=${process.env.MAXMIND_API_KEY}`);
        const maxMindData = maxMindApiResponse.data;

        // Merge data or cross-check between services if needed
        return {
            city: ipInfoData.city || maxMindData.city.names.en || 'Unknown',
            region: ipInfoData.region || maxMindData.subdivisions[0].names.en || 'Unknown',
            country: ipInfoData.country || maxMindData.country.names.en || 'Unknown',
            ip: ip
        };
    } catch (error) {
        console.error('Error fetching location from IP services:', error);
        return { city: 'Unknown', region: 'Unknown', country: 'Unknown' };
    }
}

// ----------------------
// OAuth Routes
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

        const adminUsername = process.env.ADMIN_USERNAME;
        const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH; // Bcrypt hashed password

        if (username !== adminUsername) {
            logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
            return res.status(401).json({ auth: false, message: 'Invalid username or password' });
        }

        // Use bcrypt to compare passwords
        const isPasswordValid = await bcrypt.compare(password, adminPasswordHash);

        if (!isPasswordValid) {
            logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
            return res.status(401).json({ auth: false, message: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
            expiresIn: 86400 // 24 hours
        });

        res.cookie('token', token, {
            httpOnly: false, // Make sure it's false so that JavaScript can access it
            secure: process.env.NODE_ENV === 'production', // True for production environment over HTTPS
            sameSite: 'Lax', // Set this to 'Lax' to prevent any issues with CSRF while keeping security reasonable
            path: '/', // Set the path to the root to allow JavaScript access throughout the site
            maxAge: 86400 * 1000 // Set an appropriate expiration time (e.g., 24 hours)
        });

        req.session.save((err) => {
            if (err) {
                logger.error(`Error saving session: ${err}`);
                return res.status(500).json({ auth: false, message: 'Error saving session' });
            }
            res.status(200).json({ auth: true, redirect: '/admin-dashboard.html' });
        });
    } catch (error) {
        logger.error(`Unexpected error during login: ${error}`);
        res.status(500).json({ auth: false, message: 'Internal Server Error' });
    }
});

// ----------------------
// Logout Route
// ----------------------
app.post('/logout', (req, res) => {
    // Destroy the session from MongoDB
    req.session.destroy((err) => {
        if (err) {
            logger.error(`Error destroying session: ${err}`);
            return res.status(500).json({ message: 'Error logging out' });
        }
        
        // Clear the admin session cookie from the browser
        res.clearCookie('admin_session_cookie', {
            path: '/', 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'strict'
        });

        // Optionally redirect to login page after logout
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
// Admin Dashboard Route (Protected)
// ----------------------
app.get('/admin-dashboard.html', verifyToken, (req, res) => {
    logger.info(`Access granted to user with ID: ${req.userId}`);
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
// WebSocket (Socket.IO) Configuration
// ----------------------

// server.js


// background.js

// server.js

const HEARTBEAT_TIMEOUT = 60000; // 60 seconds




// State management
const tabPresence = new Map(); // Map<tabId, presenceData>
const videoHeartbeat = {}; // Object to track heartbeats per videoId
const activeUsers = new Map(); // Map<ip, { id: socket.id, ip }>


// Function to validate video presence data
function isValidVideoPresence(data) {
    // Ensure all required fields are present and valid
    const requiredFields = ['videoId', 'title', 'description', 'channelTitle', 'viewCount', 'likeCount', 'publishedAt', 'category', 'thumbnail', 'currentTime', 'duration', 'isPaused'];
    for (let field of requiredFields) {
        if (!(field in data)) {
            logger.warn(`[Validation] Missing field: ${field}`);
            return false;
        }
    }

    // Additional validation can be added here (e.g., data types, value ranges)
    if (typeof data.videoId !== 'string' || data.videoId.trim() === '') {
        logger.warn(`[Validation] Invalid videoId: ${data.videoId}`);
        return false;
    }

    if (typeof data.title !== 'string' || data.title.trim() === '') {
        logger.warn(`[Validation] Invalid title: ${data.title}`);
        return false;
    }

    // Add more validations as needed

    return true;
}

// Event: New client connection
io.on('connection', async (socket) => {
    logger.log(`[Socket.IO] New client connected: ${socket.id}`);

    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || socket.handshake.address;
    logger.log(`New connection from IP: ${ip}`);

    // Emit initial location update
    try {
        let location = await GeoData.findOne({ ip });
        if (!location) {
            location = await getGeoLocation(ip);
            // Save to GeoData if not already present
            await GeoData.updateOne(
                { ip },
                { city: location.city, region: location.region, country: location.country, ip },
                { upsert: true }
            );
        }

        // Emit location to the connected client
        socket.emit('locationUpdate', {
            ip,
            city: location.city || 'Unknown',
            region: location.region || 'Unknown',
            country: location.country || 'Unknown'
        });
    } catch (err) {
        logger.error('Error fetching location:', err);
        socket.emit('locationUpdate', {
            ip,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown'
        });
    }

    // Check if the IP is already in the activeUsers map
    if (!activeUsers.has(ip)) {
        activeUsers.set(ip, { id: socket.id, ip });
        io.emit('activeUsersUpdate', { users: Array.from(activeUsers.values()) });
    } else {
        logger.log(`IP ${ip} is already connected.`);
    }

    // Handle Presence Updates (Video, Browsing, Offline)
    socket.on('presenceUpdate', (data) => {
        logger.log(`[Socket.IO] Received presenceUpdate from ${socket.id}:`, data);

        const { tabId, presenceType, ...rest } = data;

        if (!tabId) {
            logger.warn(`[Socket.IO] Missing tabId in presenceUpdate from ${socket.id}. Ignoring.`);
            return;
        }

        if (presenceType === 'browsing') {
            // Update browsing presence for the tab
            tabPresence.set(tabId, {
                presenceType: 'browsing',
                title: rest.title || 'YouTube',
                description: rest.description || 'Browsing videos',
                thumbnail: rest.thumbnail || 'https://www.youtube.com/img/desktop/yt_1200.png',
                timeElapsed: rest.timeElapsed || 0
            });
            logger.log(`[Socket.IO] Browsing presence updated for tab ${tabId}: ${rest.title}`);
        } else if (presenceType === 'video') {
            // Validate presence data
            if (isValidVideoPresence(rest)) {
                // Update video presence for the tab
                tabPresence.set(tabId, {
                    presenceType: 'video',
                    videoId: rest.videoId,
                    title: rest.title,
                    description: rest.description,
                    channelTitle: rest.channelTitle,
                    viewCount: rest.viewCount,
                    likeCount: rest.likeCount,
                    publishedAt: rest.publishedAt,
                    category: rest.category,
                    thumbnail: rest.thumbnail,
                    currentTime: rest.currentTime,
                    duration: rest.duration,
                    isPaused: rest.isPaused,
                    timeElapsed: rest.timeElapsed
                });
                logger.log(`[Socket.IO] Video presence updated for tab ${tabId}: ${rest.title}`);
            } else {
                logger.warn(`[Socket.IO] Invalid video presence data received from ${socket.id}. Skipping update.`);
                return; // Do not emit invalid data
            }
        } else if (presenceType === 'offline') {
            // Remove presence data for the tab
            tabPresence.delete(tabId);
            logger.log(`[Socket.IO] Tab ${tabId} marked as offline.`);
        } else {
            logger.warn(`[Socket.IO] Unknown presenceType '${presenceType}' from tab ${tabId}. Ignoring.`);
            return;
        }

        // Emit updated presence to all clients except the sender
        socket.broadcast.emit('presenceUpdate', { tabId, presenceType, ...rest });
    });

    // Handle Video Progress Updates
    socket.on('updateVideoProgress', (data) => {
        logger.log(`[Socket.IO] Video update received: ${JSON.stringify(data)}`);
        const { tabId, videoId, title, description, channelTitle, viewCount, likeCount, publishedAt, category, thumbnail, currentTime, duration, isPaused } = data;

        if (!tabId) {
            logger.warn(`[Socket.IO] Missing tabId in updateVideoProgress from ${socket.id}. Ignoring.`);
            return;
        }

        const presenceData = {
            presenceType: 'video',
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
            timeElapsed: Math.floor(currentTime)
        };

        // Validate video presence data
        if (isValidVideoPresence(presenceData)) {
            // Update existing video details
            tabPresence.set(tabId, presenceData);
            logger.log(`[Socket.IO] Updated video progress for tab ${tabId}: ${title}`);
        } else {
            logger.warn(`[Socket.IO] Invalid video progress data received from tab ${tabId}. Skipping update.`);
            return;
        }

        // Emit updated video presence to all clients except the sender
        socket.broadcast.emit('presenceUpdate', { tabId, ...presenceData });
    });

    // Handle Heartbeat Signals for YouTube Videos
    socket.on('heartbeat', (data, callback) => {
        const { tabId, videoId } = data;
        if (tabId && videoId && tabPresence.has(tabId) && tabPresence.get(tabId).videoId === videoId) {
            // Update last heartbeat timestamp for the video
            videoHeartbeat[videoId] = Date.now();
            if (callback) callback({ status: "ok" });
        } else {
            if (callback) callback({ status: "error", message: "Unknown tab ID or video ID" });
        }
    });

    // Handle Client Disconnection
    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Client disconnected: ${socket.id}`);
        // Find and remove user from activeUsers
        for (const [ipKey, userData] of activeUsers.entries()) {
            if (userData.id === socket.id) {
                activeUsers.delete(ipKey);
                break;
            }
        }
        io.emit('activeUsersUpdate', { users: Array.from(activeUsers.values()) });

        // Mark all tabs from this client as offline
        for (const [tabId, presenceData] of tabPresence.entries()) {
            io.emit('presenceUpdate', { tabId, presenceType: 'offline' });
            tabPresence.delete(tabId);
        }
    });
});

// Function to handle heartbeat expiration
setInterval(() => {
    const now = Date.now();
    for (const [videoId, lastHeartbeat] of Object.entries(videoHeartbeat)) {
        if (now - lastHeartbeat > HEARTBEAT_TIMEOUT) {
            // Heartbeat timeout: mark the video as offline
            for (const [tabId, presenceData] of tabPresence.entries()) {
                if (presenceData.presenceType === 'video' && presenceData.videoId === videoId) {
                    tabPresence.delete(tabId);
                    io.emit('presenceUpdate', { tabId, presenceType: 'offline' });
                    logger.info(`[Socket.IO] Heartbeat timeout for video ID: ${videoId}. Marked as offline.`);
                }
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
            let errorMsg = 'Failed to fetch web search data';
            try {
                const errorData = await response.json();
                errorMsg = errorData.message || errorMsg;
            } catch (e) {
                logger.error('Error parsing error response:', e);
            }
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
// Geolocation Routes
// ----------------------
app.get('/api/geo-data', async (req, res) => {
    try {
        const countryData = await GeoData.aggregate([
            { $group: { _id: "$country", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        res.json(countryData);
    } catch (error) {
        console.error('Error fetching geo data:', error);
        res.status(500).json({ error: 'Error fetching geo data' });
    }
});

// Fetch Location Route
app.get('/fetch-location', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const locationData = await getGeoLocation(ip);
        res.json(locationData);
    } catch (error) {
        logger.error('Error fetching location data:', error.message);
        res.status(500).json({ error: 'Failed to fetch location data' });
    }
});

// Get Geolocation by IP Route
app.get('/api/location/:ip', async (req, res) => {
    try {
        const ip = req.params.ip;
        const locationData = await getGeoLocation(ip);
        res.json({
            ip: ip,
            city: locationData.city,
            region: locationData.region,
            country: locationData.country,
        });
    } catch (error) {
        logger.error(`Error fetching geolocation for IP ${req.params.ip}:`, error);
        res.status(500).json({ error: 'Failed to fetch geolocation data' });
    }
});

// Track IP Route
app.post('/track', async (req, res) => {
    const ip = getClientIp(req);
    logger.info(`Extracted IP: ${ip}`);

    try {
        const location = await getAccurateGeoLocation(ip);

        // Fetch existing entry for this IP
        const existingEntry = await GeoData.findOne({ ip: location.ip });

        // Check if the location data has changed before updating
        if (existingEntry) {
            const hasChanged = (
                existingEntry.city !== location.city ||
                existingEntry.region !== location.region ||
                existingEntry.country !== location.country
            );

            if (!hasChanged) {
                logger.info(`No changes detected for IP: ${ip}, skipping update.`);
                return res.json({ message: 'No changes detected, update skipped.', ip, location });
            }
        }

        // If no existing entry, or if the data has changed, perform an upsert
        const updatedEntry = await GeoData.findOneAndUpdate(
            { ip: location.ip },  // Query to find the existing IP
            {  // Fields to update
                city: location.city,
                region: location.region,
                country: location.country,
                timestamp: new Date()
            },
            { upsert: true, new: true } // Create if doesn't exist, return updated document
        );

        logger.info(`Location data updated or inserted for IP: ${ip}`);
        res.json({ ip, location });

    } catch (err) {
        logger.error('Error fetching location or saving to MongoDB:', err);
        res.status(500).json({ error: 'Unable to get or save location' });
    }
});


// ----------------------
// Web Search Results via WebSocket
// ----------------------

// This is already handled in the Dialogflow route where 'webSearchResult' is emitted

// ----------------------
// Weather API Route (Duplicated Removed)
// ----------------------
// Note: The '/api/weather' route was already defined above. Ensure it's only defined once.

// ----------------------
// Final Cleanup
// ----------------------

// Ensure that all routes and functions are defined only once.
// Remove any duplicate definitions if present.

// ----------------------
// Start the Server
// ----------------------
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
