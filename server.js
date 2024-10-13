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
const { body, validationResult } = require('express-validator');
const uuid = require('uuid');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Configuration, OpenAIApi } = require('openai');

// ----------------------
// Load Environment Variables
// ----------------------
dotenv.config();
const rateLimitMap = new Map();

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
// Define Mongoose Schemas and Models
// ----------------------
const GeoDataSchema = new mongoose.Schema({
    ip: {
        type: String,
        required: true,
        unique: true, // Assuming one entry per IP
    },
    city: {
        type: String,
        default: 'Unknown',
    },
    region: {
        type: String,
        default: 'Unknown',
    },
    country: {
        type: String,
        default: 'Unknown',
    },
    timestamp: {
        type: Date,
        default: Date.now,
    },
});

// Explicitly set the collection name to 'geodatas'
const GeoData = mongoose.model('GeoData', GeoDataSchema, 'geodatas');

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
                "https://cdn.skypack.dev",
                "https://cdn.socket.io"
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
                "https://api.openweathermap.org",
                "https://cdn.socket.io",
                "https://mikumiku.dev" // Ensure this matches the actual domain
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

// Use the admin session store
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
        return res.redirect('/auth');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            logger.error(`Token verification failed: ${err.message}. Redirecting to login.`);
            return res.redirect('/auth');
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
        logger.error(`Error fetching Bungie token: ${error.message}`);
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
        logger.error(`Error refreshing Bungie token: ${error.message}`);
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
        logger.error(`Error fetching Bungie user info: ${error.message}`);
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
// Membership Mapping Functions
// ----------------------

// Define the membership file path
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
            logger.error(`Error parsing membership mapping file: ${err.message}`);
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
        logger.error(`Error writing to membership mapping file: ${err.message}`);
    }

    try {
        const updatedData = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info(`Verified membership mapping file content: ${updatedData}`);
    } catch (err) {
        logger.error(`Error reading membership mapping file after update: ${err.message}`);
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
async function getGeoLocation(ip) {
    try {
        const locationData = await getAccurateGeoLocation(ip);
        return locationData;
    } catch (error) {
        logger.error(`Error in getGeoLocation: ${error.message}`);
        return {
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown',
            ip: ip
        };
    }
}

// Accurate Geolocation Function (Using IPinfo and MaxMind)
async function getAccurateGeoLocation(ip) {
    try {
        // IPinfo as the primary source
        const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_API_KEY}`);
        const ipInfoData = ipInfoResponse.data;

        // Optionally, you can add MaxMind or another API for more robust location or VPN detection
        const maxMindApiKey = process.env.MAXMIND_API_KEY;
        let maxMindData = {};
        if (maxMindApiKey) {
            try {
                const maxMindApiResponse = await axios.get(`https://geoip.maxmind.com/geoip/v2.1/city/${ip}`, {
                    headers: {
                        'Authorization': `Bearer ${maxMindApiKey}`
                    }
                });
                maxMindData = maxMindApiResponse.data;
            } catch (maxMindError) {
                logger.error(`Error fetching data from MaxMind for IP ${ip}: ${maxMindError.message}`);
            }
        } else {
            logger.warn('MAXMIND_API_KEY is not set. Skipping MaxMind lookup.');
        }

        // Merge data or cross-check between services if needed
        const location = {
            city: ipInfoData.city || (maxMindData.city && maxMindData.city.names.en) || 'Unknown',
            region: ipInfoData.region || (maxMindData.subdivisions && maxMindData.subdivisions[0].names.en) || 'Unknown',
            country: ipInfoData.country || (maxMindData.country && maxMindData.country.names.en) || 'Unknown',
            ip: ip
        };

        // Log the merged location data
        logger.info(`AccurateGeoLocation for IP ${ip}: City=${location.city}, Region=${location.region}, Country=${location.country}`);

        return location;
    } catch (error) {
        logger.error(`Error fetching accurate geolocation for IP ${ip}: ${error.message}`);
        return { city: 'Unknown', region: 'Unknown', country: 'Unknown', ip: ip };
    }
}


// Web Search Function using OpenAI GPT-3.5-turbo (Removed Google Custom Search API)
/**
 * Since you want to replace Dialogflow with OpenAI's GPT-3.5-turbo, and likely use it for chatbot responses,
 * the web search functionality using Google Custom Search API can be optionally removed or adjusted.
 * However, if you still need a separate web search feature, you can integrate it with OpenAI prompts.
 * For simplicity, I'll assume you want to focus on using OpenAI for chat responses.
 */

// ----------------------
// Rate Limiting Middleware
// ----------------------
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

// ----------------------
// OAuth Routes
// ----------------------

// Login Route
app.get('/login', async (req, res) => {
    const state = generateRandomString(16);
    const user_id = req.query.user_id;
    const ip_address = getClientIp(req);
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
        const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${process.env.CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI || 'https://mikumiku.dev/callback')}`;
        res.redirect(authorizeUrl);
    } catch (err) {
        logger.error(`Error saving session to DB: ${err.message}`);
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
        logger.error(`Error during callback: ${error.message}`);
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
        logger.error(`Error fetching Bungie name: ${err.message}`);
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
            logger.warn(`Failed login attempt for username: ${username} from IP: ${getClientIp(req)}`);
            return res.status(401).json({ auth: false, message: 'Invalid username or password' });
        }

        // Use bcrypt to compare passwords
        const isPasswordValid = await bcrypt.compare(password, adminPasswordHash);

        if (!isPasswordValid) {
            logger.warn(`Failed login attempt for username: ${username} from IP: ${getClientIp(req)}`);
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
                logger.error(`Error saving session: ${err.message}`);
                return res.status(500).json({ auth: false, message: 'Error saving session' });
            }
            // Redirect to the /admin route instead of /admin-dashboard.html
            res.status(200).json({ auth: true, redirect: '/admin' });
        });
    } catch (error) {
        logger.error(`Unexpected error during login: ${error.message}`);
        res.status(500).json({ auth: false, message: 'Internal Server Error' });
    }
});

// ----------------------
// Logout Routes
// ----------------------
app.get('/auth', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

// Logout Route
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            logger.error(`Error destroying session: ${err.message}`);
            return res.status(500).json({ message: 'Error logging out' });
        }
        
        res.clearCookie('admin_session_cookie', {
            path: '/', 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'strict'
        });

        res.redirect('/auth'); // Redirect to /auth after logout
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
        logger.error(`Error saving comment: ${error.message}`);
        res.status(500).send({ error: 'Error saving comment' });
    }
});

// Get Approved Comments
app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error(`Error fetching comments: ${error.message}`);
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
        logger.error(`Error deleting comment: ${error.message}`);
        res.status(500).send({ error: 'Error deleting comment' });
    }
});

// ----------------------
// Admin Dashboard Route (Protected)
// ----------------------
app.get('/admin', verifyToken, (req, res) => {
    logger.info(`Access granted to admin user with ID: ${req.userId}`);
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Prevent direct access to the HTML file
app.get('/admin-dashboard.html', (req, res) => {
    res.redirect('/admin'); // Redirect to the /admin route
});

// ----------------------
// Geolocation Routes
// ----------------------

// Fetch Location Route
app.get('/fetch-location', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const locationData = await getGeoLocation(ip);
        res.json(locationData);
    } catch (error) {
        logger.error(`Error fetching location data for IP ${ip}: ${error.message}`);
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
        logger.error(`Error fetching geolocation for IP ${req.params.ip}: ${error.message}`);
        res.status(500).json({ error: 'Failed to fetch geolocation data' });
    }
});

// Track IP Route
app.post('/track', async (req, res) => {
    const ip = getClientIp(req);
    const userAgent = req.get('User-Agent') || '';
    logger.info(`Extracted IP: ${ip}, User-Agent: ${userAgent}`);

    // Simple bot detection
    const botPatterns = [/bot/i, /crawl/i, /spider/i, /slurp/i];
    if (botPatterns.some(pattern => pattern.test(userAgent))) {
        logger.info(`Skipped tracking for bot User-Agent: ${userAgent}`);
        return res.status(200).json({ message: 'Bot detected, tracking skipped.' });
    }

    // Rate Limiting: Prevent multiple tracking from the same IP within a short time
    const rateLimitKey = `track_${ip}`;
    const existingTimestamp = rateLimitMap.get(rateLimitKey) || 0;
    const currentTime = Date.now();

    if (currentTime - existingTimestamp < 60000) { // 1 minute
        logger.info(`Rate limit exceeded for IP: ${ip}, skipping tracking.`);
        return res.status(200).json({ message: 'Rate limit exceeded, tracking skipped.' });
    }

    rateLimitMap.set(rateLimitKey, currentTime);

    try {
        const location = await getGeoLocation(ip);

        // Check if the IP is already blocked
        if (blockedIps.has(ip)) {
            logger.warn(`Blocked IP attempted to track: ${ip}`);
            return res.status(403).json({ error: 'Access denied.' });
        }

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
            { upsert: true, new: true }
        );

        // Log the updated or inserted entry
        logger.info(`Location data saved to 'geodatas' collection: ${JSON.stringify(updatedEntry)}`);
        res.json({ ip, location });

        // Perform aggregation to group by country
        const countryData = await GeoData.aggregate([
            { $group: { _id: "$country", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        // Emit the aggregated data to all connected clients
        io.emit('geoDataUpdate', countryData);
        logger.info('Emitted geoDataUpdate event to all connected clients.');

    } catch (err) {
        logger.error(`Error fetching location or saving to MongoDB for IP ${ip}: ${err.message}`);
        res.status(500).json({ error: 'Unable to get or save location' });
    }
});

// ----------------------
// Admin Dashboard Real-Time Updates
// ----------------------

// WebSocket (Socket.IO) Configuration
const ipBanSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    blockedAt: { type: Date, default: Date.now },
});

const IPbans = mongoose.model('IPbans', ipBanSchema);

const HEARTBEAT_TIMEOUT = 60000; // 60 seconds
const blockedIps = new Set(); // Set to track blocked IPs

// State Management
let currentVideo = null;
let currentBrowsing = null;
const videoHeartbeat = {};
const activeUsers = new Map(); // Tracks active users by IP and connection type

// Block user endpoint
app.post('/api/block-user', async (req, res) => {
    const { ip } = req.body;
    if (ip) {
        blockedIps.add(ip); // Add IP to blocked list
        logger.info(`Blocked user with IP: ${ip}`);

        // Save to MongoDB IPbans collection
        try {
            await IPbans.updateOne({ ip }, { $set: { ip, blockedAt: new Date() } }, { upsert: true });
            logger.info(`IP ${ip} has been added to IPbans collection.`);
        } catch (error) {
            logger.error(`Error adding IP ${ip} to IPbans collection: ${error.message}`);
            return res.status(500).send({ status: 'error', message: 'Failed to block user.' });
        }

        // Notify all clients about the blocked IP
        io.emit('ipBlocked', { ip });

        res.status(200).send({ status: 'success', message: `User with IP ${ip} has been blocked.` });
    } else {
        res.status(400).send({ status: 'error', message: 'IP address is required.' });
    }
});

// Unblock user endpoint
app.post('/api/unblock-user', async (req, res) => {
    const { ip } = req.body;
    if (ip) {
        if (blockedIps.has(ip)) {
            blockedIps.delete(ip);
            logger.info(`Unblocked user with IP: ${ip}`);

            // Remove from MongoDB IPbans collection
            try {
                await IPbans.deleteOne({ ip });
                logger.info(`IP ${ip} has been removed from IPbans collection.`);
            } catch (error) {
                logger.error(`Error removing IP ${ip} from IPbans collection: ${error.message}`);
                return res.status(500).send({ status: 'error', message: 'Failed to unblock user.' });
            }

            // Notify all clients about the unblocked IP
            io.emit('ipUnblocked', { ip });

            // Acknowledge the unblock
            socket.emit('unblockUserResponse', { status: 'success', message: `User with IP ${ip} has been unblocked.` });
        } else {
            res.status(400).send({ status: 'error', message: `User with IP ${ip} is not blocked.` });
        }
    } else {
        res.status(400).send({ status: 'error', message: 'IP address is required.' });
    }
});

// Handle new client connections
io.on('connection', async (socket) => {
    logger.info(`[Socket.IO] New client connected: ${socket.id}`);

    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || socket.handshake.address;
    const connectionType = socket.handshake.query.connectionType || 'website'; // 'website' or 'extension'

    if (blockedIps.has(ip)) {
        logger.warn(`Blocked connection attempt from IP: ${ip}`);
        socket.disconnect(); // Disconnect if IP is blocked
        return;
    }

    logger.info(`New connection from IP: ${ip}, Type: ${connectionType}`);

    // Manage active users based on IP and connection type
    if (!activeUsers.has(ip)) {
        activeUsers.set(ip, { id: socket.id, ip, connectionTypes: new Set() });
    }
    activeUsers.get(ip).connectionTypes.add(connectionType); // Add connection type to the Set

    // Emit updated active users
    io.emit('activeUsersUpdate', {
        users: Array.from(activeUsers.values()).map(user => ({
            ip: user.ip,
            connectionTypes: Array.from(user.connectionTypes) // No need to join here
        }))
    });

    // Emit current presence state to the newly connected client
    emitCurrentPresence(socket);

    // Handle Presence Updates (Video, Browsing, Offline)
    socket.on('presenceUpdate', (data) => {
        switch (data.presenceType) {
            case 'browsing':
                handleBrowsingPresence(data);
                break;
            case 'video':
                handleVideoPresence(data);
                break;
            case 'offline':
                handleOfflinePresence();
                break;
            default:
                logger.warn(`Unknown presenceType received: ${data.presenceType}`);
        }

        // Emit updated presence to all connected clients
        io.emit('presenceUpdate', data);
    });

    // Handle block user request
    socket.on('blockUser', async (data) => {
        const { ip } = data;
        if (ip) {
            if (!blockedIps.has(ip)) {
                blockedIps.add(ip);
                logger.info(`Blocking user with IP: ${ip}`);

                // Save to MongoDB IPbans collection
                try {
                    await IPbans.updateOne({ ip }, { $set: { ip, blockedAt: new Date() } }, { upsert: true });
                    logger.info(`IP ${ip} has been added to IPbans collection.`);
                } catch (error) {
                    logger.error(`Error adding IP ${ip} to IPbans collection: ${error.message}`);
                    socket.emit('blockUserResponse', { status: 'error', message: 'Failed to block user.' });
                    return;
                }

                // Notify all clients about the blocked IP
                io.emit('ipBlocked', { ip });

                // Acknowledge the block
                socket.emit('blockUserResponse', { status: 'success', message: `User with IP ${ip} has been blocked.` });
            } else {
                socket.emit('blockUserResponse', { status: 'error', message: `User with IP ${ip} is already blocked.` });
            }
        } else {
            socket.emit('blockUserResponse', { status: 'error', message: 'IP address is required.' });
        }
    });

    // Handle unblock user request
    socket.on('unblockUser', async (data) => {
        const { ip } = data;
        if (ip) {
            if (blockedIps.has(ip)) {
                blockedIps.delete(ip);
                logger.info(`Unblocking user with IP: ${ip}`);

                // Remove from MongoDB IPbans collection
                try {
                    await IPbans.deleteOne({ ip });
                    logger.info(`IP ${ip} has been removed from IPbans collection.`);
                } catch (error) {
                    logger.error(`Error removing IP ${ip} from IPbans collection: ${error.message}`);
                    socket.emit('unblockUserResponse', { status: 'error', message: 'Failed to unblock user.' });
                    return;
                }

                // Notify all clients about the unblocked IP
                io.emit('ipUnblocked', { ip });

                // Acknowledge the unblock
                socket.emit('unblockUserResponse', { status: 'success', message: `User with IP ${ip} has been unblocked.` });
            } else {
                socket.emit('unblockUserResponse', { status: 'error', message: `User with IP ${ip} is not blocked.` });
            }
        } else {
            socket.emit('unblockUserResponse', { status: 'error', message: 'IP address is required.' });
        }
    });

    // Handle YouTube Browsing Presence Updates
    socket.on('updateBrowsingPresence', (data) => {
        handleBrowsingPresence(data);
        io.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });
    });

    // Handle YouTube Video Progress Updates
    socket.on('updateVideoProgress', (data) => {
        handleVideoPresence(data);
        io.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
    });

    // Handle Heartbeat Signals for YouTube Videos
    socket.on('heartbeat', (data, callback) => {
        const { videoId } = data;
        if (videoId && currentVideo && currentVideo.videoId === videoId) {
            videoHeartbeat[videoId] = Date.now();
            if (callback) callback({ status: "ok" });
        } else {
            if (callback) callback({ status: "error", message: "Unknown video ID" });
        }
    });

    // Handle Client Disconnection
    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Client disconnected: ${socket.id}`);
        
        if (activeUsers.has(ip)) {
            const user = activeUsers.get(ip);
            user.connectionTypes.delete(connectionType);
            if (user.connectionTypes.size === 0) {
                activeUsers.delete(ip); // Remove user if no connection types remain
            }
        }

        // Emit updated user list
        io.emit('activeUsersUpdate', { users: Array.from(activeUsers.values()).map(user => ({
            ip: user.ip,
            connectionTypes: Array.from(user.connectionTypes) // No need to join here
        })) });

        if (currentVideo || currentBrowsing) {
            currentVideo = null;
            currentBrowsing = null;
            io.emit('presenceUpdate', { presenceType: 'offline' });
            logger.info(`[Socket.IO] Emitted offline presence due to disconnection.`);
        }
    });
});

/**
 * Periodically check for heartbeat timeouts to mark videos as offline
 */
setInterval(() => {
    const now = Date.now();
    for (const [videoId, lastHeartbeat] of Object.entries(videoHeartbeat)) {
        if (now - lastHeartbeat > HEARTBEAT_TIMEOUT) {
            currentVideo = null;
            currentBrowsing = null;
            io.emit('presenceUpdate', { presenceType: 'offline' });
            delete videoHeartbeat[videoId];
            logger.info(`[Socket.IO] Heartbeat timeout for video ID: ${videoId}. Marked as offline.`);
        }
    }
}, HEARTBEAT_TIMEOUT / 2);

/**
 * Helper Functions
 */
function emitCurrentPresence(socket) {
    if (currentVideo) {
        socket.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
    } else if (currentBrowsing) {
        socket.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });
    } else {
        socket.emit('presenceUpdate', { presenceType: 'offline' });
    }
}

function handleBrowsingPresence(data) {
    logger.info(`[Socket.IO] Browsing presence detected.`);
    if (currentVideo) {
        currentVideo = null;
        logger.info(`[Socket.IO] Cleared current video presence.`);
    }

    currentBrowsing = {
        title: data.title || 'YouTube',
        description: data.description || 'Browsing videos',
        thumbnail: 'https://www.youtube.com/img/desktop/yt_1200.png',
        timeElapsed: data.timeElapsed || 0,
        presenceType: 'browsing'
    };
}

function handleVideoPresence(data) {
    const {
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
        isLive
    } = data;

    if (currentVideo && currentVideo.videoId === videoId) {
        Object.assign(currentVideo, {
            currentTime,
            duration,
            isPaused,
            title,
            description,
            channelTitle,
            viewCount,
            likeCount,
            publishedAt,
            category,
            thumbnail,
            isLive
        });
        logger.info(`[Socket.IO] Updated video: "${title}" (Live: ${isLive})`);
    } else {
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
            isLive,
            presenceType: 'video'
        };
        currentBrowsing = null;
        logger.info(`[Socket.IO] New video detected: "${title}" (Live: ${isLive})`);
    }
}

function handleOfflinePresence() {
    currentVideo = null;
    currentBrowsing = null;
    logger.info(`[Socket.IO] User marked as offline.`);
}

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
        logger.error(`Error retrieving video metadata: ${err.message}`);
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
            logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
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
            // For example:
            // const video = new Video(videoMetadata);
            // await video.save();

            logger.info(`New video added: ${JSON.stringify(videoMetadata)}`);
            res.status(201).json({ message: 'Video added successfully', video: videoMetadata });
        } catch (err) {
            logger.error(`Error saving video metadata: ${err.message}`);
            res.status(500).json({ error: 'Error saving video metadata' });
        }
    }
);

// ----------------------
// OpenAI GPT-3.5-turbo Integration
// ----------------------

// Initialize OpenAI Client
const configuration = new Configuration({
    apiKey: process.env.OPENAI_API_KEY,
});
const openai = new OpenAIApi(configuration);

// In-memory session storage (for demonstration purposes only)
const sessions = {};

// Rate Limiting Middleware
const openAICallLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 60, // Limit each IP to 60 requests per windowMs (adjust as needed)
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Utility function for exponential backoff
async function makeOpenAIRequest(messages, retries = 3, backoff = 1000) {
    try {
        const response = await openai.createChatCompletion({
            model: 'gpt-3.5-turbo',
            messages: messages,
            temperature: 0.7,
            max_tokens: 150,
        });
        return response.data.choices[0].message.content.trim();
    } catch (error) {
        if (error.response && error.response.status === 429 && retries > 0) {
            console.warn(`Rate limit exceeded. Retrying in ${backoff}ms...`);
            await new Promise(res => setTimeout(res, backoff));
            return makeOpenAIRequest(messages, retries - 1, backoff * 2);
        } else {
            throw error;
        }
    }
}

// POST /api/openai-chat
app.post('/api/openai-chat', openAICallLimiter, async (req, res) => {
    const { message, sessionId } = req.body;

    if (!message || !sessionId) {
        return res.status(400).json({ error: 'Message and sessionId are required.' });
    }

    // Initialize session if it doesn't exist
    if (!sessions[sessionId]) {
        sessions[sessionId] = [
            { role: 'system', content: 'You are Haru AI, a helpful assistant.' }
        ];
    }

    // Add user message to session
    sessions[sessionId].push({ role: 'user', content: message });

    try {
        const botResponse = await makeOpenAIRequest(sessions[sessionId]);
        sessions[sessionId].push({ role: 'assistant', content: botResponse });

        res.json({ response: botResponse });
    } catch (error) {
        console.error(`Error communicating with OpenAI: ${error.message}`);
        if (error.response && error.response.status === 429) {
            res.status(429).json({ error: 'Too many requests. Please try again later.' });
        } else {
            res.status(500).json({ error: 'An error occurred while processing your request.' });
        }
    }
});

// ----------------------
// Geolocation Routes (continued)
// ----------------------

// Get GeoData Aggregated by Country
app.get('/api/geo-data', async (req, res) => {
    try {
        const countryData = await GeoData.aggregate([
            { $group: { _id: "$country", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        res.json(countryData);
    } catch (error) {
        logger.error(`Error fetching geo data: ${error.message}`);
        res.status(500).json({ error: 'Error fetching geo data' });
    }
});

// ----------------------
// Weather Route
// ----------------------
app.get('/api/weather', async (req, res) => {
    const city = req.query.city || 'Leeds';
    const units = 'metric'; // Use 'imperial' for Fahrenheit
    const apiKey = process.env.OPENWEATHER_API_KEY;

    // Validate the presence of the API key
    if (!apiKey) {
        logger.error('OPENWEATHER_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    // Construct the API URL using template literals
    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await axios.get(apiUrl);

        // Handle non-OK responses
        if (response.status !== 200) {
            let errorMsg = 'Failed to fetch weather data';
            try {
                const errorData = response.data;
                // OpenWeatherMap returns error messages in the 'message' field
                errorMsg = errorData.message || errorMsg;
            } catch (e) {
                logger.error('Error parsing error response:', e);
            }
            return res.status(response.status).json({ error: errorMsg });
        }

        const data = response.data;
        res.json(data);
    } catch (error) {
        logger.error(`Error fetching weather data for city ${city}:`, error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// ----------------------
// Start the Server
// ----------------------
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
