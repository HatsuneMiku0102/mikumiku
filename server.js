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
const { MongoClient } = require('mongodb');
const nodemailer = require('nodemailer');
const nacl = require('tweetnacl');
const os   = require('os');

// ----------------------
// Load Environment Variables
// ----------------------
dotenv.config();
const rateLimitMap = new Map();




const DISCORD_PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;




// ---------------------
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


app.use(bodyParser.json({
  verify: (req, res, buf) => {
    if (req.path === '/interactions') req.rawBody = buf.toString();
  }
}));






app.post('/interactions', async (req, res) => {
  // … signature verification …

  if (payload.type === 2 && payload.data.name === 'status') {
    const now        = Date.now();
    const sentMs     = Number(timestamp) * 1000;
    const latency    = now - sentMs;
    let webStatus, webLatency;
    try {
      const start    = Date.now();
      const resp     = await axios.get('https://mikumiku.dev/');
      webStatus      = `${resp.status} ${resp.statusText}`;
      webLatency     = `${Date.now() - start} ms`;
    } catch {
      webStatus      = 'Error';
      webLatency     = 'N/A';
    }
    const upSec     = process.uptime();
    const hours     = Math.floor(upSec / 3600);
    const mins      = Math.floor((upSec % 3600) / 60);
    const secs      = Math.floor(upSec % 60);
    const uptime    = `${hours}h ${mins}m ${secs}s`;
    const memMb     = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2);
    const loadAvg   = os.loadavg()[0].toFixed(2);
    const dbState   = mongoose.connection.readyState; 
    const sockets   = io.engine.clientsCount;
    const env       = process.env.NODE_ENV || 'unknown';
    const version   = process.env.COMMIT_SHA?.slice(0,7) || process.version;

    const embed = {
      author: {
        name:  '🔧 Mikumiku Status',
        icon_url: 'https://mikumiku.dev/assets/miku_icon.png'
      },
      thumbnail: {
        url: 'https://mikumiku.dev/assets/status_thumb.png'
      },
      title: 'System Overview',
      color: 0x39C5BB,
      description:
        `> **Latency:** \`${latency} ms\`\n` +
        `> **Web:** \`${webStatus}\` (\`${webLatency}\`)\n` +
        `> **Load Avg (1m):** \`${loadAvg}\`\n`,
      fields: [
        { name: 'Uptime',            value: uptime,             inline: true },
        { name: 'Memory',            value: `${memMb} MB`,       inline: true },
        { name: 'DB Status',         value: `${dbState}`,        inline: true },
        { name: 'Sockets',           value: `${sockets}`,        inline: true },
        { name: 'Env',               value: env,                 inline: true },
        { name: 'Version',           value: version,             inline: true }
      ],
      footer: {
        text: 'Powered by mikumiku.dev',
        icon_url: 'https://mikumiku.dev/assets/logo.png'
      },
      timestamp: new Date().toISOString()
    };

    return res.json({ type: 4, data: { embeds: [embed] } });
  }

  return res.sendStatus(400);
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
        "https://cdn.socket.io",
        "https://api.mapbox.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com",
        "https://api.mapbox.com"
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
        "https://www.youtube.com",
        "https://raw.githubusercontent.com",
        "https://api.tiles.mapbox.com",
        "https://*.tiles.mapbox.com"
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
        "https://mikumiku.dev",
        "https://api.mapbox.com",
        "https://events.mapbox.com"
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
      workerSrc: ["'self'", "blob:"],
      upgradeInsecureRequests: []
    }
  })
);

app.set('trust proxy', true);

// Create a proxy endpoint that fetches status from your HTTP-only server
app.get('/status-proxy', async (req, res) => {
  try {
    const response = await fetch('http://us-nyc02.pylex.xyz:8282/status');
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Error fetching status:', error);
    res.status(500).json({ status: 'offline' });
  }
});



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
// Modified to include the "loc" property if available from IPinfo
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
            ip: ip,
            loc: ipInfoData.loc || null  // <-- Added loc property here
        };

        logger.info(`AccurateGeoLocation for IP ${ip}: City=${location.city}, Region=${location.region}, Country=${location.country}`);

        return location;
    } catch (error) {
        logger.error(`Error fetching accurate geolocation for IP ${ip}: ${error.message}`);
        return { city: 'Unknown', region: 'Unknown', country: 'Unknown', ip: ip };
    }
}

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

        const isPasswordValid = await bcrypt.compare(password, adminPasswordHash);

        if (!isPasswordValid) {
            logger.warn(`Failed login attempt for username: ${username} from IP: ${getClientIp(req)}`);
            return res.status(401).json({ auth: false, message: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
            expiresIn: 86400 // 24 hours
        });

        res.cookie('token', token, {
            httpOnly: false,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            path: '/',
            maxAge: 86400 * 1000
        });

        req.session.save((err) => {
            if (err) {
                logger.error(`Error saving session: ${err.message}`);
                return res.status(500).json({ auth: false, message: 'Error saving session' });
            }
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

        res.redirect('/auth');
    });
});

// ----------------------
// Comment Routes
// ----------------------
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

app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error(`Error fetching comments: ${error.message}`);
        res.status(500).send({ error: 'Error fetching comments' });
    }
});

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

app.get('/admin-dashboard.html', (req, res) => {
    res.redirect('/admin');
});

// ----------------------
// Geolocation Routes
// ----------------------
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

// ----------------------
// Tracking Visitor Locations Endpoint
// ----------------------
app.post('/track-visitor', async (req, res) => {
  const ip = getClientIp(req);
  try {
    const location = await getGeoLocation(ip);
    if (location && location.loc) {
      // Parse the latitude and longitude from the "loc" property
      const [latitude, longitude] = location.loc.split(',');
      // Use the IP as a unique visitor ID (or generate a new one as needed)
      const visitorId = ip;
      // Create an info string using the city and country
      const info = `${location.city || "Unknown City"}, ${location.country || "Unknown Country"}`;
      
      // Emit the visitor location event via Socket.IO to all connected clients.
      io.emit("visitorLocation", {
        id: visitorId,
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        info: info
      });
      
      logger.info(`Emitted visitorLocation for ${visitorId}: [${latitude}, ${longitude}] - ${info}`);
    } else {
      logger.warn(`No coordinate data available for IP ${ip}.`);
    }
    res.status(200).json({ success: true });
  } catch (error) {
    logger.error(`Error tracking visitor location for IP ${ip}: ${error.message}`);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ----------------------
// Admin Dashboard Real-Time Updates
// ----------------------
const ipBanSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    blockedAt: { type: Date, default: Date.now },
});

const IPbans = mongoose.model('IPbans', ipBanSchema);

const HEARTBEAT_TIMEOUT = 60000; // 60 seconds
const blockedIps = new Set(); // Set to track blocked IPs

let currentVideo = null;
let currentBrowsing = null;
const videoHeartbeat = {};
const activeUsers = new Map(); // Tracks active users by IP and connection type

app.post('/api/block-user', async (req, res) => {
    const { ip } = req.body;
    if (ip) {
        blockedIps.add(ip);
        logger.info(`Blocked user with IP: ${ip}`);

        try {
            await IPbans.updateOne({ ip }, { $set: { ip, blockedAt: new Date() } }, { upsert: true });
            logger.info(`IP ${ip} has been added to IPbans collection.`);
        } catch (error) {
            logger.error(`Error adding IP ${ip} to IPbans collection: ${error.message}`);
            return res.status(500).send({ status: 'error', message: 'Failed to block user.' });
        }

        io.emit('ipBlocked', { ip });
        res.status(200).send({ status: 'success', message: `User with IP ${ip} has been blocked.` });
    } else {
        res.status(400).send({ status: 'error', message: 'IP address is required.' });
    }
});

app.post('/api/unblock-user', async (req, res) => {
    const { ip } = req.body;
    if (ip) {
        if (blockedIps.has(ip)) {
            blockedIps.delete(ip);
            logger.info(`Unblocked user with IP: ${ip}`);

            try {
                await IPbans.deleteOne({ ip });
                logger.info(`IP ${ip} has been removed from IPbans collection.`);
            } catch (error) {
                logger.error(`Error removing IP ${ip} from IPbans collection: ${error.message}`);
                return res.status(500).send({ status: 'error', message: 'Failed to unblock user.' });
            }

            io.emit('ipUnblocked', { ip });
            // Acknowledge the unblock via the socket if available
            res.status(200).send({ status: 'success', message: `User with IP ${ip} has been unblocked.` });
        } else {
            res.status(400).send({ status: 'error', message: `User with IP ${ip} is not blocked.` });
        }
    } else {
        res.status(400).send({ status: 'error', message: 'IP address is required.' });
    }
});

io.on('connection', async (socket) => {
    logger.info(`[Socket.IO] New client connected: ${socket.id}`);

    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || socket.handshake.address;
    const connectionType = socket.handshake.query.connectionType || 'website';

    if (blockedIps.has(ip)) {
        logger.warn(`Blocked connection attempt from IP: ${ip}`);
        socket.disconnect();
        return;
    }

    logger.info(`New connection from IP: ${ip}, Type: ${connectionType}`);

    if (!activeUsers.has(ip)) {
        activeUsers.set(ip, { id: socket.id, ip, connectionTypes: new Set() });
    }
    activeUsers.get(ip).connectionTypes.add(connectionType);

    io.emit('activeUsersUpdate', {
        users: Array.from(activeUsers.values()).map(user => ({
            ip: user.ip,
            connectionTypes: Array.from(user.connectionTypes)
        }))
    });

    emitCurrentPresence(socket);

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
        io.emit('presenceUpdate', data);
    });

    socket.on('blockUser', async (data) => {
        const { ip } = data;
        if (ip) {
            if (!blockedIps.has(ip)) {
                blockedIps.add(ip);
                logger.info(`Blocking user with IP: ${ip}`);

                try {
                    await IPbans.updateOne({ ip }, { $set: { ip, blockedAt: new Date() } }, { upsert: true });
                    logger.info(`IP ${ip} has been added to IPbans collection.`);
                } catch (error) {
                    logger.error(`Error adding IP ${ip} to IPbans collection: ${error.message}`);
                    socket.emit('blockUserResponse', { status: 'error', message: 'Failed to block user.' });
                    return;
                }

                io.emit('ipBlocked', { ip });
                socket.emit('blockUserResponse', { status: 'success', message: `User with IP ${ip} has been blocked.` });
            } else {
                socket.emit('blockUserResponse', { status: 'error', message: `User with IP ${ip} is already blocked.` });
            }
        } else {
            socket.emit('blockUserResponse', { status: 'error', message: 'IP address is required.' });
        }
    });

    socket.on('unblockUser', async (data) => {
        const { ip } = data;
        if (ip) {
            if (blockedIps.has(ip)) {
                blockedIps.delete(ip);
                logger.info(`Unblocking user with IP: ${ip}`);

                try {
                    await IPbans.deleteOne({ ip });
                    logger.info(`IP ${ip} has been removed from IPbans collection.`);
                } catch (error) {
                    logger.error(`Error removing IP ${ip} from IPbans collection: ${error.message}`);
                    socket.emit('unblockUserResponse', { status: 'error', message: 'Failed to unblock user.' });
                    return;
                }

                io.emit('ipUnblocked', { ip });
                socket.emit('unblockUserResponse', { status: 'success', message: `User with IP ${ip} has been unblocked.` });
            } else {
                socket.emit('unblockUserResponse', { status: 'error', message: `User with IP ${ip} is not blocked.` });
            }
        } else {
            socket.emit('unblockUserResponse', { status: 'error', message: 'IP address is required.' });
        }
    });

    socket.on('updateBrowsingPresence', (data) => {
        handleBrowsingPresence(data);
        io.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });
    });

    socket.on('updateVideoProgress', (data) => {
        handleVideoPresence(data);
        io.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
    });

    socket.on('heartbeat', (data, callback) => {
        const { videoId } = data;
        if (videoId && currentVideo && currentVideo.videoId === videoId) {
            videoHeartbeat[videoId] = Date.now();
            if (callback) callback({ status: "ok" });
        } else {
            if (callback) callback({ status: "error", message: "Unknown video ID" });
        }
    });

    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Client disconnected: ${socket.id}`);
        
        if (activeUsers.has(ip)) {
            const user = activeUsers.get(ip);
            user.connectionTypes.delete(connectionType);
            if (user.connectionTypes.size === 0) {
                activeUsers.delete(ip);
            }
        }

        io.emit('activeUsersUpdate', { users: Array.from(activeUsers.values()).map(user => ({
            ip: user.ip,
            connectionTypes: Array.from(user.connectionTypes)
        })) });

        if (currentVideo || currentBrowsing) {
            currentVideo = null;
            currentBrowsing = null;
            io.emit('presenceUpdate', { presenceType: 'offline' });
            logger.info(`[Socket.IO] Emitted offline presence due to disconnection.`);
        }
    });
});

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
        logger.info(`[Socket.IO] Updated video: "${title}" (Live: ${isLive}, Paused: ${isPaused})`);
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
        logger.info(`[Socket.IO] New video detected: "${title}" (Live: ${isLive}, Paused: ${isPaused})`);
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
app.get('/api/videos/public', async (req, res) => {
    try {
        res.json([]);
    } catch (err) {
        logger.error(`Error retrieving video metadata: ${err.message}`);
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
const configuration = new Configuration({
    apiKey: process.env.OPENAI_API_KEY,
});
const openai = new OpenAIApi(configuration);

const sessions = {};

const openAICallLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

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

app.post('/api/openai-chat', openAICallLimiter, async (req, res) => {
    const { message, sessionId } = req.body;

    if (!message || !sessionId) {
        return res.status(400).json({ error: 'Message and sessionId are required.' });
    }

    if (!sessions[sessionId]) {
        sessions[sessionId] = [
            { role: 'system', content: 'You are Haru AI, a helpful assistant.' }
        ];
    }

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
    const units = 'metric';
    const apiKey = process.env.OPENWEATHER_API_KEY;

    if (!apiKey) {
        logger.error('OPENWEATHER_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await axios.get(apiUrl);

        if (response.status !== 200) {
            let errorMsg = 'Failed to fetch weather data';
            try {
                const errorData = response.data;
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


// -----------
// Bot Status Update
// ------------------

// Variables to track heartbeat and vital info
let lastHeartbeat = 0;
let latestBotInfo = {
  status: 'offline',
  uptime: 'N/A',
  latency: 'N/A',
  memoryUsage: 'N/A',
  botName: 'N/A'
};

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  // Send current status when a client connects
  socket.emit('botStatusUpdate', latestBotInfo);

  // Listen for heartbeat events from the bot
  socket.on('botHeartbeat', (data) => {
    console.log('Received botHeartbeat:', data);
    lastHeartbeat = Date.now();
    latestBotInfo = {
      status: 'online',
      uptime: data.uptime,
      latency: data.latency,
      memoryUsage: data.memoryUsage,
      botName: data.botName
    };
    // Broadcast the updated status with vital info to all clients
    io.emit('botStatusUpdate', latestBotInfo);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Check every 30 seconds; if no heartbeat in 2 minutes, mark bot offline.
setInterval(() => {
  const now = Date.now();
  if (now - lastHeartbeat > 2 * 60 * 1000) {
    if (latestBotInfo.status !== 'offline') {
      console.log('Heartbeat timeout. Marking bot as offline.');
      latestBotInfo.status = 'offline';
      io.emit('botStatusUpdate', latestBotInfo);
    }
  }
}, 30000);

// -------------------
// Yes
// -------------------
const MAX_MINUTES = 60
let timelineCollection
let configCollection

// Global variables for offline detection and latency alerts
let lastBotStatusUpdate = Date.now()
let smsSent = false
let highLatencyAlertSent = false
const OFFLINE_TIMEOUT = 90000 // 90 seconds
const HIGH_LATENCY_THRESHOLD = 100 // in milliseconds

if (!process.env.MONGO_URL) {
  console.error("Error: MONGO_URL environment variable not set.")
  process.exit(1)
}

const dbName = process.env.MONGO_DB_NAME || "myfirstdatabase"
const client = new MongoClient(process.env.MONGO_URL, { useUnifiedTopology: true })

async function connectToMongo() {
  try {
    await client.connect()
    const db = client.db(dbName)
    configCollection = db.collection("config")
    timelineCollection = db.collection("timeline")
    console.log("Connected to MongoDB.")

    let toggleDoc = await configCollection.findOne({ _id: "toggle" })
    if (!toggleDoc) {
      toggleDoc = { _id: "toggle", commands_enabled: true }
      await configCollection.insertOne(toggleDoc)
      console.log("Inserted default toggle config:", toggleDoc)
    } else {
      console.log("Existing toggle config:", toggleDoc)
    }
  } catch (err) {
    console.error("Error connecting to MongoDB:", err)
  }
}
connectToMongo()

app.use(express.json())

app.get('/api/timeline', async (req, res) => {
  try {
    const entries = await timelineCollection.find().sort({ rawTimestamp: 1 }).toArray()
    res.json(entries)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/timeline', async (req, res) => {
  try {
    const update = req.body
    const lastEntryArray = await timelineCollection.find().sort({ rawTimestamp: -1 }).limit(1).toArray()
    if (lastEntryArray.length > 0) {
      const lastEntry = lastEntryArray[0]
      const lastMinute = Math.floor(lastEntry.rawTimestamp / 60000)
      const newMinute = Math.floor(update.rawTimestamp / 60000)
      if (lastMinute === newMinute) {
        console.log("Duplicate heartbeat detected; not inserting new timeline entry.")
        return res.json({ status: 'duplicate' })
      }
    }
    await timelineCollection.insertOne(update)
    const count = await timelineCollection.countDocuments()
    if (count > MAX_MINUTES) {
      const excess = count - MAX_MINUTES
      const oldestEntries = await timelineCollection.find().sort({ rawTimestamp: 1 }).limit(excess).toArray()
      const idsToDelete = oldestEntries.map(entry => entry._id)
      await timelineCollection.deleteMany({ _id: { $in: idsToDelete } })
    }
    res.json({ status: 'ok' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/toggle', async (req, res) => {
  try {
    const toggleDoc = await configCollection.findOne({ _id: "toggle" })
    res.json(toggleDoc)
  } catch (err) {
    console.error("Error reading toggle config:", err)
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/toggle', async (req, res) => {
  try {
    const data = req.body
    if (typeof data.commands_enabled === 'undefined') {
      res.status(400).json({ status: 'error', message: "Missing 'commands_enabled' property." })
      return
    }
    await configCollection.updateOne({ _id: "toggle" }, { $set: { commands_enabled: data.commands_enabled } })
    const toggleDoc = await configCollection.findOne({ _id: "toggle" })
    res.json({ status: 'success', commands_enabled: toggleDoc.commands_enabled })
  } catch (err) {
    console.error("Error updating toggle config:", err)
    res.status(500).json({ status: 'error', message: 'Could not update configuration.' })
  }
})

// Socket.IO integration
io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.id}`)

  socket.on('getToggleState', async () => {
    if (!configCollection) {
      console.error(`configCollection is undefined for ${socket.id}`)
      socket.emit('toggleState', { commands_enabled: true })
      return
    }
    try {
      const toggleDoc = await configCollection.findOne({ _id: "toggle" })
      console.log(`Emitting toggleState to ${socket.id}:`, toggleDoc)
      socket.emit('toggleState', toggleDoc)
    } catch (err) {
      console.error(`Error reading toggle config for ${socket.id}:`, err)
      socket.emit('toggleState', { commands_enabled: true })
    }
  })

  socket.on('toggleCommands', async (data) => {
    console.log(`Received toggleCommands from ${socket.id}:`, data)
    if (typeof data.commands_enabled === 'undefined') {
      console.error(`Missing 'commands_enabled' property from ${socket.id}`)
      socket.emit('toggleResponse', { status: 'error', message: "Missing 'commands_enabled' property." })
      return
    }
    if (!configCollection) {
      console.error(`configCollection is undefined for ${socket.id} when updating toggle.`)
      socket.emit('toggleResponse', { status: 'error', message: "Database not connected." })
      return
    }
    try {
      await configCollection.updateOne({ _id: "toggle" }, { $set: { commands_enabled: data.commands_enabled } })
      const toggleDoc = await configCollection.findOne({ _id: "toggle" })
      console.log(`Toggle updated successfully by ${socket.id}:`, toggleDoc)
      socket.emit('toggleResponse', { status: 'success', commands_enabled: toggleDoc.commands_enabled })
      socket.broadcast.emit('toggleUpdated', { commands_enabled: toggleDoc.commands_enabled })
    } catch (err) {
      console.error(`Error updating toggle config for ${socket.id}:`, err)
      socket.emit('toggleResponse', { status: 'error', message: 'Could not update configuration.' })
    }
  })

  // Listen for botStatusUpdate events from your bot
  // Listen for botHeartbeat events from your bot
socket.on('botHeartbeat', (data) => {
  // Normalize and log the heartbeat data
  const status = (data.status || "").toLowerCase().trim();
  console.log(`Received botHeartbeat from ${socket.id}: status: "${status}", latency: ${data.latency}`);
  lastBotStatusUpdate = Date.now();
  
  if (status === 'online') {
    smsSent = false;
    const latency = parseInt(data.latency);
    if (latency > HIGH_LATENCY_THRESHOLD && !highLatencyAlertSent) {
      console.log(`High latency detected (${latency}ms). Sending SMS alert.`);
      sendSMSAlert("Alert: The bot is experiencing high latency!");
      highLatencyAlertSent = true;
    } else if (latency <= HIGH_LATENCY_THRESHOLD) {
      if (highLatencyAlertSent) {
        console.log(`Latency back to normal (${latency}ms). Resetting high latency alert flag.`);
      }
      highLatencyAlertSent = false;
    }
  } else {
    console.log(`Bot status is not online: "${status}"`);
  }
});



  socket.on('disconnect', (reason) => {
    console.log(`Socket disconnected: ${socket.id}, Reason: ${reason}`)
  })
})

// Serve the Aria status page
app.get('/aria-status', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'aria-status.html'))
})

// Function to send an SMS via ClickSend
function sendSMSAlert(message) {
  const smsData = {
    messages: [
      {
        source: "nodejs",
        from: process.env.SMS_SENDER,       // e.g., "YourApp"
        to: process.env.TO_PHONE_NUMBER,      // e.g., "447852492759" (international format)
        body: message
      }
    ]
  }

  const auth = {
    username: process.env.CLICKSEND_USERNAME,
    password: process.env.CLICKSEND_API_KEY
  }

  axios.post('https://rest.clicksend.com/v3/sms/send', smsData, { auth })
    .then(response => {
      console.log('SMS sent successfully via ClickSend:', response.data)
    })
    .catch(error => {
      console.error('Error sending SMS via ClickSend:', error.response ? error.response.data : error.message)
    })
}

// Periodically check if the bot has gone offline and send SMS if needed
setInterval(() => {
  const elapsed = Date.now() - lastBotStatusUpdate
  console.log(`Time elapsed since last update: ${elapsed} ms`)
  if (elapsed > OFFLINE_TIMEOUT) {
    if (!smsSent) {
      console.log('Bot appears offline. Sending SMS alert.')
      sendSMSAlert("Alert: The bot is offline!")
      smsSent = true
    }
  }
}, 5000)


// ----------------------
// Start the Server
// ----------------------
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
