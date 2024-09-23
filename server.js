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

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "chrome-extension://<ealgoodedcojbceodddhbpcklnpneocp>",
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    }
});

const PORT = process.env.PORT || 3000;

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

app.set('trust proxy', 1);

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());

// MongoDB Connection
const mongoUrl = process.env.MONGO_URL;

mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error('Error connecting to MongoDB:', err);
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
    logger.error('Session store error:', error);
});

app.use(session({
    secret: process.env.SESSION_SECRET || '703c21839606106f7636c214e94869353b5b4d30f6c3a69dd8c75335f45fde4b',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Set CSP headers using helmet

app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://www.youtube.com", "https://www.youtube.com/iframe_api"], // Add YouTube script sources
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "https://i.ytimg.com", "https://img.youtube.com"], // Allow YouTube images and thumbnails
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://www.googleapis.com", "https://*.youtube.com"], // Allow YouTube API calls
        frameSrc: ["'self'", "https://discord.com", "https://www.youtube.com"], // Allow embedding YouTube videos in iframes
        mediaSrc: ["'self'", "https://www.youtube.com"], // Allow media from YouTube
        frameAncestors: ["'self'", "https://discord.com"]
    }
}));



// Serve static files from 'public'
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 0,
    lastModified: false
}));

// MongoDB Schemas and Models
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

// Helper Functions
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
logger.info('Hashed Password:', hashedPassword);

// JWT Verification Middleware
function verifyToken(req, res, next) {
    const token = req.cookies.token;
    logger.info('Token from cookie:', token);

    if (!token) {
        logger.info('Token not found. Redirecting to login.');
        return res.redirect('/admin-login.html');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            logger.info('Token verification failed:', err.message);
            return res.redirect('/admin-login.html');
        }
        logger.info('Token successfully verified. User ID:', decoded.id);
        req.userId = decoded.id;
        next();
    });
}

// OAuth Configuration
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://mikumiku.dev/callback';

const membershipFilePath = path.join(__dirname, 'membership_mapping.json');

function updateMembershipMapping(discordId, userInfo) {
    let membershipMapping = {};

    if (fs.existsSync(membershipFilePath)) {
        const data = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info('Read existing membership mapping file:', data);
        try {
            membershipMapping = JSON.parse(data);
        } catch (err) {
            logger.error('Error parsing membership mapping file:', err);
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
        logger.info('Updated membership mapping file:', JSON.stringify(membershipMapping, null, 2));
    } catch (err) {
        logger.error('Error writing to membership mapping file:', err);
    }

    try {
        const updatedData = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info('Verified membership mapping file content:', updatedData);
    } catch (err) {
        logger.error('Error reading membership mapping file after update:', err);
    }
}

async function sendUserInfoToDiscordBot(discordId, userInfo) {
    logger.info('User info ready to be sent to Discord bot:', userInfo);
}

// OAuth Routes
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
        logger.error('Error saving session to DB:', err);
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
        logger.info('User Info Response:', userInfo);

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error('Incomplete user info response:', userInfo);
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
        logger.error('Error fetching Bungie name:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Comment Routes
app.post('/api/comments', async (req, res) => {
    try {
        const { username, comment } = req.body;
        const newComment = new Comment({ username, comment });
        await newComment.save();
        res.status(201).send(newComment);
    } catch (error) {
        logger.error('Error saving comment:', error);
        res.status(500).send({ error: 'Error saving comment' });
    }
});

app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error('Error fetching comments:', error);
        res.status(500).send({ error: 'Error fetching comments' });
    }
});

app.delete('/api/comments/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        await Comment.findByIdAndDelete(id);
        res.status(200).send({ message: 'Comment deleted' });
    } catch (error) {
        logger.error('Error deleting comment:', error);
        res.status(500).send({ error: 'Error deleting comment' });
    }
});

// Utility Functions
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
        logger.info('Refresh Token Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error refreshing Bungie token:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
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
        logger.info('Pending Clan Members Response:', response.data);
        return response.data.Response.results;
    } catch (error) {
        logger.error('Error fetching pending clan members:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
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
        logger.error('Error fetching pending clan members:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

app.get('/api/clan/pending/fromdb', verifyToken, async (req, res) => {
    try {
        const pendingMembers = await PendingMember.find();
        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error('Error retrieving pending clan members from DB:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Additional Security Configurations
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect(`https://${req.headers.host}${req.url}`);
        }
    }
    next();
});

// Protected Admin Dashboard Route
app.get('/admin-dashboard-:random.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// Login Route
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
    logger.info('Stored dashboardURL in session:', req.session.dashboardURL);

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
            logger.error('Error saving session:', err);
            return res.status(500).json({ auth: false, message: 'Error saving session' });
        }
        res.status(200).json({ auth: true, redirect: dashboardURL });
    });
});

// Logout Route
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy();
    res.redirect('/admin-login.html');
});

// Video Routes
app.get('/api/videos/public', async (req, res) => {
    try {
        res.json([]);
    } catch (err) {
        logger.error('Error retrieving video metadata:', err);
        res.status(500).send({ error: 'Error retrieving video metadata' });
    }
});

app.post('/api/videos', verifyToken, async (req, res) => {
    const videoMetadata = {
        url: req.body.url.replace('youtu.be', 'youtube.com/embed'),
        title: req.body.title,
        description: req.body.description,
        category: req.body.category,
        uploadedAt: new Date()
    };

    try {
        res.status(201).send({ message: 'Video added', video: videoMetadata });
    } catch (err) {
        logger.error('Error saving video metadata:', err);
        res.status(500).send({ error: 'Error saving video metadata' });
    }
});

// Video Status Variables
let currentVideoTitle = 'Loading...';
let currentVideoUrl = '';
let videoStartTimestamp = Date.now();

// Socket.IO Connection Handling
io.on('connection', (socket) => {
    logger.info('New client connected');

    socket.emit('nowPlayingUpdate', { 
        title: currentVideoTitle, 
        videoUrl: currentVideoUrl, 
        startTimestamp: videoStartTimestamp, 
        currentTime: (Date.now() - videoStartTimestamp) / 1000 
    });

    socket.on('updateVideoTitle', ({ title, videoUrl, currentTime }) => {
        logger.info('Received video title:', title);
        logger.info('Received video URL:', videoUrl);
        logger.info('Received current time:', currentTime);

        currentVideoTitle = title;
        currentVideoUrl = videoUrl;
        videoStartTimestamp = Date.now() - (currentTime * 1000);

        io.emit('nowPlayingUpdate', { 
            title, 
            videoUrl, 
            startTimestamp: videoStartTimestamp,
            currentTime: currentTime 
        });

        if (title === 'Offline') {
            io.emit('nowPlayingUpdate', {
                title: 'Offline',
                videoUrl: '',
                startTimestamp: 0,
                currentTime: 0
            });
        }
    });

    socket.on('disconnect', () => {
        logger.info('Client disconnected');
    });
});

// Real-time Data Endpoint
app.post('/api/update', (req, res) => {
    const data = req.body;
    io.emit('updateData', data);
    res.status(200).send({ message: 'Data sent to clients' });
});

// Active Users Tracking
let activeUsers = [];

async function fetchLocationData(ip) {
    try {
        const singleIp = ip.split(',')[0].trim();
        const response = await axios.get(`https://ipinfo.io/${singleIp}?token=14eb346301d8b9`);
        const { ip: userIP, city, region, country } = response.data;
        return { ip: userIP, city, region, country };
    } catch (error) {
        logger.error('Error fetching location data:', error);
        return { ip, city: 'Unknown', region: 'Unknown', country: 'Unknown' };
    }
}

function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
        return ip.replace('::ffff:', '');
    }
    return ip;
}

io.on('connection', async (socket) => {  
    let ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

    if (ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }

    ip = normalizeIp(ip);

    if (!activeUsers.some(user => user.ip === ip)) {
        const locationData = await fetchLocationData(ip);
        activeUsers.push(locationData);
    }

    io.emit('activeUsersUpdate', { users: activeUsers });

    socket.on('disconnect', () => {
        activeUsers = activeUsers.filter(user => user.ip !== ip);
        io.emit('activeUsersUpdate', { users: activeUsers });
    });
});

// Additional Routes
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
        logger.error('Error checking YouTube API:', error);
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
        logger.error('Error checking Bungie API:', error);
        return res.json({ status: 'Bungie API is unavailable', available: false });
    }
});


app.get('/weather', async (req, res) => {
    const city = req.query.city || 'Leeds';
    const units = 'metric'; // or 'imperial' for Fahrenheit
    const apiKey = process.env.OPENWEATHERMAP_API_KEY;
    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            return res.status(response.status).json({ error: 'Failed to fetch weather data' });
        }
        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('Error fetching weather data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Start the server
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
